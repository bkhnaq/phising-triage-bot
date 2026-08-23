"""Build safe RFC 822 messages from the regression corpus specification."""

from __future__ import annotations

import html as html_module
import re
from email.message import EmailMessage
from email.utils import parseaddr
from pathlib import Path

FIXED_DATE = "Sun, 23 Aug 2026 09:00:00 +0700"


def build_email(sample: dict, *, repository_root: Path | None = None) -> str:
    """Return one raw email, reading a checked-in fixture when requested."""
    raw_fixture = sample.get("raw_fixture")
    if raw_fixture:
        root = repository_root or Path(__file__).resolve().parents[1]
        fixture = (root / str(raw_fixture)).resolve()
        if root.resolve() not in fixture.parents:
            raise ValueError(f"Raw fixture escapes repository root: {raw_fixture}")
        return fixture.read_text(encoding="utf-8")

    spec = sample.get("email")
    if not isinstance(spec, dict):
        raise ValueError(f"Sample {sample.get('sample_id')} has no email specification")

    sender = str(spec.get("from", "Sender <sender@example.org>"))
    sender_address = parseaddr(sender)[1]
    sender_domain = _email_domain(sender_address) or "example.org"
    return_path = str(spec.get("return_path", sender_address))
    message_id_domain = str(spec.get("message_id_domain", sender_domain))

    message = EmailMessage()
    message["From"] = sender
    message["To"] = str(spec.get("to", "analyst@corp.example.org"))
    message["Subject"] = str(spec.get("subject", "Regression fixture"))
    message["Date"] = str(spec.get("date", FIXED_DATE))
    message["Message-ID"] = f"<{sample['sample_id']}@{message_id_domain}>"
    message["Return-Path"] = f"<{return_path.strip('<>')}>"
    if spec.get("reply_to"):
        message["Reply-To"] = str(spec["reply_to"])

    if not bool(spec.get("omit_received", False)):
        origin_ip = (
            "203.0.113.25"
            if sample.get("environment") in {"TEST", "LAB"}
            else "93.184.216.34"
        )
        message["Received"] = (
            f"from relay.{sender_domain} (relay.{sender_domain} [{origin_ip}]) "
            f"by mx.corp.example.org with ESMTP id {sample['sample_id']}; {FIXED_DATE}"
        )

    if not bool(spec.get("omit_authentication", False)):
        auth = spec.get("auth") or {}
        spf = str(auth.get("spf", "none"))
        dkim = str(auth.get("dkim", "none"))
        dmarc = str(auth.get("dmarc", "none"))
        mailfrom = str(
            auth.get("mailfrom", _email_domain(return_path) or sender_domain)
        )
        header_from = str(auth.get("header_from", sender_domain))
        dkim_domain = str(auth.get("dkim_domain", header_from))
        message["Authentication-Results"] = (
            "mx.corp.example.org; "
            f"spf={spf} smtp.mailfrom={mailfrom}; "
            f"dkim={dkim} header.d={dkim_domain}; "
            f"dmarc={dmarc} header.from={header_from}"
        )

    plain = str(spec.get("body_text", ""))
    html = str(spec.get("body_html", ""))
    if html:
        if not plain:
            plain = html_module.unescape(re.sub(r"<[^>]+>", " ", html))
            plain = re.sub(r"\s+", " ", plain).strip()
        message.set_content(plain)
        message.add_alternative(html, subtype="html")
    else:
        message.set_content(plain)

    for attachment in spec.get("attachments", []):
        content_type = str(attachment.get("content_type", "application/octet-stream"))
        maintype, _, subtype = content_type.partition("/")
        message.add_attachment(
            str(attachment.get("content", "INERT REGRESSION FIXTURE")).encode("utf-8"),
            maintype=maintype or "application",
            subtype=subtype or "octet-stream",
            filename=str(attachment.get("filename", "fixture.bin")),
        )

    return message.as_string()


def _email_domain(value: str) -> str:
    address = parseaddr(value)[1] or value
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[-1].lower().rstrip(".")
