"""
Email Parser Module
-------------------
Parses .eml files into structured data using Python's built-in `email` library.

Usage:
    from email_analysis.email_parser import parse_eml_file
    email_data = parse_eml_file("sample.eml")
"""

import email
import email.policy
from email.message import EmailMessage
import logging
from pathlib import Path
import re

logger = logging.getLogger(__name__)


def parse_eml_file(file_path: str) -> dict:
    """
    Parse a .eml file and return a dictionary with key email fields.

    Args:
        file_path: Path to the .eml file on disk.

    Returns:
        Dictionary containing:
          - subject, from, to, date, message_id
          - headers  (list of (name, value) tuples)
          - body_text (plain-text body, if available)
          - body_html (HTML body, if available)
          - raw_message (the full email.message.EmailMessage object)
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"EML file not found: {file_path}")

    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=email.policy.default)

    result = {
        "subject": msg.get("Subject", ""),
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "return_path": msg.get("Return-Path", ""),
        "reply_to": msg.get("Reply-To", ""),
        "received": [str(value) for value in msg.get_all("Received", [])],
        "headers": list(msg.items()),
        "body_text": _get_body(msg, "text/plain"),
        "body_html": _get_body(msg, "text/html"),
        "mime_parts": _collect_mime_parts(msg),
        "raw_message": msg,
    }
    _recover_pasted_headers(result)

    logger.info("Parsed email: subject=%s from=%s", result["subject"], result["from"])
    return result


def _get_body(msg: EmailMessage, content_type: str) -> str:
    """Select the actual body, excluding attachments and nested attached email."""
    part = msg.get_body(preferencelist=(content_type.split("/", 1)[1],))
    if part is None:
        return ""
    try:
        payload = part.get_content()
    except (LookupError, UnicodeError):
        logger.warning("Invalid MIME charset; decoding body as UTF-8 with replacement")
        raw = part.get_payload(decode=True)
        return raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else ""
    return payload if isinstance(payload, str) else ""


def _collect_mime_parts(msg: EmailMessage) -> list[dict]:
    """Preserve MIME provenance without duplicating potentially large payloads."""
    parts = list(msg.walk()) if msg.is_multipart() else [msg]
    return [
        {
            "content_type": part.get_content_type(),
            "content_disposition": part.get_content_disposition() or "",
            "content_transfer_encoding": part.get("Content-Transfer-Encoding", ""),
            "charset": part.get_content_charset() or "",
        }
        for part in parts
        if not part.is_multipart()
    ]


def _recover_pasted_headers(result: dict) -> None:
    """Recover common headers when pasted text has a blank line after Subject."""
    body = result.get("body_text") or ""
    if not body:
        return

    lines = body.splitlines()
    recovered: dict[str, str] = {}
    consumed = 0
    saw_header = False

    for idx, line in enumerate(lines):
        if not line.strip():
            consumed = idx + 1 if saw_header else 0
            break

        match = re.match(r"^(Subject|From|To|Date|Message-ID)\s*:\s*(.*)$", line, re.I)
        if not match:
            return

        name = _canonical_header_name(match.group(1))
        recovered[name] = match.group(2).strip()
        saw_header = True
        consumed = idx + 1

    if not recovered:
        return

    field_map = {
        "Subject": "subject",
        "From": "from",
        "To": "to",
        "Date": "date",
        "Message-ID": "message_id",
    }
    for header_name, field_name in field_map.items():
        if not result.get(field_name) and recovered.get(header_name):
            result[field_name] = recovered[header_name]

    existing_headers = {name.lower() for name, _value in result.get("headers", [])}
    for header_name, value in recovered.items():
        if header_name.lower() not in existing_headers:
            result["headers"].append((header_name, value))

    if consumed > 0:
        result["body_text"] = "\n".join(lines[consumed:]).lstrip()


def _canonical_header_name(name: str) -> str:
    normalized = name.strip().lower()
    if normalized == "message-id":
        return "Message-ID"
    return normalized.title()
