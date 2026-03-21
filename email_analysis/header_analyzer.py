"""
Header Analyzer Module
----------------------
Checks SPF/DKIM/DMARC and performs header forensics for phishing triage.

These headers are set by the receiving mail server - the bot simply reads and
interprets them to determine whether the email passed authentication checks.

Usage:
    from email_analysis.header_analyzer import analyze_headers
    auth_results = analyze_headers(email_data["headers"])
"""

import logging
import re

logger = logging.getLogger(__name__)

_EMAIL_EXTRACT_RE = re.compile(r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_MESSAGE_ID_DOMAIN_RE = re.compile(r"<[^@<>]+@([A-Za-z0-9.-]+)>")

# High-value brands commonly impersonated in sender display names.
_BRAND_DOMAINS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.me"},
    "microsoft": {
        "microsoft.com",
        "outlook.com",
        "office.com",
        "office365.com",
        "live.com",
    },
    "google": {"google.com", "gmail.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com"},
    "outlook": {"outlook.com", "outlook.live.com"},
    "office365": {"office.com", "office365.com"},
}


def analyze_headers(headers: list[tuple[str, str]]) -> dict:
    """
    Analyze SPF, DKIM, and DMARC results from email headers.

    Args:
        headers: List of (header_name, header_value) tuples from the parsed email.

    Returns:
        Dictionary with keys: spf, dkim, dmarc, forensics.
        The first three values are auth dicts with 'result' and 'details'.
        'forensics' contains sender/path anomalies and forensic findings.
    """
    auth_results = {
        "spf": {"result": "none", "details": ""},
        "dkim": {"result": "none", "details": ""},
        "dmarc": {"result": "none", "details": ""},
    }

    for name, value in headers:
        lower_name = name.lower()

        # ── SPF ──────────────────────────────────────────────
        if lower_name == "received-spf":
            auth_results["spf"] = _parse_received_spf(value)

        # ── Authentication-Results (SPF / DKIM / DMARC) ─────
        if lower_name == "authentication-results":
            _parse_authentication_results(value, auth_results)

    auth_results["forensics"] = _run_header_forensics(headers)

    logger.info(
        "Auth results – SPF: %s | DKIM: %s | DMARC: %s | Header findings: %d",
        auth_results["spf"]["result"],
        auth_results["dkim"]["result"],
        auth_results["dmarc"]["result"],
        len(auth_results["forensics"]["findings"]),
    )
    return auth_results


def _parse_received_spf(value: str) -> dict:
    """Parse the Received-SPF header (e.g., 'pass (domain of ...) ...')."""
    value_lower = value.strip().lower()
    for keyword in (
        "pass",
        "fail",
        "softfail",
        "neutral",
        "none",
        "temperror",
        "permerror",
    ):
        if value_lower.startswith(keyword):
            return {"result": keyword, "details": value.strip()}
    return {"result": "unknown", "details": value.strip()}


def _parse_authentication_results(value: str, auth_results: dict) -> None:
    """
    Parse the Authentication-Results header which may contain
    spf=pass, dkim=pass, dmarc=pass (or fail, etc.).
    """
    value_lower = value.lower()

    # SPF
    spf_match = re.search(r"spf\s*=\s*(\w+)", value_lower)
    if spf_match:
        auth_results["spf"] = {
            "result": spf_match.group(1),
            "details": value.strip(),
        }

    # DKIM
    dkim_match = re.search(r"dkim\s*=\s*(\w+)", value_lower)
    if dkim_match:
        auth_results["dkim"] = {
            "result": dkim_match.group(1),
            "details": value.strip(),
        }

    # DMARC
    dmarc_match = re.search(r"dmarc\s*=\s*(\w+)", value_lower)
    if dmarc_match:
        auth_results["dmarc"] = {
            "result": dmarc_match.group(1),
            "details": value.strip(),
        }


def _run_header_forensics(headers: list[tuple[str, str]]) -> dict:
    """Run sender/path header checks and return forensic findings."""
    from_raw = _get_header_value(headers, "from")
    return_path_raw = _get_header_value(headers, "return-path")
    reply_to_raw = _get_header_value(headers, "reply-to")
    message_id_raw = _get_header_value(headers, "message-id")
    received_chain = get_received_chain(headers)

    from_email = _extract_email(from_raw)
    return_path_email = _extract_email(return_path_raw)
    reply_to_email = _extract_email(reply_to_raw)

    from_domain = _extract_domain(from_email)
    return_path_domain = _extract_domain(return_path_email)
    reply_to_domain = _extract_domain(reply_to_email)
    message_id_domain = _extract_message_id_domain(message_id_raw)

    findings: list[dict] = []

    if from_domain and return_path_domain and from_domain != return_path_domain:
        findings.append(
            {
                "type": "return_path_mismatch",
                "summary": "Return-Path domain differs from From domain",
                "details": f"From={from_domain}, Return-Path={return_path_domain}",
                "risk_score": 15,
            }
        )

    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        findings.append(
            {
                "type": "reply_to_mismatch",
                "summary": "Reply-To domain differs from From domain",
                "details": f"From={from_domain}, Reply-To={reply_to_domain}",
                "risk_score": 10,
            }
        )

    if from_domain and message_id_domain and from_domain != message_id_domain:
        findings.append(
            {
                "type": "message_id_mismatch",
                "summary": "Message-ID domain differs from From domain",
                "details": f"From={from_domain}, Message-ID={message_id_domain}",
                "risk_score": 5,
            }
        )

    if not received_chain:
        findings.append(
            {
                "type": "missing_received_headers",
                "summary": "No Received headers found",
                "details": "Message route cannot be reconstructed",
                # Missing relay metadata reduces confidence/completeness, not phishing certainty.
                "risk_score": 0,
                "evidence_state": "none",
            }
        )
    elif len(received_chain) > 7:
        findings.append(
            {
                "type": "excessive_hops",
                "summary": "Unusually long Received chain",
                "details": f"Received hop count={len(received_chain)}",
                "risk_score": 5,
            }
        )

    brand_finding = _detect_sender_brand_impersonation(from_raw, from_domain)
    if brand_finding:
        findings.append(brand_finding)

    return {
        "from": from_raw,
        "from_email": from_email,
        "from_domain": from_domain,
        "return_path": return_path_raw,
        "return_path_domain": return_path_domain,
        "reply_to": reply_to_raw,
        "reply_to_domain": reply_to_domain,
        "message_id": message_id_raw,
        "message_id_domain": message_id_domain,
        "received_hops": len(received_chain),
        "findings": findings,
    }


def _get_header_value(headers: list[tuple[str, str]], header_name: str) -> str:
    """Return the first matching header value (case-insensitive)."""
    for name, value in headers:
        if name.lower() == header_name.lower():
            return value.strip()
    return ""


def _extract_email(value: str) -> str:
    """Extract a bare email address from a header string."""
    if not value:
        return ""
    match = _EMAIL_EXTRACT_RE.search(value)
    if not match:
        return ""
    return match.group(1).strip().lower()


def _extract_domain(email_addr: str) -> str:
    """Extract and normalize domain from an email address."""
    if "@" not in email_addr:
        return ""
    return email_addr.split("@", 1)[1].strip().lower().rstrip(".")


def _extract_message_id_domain(message_id: str) -> str:
    """Extract domain part from Message-ID header."""
    if not message_id:
        return ""
    match = _MESSAGE_ID_DOMAIN_RE.search(message_id)
    if not match:
        return ""
    return match.group(1).strip().lower().rstrip(".")


def _detect_sender_brand_impersonation(from_raw: str, from_domain: str) -> dict | None:
    """
    Flag display-name brand impersonation.

    Example: "PayPal Security <alert@evil.com>"
    """
    if not from_raw or not from_domain:
        return None

    display_name = from_raw.split("<", 1)[0].strip().strip('"').lower()
    if not display_name:
        return None

    for brand, legit_domains in _BRAND_DOMAINS.items():
        if brand in display_name and from_domain not in legit_domains:
            return {
                "type": "sender_brand_impersonation",
                "summary": "Brand appears in display name but sender domain is unofficial",
                "details": f"Brand={brand}, sender_domain={from_domain}",
                "risk_score": 20,
            }

    return None


def get_return_path(headers: list[tuple[str, str]]) -> str:
    """Extract the Return-Path header (envelope sender)."""
    for name, value in headers:
        if name.lower() == "return-path":
            return value.strip()
    return ""


def get_received_chain(headers: list[tuple[str, str]]) -> list[str]:
    """Return all Received headers in order (useful for hop analysis)."""
    return [value.strip() for name, value in headers if name.lower() == "received"]
