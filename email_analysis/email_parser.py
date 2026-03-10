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
        "headers": list(msg.items()),
        "body_text": _get_body(msg, "text/plain"),
        "body_html": _get_body(msg, "text/html"),
        "raw_message": msg,
    }

    logger.info("Parsed email: subject=%s from=%s", result["subject"], result["from"])
    return result


def _get_body(msg: EmailMessage, content_type: str) -> str:
    """Extract the first body part matching the given content type."""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == content_type:
                payload = part.get_content()
                if isinstance(payload, str):
                    return payload
        return ""
    else:
        if msg.get_content_type() == content_type:
            payload = msg.get_content()
            return payload if isinstance(payload, str) else ""
        return ""
