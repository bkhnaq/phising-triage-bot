"""Canonical text preparation shared by training and local inference."""

from __future__ import annotations

import hashlib
import html
import re
import unicodedata
from collections.abc import Mapping, Sequence
from urllib.parse import urlsplit

_CONTROL_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_HTML_TAG_PATTERN = re.compile(r"<[^>]+>")
_WHITESPACE_PATTERN = re.compile(r"\s+")


def normalize_text(value: object) -> str:
    """Return Unicode-normalized, control-free, single-spaced text."""
    if value is None:
        return ""
    text = unicodedata.normalize("NFKC", str(value))
    text = _CONTROL_PATTERN.sub(" ", text)
    return _WHITESPACE_PATTERN.sub(" ", text).strip()


def content_sha256(subject: str, sender: str, body: str) -> str:
    """Hash normalized semantic content for exact duplicate detection."""
    canonical = "\x1f".join(
        (normalize_text(subject), normalize_text(sender), normalize_text(body))
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def balanced_truncate(text: str, max_chars: int, marker: str = "\n[...]\n") -> str:
    """Truncate the middle while retaining evidence at both ends."""
    if max_chars <= len(marker):
        raise ValueError("max_chars must be greater than marker length")
    if len(text) <= max_chars:
        return text
    remaining = max_chars - len(marker)
    head = (remaining + 1) // 2
    tail = remaining - head
    return f"{text[:head]}{marker}{text[-tail:]}"


def prepare_model_input(text: str, max_length: int) -> str:
    """Apply the shared character bound before model tokenization."""
    if isinstance(max_length, bool) or not isinstance(max_length, int):
        raise ValueError("max_length must be a positive integer")
    if max_length <= 0:
        raise ValueError("max_length must be a positive integer")
    return balanced_truncate(text, max(80, max_length * 4))


def _clean_html(value: object) -> str:
    raw = html.unescape(str(value or ""))
    return normalize_text(_HTML_TAG_PATTERN.sub(" ", raw))


def _url_hosts(urls: Sequence[Mapping[str, object]] | None) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()
    for item in urls or ():
        raw_url = normalize_text(item.get("url", ""))
        if not raw_url:
            continue
        try:
            host = (urlsplit(raw_url).hostname or "").lower().rstrip(".")
        except ValueError:
            continue
        if host and host not in seen:
            seen.add(host)
            hosts.append(host)
    return hosts


def format_email_text(
    email_data: Mapping[str, object],
    urls: Sequence[Mapping[str, object]] | None = None,
    max_chars: int = 12000,
) -> str:
    """Format an email while reserving space for high-value metadata."""
    if max_chars < 80:
        raise ValueError("max_chars must be at least 80")

    subject = normalize_text(email_data.get("subject", ""))
    sender = normalize_text(email_data.get("from") or email_data.get("sender") or "")
    hosts = ", ".join(_url_hosts(urls)) or "(none)"
    body = normalize_text(email_data.get("body_text") or email_data.get("body") or "")
    if not body:
        body = _clean_html(email_data.get("body_html", ""))

    prefix = (
        f"Subject: {subject or '(none)'}\n"
        f"From: {sender or '(none)'}\n"
        f"URL hosts: {hosts}\n"
        "Body:\n"
    )
    available = max_chars - len(prefix)
    marker = "\n[...]\n"
    if available <= len(marker):
        raise ValueError("max_chars is too small for email metadata")
    return prefix + balanced_truncate(body, available, marker=marker)
