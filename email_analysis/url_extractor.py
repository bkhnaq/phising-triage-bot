"""
URL Extractor Module
--------------------
Extracts URLs from email bodies, detects shortened URLs, and expands them.

Usage:
    from email_analysis.url_extractor import extract_urls
    url_info = extract_urls(body_text, body_html)
"""

import logging
import re
from html.parser import HTMLParser
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

# Regex to capture http/https URLs from plain text
_URL_REGEX = re.compile(
    r"https?://[^\s<>\"')\]},;]+",
    re.IGNORECASE,
)

# Well-known URL shortener domains
_SHORTENER_DOMAINS = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "rebrand.ly",
        "cutt.ly",
        "shorturl.at",
        "tiny.cc",
        "lnkd.in",
        "rb.gy",
    }
)

# Request timeout for expanding shortened URLs (seconds)
_EXPAND_TIMEOUT = 5


def extract_urls(body_text: str = "", body_html: str = "") -> list[dict]:
    """
    Extract all URLs from the email body (plain text + HTML).

    Args:
        body_text: Plain-text email body.
        body_html: HTML email body.

    Returns:
        List of dicts, each containing:
            - url: the original URL found
            - domain: extracted domain
            - is_shortened: bool
            - expanded_url: resolved URL if shortened, else same as url
    """
    raw_urls: set[str] = set()

    # 1) Extract from plain text
    if body_text:
        raw_urls.update(_URL_REGEX.findall(body_text))

    # 2) Extract from HTML (href attributes + visible text)
    if body_html:
        raw_urls.update(_extract_urls_from_html(body_html))

    results: list[dict] = []
    for url in sorted(raw_urls):
        domain = _extract_domain(url)
        is_shortened = domain.lower() in _SHORTENER_DOMAINS
        expanded = _expand_url(url) if is_shortened else url

        results.append(
            {
                "url": url,
                "domain": domain,
                "is_shortened": is_shortened,
                "expanded_url": expanded,
            }
        )

    logger.info("Extracted %d unique URL(s) from email body", len(results))
    return results


# ── HTML link extractor ──────────────────────────────────────


class _LinkParser(HTMLParser):
    """Simple HTML parser that collects href values and text URLs."""

    def __init__(self):
        super().__init__()
        self.urls: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        if tag == "a":
            for attr_name, attr_value in attrs:
                if attr_name == "href" and attr_value:
                    self.urls.append(attr_value)

    def handle_data(self, data: str):
        self.urls.extend(_URL_REGEX.findall(data))


def _extract_urls_from_html(html: str) -> list[str]:
    """Parse HTML and return all URLs found in hrefs and visible text."""
    parser = _LinkParser()
    parser.feed(html)
    return parser.urls


# ── Helpers ──────────────────────────────────────────────────


def _extract_domain(url: str) -> str:
    """Return the network-location (domain) part of a URL."""
    parsed = urlparse(url)
    return parsed.netloc or ""


def _expand_url(short_url: str) -> str:
    """
    Follow redirects on a shortened URL and return the final destination.
    Returns the original URL on any error.
    """
    try:
        resp = requests.head(
            short_url,
            allow_redirects=True,
            timeout=_EXPAND_TIMEOUT,
        )
        return resp.url
    except requests.RequestException as exc:
        logger.warning("Could not expand URL %s: %s", short_url, exc)
        return short_url
