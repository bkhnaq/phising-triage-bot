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

from urllib3.exceptions import HTTPError

from config.settings import OFFLINE_MODE, THREAT_INTEL_CACHE_TTL_SECONDS
from email_analysis.domain_utils import registered_domain
from email_analysis.safe_http import SafeHTTPError, fetch_url
from email_analysis.url_utils import analyze_url
from threat_intel.cache import TTLCache

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

_EXPAND_CACHE = TTLCache(THREAT_INTEL_CACHE_TTL_SECONDS)


def extract_urls(
    body_text: str = "",
    body_html: str = "",
    max_urls: int | None = None,
) -> list[dict]:
    """
    Extract all URLs from the email body (plain text + HTML).

    Args:
        body_text: Plain-text email body.
        body_html: HTML email body.
        max_urls: Maximum number of unique URLs to analyze.

    Returns:
        List of dicts, each containing:
            - url: the original URL found
            - domain: extracted domain
            - is_shortened: bool
            - expanded_url: resolved URL if shortened, else same as url
    """
    raw_urls = sorted(_collect_raw_urls(body_text, body_html))
    link_relationships = _extract_link_relationships(body_html)
    if max_urls is not None:
        raw_urls = raw_urls[: max(0, max_urls)]

    results: list[dict] = []
    for url in raw_urls:
        try:
            url_analysis = analyze_url(url)
        except (UnicodeError, ValueError):
            logger.warning("Skipping malformed URL during extraction")
            continue
        domain = url_analysis.domain
        is_shortened = domain.lower() in _SHORTENER_DOMAINS
        expanded = _expand_url(url) if is_shortened else url

        link_evidence = _best_link_evidence(url, link_relationships)
        results.append(
            {
                "url": url,
                "domain": domain,
                "registered_domain": url_analysis.registered_domain,
                "normalized_url": url_analysis.normalized_url,
                "decoded_domain": url_analysis.decoded_domain,
                "is_shortened": is_shortened,
                "expanded_url": expanded,
                "url_risk_score": url_analysis.risk_score,
                "url_warnings": url_analysis.suspicious_reasons,
                "has_userinfo": url_analysis.has_userinfo,
                "is_punycode": url_analysis.is_punycode,
                "is_ip_host": url_analysis.is_ip_host,
                **link_evidence,
            }
        )

    logger.info("Extracted %d unique URL(s) from email body", len(results))
    return results


def count_unique_urls(body_text: str = "", body_html: str = "") -> int:
    """Count unique raw URLs without normalizing or expanding them."""
    return len(_collect_raw_urls(body_text, body_html))


def _collect_raw_urls(body_text: str, body_html: str) -> set[str]:
    """Collect deduplicated URL strings from plain-text and HTML bodies."""
    raw_urls: set[str] = set()
    if body_text:
        raw_urls.update(_URL_REGEX.findall(body_text))
    if body_html:
        raw_urls.update(_extract_urls_from_html(body_html))
    return raw_urls


# ── HTML link extractor ──────────────────────────────────────


class _LinkParser(HTMLParser):
    """Collect hrefs, visible URLs, and anchor text-to-target relationships."""

    def __init__(self):
        super().__init__()
        self.urls: list[str] = []
        self.link_relationships: list[dict] = []
        self._anchor_href: str | None = None
        self._anchor_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        if tag == "a":
            self._anchor_href = None
            self._anchor_text = []
            for attr_name, attr_value in attrs:
                if attr_name.lower() == "href" and attr_value:
                    self._anchor_href = attr_value.strip()
                    self.urls.append(self._anchor_href)

    def handle_data(self, data: str):
        self.urls.extend(_URL_REGEX.findall(data))
        if self._anchor_href is not None:
            self._anchor_text.append(data)

    def handle_endtag(self, tag: str):
        if tag.lower() != "a" or self._anchor_href is None:
            return
        visible_text = " ".join(self._anchor_text).strip()
        for displayed_url in _URL_REGEX.findall(visible_text):
            self.link_relationships.append(
                {
                    "href": self._anchor_href,
                    "displayed_url": displayed_url,
                    "anchor_text": visible_text,
                }
            )
        self._anchor_href = None
        self._anchor_text = []


def _extract_urls_from_html(html: str) -> list[str]:
    """Parse HTML and return all URLs found in hrefs and visible text."""
    parser = _LinkParser()
    parser.feed(html)
    return parser.urls


def _extract_link_relationships(html: str) -> list[dict]:
    """Return URL-like anchor text paired with its actual href target."""
    if not html:
        return []
    parser = _LinkParser()
    try:
        parser.feed(html)
    except (UnicodeError, ValueError):
        logger.debug("Could not parse HTML anchor relationships")
        return []
    return parser.link_relationships


def _best_link_evidence(url: str, relationships: list[dict]) -> dict:
    """Describe whether an HTML anchor's displayed URL matches its target."""
    relevant = [item for item in relationships if item.get("href") == url]
    if not relevant:
        return {
            "link_target_comparison": "unavailable",
            "deceptive_hyperlink": False,
        }

    candidates: list[dict] = []
    for item in relevant:
        displayed_url = str(item.get("displayed_url", ""))
        try:
            actual_domain = (urlparse(url).hostname or "").lower()
            displayed_domain = (urlparse(displayed_url).hostname or "").lower()
            actual_root = registered_domain(actual_domain)
            displayed_root = registered_domain(displayed_domain)
        except (UnicodeError, ValueError):
            continue
        if not actual_root or not displayed_root:
            continue
        mismatch = actual_root != displayed_root
        candidates.append(
            {
                "link_target_comparison": "mismatch" if mismatch else "match",
                "deceptive_hyperlink": mismatch,
                "displayed_url": displayed_url,
                "displayed_domain": displayed_domain,
                "actual_domain": actual_domain,
                "anchor_text": str(item.get("anchor_text", ""))[:500],
            }
        )

    if not candidates:
        return {
            "link_target_comparison": "unavailable",
            "deceptive_hyperlink": False,
        }
    return next(
        (item for item in candidates if item["deceptive_hyperlink"]), candidates[0]
    )


# ── Helpers ──────────────────────────────────────────────────


def _extract_domain(url: str) -> str:
    """Return the network-location (domain) part of a URL."""
    parsed = urlparse(url)
    return parsed.hostname or ""


def _expand_url(short_url: str) -> str:
    """
    Follow redirects on a shortened URL and return the final destination.
    Returns the original URL on any error.
    """
    if OFFLINE_MODE:
        return short_url

    found, cached = _EXPAND_CACHE.get(short_url)
    if found:
        return cached

    try:
        resp = fetch_url(
            short_url,
            method="HEAD",
            max_bytes=0,
        )
        expanded = resp.url
    except (SafeHTTPError, HTTPError, OSError) as exc:
        logger.warning("Could not expand URL %s: %s", short_url, exc)
        expanded = short_url

    _EXPAND_CACHE.set(short_url, expanded)
    return expanded
