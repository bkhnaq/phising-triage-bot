"""Lightweight landing-page intelligence for extracted URLs."""

from __future__ import annotations

import codecs
from html.parser import HTMLParser
import logging
import re
from urllib.parse import urljoin, urlparse

from urllib3.exceptions import HTTPError

from config.settings import (
    OFFLINE_MODE,
    SAFE_HTTP_MAX_BYTES,
    THREAT_INTEL_CACHE_TTL_SECONDS,
)
from email_analysis.domain_utils import any_domain_match, registered_domain
from email_analysis.safe_http import SafeHTTPError, fetch_url
from threat_intel.cache import TTLCache

logger = logging.getLogger(__name__)

_MAX_PAGES = 5
_CACHE = TTLCache(THREAT_INTEL_CACHE_TTL_SECONDS)
_TITLE_KEYWORDS = frozenset({"login", "sign in", "verify", "account", "password"})
_BRANDS = {
    "paypal": {"paypal.com", "paypal.me"},
    "microsoft": {"microsoft.com", "office.com", "office365.com", "live.com"},
    "google": {"google.com", "gmail.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com"},
    "chase": {"chase.com"},
}


class _LandingParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title_parts: list[str] = []
        self.forms: list[dict] = []
        self.password_fields = 0
        self.meta_refresh_urls: list[str] = []
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        attr = {k.lower(): v or "" for k, v in attrs}
        tag_lower = tag.lower()
        if tag_lower == "title":
            self._in_title = True
        elif tag_lower == "form":
            self.forms.append(
                {
                    "action": attr.get("action", ""),
                    "method": (attr.get("method", "") or "GET").upper(),
                }
            )
        elif tag_lower == "input" and attr.get("type", "text").lower() == "password":
            self.password_fields += 1
        elif tag_lower == "meta" and attr.get("http-equiv", "").lower() == "refresh":
            match = re.search(r"url\s*=\s*([^;]+)", attr.get("content", ""), re.I)
            if match:
                self.meta_refresh_urls.append(match.group(1).strip("'\" "))

    def handle_endtag(self, tag: str):
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data: str):
        if self._in_title:
            self.title_parts.append(data.strip())


def analyze_landing_pages(urls: list[dict], max_pages: int = _MAX_PAGES) -> list[dict]:
    """Fetch and inspect a small set of landing pages."""
    findings: list[dict] = []
    seen: set[str] = set()

    for item in urls:
        if len(findings) >= max_pages:
            break
        url = item.get("expanded_url") or item.get("normalized_url") or item.get("url")
        if not url or url in seen:
            continue
        seen.add(url)
        findings.append(analyze_landing_page(url))

    return findings


def analyze_landing_page(url: str) -> dict:
    result: dict = {
        "url": url,
        "final_url": url,
        "domain": "",
        "title": "",
        "forms": [],
        "password_fields": 0,
        "meta_refresh_urls": [],
        "brand_mentions": [],
        "findings": [],
        "risk_score": 0,
        "state": "not_checked",
        "error": None,
    }

    if OFFLINE_MODE:
        result["error"] = "offline mode enabled"
        return result

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        result["error"] = "unsupported URL scheme"
        return result

    found, cached = _CACHE.get(url)
    if found:
        return cached

    try:
        resp = fetch_url(
            url,
            method="GET",
            max_bytes=SAFE_HTTP_MAX_BYTES,
        )
        content_type = resp.headers.get("content-type", "").lower()
        result["final_url"] = resp.url
        result["domain"] = registered_domain(urlparse(resp.url).hostname or "")
        if "text/html" not in content_type:
            result["state"] = "clean"
            _CACHE.set(url, result)
            return result

        html = resp.body.decode(_response_charset(content_type), errors="replace")
        _analyze_html(result, html)
        result["state"] = "suspicious" if result["risk_score"] > 0 else "clean"

    except SafeHTTPError as exc:
        result["error"] = exc.code
        result["state"] = "unavailable"
        logger.debug("Landing page analysis failed for %s: %s", url, exc)
    except (HTTPError, OSError, UnicodeError, ValueError) as exc:
        result["error"] = "Landing page analysis failed"
        result["state"] = "unavailable"
        logger.debug("Landing page analysis failed for %s: %s", url, exc)

    _CACHE.set(url, result)
    return result


def _response_charset(content_type: str) -> str:
    match = re.search(
        r"(?:^|;)\s*charset\s*=\s*['\"]?([^;'\"\s]+)",
        content_type,
        re.IGNORECASE,
    )
    if match is None:
        return "utf-8"
    try:
        return codecs.lookup(match.group(1)).name
    except LookupError:
        return "utf-8"


def _analyze_html(result: dict, html: str) -> None:
    parser = _LandingParser()
    parser.feed(html)

    title = " ".join(part for part in parser.title_parts if part).strip()
    result["title"] = title[:160]
    result["forms"] = parser.forms[:5]
    result["password_fields"] = parser.password_fields
    result["meta_refresh_urls"] = parser.meta_refresh_urls[:5]

    findings: list[str] = []
    risk = 0
    final_domain = registered_domain(urlparse(result["final_url"]).hostname or "")

    if parser.password_fields:
        findings.append(
            f"Landing page contains password field(s): {parser.password_fields}"
        )
        risk += 20

    for form in parser.forms:
        action = form.get("action", "")
        method = form.get("method", "")
        if not action or method != "POST":
            continue
        action_url = urljoin(result["final_url"], action)
        action_domain = registered_domain(urlparse(action_url).hostname or "")
        if action_domain and action_domain != final_domain:
            findings.append(f"Landing form posts to external domain: {action_domain}")
            risk += 15

    if parser.meta_refresh_urls:
        findings.append("Landing page uses meta refresh redirect")
        risk += 8

    title_lower = title.lower()
    title_hits = [kw for kw in _TITLE_KEYWORDS if kw in title_lower]
    if len(title_hits) >= 2:
        findings.append(
            f"Credential-themed landing title: {', '.join(sorted(title_hits))}"
        )
        risk += 8

    brand_mentions = _detect_brand_mentions(html, final_domain)
    if brand_mentions:
        result["brand_mentions"] = brand_mentions
        findings.append(f"Landing page mentions brand(s): {', '.join(brand_mentions)}")
        risk += 10

    result["findings"] = findings
    result["risk_score"] = min(risk, 35)


def _detect_brand_mentions(html: str, final_domain: str) -> list[str]:
    text = re.sub(r"<[^>]+>", " ", html).lower()
    mentions: list[str] = []
    for brand, domains in _BRANDS.items():
        if brand not in text:
            continue
        if any_domain_match(final_domain, domains):
            continue
        mentions.append(brand)
    return mentions[:5]
