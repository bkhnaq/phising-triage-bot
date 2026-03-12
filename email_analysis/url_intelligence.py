"""
URL Intelligence Module
------------------------
Advanced URL analysis including:

  - URL shortener detection and expansion
  - Full redirect chain analysis with intermediate domain inspection
  - Suspicious endpoint detection
  - Final landing domain analysis

Usage:
    from email_analysis.url_intelligence import analyze_urls
    findings = analyze_urls(urls)
"""

import logging
import re
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

_REDIRECT_TIMEOUT = 5
_MAX_REDIRECTS = 10


def _friendly_error(exc: Exception) -> str:
    """Convert a requests exception into a human-readable message."""
    raw = str(exc)
    if "NameResolutionError" in raw or "getaddrinfo failed" in raw or "Name or service not known" in raw:
        return "Domain could not be resolved"
    if "Max retries exceeded" in raw:
        return "Domain could not be resolved"
    if "ConnectTimeout" in raw or "connect timed out" in raw.lower():
        return "Connection timed out"
    if "ReadTimeout" in raw or "read timed out" in raw.lower():
        return "Request timed out"
    if "TooManyRedirects" in raw:
        return "Too many redirects"
    if "SSLError" in raw or "CERTIFICATE_VERIFY_FAILED" in raw:
        return "SSL certificate error"
    if "ConnectionError" in raw or "HTTPConnectionPool" in raw or "HTTPSConnectionPool" in raw:
        return "Connection failed"
    return "Redirect analysis failed"

# ── Extended URL shortener list ──────────────────────────────
SHORTENER_DOMAINS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
    "tiny.cc", "lnkd.in", "rb.gy", "bl.ink", "soo.gd",
    "s.id", "clck.ru", "v.gd", "short.io", "hyp.er",
    "t.ly", "trib.al", "snip.ly", "qr.ae", "amzn.to",
    "youtu.be", "j.mp", "rotf.lol", "cli.re", "hubs.la",
    "shorte.st", "adf.ly",
})

# Suspicious path keywords in final URLs
_SUSPICIOUS_PATH_KEYWORDS = frozenset({
    "login", "signin", "verify", "confirm", "secure", "update",
    "account", "password", "credential", "auth", "validate",
    "billing", "payment", "invoice",
})


def analyze_urls(urls: list[dict]) -> dict:
    """
    Perform comprehensive URL intelligence analysis.

    Args:
        urls: List of URL dicts from url_extractor.

    Returns:
        Dict with keys:
            shortener_findings – list of shortener detection dicts
            redirect_findings  – list of redirect chain dicts
            suspicious_endpoints – list of suspicious endpoint dicts
            risk_score         – aggregate risk
    """
    shortener_findings = detect_shorteners(urls)
    redirect_findings = analyze_redirect_chains(urls)
    suspicious_endpoints = detect_suspicious_endpoints(urls)

    total_risk = (
        sum(f["risk_score"] for f in shortener_findings)
        + sum(f["risk_score"] for f in redirect_findings)
        + sum(f["risk_score"] for f in suspicious_endpoints)
    )

    return {
        "shortener_findings": shortener_findings,
        "redirect_findings": redirect_findings,
        "suspicious_endpoints": suspicious_endpoints,
        "risk_score": min(total_risk, 50),
    }


def detect_shorteners(urls: list[dict]) -> list[dict]:
    """
    Detect shortened URLs and expand them to reveal final destination.

    Returns:
        List of dicts with: url, domain, expanded_url, expanded_domain, risk_score.
    """
    findings: list[dict] = []

    for u in urls:
        domain = u.get("domain", "").lower()
        if domain not in SHORTENER_DOMAINS:
            continue

        original_url = u["url"]
        expanded_url = expand_url(original_url)
        expanded_domain = urlparse(expanded_url).netloc if expanded_url != original_url else ""

        finding = {
            "url": original_url,
            "domain": domain,
            "expanded_url": expanded_url,
            "expanded_domain": expanded_domain,
            "risk_score": 10,
        }

        # Extra risk if expanded URL has suspicious path
        if expanded_url != original_url:
            parsed = urlparse(expanded_url)
            path_lower = parsed.path.lower()
            for kw in _SUSPICIOUS_PATH_KEYWORDS:
                if kw in path_lower:
                    finding["risk_score"] += 5
                    break

        findings.append(finding)
        logger.info(
            "URL shortener: %s → %s",
            original_url,
            expanded_url if expanded_url != original_url else "(expansion failed)",
        )

    return findings


def expand_url(short_url: str) -> str:
    """
    Follow redirects on a shortened URL and return the final destination.
    """
    try:
        resp = requests.head(
            short_url,
            allow_redirects=True,
            timeout=_REDIRECT_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0 (PhishBot URL Expander)"},
        )
        return resp.url
    except requests.RequestException as exc:
        logger.debug("Could not expand URL %s: %s", short_url, exc)
        return short_url


def analyze_redirect_chains(urls: list[dict]) -> list[dict]:
    """
    Follow URL redirects and report full chain with intermediate domain analysis.

    Returns:
        List of dicts with: url, chain, hops, final_url, final_domain,
                           intermediate_domains, suspicious_intermediates,
                           risk_score, error.
    """
    findings: list[dict] = []
    checked: set[str] = set()

    for u in urls:
        url = u.get("expanded_url", u["url"])
        if url in checked:
            continue
        checked.add(url)

        chain_result = follow_redirect_chain(url)
        if chain_result["hops"] > 0 or chain_result.get("error"):
            findings.append(chain_result)

    return findings


def follow_redirect_chain(url: str) -> dict:
    """
    Follow redirects for a single URL and return the full chain.

    Returns:
        Dict with chain details and suspicious intermediate domain analysis.
    """
    result: dict = {
        "url": url,
        "chain": [url],
        "hops": 0,
        "final_url": url,
        "final_domain": urlparse(url).netloc,
        "intermediate_domains": [],
        "suspicious_intermediates": [],
        "risk_score": 0,
        "error": None,
    }

    try:
        resp = requests.get(
            url,
            allow_redirects=True,
            timeout=_REDIRECT_TIMEOUT,
            stream=True,
            headers={"User-Agent": "Mozilla/5.0 (PhishBot)"},
        )
        resp.close()

        if resp.history:
            result["chain"] = [r.url for r in resp.history] + [resp.url]
            result["hops"] = len(resp.history)
            result["final_url"] = resp.url
            result["final_domain"] = urlparse(resp.url).netloc

            # Analyze intermediate domains
            origin_domain = urlparse(url).netloc.lower()
            final_domain = urlparse(resp.url).netloc.lower()

            for r in resp.history:
                intermediate_domain = urlparse(r.url).netloc.lower()
                if intermediate_domain not in (origin_domain, final_domain):
                    result["intermediate_domains"].append(intermediate_domain)
                    # Check if intermediate is a shortener
                    if intermediate_domain in SHORTENER_DOMAINS:
                        result["suspicious_intermediates"].append({
                            "domain": intermediate_domain,
                            "reason": "URL shortener in redirect chain",
                        })

        # Risk scoring
        if result["hops"] > 2:
            result["risk_score"] = 15
        elif result["hops"] > 0:
            result["risk_score"] = 5

        if result["suspicious_intermediates"]:
            result["risk_score"] += 10

        # Check if final domain differs significantly from origin
        if result["hops"] > 0:
            origin_netloc = urlparse(url).netloc.lower()
            final_netloc = result["final_domain"].lower()
            if origin_netloc != final_netloc:
                result["risk_score"] += 5

    except requests.RequestException as exc:
        result["error"] = _friendly_error(exc)
        logger.debug("Redirect chain check failed for %s: %s", url, exc)

    return result


def detect_suspicious_endpoints(urls: list[dict]) -> list[dict]:
    """
    Detect URLs with suspicious path patterns suggesting credential harvesting pages.

    Returns:
        List of dicts with: url, keyword, risk_score.
    """
    findings: list[dict] = []
    seen: set[str] = set()

    for u in urls:
        url = u.get("expanded_url", u["url"])
        if url in seen:
            continue
        seen.add(url)

        parsed = urlparse(url)
        path_lower = (parsed.path + "?" + parsed.query).lower() if parsed.query else parsed.path.lower()

        matched_keywords = [kw for kw in _SUSPICIOUS_PATH_KEYWORDS if kw in path_lower]
        if len(matched_keywords) >= 2:
            findings.append({
                "url": url,
                "keywords": matched_keywords,
                "risk_score": 10,
            })

    return findings
