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
    if (
        "NameResolutionError" in raw
        or "getaddrinfo failed" in raw
        or "Name or service not known" in raw
    ):
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
    if (
        "ConnectionError" in raw
        or "HTTPConnectionPool" in raw
        or "HTTPSConnectionPool" in raw
    ):
        return "Connection failed"
    return "Redirect analysis failed"


# ── Extended URL shortener list ──────────────────────────────
SHORTENER_DOMAINS: frozenset[str] = frozenset(
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
        "bl.ink",
        "soo.gd",
        "s.id",
        "clck.ru",
        "v.gd",
        "short.io",
        "hyp.er",
        "t.ly",
        "trib.al",
        "snip.ly",
        "qr.ae",
        "amzn.to",
        "youtu.be",
        "j.mp",
        "rotf.lol",
        "cli.re",
        "hubs.la",
        "shorte.st",
        "adf.ly",
    }
)

# Suspicious path keywords in final URLs
_SUSPICIOUS_PATH_KEYWORDS = frozenset(
    {
        "login",
        "signin",
        "verify",
        "confirm",
        "secure",
        "update",
        "account",
        "password",
        "credential",
        "auth",
        "validate",
        "billing",
        "payment",
        "invoice",
    }
)

_SUSPICIOUS_DOMAIN_KEYWORDS = frozenset(
    {
        "login",
        "verify",
        "secure",
        "account",
        "auth",
        "wallet",
        "billing",
        "password",
        "update",
        "signin",
    }
)

# Known legitimate email service providers (ESP) and common tracking endpoints.
_KNOWN_ESP_RULES: dict[str, dict[str, tuple[str, ...]]] = {
    "BlueHornet": {
        "domains": ("bluehornet.com",),
        "tracking_paths": ("/ct/", "/lt/", "/open/"),
    },
    "Mailchimp": {
        "domains": ("mailchi.mp", "list-manage.com", "mailchimp.com"),
        "tracking_paths": ("/track/", "/click/", "/c/", "/"),
    },
    "SendGrid": {
        "domains": ("sendgrid.net", "sendgrid.com"),
        "tracking_paths": ("/wf/", "/ls/", "/track/", "/"),
    },
    "Constant Contact": {
        "domains": ("constantcontact.com", "rs6.net"),
        "tracking_paths": ("/", "/r/", "/click/", "/tn.jsp"),
    },
    "HubSpot": {
        "domains": ("hubspotlinks.com", "hs-analytics.net", "hubspot.com"),
        "tracking_paths": ("/", "/track", "/click", "/e1t/"),
    },
    "Salesforce Marketing Cloud": {
        "domains": ("exacttarget.com", "sfmc-content.com", "marketingcloudapps.com"),
        "tracking_paths": ("/", "/redirect", "/click", "/r/"),
    },
    "Amazon SES": {
        "domains": ("amazonses.com", "awstrack.me"),
        "tracking_paths": ("/", "/track", "/r/", "/click"),
    },
}


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
    esp_findings = detect_esp_patterns(urls)
    _merge_redirect_context_into_esp(esp_findings, redirect_findings)

    total_risk = (
        sum(f["risk_score"] for f in shortener_findings)
        + sum(f["risk_score"] for f in redirect_findings)
        + sum(f["risk_score"] for f in suspicious_endpoints)
    )

    return {
        "shortener_findings": shortener_findings,
        "redirect_findings": redirect_findings,
        "suspicious_endpoints": suspicious_endpoints,
        "esp_findings": esp_findings,
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
        expanded_domain = (
            urlparse(expanded_url).netloc if expanded_url != original_url else ""
        )

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
        source_url = u["url"]
        url = u.get("expanded_url", source_url)
        if url in checked:
            continue
        checked.add(url)

        esp_info = classify_esp_url(source_url)

        chain_result = follow_redirect_chain(
            url,
            source_url=source_url,
            esp_info=esp_info,
        )
        if (
            chain_result["hops"] > 0
            or chain_result.get("error")
            or chain_result.get("suspicious_landing")
        ):
            findings.append(chain_result)

    return findings


def follow_redirect_chain(
    url: str,
    source_url: str | None = None,
    esp_info: dict | None = None,
) -> dict:
    """
    Follow redirects for a single URL and return the full chain.

    Returns:
        Dict with chain details and suspicious intermediate domain analysis.
    """
    source = source_url or url
    origin_domain = _normalize_domain(urlparse(source).netloc)

    result: dict = {
        "source_url": source,
        "url": url,
        "chain": [url],
        "hops": 0,
        "final_url": url,
        "final_domain": _normalize_domain(urlparse(url).netloc),
        "intermediate_domains": [],
        "suspicious_intermediates": [],
        "is_esp_tracking": bool(esp_info and esp_info.get("is_tracking")),
        "esp_provider": esp_info.get("provider") if esp_info else "",
        "suspicious_landing": False,
        "landing_reason": "",
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
            result["final_domain"] = _normalize_domain(urlparse(resp.url).netloc)

            # Analyze intermediate domains
            final_domain = _normalize_domain(urlparse(resp.url).netloc)

            for r in resp.history:
                intermediate_domain = _normalize_domain(urlparse(r.url).netloc)
                if intermediate_domain not in (origin_domain, final_domain):
                    result["intermediate_domains"].append(intermediate_domain)
                    # Check if intermediate is a shortener
                    if intermediate_domain in SHORTENER_DOMAINS:
                        result["suspicious_intermediates"].append(
                            {
                                "domain": intermediate_domain,
                                "reason": "URL shortener in redirect chain",
                            }
                        )

        suspicious_landing, landing_reason = _is_suspicious_landing(
            result["final_url"],
            result["final_domain"],
        )
        result["suspicious_landing"] = suspicious_landing
        result["landing_reason"] = landing_reason

        # Rule update:
        # For known ESP tracking URLs, redirects are expected and not risky by default.
        # Increase risk only when landing evidence itself is suspicious.
        if result["is_esp_tracking"]:
            if suspicious_landing:
                result["risk_score"] += 12
        else:
            if result["hops"] > 2:
                result["risk_score"] = 15
            elif result["hops"] > 0:
                result["risk_score"] = 5

            if result["suspicious_intermediates"]:
                result["risk_score"] += 10

            if result["hops"] > 0 and origin_domain != result["final_domain"]:
                result["risk_score"] += 5

            if suspicious_landing:
                result["risk_score"] += 8

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
        source_url = u["url"]
        url = u.get("expanded_url", source_url)
        if url in seen:
            continue
        seen.add(url)

        esp_info = classify_esp_url(source_url)
        # Known ESP tracking endpoints are not suspicious by default.
        if esp_info and esp_info.get("is_tracking"):
            continue

        parsed = urlparse(url)
        path_lower = (
            (parsed.path + "?" + parsed.query).lower()
            if parsed.query
            else parsed.path.lower()
        )

        matched_keywords = [kw for kw in _SUSPICIOUS_PATH_KEYWORDS if kw in path_lower]
        if len(matched_keywords) >= 2:
            findings.append(
                {
                    "url": url,
                    "keywords": matched_keywords,
                    "risk_score": 10,
                }
            )

    return findings


def detect_esp_patterns(urls: list[dict]) -> list[dict]:
    """
    Detect likely legitimate ESP / marketing-tracking URLs.

    Returns:
        List of dicts with provider, URL, tracking status, and default risk adjustment.
    """
    findings: list[dict] = []
    seen: set[str] = set()

    for u in urls:
        source_url = u["url"]
        if source_url in seen:
            continue
        seen.add(source_url)

        esp_info = classify_esp_url(source_url)
        if not esp_info:
            continue

        findings.append(
            {
                "url": source_url,
                "domain": esp_info["domain"],
                "provider": esp_info["provider"],
                "is_tracking": esp_info["is_tracking"],
                "reason": esp_info["reason"],
                "final_domain": "",
                "suspicious_landing": False,
                # Applied in risk scoring when there is no contradictory evidence.
                "risk_adjustment": -8 if esp_info["is_tracking"] else -4,
            }
        )

    return findings


def classify_esp_url(url: str) -> dict | None:
    """Classify a URL as belonging to a known ESP/tracking service."""
    parsed = urlparse(url)
    domain = _normalize_domain(parsed.netloc)
    path = parsed.path.lower()

    if not domain:
        return None

    for provider, rule in _KNOWN_ESP_RULES.items():
        if not _domain_matches(domain, rule["domains"]):
            continue

        tracking_paths = rule.get("tracking_paths", ())
        is_tracking = any(path.startswith(p) or p in path for p in tracking_paths)

        return {
            "provider": provider,
            "domain": domain,
            "is_tracking": is_tracking,
            "reason": (
                "Known ESP tracking URL pattern"
                if is_tracking
                else "Known ESP sender infrastructure"
            ),
        }

    return None


def _merge_redirect_context_into_esp(
    esp_findings: list[dict], redirect_findings: list[dict]
) -> None:
    """Enrich ESP findings with redirect context (final landing domain and landing risk)."""
    redirect_by_source = {
        r.get("source_url", r.get("url", "")): r for r in redirect_findings
    }

    for finding in esp_findings:
        redirect = redirect_by_source.get(finding.get("url", ""))
        if not redirect:
            continue
        finding["final_domain"] = redirect.get("final_domain", "")
        finding["suspicious_landing"] = bool(redirect.get("suspicious_landing"))


def _is_suspicious_landing(url: str, domain: str) -> tuple[bool, str]:
    """Return whether a landing URL/domain appears suspicious and why."""
    dom = _normalize_domain(domain)
    if not dom:
        return False, ""

    if dom.startswith("xn--") or ".xn--" in dom:
        return True, "Punycode domain"

    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", dom):
        return True, "IP-address landing domain"

    base = dom.split(".")[0]
    if any(kw in base for kw in _SUSPICIOUS_DOMAIN_KEYWORDS):
        return True, "Suspicious landing domain keyword"

    parsed = urlparse(url)
    path_and_query = (
        (parsed.path + "?" + parsed.query).lower()
        if parsed.query
        else parsed.path.lower()
    )
    path_hits = [kw for kw in _SUSPICIOUS_PATH_KEYWORDS if kw in path_and_query]
    if len(path_hits) >= 2:
        return True, "Credential-style landing endpoint"

    return False, ""


def _normalize_domain(netloc: str) -> str:
    return (netloc or "").lower().split(":", 1)[0].strip().rstrip(".")


def _domain_matches(domain: str, candidates: tuple[str, ...]) -> bool:
    return any(domain == c or domain.endswith("." + c) for c in candidates)
