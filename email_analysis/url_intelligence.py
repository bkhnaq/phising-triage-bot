"""Static URL detection: shorteners, deceptive anchors, keywords, ESP context."""

import logging
from urllib.parse import urlparse


from email_analysis.domain_utils import domain_info, is_domain_or_subdomain
from scoring.config import weight

logger = logging.getLogger(__name__)


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
    """Analyze extracted URLs locally; network enrichment belongs to Shuffle."""
    shortener_findings = detect_shorteners(urls)
    suspicious_endpoints = detect_suspicious_endpoints(urls)
    deceptive_links = detect_deceptive_links(urls)
    esp_findings = detect_esp_patterns(urls)

    total_risk = (
        sum(f["risk_score"] for f in shortener_findings)
        + sum(f["risk_score"] for f in suspicious_endpoints)
        + sum(f["risk_score"] for f in deceptive_links)
    )

    return {
        "shortener_findings": shortener_findings,
        "suspicious_endpoints": suspicious_endpoints,
        "deceptive_links": deceptive_links,
        "esp_findings": esp_findings,
        "risk_score": min(total_risk, 50),
    }


def detect_deceptive_links(urls: list[dict]) -> list[dict]:
    """Return strong findings when visible anchor URLs differ from actual hrefs."""
    findings: list[dict] = []
    for item in urls:
        if not item.get("deceptive_hyperlink"):
            continue
        esp_context = classify_esp_url(str(item.get("url", "")))
        known_tracking_intermediary = bool(
            esp_context and esp_context.get("is_tracking")
        )
        findings.append(
            {
                "url": item.get("url", ""),
                "deceptive_link": True,
                "displayed_url": item.get("displayed_url", ""),
                "displayed_domain": item.get("displayed_domain", ""),
                "actual_domain": item.get("actual_domain", item.get("domain", "")),
                "state": "contextual" if known_tracking_intermediary else "suspicious",
                "provider": esp_context.get("provider") if esp_context else "",
                "requires_redirect_validation": known_tracking_intermediary,
                "risk_score": (
                    0 if known_tracking_intermediary else weight("deceptive_hyperlink")
                ),
            }
        )
    return findings


def detect_shorteners(urls: list[dict]) -> list[dict]:
    """Identify shortener infrastructure without opening the URL."""
    return [
        {
            "url": item["url"],
            "domain": item["domain"],
            "risk_score": weight("url_shortener"),
            "resolution_status": "PENDING_SOAR",
        }
        for item in urls
        if item.get("domain", "").lower() in SHORTENER_DOMAINS
    ]


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
        url = source_url
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

        matched_keywords = sorted(
            kw for kw in _SUSPICIOUS_PATH_KEYWORDS if kw in path_lower
        )
        if len(matched_keywords) >= 2:
            findings.append(
                {
                    "url": url,
                    "keywords": matched_keywords,
                    "risk_score": weight("suspicious_endpoint"),
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


def _normalize_domain(netloc: str) -> str:
    return domain_info(netloc).ascii_host


def _domain_matches(domain: str, candidates: tuple[str, ...]) -> bool:
    return any(is_domain_or_subdomain(domain, candidate) for candidate in candidates)
