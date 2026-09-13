"""
Heuristic Analyzer Module
-------------------------
SOC-style heuristic detection rules for phishing triage:
  - Brand impersonation in URLs/domains
  - Suspicious domain keywords
  - URL shortener detection

Usage:
    from email_analysis.heuristic_analyzer import run_heuristics
    results = run_heuristics(urls)
"""

import logging
import math
from urllib.parse import urlparse


from email_analysis.domain_randomness import analyze_domain_randomness
from email_analysis.domain_utils import any_domain_match, registered_domain
from scoring.config import weight

from email_analysis.homograph_analyzer import detect_homograph_brands

logger = logging.getLogger(__name__)

# ── Brand impersonation ──────────────────────────────────────

# Map of brand keywords → their legitimate domains.
# A brand keyword found in a domain NOT in the official set is suspicious.
_BRAND_DOMAINS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.me"},
    "microsoft": {
        "microsoft.com",
        "live.com",
        "outlook.com",
        "office.com",
        "office365.com",
    },
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.ca"},
    "google": {"google.com", "gmail.com", "googleapis.com"},
    "bank": set(),  # generic – any domain containing "bank" is flagged
    "outlook": {"outlook.com", "outlook.live.com"},
    "office365": {"office365.com", "office.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "wellsfargo": {"wellsfargo.com"},
    "chase": {"chase.com"},
}

# ── Suspicious keywords ─────────────────────────────────────

_SUSPICIOUS_KEYWORDS: list[str] = [
    "verify",
    "login",
    "secure",
    "update",
    "account",
    "reset",
    "billing",
    "confirm",
    "suspend",
    "locked",
    "urgent",
    "expire",
    "authenticate",
    "wallet",
    "signin",
]

# ── URL shorteners ───────────────────────────────────────────

_SHORTENER_DOMAINS: frozenset[str] = frozenset(
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

# ── Homograph attack ─────────────────────────────────────────

# Characters that look alike across scripts (Latin ↔ Cyrillic etc.)
_CONFUSABLES: dict[str, str] = {
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0443": "y",  # Cyrillic у
    "\u0445": "x",  # Cyrillic х
    "\u0456": "i",  # Cyrillic і
    "\u0501": "d",  # Cyrillic ԁ
    "\u04cf": "l",  # Cyrillic ӏ
    "\u0261": "g",  # Latin small script g
    "\u01c3": "!",  # Latin letter retroflex click
}

# ── Public API ───────────────────────────────────────────────


def run_heuristics(urls: list[dict]) -> dict:
    """
    Run all heuristic checks against extracted URLs and return results.

    Args:
        urls: List of URL dicts from url_extractor (keys: url, domain, …).

    Returns:
        Dict with keys:
            brand_impersonation  – list of finding dicts
            suspicious_keywords  – list of finding dicts
            url_shorteners       – list of finding dicts
    """
    domains = _unique_domains(urls)

    return {
        "brand_impersonation": detect_brand_impersonation(urls, domains),
        "suspicious_keywords": detect_suspicious_keywords(urls, domains),
        "url_shorteners": detect_url_shorteners(urls),
        "homograph": detect_homograph(domains),
        "homograph_brands": detect_homograph_brands(domains),
        "domain_entropy": calculate_entropy_findings(domains),
    }


# ── Detection functions ─────────────────────────────────────


def detect_brand_impersonation(
    urls: list[dict],
    domains: list[str] | None = None,
) -> list[dict]:
    """
    Detect brand names inside URLs/domains that don't belong to the brand.

    Returns:
        List of dicts with keys: brand, domain, risk_score.
    """
    if domains is None:
        domains = _unique_domains(urls)

    findings: list[dict] = []
    seen: set[tuple[str, str]] = set()

    for domain in domains:
        domain_lower = domain.lower()
        for brand, legit_domains in _BRAND_DOMAINS.items():
            if brand in domain_lower and not any_domain_match(
                domain_lower, legit_domains
            ):
                key = (brand, domain_lower)
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "brand": brand,
                            "domain": domain,
                            "risk_score": weight("brand_domain_keyword"),
                        }
                    )
                    logger.warning(
                        "Brand impersonation: '%s' found in non-official domain %s",
                        brand,
                        domain,
                    )

    return findings


def detect_suspicious_keywords(
    urls: list[dict],
    domains: list[str] | None = None,
) -> list[dict]:
    """
    Detect phishing-related keywords in domains or full URL paths.

    Returns:
        List of dicts with keys: keyword, source (domain or URL), risk_score.
    """
    if domains is None:
        domains = _unique_domains(urls)

    findings: list[dict] = []
    seen: set[tuple[str, str]] = set()

    # Check domains
    for domain in domains:
        domain_lower = domain.lower()
        for kw in _SUSPICIOUS_KEYWORDS:
            if kw in domain_lower:
                key = (kw, domain_lower)
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "keyword": kw,
                            "source": domain,
                            "risk_score": weight("suspicious_keyword"),
                        }
                    )

    # Check full URL paths (catch keywords not in the domain itself)
    for u in urls:
        url_lower = u["url"].lower()
        parsed = urlparse(url_lower)
        path_and_query = (
            parsed.path + "?" + parsed.query if parsed.query else parsed.path
        )
        for kw in _SUSPICIOUS_KEYWORDS:
            if kw in path_and_query:
                key = (kw, url_lower)
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "keyword": kw,
                            "source": u["url"],
                            "risk_score": weight("suspicious_keyword"),
                        }
                    )

    return findings


def detect_url_shorteners(urls: list[dict]) -> list[dict]:
    """
    Flag URLs that use well-known URL shortener services.

    Returns:
        List of dicts with keys: url, domain, risk_score.
    """
    findings: list[dict] = []

    for u in urls:
        domain = u.get("domain", "").lower()
        if domain in _SHORTENER_DOMAINS:
            findings.append(
                {
                    "url": u["url"],
                    "domain": domain,
                    "risk_score": weight("url_shortener"),
                }
            )
            logger.info("URL shortener detected: %s (%s)", u["url"], domain)

    return findings


# ── Homograph detection ──────────────────────────────────────


def detect_homograph(domains: list[str]) -> list[dict]:
    """
    Detect domains that use visually similar characters (IDN homograph attacks).

    Checks for:
      1. Mixed-script domains (e.g. Cyrillic + Latin)
      2. Known confusable characters
      3. Punycode (xn--) domains that decode to mixed scripts

    Returns:
        List of dicts with keys: domain, decoded, details, risk_score.
    """
    findings: list[dict] = []
    checked: set[str] = set()

    for raw_domain in domains:
        domain = raw_domain.lower().split(":")[0]  # strip port
        if domain in checked:
            continue
        checked.add(domain)

        # Decode punycode labels (xn--...)
        decoded = domain
        if "xn--" in domain:
            try:
                decoded = domain.encode("ascii").decode("idna")
            except (UnicodeError, UnicodeDecodeError):
                pass

        # Analyse scripts used in the decoded domain (ignore dots and hyphens)
        scripts: set[str] = set()
        has_confusable = False
        for ch in decoded:
            if ch in ("-", "."):
                continue
            scripts.add(_script_of(ch))
            if ch in _CONFUSABLES:
                has_confusable = True

        mixed_script = len(scripts) > 1

        if mixed_script or has_confusable:
            detail_parts: list[str] = []
            if mixed_script:
                detail_parts.append(f"mixed scripts: {', '.join(sorted(scripts))}")
            if has_confusable:
                confusable_chars = [ch for ch in decoded if ch in _CONFUSABLES]
                detail_parts.append(f"confusable chars: {confusable_chars}")
            findings.append(
                {
                    "domain": raw_domain,
                    "decoded": decoded,
                    "details": "; ".join(detail_parts),
                    "risk_score": weight("homograph_domain"),
                }
            )
            logger.warning("Homograph attack suspected: %s → %s", raw_domain, decoded)

    return findings


def _script_of(ch: str) -> str:
    """Fallback script detection when unicodedata.script is unavailable."""
    cp = ord(ch)
    if 0x0400 <= cp <= 0x04FF:
        return "Cyrillic"
    if 0x0370 <= cp <= 0x03FF:
        return "Greek"
    if 0x0000 <= cp <= 0x024F:
        return "Latin"
    return "Unknown"


# ── Domain entropy ───────────────────────────────────────────


def calculate_entropy(domain: str) -> float:
    """
    Calculate Shannon entropy of a domain name string.

    Higher entropy often indicates randomly generated phishing domains.
    Typical legit domains: 2.5 – 3.5.  Suspicious if > 3.5.
    """
    # Strip TLD – only measure the meaningful part
    label = domain.split(":")[0]  # strip port
    parts = label.rsplit(".", 1)
    name = parts[0] if parts else label
    name = name.replace(".", "").replace("-", "")

    if not name:
        return 0.0

    length = len(name)
    freq: dict[str, int] = {}
    for ch in name:
        freq[ch] = freq.get(ch, 0) + 1

    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 2)


def calculate_entropy_findings(domains: list[str]) -> list[dict]:
    """Flag multi-feature randomized patterns, never entropy in isolation."""
    findings: list[dict] = []
    checked: set[str] = set()

    for raw_domain in domains:
        domain = raw_domain.lower().split(":")[0]
        reg = _registrable_domain(domain)
        if not reg or reg in checked:
            continue
        checked.add(reg)

        analysis = analyze_domain_randomness(reg)
        if int(analysis.get("risk_score", 0)) > 0:
            findings.append(analysis)
            logger.info(
                "Randomized domain pattern: %s (%s, entropy=%.2f)",
                reg,
                analysis.get("classification"),
                float(analysis.get("entropy", 0.0)),
            )

    return findings


# ── Redirect chain detection ─────────────────────────────────


# ── Internal helpers ─────────────────────────────────────────


def _unique_domains(urls: list[dict]) -> list[str]:
    """Return deduplicated list of domains from URL dicts."""
    seen: set[str] = set()
    result: list[str] = []
    for u in urls:
        d = u.get("domain", "").lower()
        if d and d not in seen:
            seen.add(d)
            result.append(d)
    return result


def _registrable_domain(netloc: str) -> str:
    """
    Strip port numbers and return just the domain for WHOIS lookup.
    E.g. 'evil.example.com:8080' → 'example.com'
    """
    return registered_domain(netloc)
