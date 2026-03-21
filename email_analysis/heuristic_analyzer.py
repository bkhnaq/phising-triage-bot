"""
Heuristic Analyzer Module
-------------------------
SOC-style heuristic detection rules for phishing triage:
  - Brand impersonation in URLs/domains
  - Suspicious domain keywords
  - Domain age via WHOIS
  - URL shortener detection

Usage:
    from email_analysis.heuristic_analyzer import run_heuristics
    results = run_heuristics(urls)
"""

import logging
import math
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import whois

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

# ── Redirect chain ───────────────────────────────────────────

_REDIRECT_TIMEOUT = 5  # seconds per request
_MAX_REDIRECTS = 10  # safety cap

# ── WHOIS timeout (seconds) ─────────────────────────────────
_WHOIS_TIMEOUT = 10


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
            domain_age           – list of finding dicts
            url_shorteners       – list of finding dicts
    """
    domains = _unique_domains(urls)

    return {
        "brand_impersonation": detect_brand_impersonation(urls, domains),
        "suspicious_keywords": detect_suspicious_keywords(urls, domains),
        "domain_age": check_domain_age(domains),
        "url_shorteners": detect_url_shorteners(urls),
        "homograph": detect_homograph(domains),
        "homograph_brands": detect_homograph_brands(domains),
        "domain_entropy": calculate_entropy_findings(domains),
        "redirect_chains": check_redirect_chains(urls),
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
            if brand in domain_lower and domain_lower not in legit_domains:
                key = (brand, domain_lower)
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "brand": brand,
                            "domain": domain,
                            "risk_score": 25,
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
                            "risk_score": 15,
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
                            "risk_score": 15,
                        }
                    )

    return findings


def get_domain_age(domain: str) -> dict:
    """
    Perform a WHOIS lookup for a single domain, clean the raw output,
    and return structured age information.

    The raw WHOIS text is stripped of "TERMS OF USE" boilerplate so that
    only useful registration data is processed.

    Args:
        domain: A registrable domain name (e.g. ``example.com``).

    Returns:
        Dict with keys:
            created      – creation date as ``YYYY-MM-DD`` string, or None
            age_days     – int number of days since creation, or None
            registrar    – registrar name, or None
            name_servers – list of name-server strings
            error        – error description string, or None
    """
    result: dict = {
        "created": None,
        "age_days": None,
        "registrar": None,
        "name_servers": [],
        "error": None,
    }

    try:
        w = whois.whois(domain)

        # ── Clean raw WHOIS text ─────────────────────────────
        raw_text = w.get("text") or ""
        if isinstance(raw_text, list):
            raw_text = "\n".join(raw_text)
        if "TERMS OF USE" in raw_text:
            raw_text = raw_text.split("TERMS OF USE")[0].rstrip()
        # Store the cleaned text back (informational only)
        w["text"] = raw_text

        # ── Registrar ────────────────────────────────────────
        registrar = w.get("registrar")
        if registrar:
            result["registrar"] = str(registrar).strip()

        # ── Name servers ─────────────────────────────────────
        ns = w.get("name_servers")
        if ns:
            if isinstance(ns, str):
                ns = [ns]
            result["name_servers"] = sorted({s.lower().strip() for s in ns if s})

        # ── Creation date ────────────────────────────────────
        creation = w.get("creation_date")
        if isinstance(creation, list):
            creation = creation[0]

        if creation is None:
            result["error"] = "creation_date not available"
            return result

        # Make timezone-aware if naive
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)

        age_days = (datetime.now(timezone.utc) - creation).days
        result["created"] = creation.strftime("%Y-%m-%d")
        result["age_days"] = age_days

    except Exception as exc:
        err_msg = str(exc)
        # Strip verbose WHOIS boilerplate from error messages
        if "TERMS OF USE" in err_msg:
            err_msg = err_msg.split("TERMS OF USE")[0].rstrip()
        # Keep only the first meaningful line
        first_line = err_msg.strip().split("\n")[0].strip()
        result["error"] = (
            f"lookup failed ({first_line})" if first_line else "lookup failed"
        )
        logger.debug("WHOIS lookup failed for %s: %s", domain, first_line)

    return result


def check_domain_age(domains: list[str]) -> list[dict]:
    """
    Query WHOIS for each domain and flag recently registered ones.

    Scoring:
        < 30 days  → +20 risk

    Returns:
        List of dicts with keys:
            domain, created, age_days, registrar, name_servers,
            risk_score, error.
    """
    findings: list[dict] = []
    checked: set[str] = set()

    for raw_domain in domains:
        domain = _registrable_domain(raw_domain)
        if not domain or domain in checked:
            continue
        checked.add(domain)

        age_info = get_domain_age(domain)

        finding: dict = {
            "domain": domain,
            "created": age_info["created"],
            "age_days": age_info["age_days"],
            "registrar": age_info["registrar"],
            "name_servers": age_info["name_servers"],
            "risk_score": 0,
            "error": age_info["error"],
        }

        if age_info["age_days"] is not None and age_info["age_days"] < 30:
            finding["risk_score"] = 20
            logger.warning(
                "Young domain: %s registered %d day(s) ago (+20 risk)",
                domain,
                age_info["age_days"],
            )

        findings.append(finding)

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
                    "risk_score": 10,
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
                    "risk_score": 30,
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
    """
    Flag domains with high Shannon entropy.

    Returns:
        List of dicts with keys: domain, entropy, risk_score.
    """
    findings: list[dict] = []
    checked: set[str] = set()
    threshold = 3.5

    for raw_domain in domains:
        domain = raw_domain.lower().split(":")[0]
        reg = _registrable_domain(domain)
        if not reg or reg in checked:
            continue
        checked.add(reg)

        ent = calculate_entropy(reg)
        risk = 15 if ent > threshold else 0

        if risk > 0:
            findings.append(
                {
                    "domain": reg,
                    "entropy": ent,
                    "risk_score": risk,
                }
            )
            logger.info("High entropy domain: %s (%.2f)", reg, ent)

    return findings


# ── Redirect chain detection ─────────────────────────────────


def check_redirect_chain(url: str) -> dict:
    """
    Follow redirects for a single URL and return the chain.

    Returns:
        Dict with keys: url, chain (list of URLs), hops, final_url, risk_score, error.
    """
    result: dict = {
        "url": url,
        "chain": [url],
        "hops": 0,
        "final_url": url,
        "risk_score": 0,
        "error": None,
    }
    try:
        resp = requests.get(
            url,
            allow_redirects=True,
            timeout=_REDIRECT_TIMEOUT,
            stream=True,  # don't download body
            headers={"User-Agent": "Mozilla/5.0 (PhishBot)"},
        )
        resp.close()

        if resp.history:
            result["chain"] = [r.url for r in resp.history] + [resp.url]
            result["hops"] = len(resp.history)
            result["final_url"] = resp.url

        if result["hops"] > 1:
            result["risk_score"] = 10
            logger.info(
                "Redirect chain: %s → %d hop(s) → %s",
                url,
                result["hops"],
                result["final_url"],
            )

    except requests.RequestException as exc:
        result["error"] = str(exc)
        logger.debug("Redirect chain check failed for %s: %s", url, exc)

    return result


def check_redirect_chains(urls: list[dict]) -> list[dict]:
    """
    Check redirect chains for all extracted URLs.

    Returns:
        List of redirect-chain result dicts (only those with > 1 hop or errors).
    """
    findings: list[dict] = []
    for u in urls:
        chain = check_redirect_chain(u["url"])
        if chain["hops"] > 1 or chain.get("error"):
            findings.append(chain)
    return findings


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
    # Remove port
    host = netloc.split(":")[0].strip().lower()
    if not host:
        return ""
    # Simple heuristic: take last two labels (or three for co.uk etc.)
    parts = host.split(".")
    if len(parts) >= 2:
        # Handle two-part TLDs like co.uk, com.au
        if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "ac", "gov"):
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return host
