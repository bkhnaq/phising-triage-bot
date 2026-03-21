"""
Domain Intelligence Module
---------------------------
Comprehensive domain investigation providing:

  - WHOIS lookup (creation date, age, registrar, country)
  - DNS record analysis (A, AAAA, MX, NS, TXT, CNAME)
  - MX record validation
  - Domain entropy scoring
  - Lookalike domain detection
  - Levenshtein distance for brand similarity

Usage:
    from email_analysis.domain_intelligence import analyze_domain_intelligence
    findings = analyze_domain_intelligence(domains)
"""

import logging
import math
from datetime import datetime, timezone

import dns.resolver
import whois

logger = logging.getLogger(__name__)

_WHOIS_TIMEOUT = 10
_DNS_TIMEOUT = 5

# Entropy threshold for flagging suspicious domains
_ENTROPY_THRESHOLD = 3.5

# Protected brands for lookalike detection
_PROTECTED_BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.me"},
    "microsoft": {
        "microsoft.com",
        "outlook.com",
        "office.com",
        "office365.com",
        "live.com",
    },
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.co.uk"},
    "google": {"google.com", "gmail.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
}


def analyze_domain_intelligence(domains: list[str]) -> dict:
    """
    Run comprehensive domain intelligence on a list of domains.

    Args:
        domains: List of domain strings to investigate.

    Returns:
        Dict with keys:
            whois_results     – list of WHOIS finding dicts
            dns_results       – list of DNS analysis dicts
            entropy_results   – list of entropy finding dicts
            lookalike_results – list of lookalike finding dicts
            risk_score        – aggregate risk score
    """
    unique = _deduplicate_domains(domains)

    whois_results = []
    dns_results = []
    entropy_results = []
    lookalike_results = []
    total_risk = 0

    for domain in unique:
        reg_domain = _registrable_domain(domain)
        if not reg_domain:
            continue

        # WHOIS
        w = whois_lookup(reg_domain)
        whois_results.append(w)
        total_risk += w.get("risk_score", 0)

        # DNS
        d = dns_lookup(reg_domain)
        dns_results.append(d)
        total_risk += d.get("risk_score", 0)

        # Entropy
        ent = entropy_check(reg_domain)
        if ent["risk_score"] > 0:
            entropy_results.append(ent)
            total_risk += ent["risk_score"]

        # Lookalike
        look = lookalike_check(reg_domain)
        lookalike_results.extend(look)
        total_risk += sum(lookalike_item["risk_score"] for lookalike_item in look)

    return {
        "whois_results": whois_results,
        "dns_results": dns_results,
        "entropy_results": entropy_results,
        "lookalike_results": lookalike_results,
        "risk_score": min(total_risk, 60),
    }


def whois_lookup(domain: str) -> dict:
    """
    Perform WHOIS lookup with enhanced intelligence extraction.

    Returns:
        Dict with: domain, created, age_days, registrar, country,
                   name_servers, expires, updated, risk_score, error.
    """
    result: dict = {
        "domain": domain,
        "created": None,
        "age_days": None,
        "registrar": None,
        "country": None,
        "name_servers": [],
        "expires": None,
        "updated": None,
        "risk_score": 0,
        "error": None,
    }

    try:
        w = whois.whois(domain)

        # Clean WHOIS text
        raw_text = w.get("text") or ""
        if isinstance(raw_text, list):
            raw_text = "\n".join(raw_text)
        if "TERMS OF USE" in raw_text:
            raw_text = raw_text.split("TERMS OF USE")[0].rstrip()
        w["text"] = raw_text

        # Registrar
        registrar = w.get("registrar")
        if registrar:
            result["registrar"] = str(registrar).strip()

        # Country
        country = w.get("country")
        if country:
            result["country"] = str(country).strip().upper()

        # Name servers
        ns = w.get("name_servers")
        if ns:
            if isinstance(ns, str):
                ns = [ns]
            result["name_servers"] = sorted({s.lower().strip() for s in ns if s})

        # Expiration date
        expires = w.get("expiration_date")
        if isinstance(expires, list):
            expires = expires[0]
        if expires:
            result["expires"] = expires.strftime("%Y-%m-%d")

        # Updated date
        updated = w.get("updated_date")
        if isinstance(updated, list):
            updated = updated[0]
        if updated:
            result["updated"] = updated.strftime("%Y-%m-%d")

        # Creation date and age
        creation = w.get("creation_date")
        if isinstance(creation, list):
            creation = creation[0]

        if creation is None:
            result["error"] = "creation_date not available"
            return result

        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)

        age_days = (datetime.now(timezone.utc) - creation).days
        result["created"] = creation.strftime("%Y-%m-%d")
        result["age_days"] = age_days

        # Risk scoring based on age
        if age_days < 7:
            result["risk_score"] = 25
        elif age_days < 30:
            result["risk_score"] = 20
        elif age_days < 90:
            result["risk_score"] = 10

    except Exception as exc:
        err_msg = str(exc)
        if "TERMS OF USE" in err_msg:
            err_msg = err_msg.split("TERMS OF USE")[0].rstrip()
        first_line = err_msg.strip().split("\n")[0].strip()
        result["error"] = (
            f"lookup failed ({first_line})" if first_line else "lookup failed"
        )
        logger.debug("WHOIS lookup failed for %s: %s", domain, first_line)

    return result


def dns_lookup(domain: str) -> dict:
    """
    Perform DNS record analysis.

    Returns:
        Dict with: domain, a_records, aaaa_records, mx_records, ns_records,
                   txt_records, cname_records, has_mx, has_spf, risk_score, error.
    """
    result: dict = {
        "domain": domain,
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "cname_records": [],
        "has_mx": False,
        "has_spf": False,
        "risk_score": 0,
        "error": None,
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = _DNS_TIMEOUT
    resolver.lifetime = _DNS_TIMEOUT

    record_types = {
        "A": "a_records",
        "AAAA": "aaaa_records",
        "MX": "mx_records",
        "NS": "ns_records",
        "TXT": "txt_records",
        "CNAME": "cname_records",
    }

    for rtype, key in record_types.items():
        try:
            answers = resolver.resolve(domain, rtype)
            if rtype == "MX":
                result[key] = [
                    {"priority": r.preference, "host": str(r.exchange).rstrip(".")}
                    for r in answers
                ]
            else:
                result[key] = [str(r).strip('"') for r in answers]
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.resolver.Timeout,
        ):
            continue
        except Exception as exc:
            logger.debug("DNS %s lookup failed for %s: %s", rtype, domain, exc)

    # Analyze results
    result["has_mx"] = bool(result["mx_records"])
    result["has_spf"] = any("v=spf1" in t for t in result["txt_records"])

    # No MX records for domains that claim to send email = suspicious
    if not result["has_mx"] and not result["a_records"]:
        result["risk_score"] += 10
        result["error"] = "No A or MX records found"

    return result


def entropy_check(domain: str) -> dict:
    """
    Calculate Shannon entropy of the domain name.

    Returns:
        Dict with: domain, entropy, risk_score.
    """
    label = domain.split(":")[0]
    parts = label.rsplit(".", 1)
    name = parts[0] if parts else label
    name = name.replace(".", "").replace("-", "")

    if not name:
        return {"domain": domain, "entropy": 0.0, "risk_score": 0}

    length = len(name)
    freq: dict[str, int] = {}
    for ch in name:
        freq[ch] = freq.get(ch, 0) + 1

    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    entropy = round(entropy, 2)
    risk = 15 if entropy > _ENTROPY_THRESHOLD else 0

    return {"domain": domain, "entropy": entropy, "risk_score": risk}


def lookalike_check(domain: str) -> list[dict]:
    """
    Check domain against protected brands using Levenshtein distance.

    Returns:
        List of finding dicts: domain, brand, distance, risk_score.
    """
    findings: list[dict] = []
    base = _extract_base_label(domain)
    segments = _candidate_segments(base)

    for brand, legit_domains in _PROTECTED_BRANDS.items():
        if domain in legit_domains:
            continue

        for segment in segments:
            if abs(len(segment) - len(brand)) > 2:
                continue

            dist = _levenshtein(segment, brand)
            if 0 < dist <= 2:
                findings.append(
                    {
                        "domain": domain,
                        "brand": brand,
                        "distance": dist,
                        "detail": f"'{segment}' vs '{brand}' (distance={dist})",
                        "risk_score": 20,
                    }
                )
                break

    return findings


# ── Helpers ──────────────────────────────────────────────────


def _deduplicate_domains(domains: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for d in domains:
        d_lower = d.lower().split(":")[0]
        if d_lower and d_lower not in seen:
            seen.add(d_lower)
            result.append(d_lower)
    return result


def _registrable_domain(netloc: str) -> str:
    host = netloc.split(":")[0].strip().lower()
    if not host:
        return ""
    parts = host.split(".")
    if len(parts) >= 2:
        if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "ac", "gov"):
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return host


def _extract_base_label(domain: str) -> str:
    parts = domain.lower().split(".")
    if len(parts) >= 3 and len(parts[-2]) <= 3:
        return parts[-3]
    if len(parts) >= 2:
        return parts[-2]
    return parts[0]


def _candidate_segments(base_label: str) -> list[str]:
    segments = [base_label]
    if "-" in base_label:
        segments.extend(base_label.split("-"))
    return segments


def _levenshtein(s: str, t: str) -> int:
    n, m = len(s), len(t)
    if n == 0:
        return m
    if m == 0:
        return n
    prev = list(range(m + 1))
    curr = [0] * (m + 1)
    for i in range(1, n + 1):
        curr[0] = i
        for j in range(1, m + 1):
            cost = 0 if s[i - 1] == t[j - 1] else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev, curr = curr, prev
    return prev[m]
