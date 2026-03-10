"""
Phishing Rules Module
---------------------
Additional SOC-grade phishing detection rules:

  Rule 1 – Display Name Spoofing Detection
  Rule 2 – Lookalike Domain Detection (Levenshtein distance)

Usage:
    from email_analysis.phishing_rules import detect_display_name_spoofing, detect_lookalike_domains
"""

import logging
import re
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Protected brands: brand keyword → set of legitimate sender domains
_PROTECTED_BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.me"},
    "microsoft": {"microsoft.com", "outlook.com", "office.com", "office365.com", "live.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.ca"},
    "google": {"google.com", "gmail.com", "googleapis.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"},
}

# Regex to extract the email address from a From header value
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")


# ── Rule 1: Display Name Spoofing ────────────────────────────

def detect_display_name_spoofing(from_header: str) -> list[dict]:
    """
    Detect cases where the display name contains a protected brand but
    the sender domain does not belong to that brand.

    Args:
        from_header: Raw value of the email From header,
                     e.g. 'PayPal Security <support@evil.com>'.

    Returns:
        List of finding dicts with keys:
            brand, sender_domain, risk_score.
    """
    findings: list[dict] = []
    if not from_header:
        return findings

    # Split display name from address.  The address is typically inside < >.
    # If no angle brackets, the entire value is treated as the address (no display name).
    angle_match = re.match(r"^(.*?)\s*<[^>]+>", from_header)
    display_name = angle_match.group(1).strip() if angle_match else ""
    if not display_name:
        return findings

    display_lower = display_name.lower()

    # Extract sender domain
    email_match = _EMAIL_RE.search(from_header)
    if not email_match:
        return findings
    sender_domain = email_match.group(1).lower()

    for brand, legit_domains in _PROTECTED_BRANDS.items():
        if brand not in display_lower:
            continue
        # Check if the sender domain belongs to the brand
        if any(sender_domain == d or sender_domain.endswith("." + d) for d in legit_domains):
            continue
        findings.append({
            "brand": brand,
            "sender_domain": sender_domain,
            "risk_score": 20,
        })
        logger.warning(
            "Display name spoofing: brand '%s' in display name, sender domain %s",
            brand, sender_domain,
        )

    return findings


# ── Rule 2: Lookalike Domain Detection ───────────────────────

def _levenshtein(s: str, t: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    n, m = len(s), len(t)
    if n == 0:
        return m
    if m == 0:
        return n

    # Use two-row optimisation to save memory
    prev = list(range(m + 1))
    curr = [0] * (m + 1)

    for i in range(1, n + 1):
        curr[0] = i
        for j in range(1, m + 1):
            cost = 0 if s[i - 1] == t[j - 1] else 1
            curr[j] = min(
                prev[j] + 1,       # deletion
                curr[j - 1] + 1,   # insertion
                prev[j - 1] + cost, # substitution
            )
        prev, curr = curr, prev

    return prev[m]


def _extract_base_label(domain: str) -> str:
    """
    Extract the registrable base label from a domain.

    Examples:
        paypa1-login-security.com  →  paypa1-login-security
        sub.evil.co.uk             →  evil
    """
    parts = domain.lower().split(".")
    # Handle two-part TLDs like co.uk, com.br
    if len(parts) >= 3 and len(parts[-2]) <= 3:
        return parts[-3]
    if len(parts) >= 2:
        return parts[-2]
    return parts[0]


def _candidate_segments(base_label: str) -> list[str]:
    """
    Return segments of a domain label to compare against brand names.

    For 'paypa1-login-security', returns ['paypa1-login-security', 'paypa1', 'login', 'security'].
    This catches brands hidden as a hyphenated prefix/segment.
    """
    segments = [base_label]
    if "-" in base_label:
        segments.extend(base_label.split("-"))
    return segments


def detect_lookalike_domains(urls: list[dict]) -> list[dict]:
    """
    Detect URL domains that are within Levenshtein distance ≤ 2 of a
    protected brand name.

    Args:
        urls: List of URL dicts (from url_extractor), each with a 'domain' key.

    Returns:
        List of finding dicts with keys:
            domain, brand, distance, risk_score.
    """
    findings: list[dict] = []
    checked: set[str] = set()

    for u in urls:
        domain = (u.get("domain") or "").lower()
        if not domain or domain in checked:
            continue
        checked.add(domain)

        base_label = _extract_base_label(domain)
        segments = _candidate_segments(base_label)

        matched_brands: set[str] = set()
        for brand, legit_domains in _PROTECTED_BRANDS.items():
            # Skip if the domain IS a legitimate brand domain
            if domain in legit_domains:
                continue

            for segment in segments:
                # Only compare when lengths are close enough to possibly match
                if abs(len(segment) - len(brand)) > 2:
                    continue

                dist = _levenshtein(segment, brand)
                if 0 < dist <= 2 and brand not in matched_brands:
                    matched_brands.add(brand)
                    findings.append({
                        "domain": domain,
                        "brand": brand,
                        "distance": dist,
                        "risk_score": 20,
                    })
                    logger.warning(
                        "Lookalike domain: %s resembles brand '%s' (distance=%d)",
                        domain, brand, dist,
                    )

    return findings
