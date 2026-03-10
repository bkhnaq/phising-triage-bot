"""
Homograph / Look-alike Brand Detection Module
----------------------------------------------
Detects ASCII look-alike substitutions in domains that impersonate known brands.

Example:
    paypa1-verification-security-login.com  →  paypal  (1→l substitution)
    micr0soft-login.com                     →  microsoft  (0→o substitution)

Usage:
    from email_analysis.homograph_analyzer import normalize_domain, detect_homograph_brand
    result = detect_homograph_brand("paypa1-verification.com")
"""

import logging

logger = logging.getLogger(__name__)

# ── Look-alike character map ────────────────────────────────
# Characters commonly swapped by attackers to evade brand detection.
_LOOKALIKE_MAP: dict[str, str] = {
    "1": "l",
    "0": "o",
    "3": "e",
    "5": "s",
    "7": "t",
    "@": "a",
}

# ── Known brands and their legitimate domains ───────────────
_BRAND_KEYWORDS: list[str] = [
    "paypal",
    "microsoft",
    "apple",
    "google",
    "amazon",
    "bank",
    "outlook",
    "office365",
    "netflix",
    "facebook",
    "instagram",
    "linkedin",
    "dropbox",
    "wellsfargo",
    "chase",
]


def normalize_domain(domain: str) -> str:
    """
    Replace common look-alike characters in a domain string.

    Args:
        domain: The raw domain name (e.g. ``paypa1-login.com``).

    Returns:
        Normalized domain with substitutions applied
        (e.g. ``paypal-login.com``).
    """
    normalized = domain.lower()
    for fake, real in _LOOKALIKE_MAP.items():
        normalized = normalized.replace(fake, real)
    return normalized


def detect_homograph_brand(domain: str) -> dict | None:
    """
    Check whether a domain uses look-alike characters to impersonate a brand.

    The function normalizes the domain, then checks if a known brand appears
    in the *normalized* form but **not** in the *original* form.  This
    guarantees only actual substitutions are flagged (legitimate brand domains
    are not penalized).

    Args:
        domain: Raw domain name.

    Returns:
        A dict with detection details, or ``None`` if no impersonation found.
        Dict keys: ``original_domain``, ``normalized_domain``,
        ``brand``, ``risk_score``.
    """
    domain_lower = domain.lower()
    normalized = normalize_domain(domain_lower)

    # Only flag when normalization actually changed something
    if normalized == domain_lower:
        return None

    for brand in _BRAND_KEYWORDS:
        if brand in normalized and brand not in domain_lower:
            logger.warning(
                "Homograph brand impersonation: %s → %s (brand: %s)",
                domain, normalized, brand,
            )
            return {
                "original_domain": domain,
                "normalized_domain": normalized,
                "brand": brand,
                "risk_score": 25,
            }

    return None


def detect_homograph_brands(domains: list[str]) -> list[dict]:
    """
    Run look-alike brand detection across a list of domains.

    Args:
        domains: List of domain strings.

    Returns:
        List of finding dicts (one per flagged domain).
    """
    findings: list[dict] = []
    checked: set[str] = set()

    for raw_domain in domains:
        domain = raw_domain.lower().split(":")[0]  # strip port
        if domain in checked:
            continue
        checked.add(domain)

        result = detect_homograph_brand(domain)
        if result is not None:
            findings.append(result)

    return findings
