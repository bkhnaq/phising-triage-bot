"""Static domain analysis: randomness, special-use names, and lookalikes."""

from email_analysis.domain_randomness import analyze_domain_randomness
from email_analysis.domain_utils import base_label, registered_domain
from email_analysis.special_use import classify_domain
from scoring.config import weight

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
    """Analyze domain strings without DNS, WHOIS, or reputation lookups."""
    unique = _deduplicate_domains(domains)

    entropy_results = []
    randomness_results = []
    lookalike_results = []
    special_use_results = []
    total_risk = 0

    for domain in unique:
        reg_domain = _registrable_domain(domain)
        if not reg_domain:
            continue

        special = classify_domain(reg_domain)
        if special.is_special_use:
            special_use_results.append(special.to_dict())

        # Entropy
        randomness = entropy_check(reg_domain)
        randomness_results.append(randomness)
        if randomness["risk_score"] > 0:
            # Kept as a compatibility alias. This now means a multi-feature
            # randomized-domain finding, never entropy in isolation.
            entropy_results.append(randomness)
            total_risk += randomness["risk_score"]

        # Lookalike
        look = lookalike_check(reg_domain)
        lookalike_results.extend(look)
        total_risk += sum(lookalike_item["risk_score"] for lookalike_item in look)

    return {
        "entropy_results": entropy_results,
        "randomness_results": randomness_results,
        "lookalike_results": lookalike_results,
        "special_use_results": special_use_results,
        "risk_score": min(total_risk, 60),
    }


def entropy_check(domain: str) -> dict:
    """Compatibility wrapper for the feature-based randomness classifier."""
    return analyze_domain_randomness(domain)


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
                        "risk_score": weight("brand_lookalike"),
                    }
                )
                break

    return findings


# ── Helpers ──────────────────────────────────────────────────


def _deduplicate_domains(domains: list[str]) -> list[str]:
    """Return unique registrable domains while preserving investigation order."""
    seen: set[str] = set()
    result: list[str] = []
    for d in domains:
        d_lower = d.lower().split(":")[0]
        root = registered_domain(d_lower)
        if root and root not in seen:
            seen.add(root)
            result.append(root)
    return result


def _registrable_domain(netloc: str) -> str:
    return registered_domain(netloc)


def _extract_base_label(domain: str) -> str:
    return base_label(domain)


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
