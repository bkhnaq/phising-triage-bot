"""Feature-based domain randomness analysis; entropy alone never adds risk."""

from __future__ import annotations

from collections import Counter
import math
import re

from email_analysis.domain_utils import registered_domain
from scoring.config import weight

# Small, deterministic vocabulary used only to recognize meaningful domain tokens.
# It intentionally favors common organizational, security, and service words.
_WORDS = frozenset(
    {
        "account",
        "admin",
        "alert",
        "bank",
        "billing",
        "bridge",
        "business",
        "campus",
        "cloud",
        "company",
        "confirm",
        "customer",
        "delivery",
        "desk",
        "digital",
        "education",
        "email",
        "finance",
        "government",
        "help",
        "home",
        "human",
        "invoice",
        "it",
        "login",
        "mail",
        "market",
        "media",
        "message",
        "north",
        "notification",
        "office",
        "online",
        "password",
        "payroll",
        "portal",
        "recovery",
        "reset",
        "school",
        "secure",
        "security",
        "service",
        "social",
        "student",
        "support",
        "team",
        "technology",
        "university",
        "update",
        "verify",
        "west",
        "work",
        "workspace",
    }
)
_VOWELS = frozenset("aeiouy")


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def _word_segments(token: str) -> list[str]:
    """Return a full dictionary segmentation when one exists."""
    normalized = re.sub(r"[^a-z]", "", token.lower())
    if not normalized:
        return []
    best: list[list[str] | None] = [None] * (len(normalized) + 1)
    best[0] = []
    for end in range(1, len(normalized) + 1):
        for start in range(max(0, end - 16), end):
            prefix = best[start]
            word = normalized[start:end]
            if prefix is None or word not in _WORDS:
                continue
            candidate = [*prefix, word]
            if best[end] is None or len(candidate) < len(best[end] or []):
                best[end] = candidate
    return best[-1] or []


def analyze_domain_randomness(domain: str) -> dict:
    """Combine lexical and structural features into a bounded DGA-like score."""
    normalized = str(domain or "").strip().lower().rstrip(".")
    registrable = registered_domain(normalized) or normalized
    labels = [label for label in registrable.split(".") if label]
    host_labels = labels[:-1] if len(labels) > 1 else labels
    hostname = ".".join(host_labels)
    compact = re.sub(r"[^a-z0-9]", "", hostname)
    letters = [char for char in compact if char.isalpha()]
    digits = [char for char in compact if char.isdigit()]
    lexical_tokens = [token for token in re.split(r"[-._]+", hostname) if token]
    meaningful_tokens: list[str] = []
    for token in lexical_tokens:
        if token in _WORDS:
            meaningful_tokens.append(token)
        else:
            meaningful_tokens.extend(_word_segments(token))
    meaningful_tokens = list(dict.fromkeys(meaningful_tokens))

    entropy = round(_entropy(compact), 2)
    length = len(compact)
    digit_ratio = len(digits) / length if length else 0.0
    vowel_ratio = (
        sum(char in _VOWELS for char in letters) / len(letters) if letters else 0.0
    )
    consonant_runs = re.findall(r"[bcdfghjklmnpqrstvwxz]+", "".join(letters))
    longest_consonant_run = max(map(len, consonant_runs), default=0)
    repeated_sequence = bool(re.search(r"(.)\1{2,}|([a-z0-9]{2,4})\2{2,}", compact))
    alpha_digit_mixture = bool(letters and digits)
    alternating_mixture = bool(re.search(r"(?:[a-z]\d|\d[a-z]){2,}", compact))
    hyphen_count = hostname.count("-")
    subdomain_length = sum(len(label) for label in normalized.split(".")[:-2])
    label_count = len(normalized.split(".")) if normalized else 0

    score = 0
    reasons: list[str] = []
    if entropy >= 3.3 and length >= 9:
        score += 1
        reasons.append("high Shannon entropy combined with sufficient hostname length")
    if 0.15 <= digit_ratio <= 0.65:
        score += 1
        reasons.append("unusual digit ratio")
    if alpha_digit_mixture:
        score += 1
        reasons.append("mixed alphabetic and numeric characters")
    if alternating_mixture:
        score += 1
        reasons.append("alternating alphabet/digit pattern")
    if letters and vowel_ratio < 0.18:
        score += 1
        reasons.append("very low vowel ratio")
    if longest_consonant_run >= 5:
        score += 1
        reasons.append("long consonant sequence")
    if repeated_sequence:
        score += 1
        reasons.append("repeated character sequence")
    if length >= 18 and not meaningful_tokens:
        score += 1
        reasons.append("long hostname without recognized words")
    if subdomain_length >= 24:
        score += 1
        reasons.append("unusually long subdomain")
    if label_count >= 5:
        score += 1
        reasons.append("many domain labels")

    if meaningful_tokens:
        score -= min(5, 1 + len(meaningful_tokens))
        reasons.append("meaningful tokens reduce randomized-domain likelihood")
    if hyphen_count and meaningful_tokens:
        score -= 1
    score = max(0, score)

    if score >= 5:
        classification = "strong_dga_pattern"
        risk_score = weight("strong_dga_pattern")
        description = "Strong algorithmically generated / randomized domain pattern"
    elif score >= 3:
        classification = "possible_randomized_domain"
        risk_score = weight("possible_randomized_domain")
        description = "Possible algorithmically generated / randomized domain"
    else:
        classification = "not_randomized"
        risk_score = 0
        description = "No multi-feature randomized-domain pattern"

    return {
        "domain": normalized,
        "classification": classification,
        "description": description,
        "risk_score": risk_score,
        "randomness_score": score,
        "entropy": entropy,
        "hostname_length": length,
        "digit_ratio": round(digit_ratio, 3),
        "alpha_digit_mixture": alpha_digit_mixture,
        "hyphen_count": hyphen_count,
        "vowel_ratio": round(vowel_ratio, 3),
        "longest_consonant_run": longest_consonant_run,
        "meaningful_tokens": meaningful_tokens,
        "subdomain_length": subdomain_length,
        "label_count": label_count,
        "repeated_sequence": repeated_sequence,
        "reasons": reasons,
    }
