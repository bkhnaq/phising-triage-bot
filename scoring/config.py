"""Single source of truth for triage states, weights, caps, and coverage."""

from __future__ import annotations

from enum import StrEnum


class AuthState(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    NONE = "NONE"
    NEUTRAL = "NEUTRAL"
    SOFTFAIL = "SOFTFAIL"
    TEMPERROR = "TEMPERROR"
    PERMERROR = "PERMERROR"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def parse(cls, value: object) -> "AuthState":
        normalized = str(value or "").strip().upper().replace("-", "")
        aliases = {"TEMPFAIL": cls.TEMPERROR, "BESTGUESSPASS": cls.PASS}
        if normalized in aliases:
            return aliases[normalized]
        try:
            return cls(normalized)
        except ValueError:
            return cls.UNKNOWN


class SourceStatus(StrEnum):
    AVAILABLE = "AVAILABLE"
    ANALYZED = "ANALYZED"
    NONE_PRESENT = "NONE_PRESENT"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_ANALYZED = "NOT_ANALYZED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class ThreatIntelStatus(StrEnum):
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    CLEAN = "CLEAN"
    NOT_FOUND = "NOT_FOUND"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class EvidenceState(StrEnum):
    """Whether primitive evidence participates in final category scoring."""

    ACTIVE = "ACTIVE"
    CONSUMED = "CONSUMED"
    INFORMATIONAL = "INFORMATIONAL"
    SUPPORTING = "SUPPORTING"
    SUPPRESSED = "SUPPRESSED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class EvidenceGroup(StrEnum):
    AUTHENTICATION = "AUTHENTICATION"
    HEADER_ALIGNMENT = "HEADER_ALIGNMENT"
    URL_DECEPTION = "URL_DECEPTION"
    CREDENTIAL_LURE = "CREDENTIAL_LURE"
    SOCIAL_ENGINEERING = "SOCIAL_ENGINEERING"
    BRAND_IDENTITY = "BRAND_IDENTITY"
    THREAT_INTEL = "THREAT_INTEL"
    ATTACHMENT = "ATTACHMENT"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    AI_ML = "AI_ML"


class Verdict(StrEnum):
    """Threat identity; deliberately independent from risk severity."""

    BENIGN = "BENIGN"
    LIKELY_BENIGN = "LIKELY_BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    PHISHING = "PHISHING"
    BEC = "BEC"
    MALWARE = "MALWARE"
    SPAM = "SPAM"
    UNKNOWN = "UNKNOWN"


class RiskSeverity(StrEnum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    ELEVATED = "ELEVATED"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Every score-bearing detector and renderer must resolve values from this map.
WEIGHTS: dict[str, int] = {
    # Authentication
    "spf_fail": 12,
    "spf_softfail": 5,
    "spf_neutral": 2,
    "spf_temperror": 4,
    "spf_permerror": 5,
    "dkim_fail": 12,
    "dkim_softfail": 4,
    "dkim_neutral": 1,
    "dkim_temperror": 3,
    "dkim_permerror": 4,
    "dmarc_fail": 14,
    "dmarc_softfail": 6,
    "dmarc_temperror": 4,
    "dmarc_permerror": 5,
    # Header/relay mismatches are weak unless correlated with stronger evidence.
    "return_path_mismatch": 3,
    "reply_to_mismatch": 4,
    "message_id_mismatch": 0,
    "relay_mismatch": 2,
    "spf_alignment_mismatch": 4,
    "dkim_alignment_mismatch": 4,
    "no_aligned_authentication": 6,
    "excessive_hops": 3,
    "sender_brand_impersonation": 20,
    "display_name_spoofing": 20,
    "brand_domain_keyword": 25,
    "brand_lookalike": 20,
    "homograph_domain": 30,
    "homograph_brand": 25,
    "suspicious_keyword": 15,
    "hosting_origin": 10,
    "proxy_origin": 15,
    # URL and infrastructure
    "deceptive_hyperlink": 30,
    "suspicious_endpoint": 6,
    "url_shortener": 3,
    "shortener_credential_path": 5,
    "possible_randomized_domain": 3,
    "strong_dga_pattern": 5,
    "young_domain": 12,
    "domain_age_under_7_days": 25,
    "domain_age_under_30_days": 20,
    "domain_age_under_90_days": 10,
    "dns_no_a_or_mx": 10,
    "url_userinfo": 18,
    "url_ip_host": 10,
    "url_punycode": 12,
    "url_encoded_host": 6,
    "url_credential_path": 6,
    "redirect_many_hops": 15,
    "redirect_observed": 5,
    "redirect_shortener_intermediate": 10,
    "redirect_cross_domain": 5,
    "redirect_suspicious_landing": 8,
    "esp_suspicious_landing": 12,
    "credential_form": 10,
    "credential_external_post": 15,
    "credential_password_field": 20,
    "credential_hidden_fields": 5,
    "credential_phishing_phrase": 10,
    "credential_js_submit": 10,
    "credential_form_password_correlation": 10,
    "credential_collection": 20,
    "landing_page": 20,
    "sender_identity_mismatch": 20,
    "landing_password_field": 20,
    "landing_external_post": 15,
    "landing_login_title": 8,
    "landing_brand_mismatch": 8,
    "landing_meta_refresh": 10,
    "qr_detected": 10,
    "qr_url": 15,
    "ip_blacklisted": 20,
    "passive_dns_density": 20,
    "attachment_double_extension": 15,
    "attachment_encrypted_archive": 12,
    "attachment_archive_executable": 20,
    "attachment_vba_macro": 25,
    "attachment_html_credential_cap": 25,
    "vt_malicious_url": 20,
    "vt_suspicious_url": 8,
    "vt_malicious_hash": 25,
    "otx_pulse": 10,
    "ai_phishing": 25,
    "ai_suspicious": 10,
    "ai_support_phishing_very_high": 10,
    "ai_support_phishing_high": 8,
    "ai_support_phishing_medium": 5,
    "ai_support_phishing_low": 2,
    "ai_support_suspicious_high": 2,
    "ai_support_suspicious_medium": 1,
    # Content is aggregated by category, never per keyword.
    "urgency": 2,
    "credential_harvesting_language": 6,
    "authority": 5,
    "threats": 5,
    "financial": 7,
    "account_verification": 4,
    "password_expiration": 4,
    "call_to_action": 2,
    # Correlated findings replace overlapping primitive weight.
    "sender_auth_alignment_failure": 22,
    "credential_lure_deceptive_link": 30,
    "organization_credential_phishing": 15,
    "reply_to_payment_fraud": 12,
    "brand_credential_phish": 20,
    "brand_landing_page": 18,
    "young_obfuscated_landing": 12,
    "language_plus_credential_collection": 10,
    "multi_signal_credential_phishing": 8,
}


CATEGORY_CAPS: dict[str, int] = {
    "auth checks": 30,
    "URL behavior": 40,
    "brand impersonation": 25,
    "content/language": 15,
    "threat intelligence": 25,
    "AI / ML": 10,
    "attachment/malware": 40,
}


# Correlation produces category-owned findings. It is not itself a risk category.
FINDING_CONFIG: dict[str, dict[str, str | int]] = {
    "sender_auth_alignment_failure": {
        "category": "authentication_relay",
        "base_score": WEIGHTS["sender_auth_alignment_failure"],
        "max_score": 25,
        "severity": "HIGH",
    },
    "credential_lure_deceptive_link": {
        "category": "url_web",
        "base_score": WEIGHTS["credential_lure_deceptive_link"],
        "max_score": 35,
        "severity": "HIGH",
    },
    "organization_credential_phishing": {
        "category": "identity_impersonation",
        "base_score": WEIGHTS["organization_credential_phishing"],
        "max_score": 20,
        "severity": "HIGH",
    },
    "reply_to_payment_fraud": {
        "category": "content_social",
        "base_score": WEIGHTS["reply_to_payment_fraud"],
        "max_score": 15,
        "severity": "HIGH",
    },
    "brand_credential_phish": {
        "category": "identity_impersonation",
        "base_score": WEIGHTS["brand_credential_phish"],
        "max_score": 25,
        "severity": "HIGH",
    },
    "brand_landing_page": {
        "category": "identity_impersonation",
        "base_score": WEIGHTS["brand_landing_page"],
        "max_score": 25,
        "severity": "HIGH",
    },
    "young_obfuscated_landing": {
        "category": "url_web",
        "base_score": WEIGHTS["young_obfuscated_landing"],
        "max_score": 20,
        "severity": "MEDIUM",
    },
    "language_plus_credential_collection": {
        "category": "url_web",
        "base_score": WEIGHTS["language_plus_credential_collection"],
        "max_score": 15,
        "severity": "MEDIUM",
    },
}


CROSS_CATEGORY_CONFIG: dict[str, int] = {
    "multi_signal_credential_phishing": WEIGHTS["multi_signal_credential_phishing"],
    "additional_independent_category": 2,
    "max_bonus": 10,
}

ELIGIBLE_CROSS_CATEGORY_TYPES: frozenset[str] = frozenset(
    {
        "authentication_relay",
        "identity_impersonation",
        "url_web",
        "content_social",
        "attachment_malware",
        "threat_intelligence",
        "authentication",
        "identity",
        "url",
        "content",
        "attachment",
        "relay",
    }
)


URL_KEYWORD_CONFIG: dict[str, int] = {
    "standalone_maximum": 2,
    "per_keyword_weight": 1,
    "correlated_weight": 0,
}


AI_SCORING_CONFIG: dict[str, bool | int] = {
    "enabled": True,
    "category_maximum": CATEGORY_CAPS["AI / ML"],
}


RISK_LIMITS: dict[str, int] = {
    "low_max": 24,
    "moderate_max": 44,
    "elevated_max": 64,
    "high_max": 84,
    "critical_min": 85,
}


CRITICAL_EVIDENCE_GATE_CONFIG: dict[str, int] = {
    "critical_threshold": RISK_LIMITS["critical_min"],
    "unconfirmed_score_cap": RISK_LIMITS["high_max"],
}


COVERAGE_WEIGHTS: dict[str, int] = {
    "smtp_headers": 10,
    "authentication": 15,
    "mime_parsing": 10,
    "url_analysis": 15,
    "html_analysis": 10,
    "dns": 10,
    "whois": 5,
    "virustotal": 10,
    "otx": 5,
    "redirect": 10,
    "attachments": 5,
    "ai": 5,
}

COVERAGE_COMPLETE_STATUSES: frozenset[SourceStatus] = frozenset(
    {SourceStatus.AVAILABLE, SourceStatus.ANALYZED, SourceStatus.NONE_PRESENT}
)


RISK_THRESHOLDS: tuple[tuple[int, str], ...] = (
    (RISK_LIMITS["critical_min"], "CRITICAL"),
    (RISK_LIMITS["elevated_max"] + 1, "HIGH"),
    (RISK_LIMITS["moderate_max"] + 1, "ELEVATED"),
    (RISK_LIMITS["low_max"] + 1, "MODERATE"),
    (0, "LOW"),
)


def weight(evidence_id: str, default: int = 0) -> int:
    """Return a configured weight without scattering fallback lookups."""
    return int(WEIGHTS.get(evidence_id, default))


def auth_weight(check: str, state: AuthState | str) -> int:
    parsed = state if isinstance(state, AuthState) else AuthState.parse(state)
    return weight(f"{check.lower()}_{parsed.value.lower()}")


def ai_support_weight(label: str, confidence: float) -> int:
    """Return the bounded AI support score used by evidence and scoring."""
    if not bool(AI_SCORING_CONFIG["enabled"]):
        return 0
    normalized = str(label or "").strip().lower()
    probability = max(0.0, min(1.0, float(confidence)))
    if normalized == "phishing":
        if probability >= 0.95:
            return weight("ai_support_phishing_very_high")
        if probability >= 0.85:
            return weight("ai_support_phishing_high")
        if probability >= 0.70:
            return weight("ai_support_phishing_medium")
        if probability >= 0.55:
            return weight("ai_support_phishing_low")
    elif normalized == "suspicious":
        if probability >= 0.85:
            return weight("ai_support_suspicious_high")
        if probability >= 0.60:
            return weight("ai_support_suspicious_medium")
    return 0
