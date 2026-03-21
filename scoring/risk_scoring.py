"""
Risk Scoring Engine (v4)
-------------------------
Refactored scoring that keeps three dimensions separate:

  - risk_score        (0-100): malicious-evidence score only
  - confidence        (0.0-1.0): confidence in classification
  - data_completeness (0-100): evidence availability/coverage

Missing data (e.g. SPF/DKIM/DMARC="none" or missing Received chain)
is treated as incomplete evidence, not direct phishing evidence.
"""

import logging

from email_analysis.brand_impersonation import BRAND_DATABASE

logger = logging.getLogger(__name__)

_RULE_CATEGORIES = (
    "data completeness",
    "auth checks",
    "ESP detection",
    "URL behavior",
    "brand impersonation",
    "content/language",
    "attachment/malware",
)

_CATEGORY_CAPS = {
    "auth checks": 30,
    "URL behavior": 40,
    "brand impersonation": 35,
    "content/language": 20,
    "attachment/malware": 40,
}

_AUTH_STATUS_WEIGHTS = {
    "spf": {
        "pass": 0,
        "none": 0,
        "softfail": 5,
        "neutral": 2,
        "temperror": 4,
        "permerror": 5,
        "fail": 12,
    },
    "dkim": {
        "pass": 0,
        "none": 0,
        "neutral": 1,
        "temperror": 3,
        "permerror": 4,
        "softfail": 4,
        "fail": 12,
    },
    "dmarc": {
        "pass": 0,
        "none": 0,
        "bestguesspass": 0,
        "softfail": 6,
        "temperror": 4,
        "permerror": 5,
        "fail": 14,
    },
}

_DATA_COMPLETENESS_PENALTIES = {
    "auth_none": 12,
    "missing_received_headers": 20,
    "relay_forensics_unavailable": 6,
    "intel_error": 3,
}

_ESP_MITIGATION_MIN = -20
_ESP_MISMATCH_PENALTY = 10


def calculate_risk(
    auth_results: dict,
    url_reports: list[dict],
    hash_reports: list[dict],
    otx_reports: list[dict],
    heuristics: dict | None = None,
    qr_findings: list[dict] | None = None,
    ip_reputation: list[dict] | None = None,
    passive_dns: list[dict] | None = None,
    ai_verdict: dict | None = None,
    header_forensics: dict | None = None,
    display_name_spoofing: list[dict] | None = None,
    lookalike_domains: list[dict] | None = None,
    credential_harvesting: dict | None = None,
    language_analysis: dict | None = None,
    brand_impersonation: dict | None = None,
    attachment_risks: list[dict] | None = None,
    url_intelligence: dict | None = None,
    domain_intelligence: dict | None = None,
) -> dict:
    """Calculate risk score, confidence, and data completeness."""
    category_scores: dict[str, int] = {k: 0 for k in _RULE_CATEGORIES}
    breakdown: list[str] = []
    completeness_breakdown: list[str] = []

    strong_signals = 0
    weak_signals = 0

    data_completeness = _compute_data_completeness(
        auth_results,
        url_reports,
        hash_reports,
        otx_reports,
        header_forensics,
        completeness_breakdown,
    )
    category_scores["data completeness"] = data_completeness

    # ── 1) Auth checks (none != fail) ────────────────────────
    for check in ("spf", "dkim", "dmarc"):
        status = _status(auth_results.get(check, {}).get("result", "none"))
        pts = _AUTH_STATUS_WEIGHTS.get(check, {}).get(status, 0)
        if pts <= 0:
            continue
        category_scores["auth checks"] += pts
        breakdown.append(f"{check.upper()} {status} (+{pts})")
        if status == "fail":
            strong_signals += 1
        else:
            weak_signals += 1

    for finding in auth_results.get("forensics", {}).get("findings", []):
        if finding.get("type") == "missing_received_headers":
            continue
        pts = int(finding.get("risk_score", 0))
        if pts <= 0:
            continue
        category_scores["auth checks"] += pts
        breakdown.append(
            f"Header forensic: {finding.get('summary', 'anomaly')} (+{pts})"
        )
        if pts >= 10:
            strong_signals += 1
        else:
            weak_signals += 1

    if header_forensics and not header_forensics.get("error"):
        relay_pts = int(header_forensics.get("risk_score", 0))
        if relay_pts > 0:
            category_scores["auth checks"] += relay_pts
            breakdown.append(f"SMTP relay forensics (+{relay_pts})")
            if relay_pts >= 10:
                strong_signals += 1
            else:
                weak_signals += 1

    # ── 2) URL behavior ──────────────────────────────────────
    suspicious_url_lookup: set[str] = set()
    for report in url_reports:
        url = report.get("url", "")
        if report.get("malicious", 0) > 0:
            category_scores["URL behavior"] += 20
            suspicious_url_lookup.add(url)
            breakdown.append(
                f"Malicious URL: {url or '?'} ({report.get('malicious', 0)} engines) (+20)"
            )
            strong_signals += 1
        elif report.get("suspicious", 0) > 0:
            category_scores["URL behavior"] += 8
            suspicious_url_lookup.add(url)
            breakdown.append(f"Suspicious URL: {url or '?'} (+8)")
            weak_signals += 1

    redirect_by_url: dict[str, dict] = {}
    endpoint_url_set: set[str] = set()
    if url_intelligence:
        for finding in url_intelligence.get("shortener_findings", []):
            pts = min(4, int(finding.get("risk_score", 0)))
            if pts <= 0:
                continue
            category_scores["URL behavior"] += pts
            breakdown.append(f"Shortened URL: {finding.get('domain', '?')} (+{pts})")
            weak_signals += 1

        for finding in url_intelligence.get("redirect_findings", []):
            source_url = finding.get("source_url") or finding.get("url", "")
            redirect_by_url[source_url] = finding

            pts = int(finding.get("risk_score", 0))
            if finding.get("is_esp_tracking") and not finding.get("suspicious_landing"):
                pts = 0

            if pts <= 0:
                continue

            category_scores["URL behavior"] += pts
            breakdown.append(
                f"Redirect behavior: {source_url or '?'} → {finding.get('final_domain', '?')} (+{pts})"
            )
            if finding.get("suspicious_landing") or pts >= 10:
                strong_signals += 1
            else:
                weak_signals += 1

        for finding in url_intelligence.get("suspicious_endpoints", []):
            url = finding.get("url", "")
            endpoint_url_set.add(url)
            pts = min(8, int(finding.get("risk_score", 0)))
            if pts <= 0:
                continue
            category_scores["URL behavior"] += pts
            breakdown.append(f"Suspicious endpoint keywords in URL (+{pts})")
            weak_signals += 1

    # ── 3) ESP detection and contradiction handling ──────────
    expected_roots = _expected_context_roots(auth_results, brand_impersonation)
    if url_intelligence:
        for finding in url_intelligence.get("esp_findings", []):
            url = finding.get("url", "")
            provider = finding.get("provider", "ESP")

            redirect_ctx = redirect_by_url.get(url, {})
            final_domain = finding.get("final_domain") or redirect_ctx.get(
                "final_domain", ""
            )
            suspicious_landing = bool(
                finding.get("suspicious_landing")
                or redirect_ctx.get("suspicious_landing")
            )

            has_contradiction = (
                url in suspicious_url_lookup
                or url in endpoint_url_set
                or suspicious_landing
            )

            mismatch = _is_strong_context_mismatch(final_domain, expected_roots)
            if mismatch:
                category_scores["URL behavior"] += _ESP_MISMATCH_PENALTY
                breakdown.append(
                    f"ESP tracking URL mismatches sender/brand context: {provider} (+{_ESP_MISMATCH_PENALTY})"
                )
                strong_signals += 1
                has_contradiction = True

            if has_contradiction:
                continue

            adjust = int(finding.get("risk_adjustment", -6))
            category_scores["ESP detection"] += adjust
            breakdown.append(f"Known ESP pattern: {provider} ({adjust})")

    # ── 4) Brand impersonation ───────────────────────────────
    if brand_impersonation:
        for finding in brand_impersonation.get("domain_impersonation", []):
            pts = int(finding.get("risk_score", 0))
            if pts <= 0:
                continue
            category_scores["brand impersonation"] += pts
            breakdown.append(
                f"Brand domain impersonation: {finding.get('brand', '?')} (+{pts})"
            )
            strong_signals += 1

        for finding in brand_impersonation.get("display_name_spoofing", []):
            pts = int(finding.get("risk_score", 0))
            if pts <= 0:
                continue
            category_scores["brand impersonation"] += pts
            breakdown.append(
                f"Display-name spoofing: {finding.get('brand', '?')} (+{pts})"
            )
            strong_signals += 1

    if heuristics:
        for finding in heuristics.get("homograph", []):
            pts = int(finding.get("risk_score", 0))
            if pts <= 0:
                continue
            category_scores["brand impersonation"] += pts
            breakdown.append(f"Homograph domain pattern (+{pts})")
            strong_signals += 1

        for finding in heuristics.get("suspicious_keywords", []):
            base_pts = int(finding.get("risk_score", 0))
            # Keywords alone are noisy; dampen this signal.
            pts = max(1, min(6, int(base_pts * 0.35))) if base_pts > 0 else 0
            if pts <= 0:
                continue
            category_scores["content/language"] += pts
            breakdown.append(
                f"Keyword indicator '{finding.get('keyword', '?')}' (+{pts})"
            )
            weak_signals += 1

    # ── 5) Content/language ──────────────────────────────────
    if language_analysis:
        for cat_name, cat_info in language_analysis.get("categories", {}).items():
            cat_risk = int(cat_info.get("risk_score", 0))
            if cat_risk <= 0:
                continue
            if cat_name == "urgency":
                # Urgency is explicitly weak signal.
                pts = min(2, cat_risk)
                weak_signals += 1
            else:
                pts = min(8, cat_risk)
                weak_signals += 1
            category_scores["content/language"] += pts
            breakdown.append(f"Language pattern: {cat_name} (+{pts})")

    if ai_verdict:
        ai_label = str(ai_verdict.get("verdict", "")).lower()
        ai_conf = _clamp(float(ai_verdict.get("confidence", 0.0)), 0.0, 1.0)

        if ai_label == "phishing":
            pts = int(round(8 + 6 * ai_conf))
            category_scores["content/language"] += pts
            breakdown.append(f"AI phishing verdict (confidence={ai_conf:.0%}) (+{pts})")
            weak_signals += 1
        elif ai_label == "suspicious":
            pts = int(round(3 + 4 * ai_conf))
            category_scores["content/language"] += pts
            breakdown.append(
                f"AI suspicious verdict (confidence={ai_conf:.0%}) (+{pts})"
            )
            weak_signals += 1
        elif ai_label == "legitimate" and ai_conf >= 0.60:
            category_scores["ESP detection"] -= 4
            breakdown.append(
                f"AI legitimate verdict support (confidence={ai_conf:.0%}) (-4)"
            )

    if credential_harvesting and credential_harvesting.get("detected"):
        pts = min(20, int(credential_harvesting.get("risk_score", 0)))
        if pts > 0:
            category_scores["URL behavior"] += pts
            breakdown.append(f"Credential harvesting form indicators (+{pts})")
            strong_signals += 1

    # ── 6) Attachment/malware ────────────────────────────────
    for report in hash_reports:
        if report.get("malicious", 0) > 0:
            category_scores["attachment/malware"] += 25
            breakdown.append(
                f"Malicious attachment hash ({report.get('malicious', 0)} engines) (+25)"
            )
            strong_signals += 1

    if attachment_risks:
        for finding in attachment_risks:
            pts = int(finding.get("risk_score", 0))
            if pts <= 0:
                continue
            category_scores["attachment/malware"] += pts
            breakdown.append(
                f"Attachment risk: {finding.get('filename', '?')} (+{pts})"
            )
            if pts >= 10:
                strong_signals += 1
            else:
                weak_signals += 1

    for report in otx_reports:
        pulses = int(report.get("pulse_count", 0))
        if pulses <= 0:
            continue
        pts = 10
        if report.get("sha256"):
            category_scores["attachment/malware"] += pts
            breakdown.append(f"OTX pulse hit for attachment hash (+{pts})")
            strong_signals += 1
        else:
            category_scores["URL behavior"] += pts
            breakdown.append(f"OTX pulse hit for domain (+{pts})")
            weak_signals += 1

    # ── 7) IP/domain infrastructure signals ──────────────────
    if ip_reputation:
        for finding in ip_reputation:
            pts = int(finding.get("risk_score", 0))
            if pts <= 0:
                continue
            category_scores["URL behavior"] += pts
            breakdown.append(f"Blacklisted infrastructure IP (+{pts})")
            weak_signals += 1

    if passive_dns:
        for finding in passive_dns:
            pts = int(finding.get("risk_score", 0))
            if pts <= 0:
                continue
            category_scores["URL behavior"] += pts
            breakdown.append(f"Suspicious shared hosting density (+{pts})")
            weak_signals += 1

    if domain_intelligence:
        for w in domain_intelligence.get("whois_results", []):
            pts = min(12, int(w.get("risk_score", 0)))
            if pts <= 0:
                continue
            category_scores["URL behavior"] += pts
            breakdown.append(f"Young domain signal: {w.get('domain', '?')} (+{pts})")
            weak_signals += 1

        for e in domain_intelligence.get("entropy_results", []):
            pts = min(10, int(e.get("risk_score", 0)))
            if pts <= 0:
                continue
            category_scores["URL behavior"] += pts
            breakdown.append(f"High-entropy domain: {e.get('domain', '?')} (+{pts})")
            weak_signals += 1

        for la in domain_intelligence.get("lookalike_results", []):
            pts = min(15, int(la.get("risk_score", 0)))
            if pts <= 0:
                continue
            category_scores["brand impersonation"] += pts
            breakdown.append(
                f"Lookalike domain vs brand {la.get('brand', '?')} (+{pts})"
            )
            strong_signals += 1

    if qr_findings:
        for finding in qr_findings:
            pts = int(finding.get("risk_score", 0))
            if pts <= 0:
                continue
            category_scores["URL behavior"] += pts
            breakdown.append(
                f"QR-delivered URL indicator: {finding.get('filename', '?')} (+{pts})"
            )
            weak_signals += 1

    # Legacy optional signals (preserve compatibility)
    if display_name_spoofing:
        for finding in display_name_spoofing:
            pts = int(finding.get("risk_score", 0))
            if pts <= 0:
                continue
            category_scores["brand impersonation"] += pts
            breakdown.append(f"Display-name spoofing rule hit (+{pts})")
            weak_signals += 1

    if lookalike_domains:
        for finding in lookalike_domains:
            pts = int(finding.get("risk_score", 0))
            if pts <= 0:
                continue
            category_scores["brand impersonation"] += pts
            breakdown.append(
                f"Lookalike domain rule hit: {finding.get('domain', '?')} (+{pts})"
            )
            weak_signals += 1

    # ── Apply per-category caps ──────────────────────────────
    capped_scores: dict[str, int] = {"data completeness": data_completeness}

    for category in (
        "auth checks",
        "URL behavior",
        "brand impersonation",
        "content/language",
        "attachment/malware",
    ):
        cap = _CATEGORY_CAPS[category]
        capped_scores[category] = int(_clamp(category_scores[category], 0, cap))

    capped_scores["ESP detection"] = int(
        _clamp(category_scores["ESP detection"], _ESP_MITIGATION_MIN, 10)
    )

    risk_score = (
        capped_scores["auth checks"]
        + capped_scores["URL behavior"]
        + capped_scores["brand impersonation"]
        + capped_scores["content/language"]
        + capped_scores["attachment/malware"]
        + capped_scores["ESP detection"]
    )
    risk_score = int(_clamp(risk_score, 0, 100))

    confidence = _compute_confidence(
        risk_score,
        data_completeness,
        capped_scores,
        strong_signals,
        weak_signals,
        ai_verdict,
    )

    verdict = _derive_verdict(risk_score, confidence, data_completeness)

    logger.info(
        "Risk scoring: score=%d verdict=%s confidence=%.2f completeness=%d",
        risk_score,
        verdict,
        confidence,
        data_completeness,
    )

    return {
        "score": risk_score,
        "risk_score": risk_score,
        "verdict": verdict,
        "confidence": confidence,
        "data_completeness": data_completeness,
        "category_scores": capped_scores,
        "breakdown": breakdown,
        "completeness_breakdown": completeness_breakdown,
    }


def _compute_data_completeness(
    auth_results: dict,
    url_reports: list[dict],
    hash_reports: list[dict],
    otx_reports: list[dict],
    header_forensics: dict | None,
    completeness_breakdown: list[str],
) -> int:
    """Compute evidence completeness separately from risk."""
    score = 100

    for check in ("spf", "dkim", "dmarc"):
        status = _status(auth_results.get(check, {}).get("result", "none"))
        if status == "none":
            score -= _DATA_COMPLETENESS_PENALTIES["auth_none"]
            completeness_breakdown.append(
                f"{check.upper()} result unavailable (-{_DATA_COMPLETENESS_PENALTIES['auth_none']})"
            )

    missing_received = any(
        f.get("type") == "missing_received_headers"
        for f in auth_results.get("forensics", {}).get("findings", [])
    )
    if missing_received:
        score -= _DATA_COMPLETENESS_PENALTIES["missing_received_headers"]
        completeness_breakdown.append(
            f"Missing Received chain (-{_DATA_COMPLETENESS_PENALTIES['missing_received_headers']})"
        )

    if header_forensics and header_forensics.get("error"):
        score -= _DATA_COMPLETENESS_PENALTIES["relay_forensics_unavailable"]
        completeness_breakdown.append("Relay forensics unavailable (-6)")

    intel_errors = 0
    intel_errors += sum(
        1
        for r in url_reports
        if r.get("error") and r.get("error") != "submitted_for_analysis"
    )
    intel_errors += sum(1 for r in hash_reports if r.get("error"))
    intel_errors += sum(1 for r in otx_reports if r.get("error"))

    if intel_errors > 0:
        penalty = min(15, intel_errors * _DATA_COMPLETENESS_PENALTIES["intel_error"])
        score -= penalty
        completeness_breakdown.append(
            f"Threat-intel lookups unavailable for {intel_errors} indicator(s) (-{penalty})"
        )

    return int(_clamp(score, 0, 100))


def _compute_confidence(
    risk_score: int,
    data_completeness: int,
    category_scores: dict[str, int],
    strong_signals: int,
    weak_signals: int,
    ai_verdict: dict | None,
) -> float:
    """Estimate confidence from evidence strength + completeness."""
    evidence_points = (
        category_scores.get("auth checks", 0)
        + category_scores.get("URL behavior", 0)
        + category_scores.get("brand impersonation", 0)
        + category_scores.get("attachment/malware", 0)
        + int(category_scores.get("content/language", 0) * 0.6)
    )
    evidence_strength = _clamp(evidence_points / 90.0, 0.0, 1.0)

    signal_mix = _clamp((strong_signals + 0.5 * weak_signals) / 8.0, 0.0, 1.0)
    completeness_ratio = _clamp(data_completeness / 100.0, 0.0, 1.0)

    ai_alignment = 0.0
    if ai_verdict:
        ai_label = str(ai_verdict.get("verdict", "")).lower()
        ai_conf = _clamp(float(ai_verdict.get("confidence", 0.0)), 0.0, 1.0)
        if ai_label == "phishing" and risk_score >= 60:
            ai_alignment += 0.08 * ai_conf
        elif ai_label == "legitimate" and risk_score <= 35:
            ai_alignment += 0.08 * ai_conf
        elif ai_label == "suspicious" and 30 <= risk_score <= 75:
            ai_alignment += 0.05 * ai_conf

    confidence = (
        0.10
        + 0.42 * evidence_strength
        + 0.23 * signal_mix
        + 0.25 * completeness_ratio
        + ai_alignment
    )

    if data_completeness < 40:
        confidence *= 0.78
    elif data_completeness < 55:
        confidence *= 0.88

    return round(_clamp(confidence, 0.05, 0.99), 2)


def _derive_verdict(risk_score: int, confidence: float, data_completeness: int) -> str:
    """Map score to verdict with confidence/completeness guardrails."""
    if risk_score >= 85:
        verdict = "CRITICAL"
    elif risk_score >= 65:
        verdict = "HIGH"
    elif risk_score >= 45:
        verdict = "SUSPICIOUS"
    elif risk_score >= 25:
        verdict = "MEDIUM"
    else:
        verdict = "LOW"

    if risk_score < 20 and data_completeness < 55:
        return "INCONCLUSIVE"

    # Low completeness + limited evidence should not be escalated to critical.
    if data_completeness < 35 and risk_score < 60:
        return "INCONCLUSIVE"

    if verdict == "CRITICAL" and (confidence < 0.70 or data_completeness < 60):
        if confidence >= 0.55 and data_completeness >= 45:
            return "HIGH"
        return "SUSPICIOUS"

    if verdict == "HIGH" and confidence < 0.45 and data_completeness < 50:
        return "SUSPICIOUS"

    if (
        verdict in ("LOW", "MEDIUM", "SUSPICIOUS")
        and confidence < 0.25
        and data_completeness < 35
    ):
        return "INCONCLUSIVE"

    return verdict


def _expected_context_roots(
    auth_results: dict, brand_impersonation: dict | None
) -> set[str]:
    """Build expected landing-domain context from sender and detected brand context."""
    roots: set[str] = set()

    sender_domain = auth_results.get("forensics", {}).get("from_domain", "")
    if sender_domain:
        roots.add(_root_domain(sender_domain))

    if not brand_impersonation:
        return roots

    brand_names: set[str] = set()
    for finding in brand_impersonation.get("domain_impersonation", []):
        brand = finding.get("brand")
        if brand:
            brand_names.add(str(brand).lower())
    for finding in brand_impersonation.get("display_name_spoofing", []):
        brand = finding.get("brand")
        if brand:
            brand_names.add(str(brand).lower())
    for finding in brand_impersonation.get("body_brand_mentions", []):
        brand = finding.get("brand")
        if brand:
            brand_names.add(str(brand).lower())

    for brand_name in brand_names:
        info = BRAND_DATABASE.get(brand_name)
        if not info:
            continue
        for domain in info.get("domains", set()):
            roots.add(_root_domain(domain))

    return roots


def _is_strong_context_mismatch(final_domain: str, expected_roots: set[str]) -> bool:
    """Check strong mismatch between final landing domain and expected sender/brand roots."""
    if not final_domain or not expected_roots:
        return False
    final_root = _root_domain(final_domain)
    return final_root not in expected_roots


def _root_domain(domain: str) -> str:
    host = (domain or "").lower().split(":", 1)[0].rstrip(".")
    if not host:
        return ""
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "ac", "gov"):
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _status(value: str) -> str:
    return str(value or "none").strip().lower()


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))
