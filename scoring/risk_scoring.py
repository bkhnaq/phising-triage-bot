"""
Risk Scoring Engine (v4)
-------------------------
Refactored scoring that keeps three dimensions separate:

  - risk_score        (0-100): malicious-evidence score only
  - confidence        (0.0-1.0): confidence in classification
  - data_completeness (0-100): evidence availability/coverage

Missing data (e.g. SPF/DKIM/DMARC="unknown" or missing Received chain)
is treated as incomplete evidence, not direct phishing evidence.
"""

import logging
from itertools import combinations

from email_analysis.url_keyword_context import build_url_keyword_context
from scoring.config import (
    CATEGORY_CAPS,
    CRITICAL_EVIDENCE_GATE_CONFIG,
    COVERAGE_COMPLETE_STATUSES,
    CROSS_CATEGORY_CONFIG,
    COVERAGE_WEIGHTS,
    ELIGIBLE_CROSS_CATEGORY_TYPES,
    AuthState,
    EvidenceState,
    RISK_THRESHOLDS,
    RiskSeverity,
    SourceStatus,
    Verdict,
    ai_support_weight,
    auth_weight,
    weight,
)

logger = logging.getLogger(__name__)

_RULE_CATEGORIES = (
    "data completeness",
    "auth checks",
    "ESP detection",
    "URL behavior",
    "brand impersonation",
    "content/language",
    "AI / ML",
    "attachment/malware",
)

_CATEGORY_CAPS = CATEGORY_CAPS

_DATA_COMPLETENESS_PENALTIES = {
    "auth_none": 12,
    "missing_received_headers": 20,
    "relay_forensics_unavailable": 6,
}

_ESP_MITIGATION_MIN = -20


def calculate_risk(
    auth_results: dict,
    url_reports: list[dict] | None = None,
    hash_reports: list[dict] | None = None,
    otx_reports: list[dict] | None = None,
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
    landing_pages: list[dict] | None = None,
    evidence_bundle: dict | None = None,
    email_data: dict | None = None,
    urls: list[dict] | None = None,
    attachments: list[dict] | None = None,
) -> dict:
    """Calculate intrinsic base risk. Legacy enrichment inputs are ignored.

    score/risk_score/verdict/risk_severity remain aliases for existing Python callers.
    The SIEM contract uses only base_score/initial_severity/initial_verdict.
    """
    category_scores: dict[str, int] = {k: 0 for k in _RULE_CATEGORIES}
    breakdown: list[str] = []
    completeness_breakdown: list[str] = []
    coverage_details: dict[str, dict] = {}

    strong_signals = 0
    weak_signals = 0

    data_completeness = _compute_data_completeness(
        auth_results,
        header_forensics,
        completeness_breakdown,
        email_data=email_data,
        attachment_risks=attachment_risks,
        attachments=attachments,
        ai_verdict=ai_verdict,
        coverage_details=coverage_details,
    )
    category_scores["data completeness"] = data_completeness

    # ── 1) Auth checks (none != fail) ────────────────────────
    for check in ("spf", "dkim", "dmarc"):
        status = _status(auth_results.get(check, {}).get("result", "none"))
        pts = auth_weight(check, status)
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
        finding_type = str(finding.get("type", ""))
        # Identity spoofing is scored by the dedicated brand/identity analyzer.
        if finding_type in {"display_name_spoofing", "sender_brand_impersonation"}:
            continue
        pts = weight(finding_type, int(finding.get("risk_score", 0)))
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
    endpoint_url_set: set[str] = set()
    if url_intelligence:
        for finding in url_intelligence.get("shortener_findings", []):
            pts = min(weight("url_shortener"), int(finding.get("risk_score", 0)))
            if pts <= 0:
                continue
            category_scores["URL behavior"] += pts
            breakdown.append(f"Shortened URL: {finding.get('domain', '?')} (+{pts})")
            weak_signals += 1

        for finding in url_intelligence.get("suspicious_endpoints", []):
            url = finding.get("url", "")
            endpoint_url_set.add(url)

        for finding in url_intelligence.get("deceptive_links", []):
            pts = min(weight("deceptive_hyperlink"), int(finding.get("risk_score", 0)))
            if pts <= 0:
                continue
            category_scores["URL behavior"] += pts
            breakdown.append(
                "Deceptive hyperlink: displayed domain differs from HREF " f"(+{pts})"
            )
            strong_signals += 1

    # Known ESP context is intrinsic; it cannot suppress independent detections.
    if url_intelligence:
        deceptive_urls = {
            item.get("url")
            for item in url_intelligence.get("deceptive_links", [])
            if int(item.get("risk_score", 0)) > 0
        }
        for finding in url_intelligence.get("esp_findings", []):
            if finding.get("url") in endpoint_url_set | deceptive_urls:
                continue
            adjust = int(finding.get("risk_adjustment", -6))
            category_scores["ESP detection"] += adjust
            breakdown.append(
                f"Known ESP pattern: {finding.get('provider', 'ESP')} ({adjust})"
            )

    # ── 4) Brand impersonation ───────────────────────────────
    if brand_impersonation:
        for finding in brand_impersonation.get("sender_identity_mismatch", []):
            pts = min(
                weight("sender_identity_mismatch"), int(finding.get("risk_score", 0))
            )
            if pts <= 0:
                continue
            category_scores["brand impersonation"] += pts
            breakdown.append(
                "Sender identity mismatch: "
                f"{finding.get('sender_domain', '?')} vs "
                f"{finding.get('expected_domain', '?')} (+{pts})"
            )
            strong_signals += 1

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

    for context in build_url_keyword_context(
        urls=urls,
        heuristics=heuristics,
        url_intelligence=url_intelligence,
    ):
        pts = int(context["risk_score"])
        if pts <= 0:
            continue
        category_scores["URL behavior"] += pts
        breakdown.append(f"Standalone URL keyword context (+{pts})")
        weak_signals += 1

    # ── 5) Content/language ──────────────────────────────────
    if language_analysis:
        for cat_name, cat_info in language_analysis.get("categories", {}).items():
            cat_risk = int(cat_info.get("risk_score", 0))
            if cat_risk <= 0:
                continue
            max_by_category = {
                "urgency": weight("urgency"),
                "credential_harvesting": weight("credential_harvesting_language"),
                "authority": weight("authority"),
                "threats": weight("threats"),
                "financial": weight("financial"),
                "account_verification": weight("account_verification"),
                "password_expiration": weight("password_expiration"),
                "call_to_action": weight("call_to_action"),
            }
            pts = min(max_by_category.get(cat_name, 3), cat_risk)
            weak_signals += 1
            category_scores["content/language"] += pts
            breakdown.append(f"Language pattern: {cat_name} (+{pts})")

    if ai_verdict:
        ai_label = str(ai_verdict.get("verdict", "")).lower()
        ai_conf = _clamp(float(ai_verdict.get("confidence", 0.0)), 0.0, 1.0)
        pts = ai_support_weight(ai_label, ai_conf)

        if ai_label == "phishing":
            # The model is a bounded supporting category, not a final verdict.
            category_scores["AI / ML"] += pts
            breakdown.append(f"AI phishing support (confidence={ai_conf:.0%}) (+{pts})")
            if ai_conf >= 0.75:
                strong_signals += 1
            else:
                weak_signals += 1
        elif ai_label == "suspicious":
            category_scores["AI / ML"] += pts
            breakdown.append(
                f"AI suspicious support (confidence={ai_conf:.0%}) (+{pts})"
            )
            weak_signals += 1
        elif ai_label == "legitimate" and ai_conf >= 0.60:
            breakdown.append(
                f"AI legitimate verdict recorded (confidence={ai_conf:.0%}, no risk reduction)"
            )

    if credential_harvesting and credential_harvesting.get("detected"):
        pts = min(
            weight("credential_collection"),
            int(credential_harvesting.get("risk_score", 0)),
        )
        if pts > 0:
            category_scores["URL behavior"] += pts
            breakdown.append(f"Credential harvesting form indicators (+{pts})")
            strong_signals += 1

    # ── 6) Attachment/malware ────────────────────────────────
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

    if domain_intelligence:
        for e in domain_intelligence.get("entropy_results", []):
            classification = str(e.get("classification", ""))
            pts = weight(classification, int(e.get("risk_score", 0)))
            if pts <= 0:
                continue
            category_scores["URL behavior"] += pts
            breakdown.append(
                "Randomized-domain pattern: "
                f"{e.get('domain', '?')} ({classification or 'multi-feature'}) (+{pts})"
            )
            weak_signals += 1

        for la in domain_intelligence.get("lookalike_results", []):
            pts = min(weight("brand_lookalike"), int(la.get("risk_score", 0)))
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

    if evidence_bundle:
        for evidence in evidence_bundle.get("evidence", []):
            if (
                evidence.get("category") != "url"
                or evidence.get("source") != "url_normalizer"
            ):
                continue
            pts = min(12, int(evidence.get("risk_delta", 0)))
            if pts <= 0:
                continue
            category_scores["URL behavior"] += pts
            breakdown.append(
                f"URL obfuscation: {evidence.get('indicator', '?')} (+{pts})"
            )
            if pts >= 10:
                strong_signals += 1
            else:
                weak_signals += 1

    # Legacy optional signals (preserve compatibility)
    if display_name_spoofing:
        existing_display_spoofing = {
            (
                str(finding.get("brand", "")).lower(),
                str(finding.get("sender_domain", "")).lower(),
            )
            for finding in (brand_impersonation or {}).get("display_name_spoofing", [])
        }
        for finding in display_name_spoofing:
            key = (
                str(finding.get("brand", "")).lower(),
                str(finding.get("sender_domain", "")).lower(),
            )
            if key in existing_display_spoofing:
                continue
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

    # ── 8) Correlation / deduplication processing layer ──────
    # Findings replace the exact primitive IDs they consume, then contribute
    # inside their owning risk category. There is no "correlation" category.
    raw_category_scores = dict(category_scores)
    consumed_weights = {category: 0 for category in _CATEGORY_CAPS}
    finding_weights = {category: 0 for category in _CATEGORY_CAPS}
    category_items: dict[str, list[dict]] = {
        category: [] for category in _CATEGORY_CAPS
    }
    evidence_by_id = {
        str(item.get("id", "")): item
        for item in (evidence_bundle or {}).get("evidence", [])
    }
    proposed_correlations = list((evidence_bundle or {}).get("correlations", []))
    correlations: list[dict] = []
    consumed_evidence_ids: set[str] = set()

    for finding in proposed_correlations:
        category = _finding_risk_category(str(finding.get("category", "")))
        if category not in _CATEGORY_CAPS:
            logger.warning(
                "Ignoring finding %s with non-risk category %s",
                finding.get("type"),
                category,
            )
            continue

        declared_consumed_ids = {
            str(item) for item in finding.get("consumed_evidence", []) if item
        }
        overlap = declared_consumed_ids & consumed_evidence_ids
        if overlap:
            logger.warning(
                "Ignoring finding %s because evidence was already consumed: %s",
                finding.get("type"),
                ", ".join(sorted(overlap)),
            )
            continue
        consumed_evidence_ids.update(declared_consumed_ids)
        correlations.append(finding)

        for evidence_id in finding.get("consumed_evidence", []):
            primitive = evidence_by_id.get(str(evidence_id))
            if not primitive:
                continue
            primitive_category = _risk_category_for_evidence(primitive)
            if primitive_category not in _CATEGORY_CAPS:
                continue
            available = max(
                0,
                category_scores[primitive_category]
                - consumed_weights[primitive_category],
            )
            deduction = min(
                available,
                max(0, int(primitive.get("risk_delta", 0))),
            )
            consumed_weights[primitive_category] += deduction

        pts = max(
            0,
            int(finding.get("score_contribution", finding.get("risk_score", 0))),
        )
        finding_weights[category] += pts
        category_items[category].append(
            {
                "id": str(finding.get("type", "finding")),
                "label": str(finding.get("summary", "Correlated finding")),
                "contribution": pts,
                "kind": "finding",
            }
        )
        breakdown.append(
            f"Correlated finding [{category}]: "
            f"{finding.get('summary', 'signal cluster')} (+{pts})"
        )
        strong_signals += 1

    for category in _CATEGORY_CAPS:
        category_scores[category] = max(
            0,
            category_scores[category]
            - consumed_weights[category]
            + finding_weights[category],
        )

    # Add active primitive line items for analyst-facing reconciliation.
    for primitive in evidence_by_id.values():
        primitive_state = str(primitive.get("scoring_state", ""))
        if primitive_state not in {
            EvidenceState.ACTIVE.value,
            EvidenceState.SUPPORTING.value,
        }:
            continue
        category = _risk_category_for_evidence(primitive)
        if category not in category_items:
            continue
        pts = max(0, int(primitive.get("risk_delta", 0)))
        if pts or primitive_state == EvidenceState.SUPPORTING.value:
            category_item = {
                "id": str(primitive.get("id", "primitive")),
                "label": str(primitive.get("summary", "Primitive evidence")),
                "contribution": pts,
                "kind": "primitive",
            }
            if primitive_state == EvidenceState.SUPPORTING.value:
                category_item.update(
                    {
                        "state": primitive_state,
                        "supporting_for": primitive.get("consumed_by"),
                    }
                )
            category_items[category].append(category_item)

    # ── Apply category caps once, after correlation ──────────
    capped_scores: dict[str, int] = {"data completeness": data_completeness}
    for category, cap in _CATEGORY_CAPS.items():
        capped_scores[category] = int(_clamp(category_scores[category], 0, cap))

    capped_scores["ESP detection"] = int(
        _clamp(category_scores["ESP detection"], _ESP_MITIGATION_MIN, 10)
    )

    category_details = {
        category: {
            "primitive_raw_subtotal": raw_category_scores[category],
            "consumed_evidence_weight": consumed_weights[category],
            "finding_contribution": finding_weights[category],
            "pre_cap_subtotal": category_scores[category],
            "category_maximum": _CATEGORY_CAPS[category],
            "effective_contribution": capped_scores[category],
            "suppressed_by_category_cap": max(
                0, category_scores[category] - capped_scores[category]
            ),
            "items": category_items[category],
        }
        for category in _CATEGORY_CAPS
    }
    category_details["ESP detection"] = {
        "primitive_raw_subtotal": category_scores["ESP detection"],
        "consumed_evidence_weight": 0,
        "finding_contribution": 0,
        "pre_cap_subtotal": category_scores["ESP detection"],
        "category_maximum": 10,
        "category_minimum": _ESP_MITIGATION_MIN,
        "effective_contribution": capped_scores["ESP detection"],
        "suppressed_by_category_cap": max(
            0,
            abs(category_scores["ESP detection"]) - abs(capped_scores["ESP detection"]),
        ),
        "items": [],
    }

    cross_category_findings = _build_cross_category_findings(
        correlations,
        category_scores=capped_scores,
        ai_verdict=ai_verdict,
    )
    cross_category_bonus = sum(
        int(item["score_contribution"])
        for item in cross_category_findings
        if item.get("status") == "ACTIVE"
    )
    active_cross_raw = sum(
        int(item.get("raw_score", item.get("score_contribution", 0)))
        for item in cross_category_findings
        if item.get("status") == "ACTIVE"
    )
    cross_category_name = "Cross-category Confirmation"
    capped_scores[cross_category_name] = cross_category_bonus
    category_details[cross_category_name] = {
        "primitive_raw_subtotal": active_cross_raw,
        "consumed_evidence_weight": 0,
        "finding_contribution": active_cross_raw,
        "pre_cap_subtotal": active_cross_raw,
        "category_maximum": int(CROSS_CATEGORY_CONFIG["max_bonus"]),
        "effective_contribution": cross_category_bonus,
        "suppressed_by_category_cap": max(0, active_cross_raw - cross_category_bonus),
        "items": [
            {
                "id": str(item.get("id", "cross_category")),
                "label": str(item.get("summary", "Cross-category confirmation")),
                "contribution": int(item.get("score_contribution", 0)),
                "raw_contribution": int(item.get("raw_score", 0)),
                "kind": "cross_category",
                "state": str(item.get("status", "SUPPRESSED")),
                "suppressed_by": item.get("suppressed_by"),
            }
            for item in cross_category_findings
        ],
    }
    risk_score = (
        sum(capped_scores[category] for category in _CATEGORY_CAPS)
        + capped_scores["ESP detection"]
        + cross_category_bonus
    )
    bounded_risk_score = int(_clamp(risk_score, 0, 100))
    pre_limit_score = risk_score
    critical_gate = _evaluate_critical_evidence_gate(
        pre_calibration_score=bounded_risk_score,
        findings=correlations,
        credential_harvesting=credential_harvesting,
    )
    critical_threshold = int(CRITICAL_EVIDENCE_GATE_CONFIG["critical_threshold"])
    unconfirmed_cap = int(CRITICAL_EVIDENCE_GATE_CONFIG["unconfirmed_score_cap"])
    gate_applied = critical_gate["status"] == "NOT_MET"
    risk_score = (
        min(bounded_risk_score, unconfirmed_cap) if gate_applied else bounded_risk_score
    )
    critical_gate["applied"] = gate_applied
    critical_gate["score_cap"] = unconfirmed_cap
    critical_gate["critical_threshold"] = critical_threshold
    calibration_suppressed = bounded_risk_score - risk_score

    confidence, confidence_notes = _compute_confidence(
        risk_score,
        data_completeness,
        capped_scores,
        strong_signals,
        weak_signals,
        ai_verdict,
        correlations,
    )

    risk_severity = _derive_risk_severity(risk_score)
    verdict = _derive_threat_verdict(
        risk_score=risk_score,
        data_completeness=data_completeness,
        evidence_bundle=evidence_bundle,
        auth_results=auth_results,
        credential_harvesting=credential_harvesting,
        attachment_risks=attachment_risks,
        final_findings=correlations,
        category_scores=capped_scores,
    )

    logger.info(
        "Risk scoring: score=%d severity=%s verdict=%s confidence=%.2f completeness=%d",
        risk_score,
        risk_severity,
        verdict,
        confidence,
        data_completeness,
    )

    return {
        "base_score": risk_score,
        "initial_verdict": verdict,
        "initial_severity": risk_severity,
        "score": risk_score,
        "risk_score": risk_score,
        "verdict": verdict,
        "risk_severity": risk_severity,
        "risk_level": risk_severity,
        "confidence": confidence,
        "data_completeness": data_completeness,
        "category_scores": capped_scores,
        "raw_category_scores": raw_category_scores,
        "category_details": category_details,
        "final_findings": correlations,
        "cross_category_findings": cross_category_findings,
        "cross_category_bonus": cross_category_bonus,
        "score_reconciliation": {
            "raw_effective_total": pre_limit_score,
            "pre_calibration_score": bounded_risk_score,
            "score_maximum": 100,
            "base_score": risk_score,
            "suppressed_overall_weight": max(0, pre_limit_score - bounded_risk_score),
            "suppressed_by_calibration": calibration_suppressed,
            "critical_confirmation": bool(critical_gate["met"]),
            "critical_evidence_gate": critical_gate,
            "cross_category_bonus": cross_category_bonus,
        },
        "breakdown": breakdown,
        "completeness_breakdown": completeness_breakdown,
        "evidence_coverage": coverage_details,
        "confidence_notes": confidence_notes,
    }


def _evaluate_critical_evidence_gate(
    *,
    pre_calibration_score: int,
    findings: list[dict],
    credential_harvesting: dict | None,
) -> dict:
    """Require independent intrinsic confirmation for the highest initial severity."""
    if pre_calibration_score < int(CRITICAL_EVIDENCE_GATE_CONFIG["critical_threshold"]):
        return {
            "met": False,
            "status": "NOT_REQUIRED",
            "confirmations": [],
            "reason": "Base score did not reach the Critical threshold.",
        }
    types = {item.get("type") for item in findings}
    confirmations = []
    if "sender_auth_alignment_failure" in types and (
        "credential_lure_deceptive_link" in types
        or bool((credential_harvesting or {}).get("detected"))
    ):
        confirmations.append(
            "Independent sender authentication/alignment failure and credential phishing evidence"
        )
    return {
        "met": bool(confirmations),
        "status": "MET" if confirmations else "NOT_MET",
        "confirmations": confirmations,
        "reason": (
            "; ".join(confirmations)
            if confirmations
            else "Insufficient independent intrinsic evidence for Critical initial severity."
        ),
    }


def _risk_category_for_evidence(evidence: dict) -> str:
    primitive_category = str(evidence.get("category", ""))
    tags = {str(tag) for tag in evidence.get("tags", [])}
    if primitive_category == "brand_impersonation" or "brand" in tags:
        return "brand impersonation"
    return {
        "auth": "auth checks",
        "identity": "auth checks",
        "relay": "auth checks",
        "url": "URL behavior",
        "domain": "URL behavior",
        "credential_harvesting": "URL behavior",
        "content": "content/language",
        "ai_ml": "AI / ML",
        "attachment": "attachment/malware",
    }.get(primitive_category, "")


def _finding_risk_category(category: str) -> str:
    return {
        "authentication_relay": "auth checks",
        "url_web": "URL behavior",
        "identity_impersonation": "brand impersonation",
        "content_social": "content/language",
        "attachment_malware": "attachment/malware",
    }.get(category, category)


def _build_cross_category_findings(
    findings: list[dict],
    *,
    category_scores: dict[str, int] | None = None,
    ai_verdict: dict | None = None,
) -> list[dict]:
    """Build capped confirmations from independent, non-ML technical categories.

    Higher-order combinations are considered first. Any lower-order candidate that
    reuses one of their source findings is retained for explanation but suppressed.
    """
    eligible = [
        finding
        for finding in findings
        if str(finding.get("severity", "")).upper() == "HIGH"
        and float(finding.get("confidence", 0.0)) >= 0.80
        and str(finding.get("category", "")) in ELIGIBLE_CROSS_CATEGORY_TYPES
        and finding.get("evidence_groups")
    ]
    candidates: list[dict] = []
    maximum_order = min(4, len(eligible))
    base_score = int(CROSS_CATEGORY_CONFIG["multi_signal_credential_phishing"])
    additional_score = int(CROSS_CATEGORY_CONFIG["additional_independent_category"])
    category_maximum = int(CROSS_CATEGORY_CONFIG["max_bonus"])

    for order in range(maximum_order, 1, -1):
        for selected in combinations(eligible, order):
            categories = [str(item.get("category", "")) for item in selected]
            if len(set(categories)) != len(categories):
                continue
            used_groups: set[str] = set()
            used_evidence: set[str] = set()
            independent = True
            for finding in selected:
                groups = {
                    str(group) for group in finding.get("evidence_groups", []) if group
                }
                evidence_ids = {
                    str(item) for item in finding.get("consumed_evidence", []) if item
                }
                if used_groups & groups or used_evidence & evidence_ids:
                    independent = False
                    break
                used_groups.update(groups)
                used_evidence.update(evidence_ids)
            if not independent:
                continue

            source_findings = [str(item.get("type", "finding")) for item in selected]
            raw_score = min(
                category_maximum,
                base_score + additional_score * max(0, order - 2),
            )
            candidate_id = "cross_category:" + "+".join(sorted(source_findings))
            candidates.append(
                {
                    "id": candidate_id,
                    "type": "multi_signal_credential_phishing",
                    "name": "Multi-signal credential phishing confirmation",
                    "summary": "Multi-signal credential phishing confirmation",
                    "category": "cross_category_confirmation",
                    "severity": "HIGH",
                    "confidence": min(
                        float(item.get("confidence", 0.0)) for item in selected
                    ),
                    "confidence_level": "HIGH",
                    "source": "cross_category_confirmation",
                    "source_findings": source_findings,
                    "source_evidence": sorted(used_evidence),
                    "independent_categories": categories,
                    "evidence_groups": sorted(used_groups),
                    "raw_score": raw_score,
                }
            )

    candidates.sort(
        key=lambda item: (
            -len(item["independent_categories"]),
            -float(item["confidence"]),
            -int(item["raw_score"]),
            str(item["id"]),
        )
    )
    active_sources: list[tuple[set[str], str]] = []
    remaining = category_maximum
    results: list[dict] = []
    for candidate in candidates:
        sources = set(candidate["source_findings"])
        covering = next(
            (active_id for active, active_id in active_sources if active & sources),
            None,
        )
        if covering:
            candidate["status"] = "SUPPRESSED"
            candidate["scoring_state"] = EvidenceState.SUPPRESSED.value
            candidate["suppressed_by"] = covering
            candidate["score_contribution"] = 0
            candidate["risk_score"] = 0
        elif remaining <= 0:
            candidate["status"] = "SUPPRESSED"
            candidate["scoring_state"] = EvidenceState.SUPPRESSED.value
            candidate["suppressed_by"] = "cross_category_cap"
            candidate["score_contribution"] = 0
            candidate["risk_score"] = 0
        else:
            contribution = min(int(candidate["raw_score"]), remaining)
            candidate["status"] = "ACTIVE"
            candidate["scoring_state"] = EvidenceState.ACTIVE.value
            candidate["suppressed_by"] = None
            candidate["score_contribution"] = contribution
            candidate["risk_score"] = contribution
            remaining -= contribution
            active_sources.append((sources, str(candidate["id"])))

        independent_risk_categories = {
            _finding_risk_category(str(category))
            for category in candidate["independent_categories"]
        }
        candidate["supporting_categories"] = [
            category
            for category, score in (category_scores or {}).items()
            if score > 0
            and category not in independent_risk_categories
            and category
            not in {
                "AI / ML",
                "ESP detection",
                "data completeness",
                "Cross-category Confirmation",
            }
        ]
        if ai_verdict and not ai_verdict.get("error"):
            candidate["ai_agreement"] = {
                "verdict": str(ai_verdict.get("verdict", "UNKNOWN")).upper(),
                "confidence": float(ai_verdict.get("confidence", 0.0)),
                "role": "confidence support only",
                "score_contribution": 0,
            }
        results.append(candidate)
    return results


def _compute_data_completeness(
    auth_results: dict,
    header_forensics: dict | None,
    completeness_breakdown: list[str],
    *,
    email_data: dict | None = None,
    attachment_risks: list[dict] | None = None,
    attachments: list[dict] | None = None,
    ai_verdict: dict | None = None,
    coverage_details: dict[str, dict] | None = None,
) -> int:
    """Compute evidence completeness separately from risk."""
    if email_data is not None:
        return _compute_detailed_completeness(
            auth_results,
            header_forensics,
            completeness_breakdown,
            email_data,
            attachment_risks,
            attachments,
            ai_verdict,
            coverage_details,
        )

    score = 100

    for check in ("spf", "dkim", "dmarc"):
        auth_item = auth_results.get(check, {})
        canonical_state = auth_item.get("state")
        status = _status(
            canonical_state
            if canonical_state is not None
            else (
                "unknown"
                if auth_item.get("result") == "none"
                else auth_item.get("result", "unknown")
            )
        )
        if status in {"none", "unknown"}:
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

    return int(_clamp(score, 0, 100))


def _compute_detailed_completeness(
    auth_results: dict,
    header_forensics: dict | None,
    completeness_breakdown: list[str],
    email_data: dict,
    attachment_risks: list[dict] | None,
    attachments: list[dict] | None,
    ai_verdict: dict | None,
    coverage_details: dict[str, dict] | None,
) -> int:
    """Measure weighted source coverage with explicit applicability states."""
    sources: dict[str, dict] = {}

    def record(source: str, status: SourceStatus, reason: str = "") -> None:
        configured_weight = COVERAGE_WEIGHTS[source]
        sources[source] = {
            "status": status.value,
            "weight": configured_weight,
            "reason": reason,
        }
        if status in {
            SourceStatus.UNAVAILABLE,
            SourceStatus.FAILED,
            SourceStatus.NOT_ANALYZED,
            SourceStatus.PARTIAL,
        }:
            label = source.replace("_", " ").title()
            detail = f": {reason}" if reason else ""
            completeness_breakdown.append(
                f"{label} {status.value.lower()} (0/{configured_weight}){detail}"
            )

    forensics = auth_results.get("forensics", {})
    smtp_available = bool(
        email_data.get("from") and email_data.get("to") and forensics.get("from_domain")
    )
    record(
        "smtp_headers",
        SourceStatus.AVAILABLE if smtp_available else SourceStatus.UNAVAILABLE,
        (
            "essential sender/recipient headers are incomplete"
            if not smtp_available
            else ""
        ),
    )

    auth_states = [
        AuthState.parse(
            auth_results.get(check, {}).get("state")
            or auth_results.get(check, {}).get("result")
        )
        for check in ("spf", "dkim", "dmarc")
    ]
    auth_available = all(state is not AuthState.UNKNOWN for state in auth_states)
    record(
        "authentication",
        SourceStatus.AVAILABLE if auth_available else SourceStatus.UNAVAILABLE,
        "one or more authentication results are unknown" if not auth_available else "",
    )

    mime_available = "body_text" in email_data or "body_html" in email_data
    record(
        "mime_parsing",
        SourceStatus.ANALYZED if mime_available else SourceStatus.FAILED,
    )
    record(
        "url_analysis",
        SourceStatus.ANALYZED if mime_available else SourceStatus.FAILED,
    )
    record(
        "html_analysis",
        (
            SourceStatus.ANALYZED
            if email_data.get("body_html")
            else SourceStatus.NONE_PRESENT
        ),
        "message has no HTML MIME part" if not email_data.get("body_html") else "",
    )

    if attachments is not None:
        attachment_status = (
            SourceStatus.ANALYZED if attachments else SourceStatus.NONE_PRESENT
        )
    elif attachment_risks is not None:
        attachment_status = (
            SourceStatus.ANALYZED if attachment_risks else SourceStatus.NONE_PRESENT
        )
    else:
        attachment_status = SourceStatus.NOT_ANALYZED
    record("attachments", attachment_status)
    ai_available = bool(ai_verdict and not ai_verdict.get("error"))
    record("ai", SourceStatus.AVAILABLE if ai_available else SourceStatus.UNAVAILABLE)

    applicable = [
        details
        for details in sources.values()
        if details["status"] != SourceStatus.NOT_APPLICABLE.value
    ]
    denominator = sum(int(details["weight"]) for details in applicable)
    numerator = sum(
        int(details["weight"])
        for details in applicable
        if SourceStatus(str(details["status"])) in COVERAGE_COMPLETE_STATUSES
    )
    if coverage_details is not None:
        coverage_details.update(sources)
    return round(numerator / denominator * 100) if denominator else 100


def _compute_confidence(
    risk_score: int,
    data_completeness: int,
    category_scores: dict[str, int],
    strong_signals: int,
    weak_signals: int,
    ai_verdict: dict | None,
    final_findings: list[dict] | None = None,
) -> tuple[float, list[str]]:
    """Estimate verdict confidence independently from model confidence."""
    notes: list[str] = []
    structured_categories = (
        "auth checks",
        "URL behavior",
        "brand impersonation",
        "content/language",
        "attachment/malware",
    )
    structured_score = sum(
        category_scores.get(name, 0) for name in structured_categories
    )
    evidence_strength = _clamp(structured_score / 75.0, 0.0, 1.0)
    independent_categories = sum(
        1 for name in structured_categories if category_scores.get(name, 0) > 0
    )
    evidence_diversity = _clamp(independent_categories / 5.0, 0.0, 1.0)
    signal_mix = _clamp((strong_signals + 0.4 * weak_signals) / 8.0, 0.0, 1.0)
    completeness_ratio = _clamp(data_completeness / 100.0, 0.0, 1.0)
    correlation_strength = _clamp(
        sum(
            int(item.get("score_contribution", item.get("risk_score", 0)))
            * float(item.get("confidence", 0.0))
            for item in final_findings or []
        )
        / 45.0,
        0.0,
        1.0,
    )

    ai_alignment = 0.0
    if ai_verdict:
        ai_label = str(ai_verdict.get("verdict", "")).lower()
        ai_conf = _clamp(float(ai_verdict.get("confidence", 0.0)), 0.0, 1.0)
        if ai_label == "phishing" and structured_score >= 25:
            ai_alignment += 0.06 * ai_conf
        elif ai_label == "phishing" and structured_score < 15:
            ai_alignment -= 0.08 * ai_conf
            notes.append(
                "AI phishing verdict has limited independent evidence support."
            )
        elif ai_label == "legitimate" and structured_score >= 40:
            ai_alignment -= 0.12 * ai_conf
            notes.append("AI verdict conflicts with structured suspicious evidence.")
        elif ai_label == "legitimate" and risk_score <= 24:
            ai_alignment += 0.04 * ai_conf
        elif ai_label == "suspicious" and 25 <= structured_score <= 65:
            ai_alignment += 0.04 * ai_conf

    confidence = (
        0.12
        + 0.32 * evidence_strength
        + 0.20 * evidence_diversity
        + 0.08 * signal_mix
        + 0.20 * completeness_ratio
        + 0.10 * correlation_strength
        + ai_alignment
    )

    if data_completeness < 50:
        notes.append("Limited by incomplete intrinsic email evidence.")

    return round(_clamp(confidence, 0.05, 0.99), 2), notes


def _derive_risk_severity(risk_score: int) -> str:
    for threshold, label in RISK_THRESHOLDS:
        if risk_score >= threshold:
            return RiskSeverity(label).value
    return RiskSeverity.LOW.value


def _derive_threat_verdict(
    *,
    risk_score: int,
    data_completeness: int,
    evidence_bundle: dict | None,
    auth_results: dict,
    credential_harvesting: dict | None,
    attachment_risks: list[dict] | None,
    final_findings: list[dict],
    category_scores: dict[str, int],
) -> str:
    """Classify the threat from detections, never from a score threshold alone."""
    finding_types = {str(item.get("type", "")) for item in final_findings}
    phishing_findings = {
        "credential_lure_deceptive_link",
        "organization_credential_phishing",
        "brand_credential_phish",
        "language_plus_credential_collection",
        "reply_to_payment_fraud",
    }
    if finding_types & phishing_findings:
        return Verdict.PHISHING.value
    if credential_harvesting and credential_harvesting.get("detected"):
        return Verdict.PHISHING.value

    auth_states = {
        check: AuthState.parse(
            auth_results.get(check, {}).get("state")
            or auth_results.get(check, {}).get("result")
        )
        for check in ("spf", "dkim", "dmarc")
    }
    forwarding_survived = (
        auth_states["spf"] is AuthState.FAIL
        and auth_states["dkim"] is AuthState.PASS
        and auth_states["dmarc"] is AuthState.PASS
    )
    structured_suspicion = any(
        category_scores.get(category, 0) >= minimum
        and not (category == "auth checks" and forwarding_survived)
        for category, minimum in {
            "auth checks": 12,
            "URL behavior": 10,
            "brand impersonation": 15,
            "attachment/malware": 8,
        }.items()
    )
    if finding_types or attachment_risks or structured_suspicion or risk_score >= 25:
        return Verdict.SUSPICIOUS.value

    if all(state is AuthState.PASS for state in auth_states.values()):
        return Verdict.BENIGN.value if risk_score <= 24 else Verdict.SUSPICIOUS.value
    if forwarding_survived and risk_score <= 24:
        return Verdict.BENIGN.value
    if risk_score == 0 and data_completeness >= 70:
        return Verdict.BENIGN.value
    return Verdict.BENIGN.value


def _status(value: str) -> str:
    return str(value or "none").strip().lower()


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))
