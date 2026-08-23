"""Evidence normalization and cross-signal correlation rules."""

from __future__ import annotations

from email_analysis.evidence import EvidenceItem, evidence_to_dicts, make_evidence
from email_analysis.url_keyword_context import (
    build_url_keyword_context,
    is_credential_keyword_only_url_signal,
    url_is_deceptive_context,
)
from scoring.config import (
    FINDING_CONFIG,
    AuthState,
    EvidenceState,
    ai_support_weight,
    auth_weight,
    weight,
)


def build_evidence_bundle(
    *,
    auth_results: dict,
    urls: list[dict],
    vt_url_reports: list[dict],
    vt_hash_reports: list[dict],
    otx_reports: list[dict],
    credential_harvesting: dict | None,
    brand_impersonation: dict | None,
    language_analysis: dict | None,
    attachment_risks: list[dict] | None,
    landing_pages: list[dict] | None,
    domain_intelligence: dict | None,
    ai_verdict: dict | None = None,
    url_intelligence: dict | None = None,
    header_forensics: dict | None = None,
    heuristics: dict | None = None,
    qr_findings: list[dict] | None = None,
    ip_reputation: list[dict] | None = None,
    passive_dns: list[dict] | None = None,
) -> dict:
    evidence = []
    suspicious_deceptive_urls = {
        str(finding.get("url", ""))
        for finding in (url_intelligence or {}).get("deceptive_links", [])
        if int(finding.get("risk_score", 0)) > 0
    }

    for check in ("spf", "dkim", "dmarc"):
        auth_item = auth_results.get(check, {})
        auth_state = AuthState.parse(auth_item.get("state") or auth_item.get("result"))
        result = auth_state.value.lower()
        if result in {"fail", "softfail", "permerror"}:
            evidence.append(
                make_evidence(
                    category="auth",
                    source="header_analyzer",
                    entity_type="email",
                    indicator=check,
                    severity="high" if result == "fail" else "medium",
                    confidence=0.85,
                    risk_delta=auth_weight(check, auth_state),
                    state="suspicious",
                    summary=f"{check.upper()} {result}",
                    details=auth_results.get(check, {}).get("details", ""),
                    tags=["authentication"],
                )
            )
        elif result in {"none", "unknown"}:
            is_unknown = auth_state is AuthState.UNKNOWN
            evidence.append(
                make_evidence(
                    category="auth",
                    source="header_analyzer",
                    entity_type="email",
                    indicator=check,
                    severity="informational",
                    confidence=1.0,
                    risk_delta=0,
                    state="unknown" if is_unknown else "none",
                    summary=(
                        f"{check.upper()} result unavailable"
                        if is_unknown
                        else f"{check.upper()} explicitly reports NONE"
                    ),
                    details=auth_results.get(check, {}).get("details", ""),
                    tags=(
                        ["authentication", "missing_evidence"]
                        if is_unknown
                        else ["authentication", "explicit_none"]
                    ),
                )
            )

    for finding in auth_results.get("forensics", {}).get("findings", []):
        finding_type = str(finding.get("type", "header_finding"))
        if finding_type in {"display_name_spoofing", "sender_brand_impersonation"}:
            continue
        risk_delta = weight(finding_type, int(finding.get("risk_score", 0)))
        evidence.append(
            make_evidence(
                category="identity" if "mismatch" in finding_type else "relay",
                source="header_analyzer",
                entity_type="email_header",
                indicator=finding_type,
                severity="medium" if risk_delta else "informational",
                confidence=0.85 if risk_delta else 1.0,
                risk_delta=risk_delta,
                state="suspicious" if risk_delta else "unknown",
                summary=finding.get("summary", "Header finding"),
                details=finding.get("details", ""),
                tags=[finding_type],
            )
        )

    forensic_types = {
        str(finding.get("type", ""))
        for finding in auth_results.get("forensics", {}).get("findings", [])
    }
    for finding in auth_results.get("alignment", {}).get("findings", []):
        if str(finding.get("type", "")) in forensic_types:
            continue
        evidence.append(
            make_evidence(
                category="auth",
                source="auth_alignment",
                entity_type="domain",
                indicator=finding.get("type", "alignment"),
                severity="medium",
                confidence=0.80,
                risk_delta=weight(
                    str(finding.get("type", "")),
                    int(finding.get("risk_score", 0)),
                ),
                state="suspicious",
                summary=finding.get("summary", "Authentication alignment issue"),
                details=finding.get("details", ""),
                tags=["alignment"],
            )
        )

    relay_mismatch = next(
        (
            str(warning)
            for warning in (header_forensics or {}).get("warnings", [])
            if str(warning).startswith("Sender domain (")
            and "does not match relay server" in str(warning)
        ),
        "",
    )
    if relay_mismatch:
        evidence.append(
            make_evidence(
                category="relay",
                source="smtp_relay_analyzer",
                entity_type="email_header",
                indicator="relay_mismatch",
                severity="medium",
                confidence=0.85,
                risk_delta=weight("relay_mismatch"),
                state="suspicious",
                summary="SMTP relay domain differs from sender domain",
                details=relay_mismatch,
                tags=["relay_mismatch", "alignment"],
            )
        )

    for url in urls:
        if url.get("deceptive_hyperlink") and (
            url_intelligence is None
            or str(url.get("url", "")) in suspicious_deceptive_urls
        ):
            evidence.append(
                make_evidence(
                    category="url",
                    source="html_anchor_analyzer",
                    entity_type="url",
                    indicator=url.get("url", ""),
                    severity="high",
                    confidence=0.95,
                    risk_delta=weight("deceptive_hyperlink"),
                    state="suspicious",
                    summary="Displayed URL differs from actual HREF destination",
                    details=(
                        f"displayed={url.get('displayed_url', '')}; "
                        f"actual={url.get('url', '')}"
                    ),
                    tags=["deceptive_link", "credential_delivery"],
                )
            )
        if int(url.get("url_risk_score", 0)) <= 0:
            continue
        supporting_keyword_context = is_credential_keyword_only_url_signal(
            url
        ) and url_is_deceptive_context(url.get("url"), urls, url_intelligence)
        evidence.append(
            make_evidence(
                category="url",
                source="url_normalizer",
                entity_type="url",
                indicator=url.get("url", ""),
                severity="medium",
                confidence=0.75,
                risk_delta=(
                    0
                    if supporting_keyword_context
                    else int(url.get("url_risk_score", 0))
                ),
                state="supporting" if supporting_keyword_context else "suspicious",
                summary=(
                    "Credential-path keyword context"
                    if supporting_keyword_context
                    else "URL obfuscation indicators"
                ),
                details="; ".join(url.get("url_warnings", [])),
                tags=(
                    ["url_keyword", "supporting_context"]
                    if supporting_keyword_context
                    else ["url_obfuscation"]
                ),
            )
        )

    for finding in (url_intelligence or {}).get("shortener_findings", []):
        points = min(weight("url_shortener"), int(finding.get("risk_score", 0)))
        if points > 0:
            evidence.append(
                make_evidence(
                    category="url",
                    source="url_intelligence",
                    entity_type="url",
                    indicator=f"shortener:{finding.get('url', '')}",
                    severity="low",
                    confidence=0.80,
                    risk_delta=points,
                    state="suspicious",
                    summary=f"Shortened URL via {finding.get('domain', 'provider')}",
                    tags=["url_shortener"],
                )
            )
    for finding in (url_intelligence or {}).get("redirect_findings", []):
        points = int(finding.get("risk_score", 0))
        if finding.get("is_esp_tracking") and not finding.get("suspicious_landing"):
            points = 0
        if points > 0:
            evidence.append(
                make_evidence(
                    category="url",
                    source="redirect_analyzer",
                    entity_type="url",
                    indicator=f"redirect:{finding.get('source_url', '')}",
                    severity="high" if points >= 10 else "medium",
                    confidence=0.85,
                    risk_delta=points,
                    state="suspicious",
                    summary=(
                        "Suspicious redirect behavior to "
                        f"{finding.get('final_domain', 'unknown destination')}"
                    ),
                    tags=["redirect", "landing_page"],
                )
            )
    for context in build_url_keyword_context(
        urls=urls,
        heuristics=heuristics,
        url_intelligence=url_intelligence,
    ):
        points = int(context["risk_score"])
        evidence.append(
            make_evidence(
                category="url",
                source="url_keyword_context",
                entity_type="url",
                indicator=f"keyword:{context['keyword']}",
                severity="low",
                confidence=0.60,
                risk_delta=points,
                state="suspicious" if points else "supporting",
                summary=f"URL keyword context: {context['keyword']}",
                details="; ".join(context.get("sources", [])),
                tags=["url_keyword", str(context["role"]).lower()],
            )
        )
    for finding in (heuristics or {}).get("homograph", []):
        points = int(finding.get("risk_score", 0))
        if points > 0:
            evidence.append(
                make_evidence(
                    category="brand_impersonation",
                    source="homograph_analyzer",
                    entity_type="domain",
                    indicator=str(finding.get("domain", "homograph")),
                    severity="high",
                    confidence=0.85,
                    risk_delta=points,
                    state="suspicious",
                    summary="Homograph domain pattern",
                    tags=["brand", "homograph"],
                )
            )

    for report in vt_url_reports + vt_hash_reports:
        state = report.get("state")
        if state not in {"malicious", "suspicious"}:
            continue
        evidence.append(
            make_evidence(
                category="threat_intel",
                source="virustotal",
                entity_type="hash" if report.get("sha256") else "url",
                indicator=report.get("sha256") or report.get("url", ""),
                severity="high" if state == "malicious" else "medium",
                confidence=0.90,
                risk_delta=(
                    weight(
                        "vt_malicious_hash"
                        if report.get("sha256")
                        else "vt_malicious_url"
                    )
                    if state == "malicious"
                    else weight("vt_suspicious_url")
                ),
                state=state,
                summary=f"VirusTotal {state} detection",
                details=(
                    f"malicious={report.get('malicious', 0)}, "
                    f"suspicious={report.get('suspicious', 0)}"
                ),
                tags=["threat_intel"],
            )
        )

    for report in otx_reports:
        if report.get("state") != "suspicious":
            continue
        evidence.append(
            make_evidence(
                category="threat_intel",
                source="alienvault_otx",
                entity_type="hash" if report.get("sha256") else "url_or_domain",
                indicator=report.get("sha256")
                or report.get("url")
                or report.get("domain", ""),
                severity="medium",
                confidence=0.75,
                risk_delta=weight("otx_pulse"),
                state="suspicious",
                summary="AlienVault OTX pulse hit",
                details=", ".join(report.get("pulses", [])),
                tags=["threat_intel"],
            )
        )

    if credential_harvesting and credential_harvesting.get("detected"):
        evidence.append(
            make_evidence(
                category="credential_harvesting",
                source="html_form_detector",
                entity_type="html",
                indicator="email_body",
                severity="high",
                confidence=0.85,
                risk_delta=min(
                    weight("credential_collection"),
                    int(credential_harvesting.get("risk_score", 0)),
                ),
                state="suspicious",
                summary="Credential harvesting indicators in email HTML",
                details="; ".join(credential_harvesting.get("findings", [])[:4]),
                tags=["credential_harvesting"],
            )
        )

    if brand_impersonation:
        for finding in brand_impersonation.get("sender_identity_mismatch", []):
            evidence.append(
                make_evidence(
                    category="brand_impersonation",
                    source="sender_identity_detector",
                    entity_type="domain",
                    indicator=finding.get("sender_domain", ""),
                    severity="high",
                    confidence=0.90,
                    risk_delta=int(finding.get("risk_score", 0)),
                    state="suspicious",
                    summary="Sender domain differs from claimed organization",
                    details=finding.get("detail", ""),
                    tags=["brand", "sender_identity_mismatch"],
                )
            )
        for finding in brand_impersonation.get("domain_impersonation", []):
            evidence.append(
                make_evidence(
                    category="brand_impersonation",
                    source="brand_detector",
                    entity_type="domain",
                    indicator=finding.get("domain", ""),
                    severity="high",
                    confidence=0.85,
                    risk_delta=int(finding.get("risk_score", 0)),
                    state="suspicious",
                    summary=f"Brand impersonation: {finding.get('brand', '?')}",
                    details=finding.get("detail", ""),
                    tags=["brand"],
                )
            )
        for finding in brand_impersonation.get("display_name_spoofing", []):
            evidence.append(
                make_evidence(
                    category="brand_impersonation",
                    source="display_name_detector",
                    entity_type="email_header",
                    indicator=(
                        finding.get("sender_domain")
                        or finding.get("brand", "display_name")
                    ),
                    severity="high",
                    confidence=0.85,
                    risk_delta=int(finding.get("risk_score", 0)),
                    state="suspicious",
                    summary=f"Display-name spoofing: {finding.get('brand', '?')}",
                    details=finding.get("detail", ""),
                    tags=["brand", "display_name_spoofing"],
                )
            )

    language_weights = {
        "urgency": weight("urgency"),
        "credential_harvesting": weight("credential_harvesting_language"),
        "authority": weight("authority"),
        "threats": weight("threats"),
        "financial": weight("financial"),
        "account_verification": weight("account_verification"),
        "password_expiration": weight("password_expiration"),
        "call_to_action": weight("call_to_action"),
    }
    for category, finding in (language_analysis or {}).get("categories", {}).items():
        source_weight = int(finding.get("risk_score", 0))
        evidence.append(
            make_evidence(
                category="content",
                source="language_analyzer",
                entity_type="email_body",
                indicator=category,
                severity=(
                    "medium"
                    if category
                    in {
                        "credential_harvesting",
                        "account_verification",
                        "password_expiration",
                        "financial",
                    }
                    else "low"
                ),
                confidence=0.75,
                risk_delta=min(language_weights.get(category, 3), source_weight),
                state="suspicious",
                summary=finding.get("description", category),
                details=", ".join(finding.get("matches", [])[:5]),
                tags=["language", category],
            )
        )

    if ai_verdict and not ai_verdict.get("error"):
        label = str(ai_verdict.get("verdict", "unknown")).lower()
        ai_confidence = float(ai_verdict.get("confidence", 0.0))
        ai_points = ai_support_weight(label, ai_confidence)
        evidence.append(
            make_evidence(
                category="ai_ml",
                source=str(ai_verdict.get("provider", "ai_classifier")),
                entity_type="email",
                indicator=label,
                severity="medium" if label == "phishing" else "informational",
                confidence=ai_confidence,
                risk_delta=ai_points,
                state="suspicious" if label == "phishing" else label,
                summary=(f"AI classifier {label} probability {ai_confidence:.0%}"),
                details="; ".join(ai_verdict.get("reasons", [])[:3]),
                tags=["ai_ml"],
            )
        )

    for finding in attachment_risks or []:
        evidence.append(
            make_evidence(
                category="attachment",
                source="attachment_analyzer",
                entity_type="file",
                indicator=finding.get("filename", ""),
                severity=(
                    "high" if int(finding.get("risk_score", 0)) >= 20 else "medium"
                ),
                confidence=0.80,
                risk_delta=int(finding.get("risk_score", 0)),
                state="suspicious",
                summary=f"Risky attachment: {finding.get('category', 'unknown')}",
                details="; ".join(finding.get("warnings", [])[:4]),
                tags=["attachment"],
            )
        )

    for page in landing_pages or []:
        if int(page.get("risk_score", 0)) <= 0:
            continue
        evidence.append(
            make_evidence(
                category="landing_page",
                source="landing_page_analyzer",
                entity_type="url",
                indicator=page.get("final_url", page.get("url", "")),
                severity="high" if page.get("password_fields") else "medium",
                confidence=0.80,
                risk_delta=min(weight("landing_page"), int(page.get("risk_score", 0))),
                state=page.get("state", "suspicious"),
                summary="Suspicious landing page indicators",
                details="; ".join(page.get("findings", [])[:4]),
                tags=["landing_page"],
            )
        )

    for whois in (domain_intelligence or {}).get("whois_results", []):
        if int(whois.get("risk_score", 0)) <= 0:
            continue
        evidence.append(
            make_evidence(
                category="domain",
                source="domain_intelligence",
                entity_type="domain",
                indicator=whois.get("domain", ""),
                severity="medium",
                confidence=0.70,
                risk_delta=min(weight("young_domain"), int(whois.get("risk_score", 0))),
                state="suspicious",
                summary="Newly registered or young domain",
                details=f"age_days={whois.get('age_days')}",
                tags=["domain_age"],
            )
        )

    for result in (domain_intelligence or {}).get("entropy_results", []):
        classification = str(result.get("classification", ""))
        points = weight(classification, int(result.get("risk_score", 0)))
        if points > 0:
            evidence.append(
                make_evidence(
                    category="domain",
                    source="domain_intelligence",
                    entity_type="domain",
                    indicator=str(result.get("domain", "")),
                    severity="medium",
                    confidence=0.70,
                    risk_delta=points,
                    state="suspicious",
                    summary=f"Randomized-domain pattern: {classification}",
                    tags=["domain_randomness"],
                )
            )
    for result in (domain_intelligence or {}).get("lookalike_results", []):
        points = min(weight("brand_lookalike"), int(result.get("risk_score", 0)))
        if points > 0:
            evidence.append(
                make_evidence(
                    category="brand_impersonation",
                    source="domain_intelligence",
                    entity_type="domain",
                    indicator=str(result.get("domain", "")),
                    severity="high",
                    confidence=0.85,
                    risk_delta=points,
                    state="suspicious",
                    summary=f"Lookalike domain vs {result.get('brand', 'brand')}",
                    tags=["brand", "lookalike"],
                )
            )

    for finding in qr_findings or []:
        points = int(finding.get("risk_score", 0))
        if points > 0:
            evidence.append(
                make_evidence(
                    category="url",
                    source="qr_code_analyzer",
                    entity_type="url",
                    indicator=str(finding.get("url") or finding.get("filename", "")),
                    severity="medium",
                    confidence=0.75,
                    risk_delta=points,
                    state="suspicious",
                    summary=f"QR-delivered URL in {finding.get('filename', 'attachment')}",
                    tags=["qr_url"],
                )
            )
    for finding in ip_reputation or []:
        points = int(finding.get("risk_score", 0))
        if points > 0:
            evidence.append(
                make_evidence(
                    category="threat_intel",
                    source="ip_reputation",
                    entity_type="ip",
                    indicator=str(finding.get("ip", "")),
                    severity="medium",
                    confidence=0.75,
                    risk_delta=points,
                    state="suspicious",
                    summary="Blacklisted infrastructure IP",
                    tags=["threat_intel", "ip_reputation"],
                )
            )
    for finding in passive_dns or []:
        points = int(finding.get("risk_score", 0))
        if points > 0:
            evidence.append(
                make_evidence(
                    category="threat_intel",
                    source="passive_dns",
                    entity_type="ip",
                    indicator=str(finding.get("ip", "")),
                    severity="medium",
                    confidence=0.70,
                    risk_delta=points,
                    state="suspicious",
                    summary="Suspicious shared-hosting density",
                    tags=["threat_intel", "passive_dns"],
                )
            )

    serialized_evidence = evidence_to_dicts(evidence)
    correlations = _correlate(evidence, language_analysis)
    consumed_by = {
        evidence_id: str(finding["type"])
        for finding in correlations
        for evidence_id in finding.get("consumed_evidence", [])
    }
    for item in serialized_evidence:
        finding_id = consumed_by.get(str(item.get("id", "")))
        if finding_id:
            item["scoring_state"] = EvidenceState.CONSUMED.value
            item["consumed_by"] = finding_id
        elif item.get(
            "scoring_state"
        ) == EvidenceState.SUPPORTING.value and "url_keyword" in item.get("tags", []):
            item["consumed_by"] = (
                "credential_lure_deceptive_link"
                if any(
                    finding.get("type") == "credential_lure_deceptive_link"
                    for finding in correlations
                )
                else "deceptive_url_context"
            )
    return {
        "evidence": serialized_evidence,
        "correlations": correlations,
        "risk_score": min(sum(int(c.get("risk_score", 0)) for c in correlations), 50),
    }


def _correlate(evidence: list, language_analysis: dict | None) -> list[dict]:
    """Build category-owned findings and claim every primitive at most once."""
    suspicious_items = [
        item
        for item in evidence
        if item.state in {"suspicious", "malicious"} and item.risk_delta > 0
    ]
    correlations: list[dict] = []
    tags = {tag for item in suspicious_items for tag in item.tags}
    language_categories = set((language_analysis or {}).get("categories", {}))
    claimed_ids: set[str] = set()

    def item_id(item: EvidenceItem) -> str:
        return f"{item.source}:{item.category}:{item.indicator}"[:240]

    def select(
        *, categories: set[str] | None = None, tags: set[str] | None = None
    ) -> list[EvidenceItem]:
        selected: list[EvidenceItem] = []
        for item in suspicious_items:
            if item_id(item) in claimed_ids:
                continue
            if categories and item.category not in categories:
                continue
            if tags and not tags.intersection(item.tags):
                continue
            selected.append(item)
        return selected

    def add(
        finding_type: str,
        summary: str,
        confidence: float,
        consumed_items: list[EvidenceItem],
    ) -> bool:
        available = [
            item for item in consumed_items if item_id(item) not in claimed_ids
        ]
        if len(available) < 2:
            return False
        config = FINDING_CONFIG[finding_type]
        contribution = min(
            int(config["base_score"]),
            int(config["max_score"]),
        )
        evidence_ids = list(dict.fromkeys(item_id(item) for item in available))
        evidence_groups = sorted(
            {str(item.to_dict().get("evidence_group", "")) for item in available} - {""}
        )
        claimed_ids.update(evidence_ids)
        correlations.append(
            {
                "id": f"correlation:{finding_type}",
                "type": finding_type,
                "name": summary,
                "summary": summary,
                "category": str(config["category"]),
                "severity": str(config["severity"]),
                "confidence": confidence,
                "confidence_level": "HIGH" if confidence >= 0.80 else "MEDIUM",
                "source": "correlation_engine",
                "evidence": [item.summary for item in available],
                "evidence_ids": list(dict.fromkeys(evidence_ids)),
                "consumed_evidence": list(dict.fromkeys(evidence_ids)),
                "evidence_groups": evidence_groups,
                "risk_score": contribution,
                "score_contribution": contribution,
                "status": "detected",
            }
        )
        return True

    failed_auth = {
        item.indicator
        for item in suspicious_items
        if item.category == "auth" and item.indicator in {"spf", "dkim", "dmarc"}
    }
    auth_alignment_tags = {
        "return_path_mismatch",
        "no_aligned_authentication",
        "relay_mismatch",
        "spf_alignment_mismatch",
        "dkim_alignment_mismatch",
    }
    auth_failures = [
        item
        for item in select(categories={"auth"})
        if item.indicator in {"spf", "dkim", "dmarc"}
    ]
    alignment_items = select(tags=auth_alignment_tags)
    if {"spf", "dmarc"} <= failed_auth and alignment_items:
        add(
            "sender_auth_alignment_failure",
            "Sender authentication and alignment failure",
            0.95,
            auth_failures + alignment_items,
        )

    credential_language = bool(
        {"credential_harvesting", "account_verification"} & language_categories
    )
    authority_language = "authority" in language_categories
    if "deceptive_link" in tags and credential_language:
        deceptive_items = select(tags={"deceptive_link"})
        credential_items = select(
            categories={"content"},
            tags={"credential_harvesting", "account_verification"},
        )
        add(
            "credential_lure_deceptive_link",
            "Credential-phishing deceptive hyperlink",
            0.95,
            deceptive_items + credential_items,
        )

    if (
        "sender_identity_mismatch" in tags
        and credential_language
        and authority_language
    ):
        identity_items = select(tags={"sender_identity_mismatch"})
        credential_items = select(
            categories={"content"},
            tags={"credential_harvesting", "account_verification"},
        )
        authority_items = select(categories={"content"}, tags={"authority"})
        if identity_items and credential_items and authority_items:
            add(
                "organization_credential_phishing",
                "Organization credential-phishing pattern",
                0.90,
                identity_items + credential_items + authority_items,
            )

    if "reply_to_mismatch" in tags and "financial" in language_categories:
        reply_items = select(tags={"reply_to_mismatch"})
        financial_items = select(categories={"content"}, tags={"financial"})
        if reply_items and financial_items:
            add(
                "reply_to_payment_fraud",
                "Reply-To mismatch combined with a payment request",
                0.85,
                reply_items + financial_items,
            )

    brand_items = select(categories={"brand_impersonation"})
    collection_items = select(categories={"credential_harvesting"})
    remaining_credential_language = select(
        categories={"content"},
        tags={"credential_harvesting", "account_verification", "password_expiration"},
    )
    if brand_items and collection_items:
        add(
            "brand_credential_phish",
            "Brand impersonation and credential collection co-occur",
            0.90,
            brand_items + collection_items + remaining_credential_language,
        )

    brand_items = select(categories={"brand_impersonation"})
    landing_items = select(categories={"landing_page"})
    if landing_items and brand_items:
        add(
            "brand_landing_page",
            "Brand impersonation is reinforced by suspicious landing-page evidence",
            0.90,
            brand_items + landing_items,
        )

    domain_items = select(categories={"domain"})
    url_or_landing_items = select(categories={"url", "landing_page"})
    if domain_items and url_or_landing_items:
        add(
            "young_obfuscated_landing",
            "Young domain combined with URL or landing-page suspicious indicators",
            0.80,
            domain_items + url_or_landing_items,
        )

    if language_analysis and language_analysis.get("total_matches", 0) >= 3:
        language_items = select(categories={"content"})
        collection_items = select(categories={"credential_harvesting", "landing_page"})
        if language_items and collection_items:
            add(
                "language_plus_credential_collection",
                "Phishing language reinforces credential collection evidence",
                0.80,
                language_items + collection_items,
            )

    return correlations[:6]
