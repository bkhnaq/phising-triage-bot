"""Evidence normalization and cross-signal correlation rules."""

from __future__ import annotations

from email_analysis.evidence import evidence_to_dicts, make_evidence


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
) -> dict:
    evidence = []
    suspicious_deceptive_urls = {
        str(finding.get("url", ""))
        for finding in (url_intelligence or {}).get("deceptive_links", [])
        if int(finding.get("risk_score", 0)) > 0
    }

    for check in ("spf", "dkim", "dmarc"):
        result = str(auth_results.get(check, {}).get("result", "unknown")).lower()
        if result in {"fail", "softfail", "permerror"}:
            evidence.append(
                make_evidence(
                    category="auth",
                    source="header_analyzer",
                    entity_type="email",
                    indicator=check,
                    severity="high" if result == "fail" else "medium",
                    confidence=0.85,
                    risk_delta=12 if result == "fail" else 6,
                    state="suspicious",
                    summary=f"{check.upper()} {result}",
                    details=auth_results.get(check, {}).get("details", ""),
                    tags=["authentication"],
                )
            )
        elif result in {"none", "unknown"}:
            evidence.append(
                make_evidence(
                    category="auth",
                    source="header_analyzer",
                    entity_type="email",
                    indicator=check,
                    severity="informational",
                    confidence=1.0,
                    risk_delta=0,
                    state="unknown",
                    summary=f"{check.upper()} result unavailable",
                    details=auth_results.get(check, {}).get("details", ""),
                    tags=["authentication", "missing_evidence"],
                )
            )

    for finding in auth_results.get("forensics", {}).get("findings", []):
        finding_type = str(finding.get("type", "header_finding"))
        risk_delta = int(finding.get("risk_score", 0))
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

    for finding in auth_results.get("alignment", {}).get("findings", []):
        evidence.append(
            make_evidence(
                category="auth",
                source="auth_alignment",
                entity_type="domain",
                indicator=finding.get("type", "alignment"),
                severity="medium",
                confidence=0.80,
                risk_delta=int(finding.get("risk_score", 0)),
                state="suspicious",
                summary=finding.get("summary", "Authentication alignment issue"),
                details=finding.get("details", ""),
                tags=["alignment"],
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
                    risk_delta=30,
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
        evidence.append(
            make_evidence(
                category="url",
                source="url_normalizer",
                entity_type="url",
                indicator=url.get("url", ""),
                severity="medium",
                confidence=0.75,
                risk_delta=int(url.get("url_risk_score", 0)),
                state="suspicious",
                summary="URL obfuscation indicators",
                details="; ".join(url.get("url_warnings", [])),
                tags=["url_obfuscation"],
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
                risk_delta=25 if state == "malicious" else 8,
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
                risk_delta=10,
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
                risk_delta=min(20, int(credential_harvesting.get("risk_score", 0))),
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

    language_weights = {
        "urgency": 2,
        "credential_harvesting": 8,
        "authority": 5,
        "threats": 5,
        "financial": 8,
        "account_verification": 5,
        "password_expiration": 5,
        "call_to_action": 3,
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
        evidence.append(
            make_evidence(
                category="ai_ml",
                source=str(ai_verdict.get("provider", "ai_classifier")),
                entity_type="email",
                indicator=label,
                severity="medium" if label == "phishing" else "informational",
                confidence=float(ai_verdict.get("confidence", 0.0)),
                risk_delta=0,
                state="suspicious" if label == "phishing" else label,
                summary=f"AI classifier verdict: {label}",
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
                risk_delta=int(page.get("risk_score", 0)),
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
                risk_delta=int(whois.get("risk_score", 0)),
                state="suspicious",
                summary="Newly registered or young domain",
                details=f"age_days={whois.get('age_days')}",
                tags=["domain_age"],
            )
        )

    correlations = _correlate(evidence, language_analysis)
    return {
        "evidence": evidence_to_dicts(evidence),
        "correlations": correlations,
        "risk_score": min(sum(int(c.get("risk_score", 0)) for c in correlations), 30),
    }


def _correlate(evidence: list, language_analysis: dict | None) -> list[dict]:
    # Unknown/unavailable observations are useful for completeness, but they must
    # never satisfy a malicious-evidence correlation rule.
    categories = {
        item.category
        for item in evidence
        if item.state in {"suspicious", "malicious"} and item.risk_delta > 0
    }
    correlations: list[dict] = []
    tags = {tag for item in evidence for tag in item.tags}
    language_categories = set((language_analysis or {}).get("categories", {}))

    def add(
        finding_type: str,
        summary: str,
        risk_score: int,
        confidence: float,
        evidence_lines: list[str],
    ) -> None:
        correlations.append(
            {
                "type": finding_type,
                "name": summary,
                "summary": summary,
                "severity": "high" if risk_score >= 12 else "medium",
                "confidence": confidence,
                "source": "correlation_engine",
                "evidence": evidence_lines,
                "risk_score": risk_score,
                "status": "detected",
            }
        )

    credential_language = bool(
        {"credential_harvesting", "account_verification"} & language_categories
    )
    authority_language = "authority" in language_categories
    if (
        "sender_identity_mismatch" in tags
        and credential_language
        and authority_language
    ):
        evidence_lines = [
            "Sender domain differs from the claimed organization",
            "Message requests account authentication or reactivation",
            "Authority/help-desk impersonation language is present",
        ]
        if "password_expiration" in language_categories:
            evidence_lines.append("Password-expiration lure is present")
        add(
            "organization_credential_phishing",
            "Organization credential-phishing pattern",
            15,
            0.90,
            evidence_lines,
        )

    if "deceptive_link" in tags and credential_language:
        add(
            "deceptive_credential_link",
            "Deceptive hyperlink reinforces a credential-phishing request",
            15,
            0.95,
            [
                "Displayed URL domain differs from the actual HREF domain",
                "Message contains credential/account verification language",
            ],
        )

    if "reply_to_mismatch" in tags and "financial" in language_categories:
        add(
            "reply_to_payment_fraud",
            "Reply-To mismatch combined with a payment request",
            12,
            0.85,
            ["Reply-To differs from From", "Financial pressure language is present"],
        )

    if {"auth", "credential_harvesting", "brand_impersonation"} <= categories:
        add(
            "brand_credential_phish",
            "Auth anomaly, brand impersonation, and credential harvesting co-occur",
            15,
            0.90,
            [
                "Authentication anomaly",
                "Brand impersonation",
                "Credential collection evidence",
            ],
        )

    if "landing_page" in categories and "brand_impersonation" in categories:
        add(
            "brand_landing_page",
            "Brand impersonation is reinforced by suspicious landing-page evidence",
            15,
            0.90,
            ["Brand impersonation", "Suspicious landing-page evidence"],
        )

    if "domain" in categories and ("url" in categories or "landing_page" in categories):
        add(
            "young_obfuscated_landing",
            "Young domain combined with URL or landing-page suspicious indicators",
            12,
            0.80,
            ["Young domain", "Suspicious URL or landing page"],
        )

    if language_analysis and language_analysis.get("total_matches", 0) >= 3:
        if "credential_harvesting" in categories or "landing_page" in categories:
            add(
                "language_plus_credential_collection",
                "Phishing language reinforces credential collection evidence",
                8,
                0.80,
                [
                    "Multiple phishing-language categories",
                    "Credential collection evidence",
                ],
            )

    return correlations[:5]
