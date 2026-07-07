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
) -> dict:
    evidence = []

    for check in ("spf", "dkim", "dmarc"):
        result = str(auth_results.get(check, {}).get("result", "none")).lower()
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
    categories = {item.category for item in evidence}
    correlations: list[dict] = []

    if {"auth", "credential_harvesting", "brand_impersonation"} <= categories:
        correlations.append(
            {
                "type": "brand_credential_phish",
                "summary": "Auth anomaly, brand impersonation, and credential harvesting co-occur",
                "risk_score": 20,
            }
        )

    if "landing_page" in categories and "brand_impersonation" in categories:
        correlations.append(
            {
                "type": "brand_landing_page",
                "summary": "Brand impersonation is reinforced by suspicious landing-page evidence",
                "risk_score": 15,
            }
        )

    if "domain" in categories and ("url" in categories or "landing_page" in categories):
        correlations.append(
            {
                "type": "young_obfuscated_landing",
                "summary": "Young domain combined with URL or landing-page suspicious indicators",
                "risk_score": 12,
            }
        )

    if language_analysis and language_analysis.get("total_matches", 0) >= 3:
        if "credential_harvesting" in categories or "landing_page" in categories:
            correlations.append(
                {
                    "type": "language_plus_credential_collection",
                    "summary": "Phishing language reinforces credential collection evidence",
                    "risk_score": 8,
                }
            )

    return correlations[:5]
