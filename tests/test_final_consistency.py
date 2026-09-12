from __future__ import annotations

from email_analysis.analysis_environment import classify_analysis_environment
from email_analysis.correlation import build_evidence_bundle
from email_analysis.observables import ObservableRegistry, collect_observables
from email_analysis.special_use import (
    is_documentation_ip,
    is_nonproduction_observable,
    is_reserved_test_domain,
)
from report.report_generator import generate_report
from scoring.config import AI_SCORING_CONFIG, CROSS_CATEGORY_CONFIG, SourceStatus
from scoring.risk_scoring import _build_cross_category_findings, calculate_risk


def _bundle_inputs() -> dict:
    return {
        "urls": [],
        "vt_url_reports": [],
        "vt_hash_reports": [],
        "otx_reports": [],
        "credential_harvesting": None,
        "brand_impersonation": None,
        "language_analysis": None,
        "attachment_risks": [],
        "landing_pages": [],
        "domain_intelligence": None,
    }


def _unknown_auth() -> dict:
    return {
        "spf": {"result": "unknown"},
        "dkim": {"result": "unknown"},
        "dmarc": {"result": "unknown"},
    }


def test_ai_score_is_identical_in_raw_evidence_and_category() -> None:
    ai = {"verdict": "phishing", "confidence": 1.0, "provider": "local"}
    bundle = build_evidence_bundle(
        auth_results=_unknown_auth(), ai_verdict=ai, **_bundle_inputs()
    )
    result = calculate_risk(
        _unknown_auth(), [], [], [], ai_verdict=ai, evidence_bundle=bundle
    )
    ai_evidence = next(
        item for item in bundle["evidence"] if item["category"] == "ai_ml"
    )

    assert ai_evidence["risk_delta"] == 10
    assert ai_evidence["scoring_state"] == "ACTIVE"
    assert result["category_scores"]["AI / ML"] == 10
    assert result["category_details"]["AI / ML"]["items"] == [
        {
            "id": ai_evidence["id"],
            "label": "AI classifier phishing probability 100%",
            "contribution": 10,
            "kind": "primitive",
        }
    ]
    assert result["risk_severity"] == "LOW"


def test_ai_informational_mode_is_zero_everywhere(monkeypatch) -> None:
    monkeypatch.setitem(AI_SCORING_CONFIG, "enabled", False)
    ai = {"verdict": "phishing", "confidence": 1.0, "provider": "local"}
    bundle = build_evidence_bundle(
        auth_results=_unknown_auth(), ai_verdict=ai, **_bundle_inputs()
    )
    result = calculate_risk(
        _unknown_auth(), [], [], [], ai_verdict=ai, evidence_bundle=bundle
    )
    ai_evidence = next(
        item for item in bundle["evidence"] if item["category"] == "ai_ml"
    )

    assert ai_evidence["risk_delta"] == 0
    assert ai_evidence["scoring_state"] == "INFORMATIONAL"
    assert result["category_scores"]["AI / ML"] == 0


def _high_behavior_bundle() -> dict:
    return {
        "evidence": [],
        "correlations": [
            {
                "type": "sender_auth_alignment_failure",
                "summary": "Sender authentication and alignment failure",
                "category": "authentication_relay",
                "severity": "HIGH",
                "confidence": 0.95,
                "score_contribution": 22,
                "consumed_evidence": [],
                "evidence_groups": ["AUTHENTICATION", "HEADER_ALIGNMENT"],
            },
            {
                "type": "credential_lure_deceptive_link",
                "summary": "Credential-phishing deceptive hyperlink",
                "category": "url_web",
                "severity": "HIGH",
                "confidence": 0.95,
                "score_contribution": 30,
                "consumed_evidence": [],
                "evidence_groups": ["URL_DECEPTION", "CREDENTIAL_LURE"],
            },
            {
                "type": "brand_credential_phish",
                "summary": "Brand credential phishing",
                "category": "identity_impersonation",
                "severity": "HIGH",
                "confidence": 0.90,
                "score_contribution": 20,
                "consumed_evidence": [],
                "evidence_groups": ["BRAND_IDENTITY", "CREDENTIAL_LURE"],
            },
        ],
    }


def test_critical_gate_accepts_independent_intrinsic_phishing_confirmation() -> None:
    ai = {"verdict": "phishing", "confidence": 1.0}
    result = calculate_risk(
        {
            "spf": {"result": "pass"},
            "dkim": {"result": "pass"},
            "dmarc": {"result": "pass"},
        },
        [],
        [],
        [],
        ai_verdict=ai,
        evidence_bundle=_high_behavior_bundle(),
    )
    gate = result["score_reconciliation"]["critical_evidence_gate"]

    assert result["score_reconciliation"]["pre_calibration_score"] >= 85
    assert gate["status"] == "MET"
    assert gate["applied"] is False
    assert result["score"] >= 85
    assert result["risk_severity"] == "CRITICAL"


def test_critical_gate_allows_confirmed_malicious_case() -> None:
    result = calculate_risk(
        {
            "spf": {"result": "pass"},
            "dkim": {"result": "pass"},
            "dmarc": {"result": "pass"},
        },
        [{"url": "https://evil.invalid.test", "malicious": 5}],
        [],
        [],
        ai_verdict={"verdict": "phishing", "confidence": 1.0},
        evidence_bundle=_high_behavior_bundle(),
    )
    gate = result["score_reconciliation"]["critical_evidence_gate"]

    assert gate["status"] == "MET"
    assert gate["applied"] is False
    assert result["score"] >= 85
    assert result["risk_severity"] == "CRITICAL"


def test_observable_deduplication_and_classification_precedence() -> None:
    actual = "https://evil-public-host.com/login"
    records = collect_observables(
        urls=[
            {
                "url": actual,
                "domain": "evil-public-host.com",
                "displayed_url": "https://portal.example.org/account",
                "displayed_domain": "portal.example.org",
                "link_target_comparison": "mismatch",
            },
            {"url": actual, "domain": "evil-public-host.com"},
        ],
        attachments=[],
        url_intelligence={
            "deceptive_links": [
                {
                    "url": actual,
                    "actual_domain": "evil-public-host.com",
                    "risk_score": 30,
                }
            ]
        },
        vt_url_reports=[{"url": actual, "malicious": 4}],
    )
    actual_urls = [
        item for item in records if item["type"] == "url" and item["value"] == actual
    ]

    assert len(actual_urls) == 1
    assert actual_urls[0]["classification"] == "ioc_candidate"
    assert any(item["label"] == "Displayed URL" for item in records)

    registry = ObservableRegistry()
    registry.add("contextual", "URL", actual, "url")
    registry.add("confirmed_malicious", "Known-malicious URL", actual, "url")
    assert registry.records()[0]["classification"] == "confirmed_malicious"


def test_reserved_observables_are_nonexportable() -> None:
    records = collect_observables(
        urls=[
            {"url": "https://login.example.test/verify", "domain": "login.example.test"}
        ],
        attachments=[],
        url_intelligence=None,
    )

    assert is_reserved_test_domain("login.example.test")
    assert is_documentation_ip("203.0.113.77")
    assert is_nonproduction_observable("203.0.113.77", "ip")
    assert all(item["environment"] == "TEST" for item in records)
    assert all(item["exportable"] is False for item in records)
    assert all(item["reputation"] == "NOT_APPLICABLE" for item in records)


def test_applicable_coverage_excludes_na_and_counts_none_present() -> None:
    not_applicable = {"status": SourceStatus.NOT_APPLICABLE.value, "error": None}
    auth = {
        "spf": {"result": "pass"},
        "dkim": {"result": "pass"},
        "dmarc": {"result": "pass"},
        "forensics": {"from_domain": "sender.example", "findings": []},
    }
    result = calculate_risk(
        auth,
        [dict(not_applicable, url="https://portal.example.test")],
        [],
        [dict(not_applicable, domain="portal.example.test")],
        email_data={
            "from": "sender@sender.example",
            "to": "user@example.net",
            "body_text": "hello",
            "body_html": "<p>hello</p>",
        },
        urls=[{"url": "https://portal.example.test"}],
        attachments=[],
        domain_intelligence={
            "whois_results": [dict(not_applicable)],
            "dns_results": [dict(not_applicable)],
        },
        url_intelligence={"redirect_findings": [dict(not_applicable)]},
        ai_verdict={"verdict": "legitimate", "confidence": 0.9},
    )

    assert result["data_completeness"] == 100
    assert result["evidence_coverage"]["attachments"]["status"] == "NONE_PRESENT"


def test_external_provider_failure_does_not_reduce_intrinsic_coverage() -> None:
    auth = {
        "spf": {"result": "pass"},
        "dkim": {"result": "pass"},
        "dmarc": {"result": "pass"},
        "forensics": {"from_domain": "sender.example", "findings": []},
    }
    result = calculate_risk(
        auth,
        [
            {
                "url": "https://production.example.org",
                "status": "ERROR",
                "error": "provider timeout",
            }
        ],
        [],
        [],
        email_data={
            "from": "sender@sender.example",
            "to": "user@example.net",
            "body_text": "hello",
        },
        urls=[{"url": "https://production.example.org"}],
        attachments=[],
        domain_intelligence={},
        url_intelligence={"redirect_findings": []},
        ai_verdict={"verdict": "legitimate", "confidence": 0.9},
    )

    assert "virustotal" not in result["evidence_coverage"]
    assert result["data_completeness"] == 100


def test_normal_report_is_compact_and_debug_report_is_traceable() -> None:
    risk = {
        "score": 10,
        "verdict": "SUSPICIOUS",
        "category_details": {
            "AI / ML": {
                "primitive_raw_subtotal": 10,
                "effective_contribution": 10,
                "category_maximum": 10,
                "items": [
                    {
                        "label": "AI classifier phishing probability 100%",
                        "contribution": 10,
                    }
                ],
            }
        },
    }
    arguments = {
        "email_data": {},
        "auth_results": {},
        "urls": [],
        "attachments": [],
        "risk": risk,
        "vt_url_reports": [],
        "vt_hash_reports": [],
        "otx_reports": [],
    }

    normal = generate_report(**arguments, verbosity="NORMAL")
    debug = generate_report(**arguments, verbosity="EXPLAIN")

    assert "AI / ML: 10 / 10" in normal
    assert "AI classifier phishing probability 100%" not in normal
    assert "AI classifier phishing probability 100%" in debug


def test_critical_gate_is_not_required_below_threshold() -> None:
    result = calculate_risk(
        _unknown_auth(),
        [],
        [],
        [],
        evidence_bundle=_high_behavior_bundle(),
        language_analysis={"categories": {"account_verification": {"risk_score": 4}}},
    )
    gate = result["score_reconciliation"]["critical_evidence_gate"]

    assert result["score_reconciliation"]["pre_calibration_score"] == 84
    assert gate["status"] == "NOT_REQUIRED"
    assert gate["applied"] is False
    assert result["risk_severity"] == "HIGH"


def test_deceptive_url_keyword_context_is_supporting_zero_weight() -> None:
    actual = "https://credential.example.test/secure/login/verify"
    urls = [
        {
            "url": actual,
            "domain": "credential.example.test",
            "deceptive_hyperlink": True,
            "displayed_url": "https://portal.example.test/account",
            "displayed_domain": "portal.example.test",
            "url_risk_score": 6,
            "url_warnings": ["credential-style path keywords: login, secure, verify"],
        }
    ]
    heuristics = {
        "suspicious_keywords": [
            {"keyword": keyword, "source": actual, "risk_score": 15}
            for keyword in ("login", "account", "verify")
        ]
    }
    url_intelligence = {
        "deceptive_links": [
            {
                "url": actual,
                "actual_domain": "credential.example.test",
                "risk_score": 30,
            }
        ],
        "suspicious_endpoints": [
            {
                "url": actual,
                "keywords": ["login", "account", "verify"],
                "risk_score": 6,
            }
        ],
    }
    language = {
        "categories": {
            "credential_harvesting": {
                "risk_score": 5,
                "description": "Credential lure",
            }
        }
    }
    inputs = _bundle_inputs()
    inputs.update(
        {
            "urls": urls,
            "heuristics": heuristics,
            "url_intelligence": url_intelligence,
            "language_analysis": language,
        }
    )
    bundle = build_evidence_bundle(auth_results=_unknown_auth(), **inputs)
    result = calculate_risk(
        _unknown_auth(),
        [],
        [],
        [],
        urls=urls,
        heuristics=heuristics,
        url_intelligence=url_intelligence,
        language_analysis=language,
        evidence_bundle=bundle,
    )
    keyword_evidence = [
        item for item in bundle["evidence"] if "url_keyword" in item.get("tags", [])
    ]

    assert keyword_evidence
    assert all(item["risk_delta"] == 0 for item in keyword_evidence)
    assert all(item["scoring_state"] == "SUPPORTING" for item in keyword_evidence)
    assert result["category_scores"]["URL behavior"] == 30


def test_standalone_url_keywords_share_small_cap() -> None:
    heuristics = {
        "suspicious_keywords": [
            {
                "keyword": keyword,
                "source": "https://example.org/login",
                "risk_score": 15,
            }
            for keyword in ("login", "account", "verify")
        ]
    }
    result = calculate_risk(_unknown_auth(), [], [], [], heuristics=heuristics, urls=[])

    assert result["category_scores"]["URL behavior"] == 2


def _technical_finding(
    finding_type: str, category: str, group: str, evidence_id: str
) -> dict:
    return {
        "type": finding_type,
        "category": category,
        "severity": "HIGH",
        "confidence": 0.95,
        "evidence_groups": [group],
        "consumed_evidence": [evidence_id],
    }


def test_cross_category_cap_and_overlap_suppression() -> None:
    findings = [
        _technical_finding("auth", "authentication_relay", "AUTHENTICATION", "a"),
        _technical_finding("url", "url_web", "URL_DECEPTION", "u"),
        _technical_finding("content", "content_social", "SOCIAL_ENGINEERING", "c"),
    ]
    results = _build_cross_category_findings(findings)
    active = [item for item in results if item["status"] == "ACTIVE"]
    suppressed = [item for item in results if item["status"] == "SUPPRESSED"]

    assert (
        sum(item["score_contribution"] for item in active)
        <= CROSS_CATEGORY_CONFIG["max_bonus"]
    )
    assert len(active) == 1
    assert len(active[0]["independent_categories"]) == 3
    assert suppressed
    assert all(item["score_contribution"] == 0 for item in suppressed)


def test_ai_cannot_trigger_cross_category_confirmation() -> None:
    findings = [
        _technical_finding("url", "url_web", "URL_DECEPTION", "u"),
        _technical_finding("ai", "ai_ml", "AI_ML", "ml"),
    ]

    assert _build_cross_category_findings(findings) == []


def test_two_independent_technical_categories_trigger_confirmation() -> None:
    findings = [
        _technical_finding("auth", "authentication_relay", "AUTHENTICATION", "a"),
        _technical_finding("url", "url_web", "URL_DECEPTION", "u"),
    ]
    results = _build_cross_category_findings(findings)

    assert len(results) == 1
    assert results[0]["status"] == "ACTIVE"
    assert results[0]["score_contribution"] == 8


def _environment_report(environment: dict, observables: list[dict]) -> str:
    return generate_report(
        email_data={},
        auth_results={},
        urls=[],
        attachments=[],
        risk={"score": 0, "verdict": "UNKNOWN"},
        vt_url_reports=[],
        vt_hash_reports=[],
        otx_reports=[],
        observables=observables,
        analysis_environment=environment,
    )


def test_lab_recommendations_are_explicitly_simulated() -> None:
    observables = collect_observables(
        urls=[{"url": "https://example.test/login", "domain": "example.test"}],
        attachments=[],
        url_intelligence=None,
        origin_ip="203.0.113.5",
    )
    environment = classify_analysis_environment(observables, lab_mode=True)
    report = _environment_report(environment, observables)

    assert environment["type"] == "LAB"
    assert "LAB ENVIRONMENT DETECTED" in report
    assert "Suggested playbook:" in report
    assert "not exportable" in report


def test_production_recommendations_are_not_simulated() -> None:
    observables = collect_observables(
        urls=[{"url": "https://public-host.com/login", "domain": "public-host.com"}],
        attachments=[],
        url_intelligence=None,
    )
    environment = classify_analysis_environment(observables)
    report = _environment_report(environment, observables)

    assert environment["type"] == "PRODUCTION"
    assert "Simulated Production Response" not in report


def test_mixed_environment_preserves_per_observable_exportability() -> None:
    test_url = "https://example.test/login"
    production_url = "https://evil-real-domain.com/login"
    observables = collect_observables(
        urls=[
            {"url": test_url, "domain": "example.test"},
            {"url": production_url, "domain": "evil-real-domain.com"},
        ],
        attachments=[],
        url_intelligence={
            "deceptive_links": [
                {"url": test_url, "actual_domain": "example.test", "risk_score": 30},
                {
                    "url": production_url,
                    "actual_domain": "evil-real-domain.com",
                    "risk_score": 30,
                },
            ]
        },
    )
    environment = classify_analysis_environment(observables)
    by_value = {item["value"]: item for item in observables}

    assert environment["type"] == "MIXED"
    assert by_value[test_url]["exportable"] is False
    assert by_value[production_url]["exportable"] is True
