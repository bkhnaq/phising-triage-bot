from __future__ import annotations

from email_analysis.correlation import build_evidence_bundle
from email_analysis.header_analyzer import analyze_headers
from email_analysis.url_extractor import extract_urls
from email_analysis.url_intelligence import analyze_urls
from report.report_generator import generate_report
from scoring.config import CATEGORY_CAPS, CROSS_CATEGORY_CONFIG
from scoring.risk_scoring import calculate_risk


def _auth_with_independent_reply_to() -> dict:
    return {
        "spf": {"result": "fail"},
        "dkim": {"result": "pass"},
        "dmarc": {"result": "fail"},
        "forensics": {
            "from_domain": "example.com",
            "findings": [
                {
                    "type": "return_path_mismatch",
                    "summary": "Return-Path mismatch",
                    "risk_score": 3,
                },
                {
                    "type": "reply_to_mismatch",
                    "summary": "Reply-To mismatch",
                    "risk_score": 4,
                },
            ],
        },
    }


def _auth_bundle() -> dict:
    evidence = [
        {
            "id": "spf",
            "category": "auth",
            "risk_delta": 12,
            "state": "suspicious",
            "scoring_state": "CONSUMED",
            "consumed_by": "sender_auth_alignment_failure",
            "evidence_group": "AUTHENTICATION",
        },
        {
            "id": "dmarc",
            "category": "auth",
            "risk_delta": 14,
            "state": "suspicious",
            "scoring_state": "CONSUMED",
            "consumed_by": "sender_auth_alignment_failure",
            "evidence_group": "AUTHENTICATION",
        },
        {
            "id": "return-path",
            "category": "identity",
            "risk_delta": 3,
            "state": "suspicious",
            "scoring_state": "CONSUMED",
            "consumed_by": "sender_auth_alignment_failure",
            "evidence_group": "HEADER_ALIGNMENT",
        },
        {
            "id": "reply-to",
            "category": "identity",
            "risk_delta": 4,
            "state": "suspicious",
            "scoring_state": "ACTIVE",
            "consumed_by": None,
            "evidence_group": "HEADER_ALIGNMENT",
            "summary": "Reply-To mismatch",
        },
    ]
    finding = {
        "type": "sender_auth_alignment_failure",
        "summary": "Sender authentication and alignment failure",
        "category": "authentication_relay",
        "severity": "HIGH",
        "confidence": 0.95,
        "score_contribution": 22,
        "risk_score": 22,
        "consumed_evidence": ["spf", "dmarc", "return-path"],
        "evidence_groups": ["AUTHENTICATION", "HEADER_ALIGNMENT"],
    }
    return {"evidence": evidence, "correlations": [finding]}


def test_consumed_evidence_counted_once_without_double_suppression() -> None:
    result = calculate_risk(
        _auth_with_independent_reply_to(), [], [], [], evidence_bundle=_auth_bundle()
    )

    assert result["category_scores"]["auth checks"] == 26
    detail = result["category_details"]["auth checks"]
    assert detail["primitive_raw_subtotal"] == 33
    assert detail["consumed_evidence_weight"] == 29
    assert detail["finding_contribution"] == 22
    assert "correlation" not in result["category_scores"]
    assert "correlation" not in CATEGORY_CAPS


def test_cross_category_bonus_requires_independent_groups() -> None:
    bundle = _auth_bundle()
    bundle["correlations"].append(
        {
            "type": "credential_lure_deceptive_link",
            "summary": "Credential-phishing deceptive hyperlink",
            "category": "url_web",
            "severity": "HIGH",
            "confidence": 0.95,
            "score_contribution": 30,
            "risk_score": 30,
            "consumed_evidence": [],
            "evidence_groups": ["URL_DECEPTION", "CREDENTIAL_LURE"],
        }
    )

    result = calculate_risk(
        _auth_with_independent_reply_to(), [], [], [], evidence_bundle=bundle
    )

    assert (
        result["cross_category_bonus"]
        == CROSS_CATEGORY_CONFIG["multi_signal_credential_phishing"]
    )
    assert result["cross_category_bonus"] <= CROSS_CATEGORY_CONFIG["max_bonus"]


def test_cross_category_bonus_rejects_reused_evidence_group() -> None:
    bundle = _auth_bundle()
    bundle["correlations"][0]["evidence_groups"] = ["URL_DECEPTION"]
    bundle["correlations"].append(
        {
            "type": "credential_lure_deceptive_link",
            "summary": "Second URL finding",
            "category": "url_web",
            "severity": "HIGH",
            "confidence": 0.95,
            "score_contribution": 30,
            "risk_score": 30,
            "consumed_evidence": [],
            "evidence_groups": ["URL_DECEPTION"],
        }
    )

    result = calculate_risk(
        _auth_with_independent_reply_to(), [], [], [], evidence_bundle=bundle
    )

    assert result["cross_category_bonus"] == 0


def test_scorer_rejects_a_primitive_claimed_by_two_findings() -> None:
    bundle = _auth_bundle()
    bundle["correlations"].append(
        {
            "type": "credential_lure_deceptive_link",
            "summary": "Invalid duplicate consumer",
            "category": "url_web",
            "severity": "HIGH",
            "confidence": 0.95,
            "score_contribution": 30,
            "risk_score": 30,
            "consumed_evidence": ["spf"],
            "evidence_groups": ["URL_DECEPTION"],
        }
    )

    result = calculate_risk(
        _auth_with_independent_reply_to(), [], [], [], evidence_bundle=bundle
    )

    assert [item["type"] for item in result["final_findings"]] == [
        "sender_auth_alignment_failure"
    ]
    assert result["category_scores"]["URL behavior"] == 0


def test_verdict_is_independent_from_risk_severity() -> None:
    bundle = {
        "evidence": [],
        "correlations": [
            {
                "type": "credential_lure_deceptive_link",
                "summary": "Credential-phishing deceptive hyperlink",
                "category": "url_web",
                "severity": "HIGH",
                "confidence": 0.95,
                "score_contribution": 30,
                "risk_score": 30,
                "consumed_evidence": [],
                "evidence_groups": ["URL_DECEPTION", "CREDENTIAL_LURE"],
            }
        ],
    }
    result = calculate_risk(
        {"spf": {}, "dkim": {}, "dmarc": {}},
        [],
        [],
        [],
        evidence_bundle=bundle,
    )

    assert result["verdict"] == "PHISHING"
    assert result["risk_severity"] == "MODERATE"


def test_authenticated_third_party_sender_does_not_create_auth_finding() -> None:
    auth = analyze_headers(
        [
            ("From", "Company <news@company.com>"),
            ("Return-Path", "<bounce@sendgrid.net>"),
            (
                "Authentication-Results",
                "mx.example; spf=pass smtp.mailfrom=sendgrid.net; "
                "dkim=pass header.d=company.com; dmarc=pass header.from=company.com",
            ),
        ]
    )
    bundle = build_evidence_bundle(
        auth_results=auth,
        urls=[],
        vt_url_reports=[],
        vt_hash_reports=[],
        otx_reports=[],
        credential_harvesting=None,
        brand_impersonation=None,
        language_analysis=None,
        attachment_risks=[],
        landing_pages=[],
        domain_intelligence=None,
    )

    assert "sender_auth_alignment_failure" not in {
        finding["type"] for finding in bundle["correlations"]
    }


def test_deceptive_link_and_credential_lure_create_url_finding() -> None:
    urls = extract_urls(
        body_html=(
            '<a href="https://login-attacker.example">'
            "https://portal-company.example</a>"
        )
    )
    bundle = build_evidence_bundle(
        auth_results={"spf": {}, "dkim": {}, "dmarc": {}},
        urls=urls,
        vt_url_reports=[],
        vt_hash_reports=[],
        otx_reports=[],
        credential_harvesting=None,
        brand_impersonation=None,
        language_analysis={
            "categories": {
                "account_verification": {
                    "risk_score": 4,
                    "description": "Verify your account",
                    "matches": ["verify your account"],
                }
            },
            "total_matches": 1,
        },
        attachment_risks=[],
        landing_pages=[],
        domain_intelligence=None,
        url_intelligence=analyze_urls(urls),
    )

    finding = next(
        item
        for item in bundle["correlations"]
        if item["type"] == "credential_lure_deceptive_link"
    )
    assert finding["category"] == "url_web"
    assert finding["confidence"] >= 0.90
    assert all(
        item["scoring_state"] == "CONSUMED"
        for item in bundle["evidence"]
        if item["id"] in finding["consumed_evidence"]
    )


def test_social_engineering_language_alone_is_not_phishing_or_high() -> None:
    result = calculate_risk(
        {
            "spf": {"result": "pass"},
            "dkim": {"result": "pass"},
            "dmarc": {"result": "pass"},
            "forensics": {"findings": []},
        },
        [],
        [],
        [],
        language_analysis={
            "categories": {
                "urgency": {"risk_score": 2},
                "account_verification": {"risk_score": 4},
                "authority": {"risk_score": 5},
            }
        },
    )

    assert result["verdict"] != "PHISHING"
    assert result["risk_severity"] in {"LOW", "MODERATE"}


def test_report_separates_verdict_severity_and_renders_evidence_state() -> None:
    bundle = _auth_bundle()
    bundle["correlations"].append(
        {
            "type": "credential_lure_deceptive_link",
            "summary": "Credential-phishing deceptive hyperlink",
            "category": "url_web",
            "severity": "HIGH",
            "confidence": 0.95,
            "score_contribution": 30,
            "risk_score": 30,
            "consumed_evidence": [],
            "evidence_groups": ["URL_DECEPTION", "CREDENTIAL_LURE"],
        }
    )
    auth = _auth_with_independent_reply_to()
    risk = calculate_risk(auth, [], [], [], evidence_bundle=bundle)
    report = generate_report(
        email_data={},
        auth_results=auth,
        urls=[],
        attachments=[],
        risk=risk,
        vt_url_reports=[],
        vt_hash_reports=[],
        otx_reports=[],
        evidence_bundle=bundle,
    )

    assert "Verdict               : PHISHING" in report
    assert f"Risk Severity         : {risk['risk_severity']}" in report
    assert "Category: Authentication / Relay" in report
    assert "Cross-category confirmation" in report
    assert "[CONSUMED → sender_auth_alignment_failure]" in report
    assert "Correlated findings:" not in report
