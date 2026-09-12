from __future__ import annotations

from email_analysis.correlation import build_evidence_bundle
from email_analysis.domain_intelligence import analyze_domain_intelligence
from email_analysis.domain_randomness import analyze_domain_randomness
from email_analysis.header_analyzer import analyze_headers
from email_analysis.header_forensics import run_header_forensics
from email_analysis.special_use import classify_ip
from email_analysis.url_extractor import extract_urls
from email_analysis import url_intelligence
from scoring.config import WEIGHTS
from scoring.risk_scoring import calculate_risk


def _empty_bundle_inputs() -> dict:
    return {
        "vt_url_reports": [],
        "vt_hash_reports": [],
        "otx_reports": [],
        "attachment_risks": [],
        "landing_pages": [],
        "domain_intelligence": None,
    }


def test_meaningful_high_entropy_domain_is_not_dga() -> None:
    result = analyze_domain_randomness("northbridge-university.test")

    assert result["classification"] == "not_randomized"
    assert result["risk_score"] == 0
    assert {"north", "bridge", "university"} <= set(result["meaningful_tokens"])


def test_random_domain_uses_bounded_multifeature_score() -> None:
    result = analyze_domain_randomness("xj3kq9mz2p.example")

    assert result["classification"] in {
        "possible_randomized_domain",
        "strong_dga_pattern",
    }
    assert 2 <= result["risk_score"] <= 5


def test_reserved_test_domain_has_no_nxdomain_penalty() -> None:
    result = analyze_domain_intelligence(["example.test"])

    assert result["special_use_results"][0]["is_special_use"] is True
    assert result["risk_score"] == 0
    assert "whois_results" not in result
    assert "dns_results" not in result


def test_test_net_ip_has_no_geo_or_reputation_penalty() -> None:
    classification = classify_ip("203.0.113.77")
    forensic = run_header_forensics(
        {
            "from": "sender@example.com",
            "headers": [
                (
                    "Received",
                    "from relay.example.com (relay.example.com [203.0.113.77]) "
                    "by mx.example.com",
                )
            ],
        }
    )

    assert classification.classification == "Documentation / TEST-NET-3"
    assert forensic["origin_ip"] == "203.0.113.77"
    assert forensic["risk_score"] == 0
    assert "geolocation_status" not in forensic


def test_dkim_none_is_known_state_and_not_an_evidence_gap() -> None:
    auth = analyze_headers(
        [
            ("From", "sender@example.com"),
            ("To", "user@example.net"),
            (
                "Authentication-Results",
                "mx.example.net; spf=pass smtp.mailfrom=example.com; "
                "dkim=none; dmarc=pass header.from=example.com",
            ),
            (
                "Received",
                "from mail.example.com (mail.example.com [93.184.216.34]) "
                "by mx.example.net",
            ),
        ]
    )
    bundle = build_evidence_bundle(
        auth_results=auth,
        urls=[],
        credential_harvesting=None,
        brand_impersonation=None,
        language_analysis=None,
        **_empty_bundle_inputs(),
    )

    dkim = next(item for item in bundle["evidence"] if item["indicator"] == "dkim")
    assert auth["dkim"]["state"] == "NONE"
    assert dkim["state"] == "none"
    assert "unavailable" not in dkim["summary"].lower()


def test_third_party_return_path_mismatch_is_weak_when_auth_passes() -> None:
    auth = analyze_headers(
        [
            ("From", "Example <news@example.com>"),
            ("Return-Path", "<bounce@sendgrid.net>"),
            ("Message-ID", "<id@sendgrid.net>"),
            (
                "Received",
                "from o1.sendgrid.net (o1.sendgrid.net [93.184.216.34]) by mx.example.net",
            ),
            (
                "Authentication-Results",
                "mx.example.net; spf=pass smtp.mailfrom=sendgrid.net; "
                "dkim=pass header.d=example.com; dmarc=pass header.from=example.com",
            ),
        ]
    )
    result = calculate_risk(auth, [], [], [])

    assert result["score"] <= WEIGHTS["return_path_mismatch"]
    assert result["verdict"] == "BENIGN"
    assert result["risk_severity"] == "LOW"


def test_phishing_primitives_produce_correlated_high_risk() -> None:
    auth = analyze_headers(
        [
            ("From", "IT Support <help@northbridge-security.com>"),
            ("Return-Path", "<bounce@unrelated-mailer.com>"),
            ("Reply-To", "support@account-recovery.com"),
            (
                "Received",
                "from unrelated-mailer.com (unrelated-mailer.com [93.184.216.34]) "
                "by mx.example.net",
            ),
            (
                "Authentication-Results",
                "mx.example.net; spf=fail smtp.mailfrom=unrelated-mailer.com; "
                "dkim=none; dmarc=fail header.from=northbridge-security.com",
            ),
        ]
    )
    urls = extract_urls(
        body_html='<a href="https://evil.example/login">https://safe.example</a>'
    )
    url_intel = url_intelligence.analyze_urls(urls)
    language = {
        "categories": {
            "account_verification": {
                "risk_score": 5,
                "description": "Account verification",
                "matches": ["verify account"],
            },
            "credential_harvesting": {
                "risk_score": 5,
                "description": "Credential request",
                "matches": ["sign in"],
            },
        },
        "total_matches": 2,
    }
    bundle = build_evidence_bundle(
        auth_results=auth,
        urls=urls,
        credential_harvesting={
            "detected": True,
            "risk_score": 20,
            "findings": ["Password field posts externally"],
        },
        brand_impersonation=None,
        language_analysis=language,
        url_intelligence=url_intel,
        **_empty_bundle_inputs(),
    )
    result = calculate_risk(
        auth,
        [],
        [],
        [],
        credential_harvesting={"detected": True, "risk_score": 20},
        language_analysis=language,
        url_intelligence=url_intel,
        evidence_bundle=bundle,
    )

    types = {item["type"] for item in bundle["correlations"]}
    assert "sender_auth_alignment_failure" in types
    assert "credential_lure_deceptive_link" in types
    assert result["verdict"] == "PHISHING"
    assert result["risk_severity"] in {"HIGH", "CRITICAL"}
    assert result["confidence"] >= 0.70


def test_href_mismatch_does_not_create_redirect_destination() -> None:
    urls = extract_urls(
        body_html='<a href="https://evil.example">https://safe.example</a>'
    )
    intel = url_intelligence.analyze_urls(urls)

    deceptive = intel["deceptive_links"][0]
    assert deceptive["displayed_url"] == "https://safe.example"
    assert deceptive["url"] == "https://evil.example"
    assert "redirect_destination" not in deceptive
    assert "redirect_findings" not in intel


def test_score_and_provenance_share_central_dmarc_weight() -> None:
    auth = analyze_headers(
        [
            ("From", "sender@example.com"),
            (
                "Authentication-Results",
                "mx.example.net; spf=pass smtp.mailfrom=example.com; "
                "dkim=none; dmarc=fail header.from=example.com",
            ),
        ]
    )
    bundle = build_evidence_bundle(
        auth_results=auth,
        urls=[],
        credential_harvesting=None,
        brand_impersonation=None,
        language_analysis=None,
        **_empty_bundle_inputs(),
    )
    result = calculate_risk(auth, [], [], [], evidence_bundle=bundle)
    evidence = next(item for item in bundle["evidence"] if item["indicator"] == "dmarc")

    assert evidence["risk_weight"] == WEIGHTS["dmarc_fail"]
    assert f"DMARC fail (+{WEIGHTS['dmarc_fail']})" in result["breakdown"]
