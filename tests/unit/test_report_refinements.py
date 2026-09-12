from __future__ import annotations

import pytest

from email_analysis.header_analyzer import analyze_headers
from report.report_generator import _build_threat_summary, generate_report

pytestmark = pytest.mark.unit


def _risk() -> dict:
    return {
        "score": 0,
        "verdict": "BENIGN",
        "risk_severity": "LOW",
        "confidence": 0.8,
        "data_completeness": 80,
        "category_scores": {},
        "category_details": {},
        "breakdown": [],
        "confidence_notes": [],
    }


def _report(*, verbosity: str, auth: dict | None = None) -> str:
    return generate_report(
        email_data={
            "subject": "Fixture",
            "from": "sender@mailer.test",
            "to": "recipient@example.org",
            "date": "",
        },
        auth_results=auth
        or analyze_headers(
            [
                ("From", "sender@mailer.test"),
                ("Return-Path", "<sender@mailer.test>"),
                ("Message-ID", "<id@mailer.test>"),
                ("Received", "from mailer.test [203.0.113.4] by mx.example.org"),
            ]
        ),
        urls=[],
        attachments=[],
        risk=_risk(),
        vt_url_reports=[],
        vt_hash_reports=[],
        otx_reports=[],
        domain_intelligence={
            "whois_results": [],
            "dns_results": [],
            "randomness_results": [
                {
                    "domain": "mailer.test",
                    "description": "Human-readable domain",
                    "entropy": 2.1,
                    "risk_score": 0,
                    "meaningful_tokens": ["mailer"],
                }
            ],
        },
        analysis_environment={"type": "TEST", "reasons": ["reserved fixture"]},
        verbosity=verbosity,
    )


def test_threat_summary_exposes_nonproduction_operational_use() -> None:
    lines = _build_threat_summary(
        _risk(),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        analysis_environment={"type": "LAB"},
    )

    assert "Environment           : LAB" in lines
    assert "Operational Use       : NON-PRODUCTION / LAB PIPELINE" in lines


def test_normal_report_compacts_zero_risk_test_domain_randomness() -> None:
    report = _report(verbosity="NORMAL")

    assert "Reserved .test domains analyzed" in report
    assert "Entropy: 2.1" not in report


def test_debug_report_keeps_domain_randomness_details() -> None:
    report = _report(verbosity="DEBUG")

    assert "mailer.test" in report
    assert "Entropy: 2.1" in report


def test_message_id_mismatch_explains_informational_zero_score() -> None:
    auth = analyze_headers(
        [
            ("From", "events@corp.example.org"),
            ("Return-Path", "<events@corp.example.org>"),
            ("Message-ID", "<id@mailer.example.org>"),
            ("Received", "from mailer.example.org [93.184.216.34] by mx.example.org"),
        ]
    )

    report = _report(verbosity="NORMAL", auth=auth)

    assert "Message-ID domain differs from From domain" in report
    assert "Informational only; contribution +0" in report
