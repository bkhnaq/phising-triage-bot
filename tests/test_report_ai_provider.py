from report.report_generator import generate_report


def _minimal_report(**overrides) -> str:
    arguments = {
        "email_data": {},
        "auth_results": {},
        "urls": [],
        "attachments": [],
        "risk": {"score": 0, "verdict": "LOW"},
        "vt_url_reports": [],
        "vt_hash_reports": [],
        "otx_reports": [],
    }
    arguments.update(overrides)
    return generate_report(**arguments)


def test_high_risk_report_has_actions_iocs_and_safe_ai_unavailable_state() -> None:
    report = _minimal_report(
        risk={"score": 90, "verdict": "CRITICAL"},
        urls=[
            {
                "url": "https://source.test/login",
                "normalized_url": "https://final.test/login",
                "registered_domain": "final.test",
            },
            {
                "url": "https://source.test/login",
                "normalized_url": "https://final.test/login",
                "registered_domain": "final.test",
            },
        ],
        attachments=[
            {
                "filename": "sample.bin",
                "content_type": "application/octet-stream",
                "size_bytes": 10,
                "sha256": "a" * 64,
            }
        ],
        ai_verdict={
            "error": "local artifact unavailable at C:/private/path",
            "provider": "local",
            "model": "mmbert",
        },
    )

    assert "RECOMMENDED SOC ACTIONS" in report
    assert "IOC SUMMARY" in report
    assert "Quarantine the message" in report
    assert "AI analysis unavailable" in report
    assert "Human validation" in report
    assert report.count("https://final.test/login") == 1
    assert report.count("final.test") == 2  # URL hostname plus one Domain IOC.
    assert report.count("a" * 64) == 2  # Attachment listing plus one SHA-256 IOC.
    assert "C:/private/path" not in report


def test_empty_ioc_summary_is_explicit() -> None:
    report = _minimal_report()

    assert "IOC SUMMARY" in report
    assert "No IOCs extracted" in report


def test_report_identifies_local_ai_provider_and_model() -> None:
    report = generate_report(
        email_data={},
        auth_results={},
        urls=[],
        attachments=[],
        risk={"score": 10, "verdict": "LOW"},
        vt_url_reports=[],
        vt_hash_reports=[],
        otx_reports=[],
        ai_verdict={
            "verdict": "legitimate",
            "confidence": 0.91,
            "reasons": [],
            "provider": "local",
            "model": "jhu-clsp/mmBERT-small",
            "fallback_used": False,
        },
    )

    assert "Provider   : local" in report
    assert "Model      : jhu-clsp/mmBERT-small" in report


def test_report_marks_groq_fallback() -> None:
    report = generate_report(
        email_data={},
        auth_results={},
        urls=[],
        attachments=[],
        risk={"score": 25, "verdict": "HIGH"},
        vt_url_reports=[],
        vt_hash_reports=[],
        otx_reports=[],
        ai_verdict={
            "verdict": "phishing",
            "confidence": 0.95,
            "reasons": [],
            "provider": "groq",
            "model": "llama-3.3-70b-versatile",
            "fallback_used": True,
        },
    )

    assert "Provider   : groq (fallback)" in report
