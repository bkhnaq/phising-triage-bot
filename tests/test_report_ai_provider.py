from report.report_generator import generate_report


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
