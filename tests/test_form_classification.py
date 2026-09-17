"""Business regressions: ordinary email forms are not credential phishing."""

import pytest

from email_analysis.html_form_detector import detect_credential_harvesting
from email_analysis.pipeline import PhishingPipeline


@pytest.mark.parametrize(
    "fields",
    [
        '<input type="checkbox" name="weekly">',
        '<input type="email" name="subscriber">',
        '<input type="hidden" name="tracking">' * 5,
        '<textarea name="feedback"></textarea><script>document.forms[0].submit()</script>',
    ],
)
def test_preferences_form_is_not_credential_phishing(fields, monkeypatch, tmp_path):
    from email_analysis import ai_classifier

    monkeypatch.setattr(
        ai_classifier,
        "classify_email",
        lambda *args, **kwargs: {
            "verdict": "legitimate",
            "confidence": 0.95,
            "risk_score": 0,
            "provider": "test",
        },
    )
    html = (
        '<form action="https://news.example.org/preferences" method="post">'
        + fields
        + "<button>Save preferences</button></form>"
    )
    detection = detect_credential_harvesting(html)
    assert not detection["detected"]
    assert detection["risk_score"] == 0
    assert detection["forms"]
    result = PhishingPipeline(
        upload_dir=str(tmp_path), events_jsonl_path=""
    ).analyze_raw(
        "From: newsletter@news.example.org\nSubject: Newsletter preferences\n"
        "Content-Type: text/html\n\n" + html
    )
    assert result["risk"]["verdict"] == "BENIGN"
    assert result["risk"]["risk_severity"] == "LOW"
    assert not any(
        item["category"] == "credential_harvesting"
        for item in result["evidence_bundle"]["evidence"]
    )


def test_password_collection_still_detected():
    result = detect_credential_harvesting(
        '<form method="POST" action="https://evil.test/collect">'
        '<input type="password" name="password"></form>'
    )
    assert result["detected"]
    assert result["risk_score"] > 0
