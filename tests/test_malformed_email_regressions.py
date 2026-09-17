"""Regression coverage for malformed input and concurrent attachment lifetimes."""

from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path

import pytest

from email_analysis import attachment_analyzer as attachments
from email_analysis.email_parser import _get_body
from email_analysis.html_form_detector import detect_credential_harvesting
from email_analysis.pipeline import PhishingPipeline
from email_analysis.url_extractor import extract_urls
from email_analysis.url_utils import analyze_url


def test_unknown_charset_preserves_body():
    msg = BytesParser(policy=policy.default).parsebytes(
        b"Content-Type: text/plain; charset=x-unknown\n\nhttps://evil.test/login"
    )
    assert _get_body(msg, "text/plain") == "https://evil.test/login"


def test_text_attachment_does_not_replace_body():
    msg = EmailMessage()
    msg.make_mixed()
    attached = EmailMessage()
    attached.set_content("attached text")
    attached["Content-Disposition"] = 'attachment; filename="notes.txt"'
    msg.attach(attached)
    body = EmailMessage()
    body.set_content("actual body")
    msg.attach(body)
    assert _get_body(msg, "text/plain").strip() == "actual body"


def test_malformed_html_preserves_following_links_and_forms():
    html = '<![bad]><a href="https://evil.test/login">Login</a><form method="POST" action="https://[bad"><input type="password"></form>'
    assert extract_urls(body_html=html)[0]["url"] == "https://evil.test/login"
    assert detect_credential_harvesting(html)["detected"]


def _message():
    msg = EmailMessage()
    msg.set_content("body")
    msg.add_attachment(
        b"file",
        maintype="application",
        subtype="octet-stream",
        filename="a.exe",
        disposition="inline",
    )
    return msg


def test_inline_files_are_counted_and_extracted(tmp_path):
    msg = _message()
    assert attachments.count_attachments(msg) == 1
    found = attachments.extract_attachments(msg, str(tmp_path))
    assert found[0]["filename"] == "a.exe"
    assert Path(found[0]["saved_path"]).read_bytes() == b"file"


def test_identical_requests_have_independent_attachment_files(tmp_path):
    first = attachments.extract_attachments(_message(), str(tmp_path))[0]
    second = attachments.extract_attachments(_message(), str(tmp_path))[0]
    assert first["saved_path"] != second["saved_path"]
    Path(first["saved_path"]).unlink()
    assert Path(second["saved_path"]).read_bytes() == b"file"


def test_partial_extraction_failure_cleans_files(monkeypatch, tmp_path):
    msg = _message()
    msg.add_attachment(
        b"second", maintype="application", subtype="octet-stream", filename="b.exe"
    )
    original = attachments._safe_attachment_path

    def fail_second(directory, filename, digest):
        if filename == "b.exe":
            raise OSError("disk failure")
        return original(directory, filename, digest)

    monkeypatch.setattr(attachments, "_safe_attachment_path", fail_second)
    with pytest.raises(OSError):
        attachments.extract_attachments(msg, str(tmp_path))
    assert list(tmp_path.iterdir()) == []


def test_collision_does_not_delete_existing_file(monkeypatch, tmp_path):
    existing = tmp_path / "existing"
    existing.write_bytes(b"keep")
    monkeypatch.setattr(attachments, "_safe_attachment_path", lambda *args: existing)
    with pytest.raises(FileExistsError):
        attachments.extract_attachments(_message(), str(tmp_path))
    assert existing.read_bytes() == b"keep"


def test_lab_mode_configuration_and_explicit_override(monkeypatch, tmp_path):
    from config import settings

    monkeypatch.setattr(settings, "LAB_MODE", True)
    assert PhishingPipeline(str(tmp_path)).lab_mode is True
    assert PhishingPipeline(str(tmp_path), lab_mode=False).lab_mode is False


def test_zero_port_is_preserved():
    assert (
        analyze_url("https://example.com:0/login").normalized_url
        == "https://example.com:0/login"
    )


def test_malformed_qr_url_does_not_crash(monkeypatch, tmp_path):
    from email_analysis import qr_code_analyzer as qr

    file = tmp_path / "qr.png"
    file.write_bytes(b"placeholder")
    monkeypatch.setattr(qr, "_decode_qr", lambda path: [("https://[bad", "QRCODE")])
    result = qr.scan_attachments_for_qr(
        [{"saved_path": str(file), "filename": "qr.png"}]
    )
    assert result[0]["url"] is None


def test_invalid_unicode_leaves_no_temporary_email(tmp_path):
    with pytest.raises(UnicodeEncodeError):
        PhishingPipeline(str(tmp_path)).analyze_raw("Subject: x\n\n\ud800")
    assert list(tmp_path.iterdir()) == []


def test_qr_url_keeps_significant_punctuation():
    from email_analysis.qr_code_analyzer import extract_qr_urls

    url = "https://evil.test/login?a=one,two&token='value'"
    result = extract_qr_urls([{"url": url}])
    assert result[0]["url"] == url
    assert result[0]["source"] == "qr_code"
