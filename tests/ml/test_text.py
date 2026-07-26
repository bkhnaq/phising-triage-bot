from __future__ import annotations

from ml.text import (
    balanced_truncate,
    content_sha256,
    format_email_text,
    normalize_text,
)


def test_normalize_text_removes_controls_and_collapses_whitespace() -> None:
    assert normalize_text("  Xin\tchào\r\nbạn\x00  ") == "Xin chào bạn"


def test_content_hash_is_stable_after_whitespace_normalization() -> None:
    first = content_sha256("Hello", "a@example.test", "One\n two")
    second = content_sha256(" Hello ", "a@example.test", "One   two")

    assert first == second
    assert len(first) == 64


def test_balanced_truncate_preserves_both_ends_at_exact_limit() -> None:
    text = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    truncated = balanced_truncate(text, max_chars=15, marker="[cut]")

    assert truncated == "ABCDE[cut]VWXYZ"
    assert len(truncated) == 15


def test_balanced_truncate_leaves_short_text_unchanged() -> None:
    assert balanced_truncate("short", max_chars=10) == "short"


def test_formatter_preserves_metadata_url_hosts_and_both_body_ends() -> None:
    email = {
        "subject": "Xác minh tài khoản",
        "from": "Support <help@example.test>",
        "body_text": "HEAD-" + ("x" * 200) + "-TAIL",
    }
    urls = [
        {"url": "https://login.example.test/a"},
        {"url": "https://login.example.test/b"},
        {"url": "http://192.0.2.10/path"},
    ]

    formatted = format_email_text(email, urls, max_chars=180)

    assert len(formatted) <= 180
    assert "Subject: Xác minh tài khoản" in formatted
    assert "From: Support <help@example.test>" in formatted
    assert "URL hosts: login.example.test, 192.0.2.10" in formatted
    assert "HEAD-" in formatted
    assert "-TAIL" in formatted
    assert "[...]" in formatted


def test_formatter_uses_cleaned_html_when_plain_body_is_missing() -> None:
    formatted = format_email_text(
        {
            "subject": "Notice",
            "sender": "security@example.test",
            "body_html": "<p>Click&nbsp;<b>now</b></p>",
        }
    )

    assert "From: security@example.test" in formatted
    assert "Body:\nClick now" in formatted
    assert "<b>" not in formatted
