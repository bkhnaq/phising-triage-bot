from __future__ import annotations

import logging
from pathlib import Path
import sys
import types

import pytest

from cli import _write_report, build_parser, run_cli


def test_log_formatter_redacts_telegram_token_from_request_url() -> None:
    import main

    token = "123456789:abcdefghijklmnopqrstuvwxyz_ABCD12345"
    record = logging.LogRecord(
        name="httpx",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=f"POST https://api.telegram.org/bot{token}/getUpdates",
        args=(),
        exc_info=None,
    )

    rendered = main._RedactingFormatter("%(message)s").format(record)

    assert token not in rendered
    assert "[REDACTED_TELEGRAM_TOKEN]" in rendered


def _install_fake_pipeline(
    monkeypatch, expected_path: Path, report: str = "SOC REPORT"
) -> None:
    fake_pipeline = types.ModuleType("email_analysis.pipeline")

    class FakePipeline:
        def analyze_file(self, path: str) -> dict:
            assert path == str(expected_path)
            return {"report": report}

    fake_pipeline.PhishingPipeline = FakePipeline
    monkeypatch.setitem(sys.modules, "email_analysis.pipeline", fake_pipeline)


def test_analyze_prints_pipeline_report(monkeypatch, tmp_path: Path, capsys) -> None:
    sample = tmp_path / "mail.eml"
    sample.write_text("From: a@example.test\n\nHello", encoding="utf-8")
    _install_fake_pipeline(monkeypatch, sample.resolve())

    assert run_cli(["--analyze", str(sample)]) == 0
    assert capsys.readouterr().out.strip() == "SOC REPORT"


@pytest.mark.parametrize("filename", ["missing.eml", "message.txt"])
def test_analyze_rejects_missing_or_non_eml_input(
    tmp_path: Path, filename: str
) -> None:
    path = tmp_path / filename
    if path.suffix == ".txt":
        path.write_text("not an email", encoding="utf-8")

    assert run_cli(["--analyze", str(path)]) == 2


def test_analyze_writes_utf8_report(monkeypatch, tmp_path: Path, capsys) -> None:
    sample = tmp_path / "mail.eml"
    output = tmp_path / "reports" / "triage.md"
    sample.write_text("From: a@example.test\n\nHello", encoding="utf-8")
    _install_fake_pipeline(monkeypatch, sample.resolve(), "Báo cáo SOC")

    assert run_cli(["--analyze", str(sample), "--output", str(output)]) == 0
    assert output.read_text(encoding="utf-8") == "Báo cáo SOC"
    assert capsys.readouterr().out == ""


def test_report_falls_back_to_utf8_for_legacy_console(monkeypatch) -> None:
    import io
    import cli

    class LegacyConsole:
        encoding = "cp1252"

        def __init__(self) -> None:
            self.buffer = io.BytesIO()

        def write(self, text: str) -> int:
            text.encode(self.encoding)
            return len(text)

        def flush(self) -> None:
            pass

    console = LegacyConsole()
    monkeypatch.setattr(cli.sys, "stdout", console)

    _write_report("Báo cáo 🔍")

    assert console.buffer.getvalue().decode("utf-8") == "Báo cáo 🔍\n"


def test_offline_mode_is_enabled_before_pipeline_import(
    monkeypatch, tmp_path: Path
) -> None:
    from config import settings

    sample = tmp_path / "mail.eml"
    sample.write_text("From: a@example.test\n\nHello", encoding="utf-8")
    original_offline = settings.OFFLINE_MODE
    observed: list[bool] = []
    fake_pipeline = types.ModuleType("email_analysis.pipeline")

    class FakePipeline:
        def analyze_file(self, _path: str) -> dict:
            observed.append(settings.OFFLINE_MODE)
            return {"report": "SOC REPORT"}

    fake_pipeline.PhishingPipeline = FakePipeline
    monkeypatch.setitem(sys.modules, "email_analysis.pipeline", fake_pipeline)
    try:
        assert run_cli(["--analyze", str(sample), "--offline"]) == 0
    finally:
        settings.OFFLINE_MODE = original_offline

    assert observed == [True]


def test_modes_are_mutually_exclusive() -> None:
    parser = build_parser()

    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["--api", "--healthcheck"])

    assert exc.value.code == 2
