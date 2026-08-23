from __future__ import annotations

import json
from pathlib import Path

import pytest

from evaluation.runner import main

pytestmark = pytest.mark.integration


def test_evaluation_cli_writes_machine_and_human_reports(tmp_path: Path) -> None:
    output_json = tmp_path / "results.json"
    output_report = tmp_path / "report.md"

    exit_code = main(
        [
            "--baseline",
            str(tmp_path / "missing-baseline.json"),
            "--output-json",
            str(output_json),
            "--output-report",
            str(output_report),
            "--quality-gate",
        ]
    )

    assert exit_code == 0
    data = json.loads(output_json.read_text(encoding="utf-8"))
    assert data["mode"] == "offline_deterministic"
    assert data["dataset"]["total"] >= 30
    assert data["quality_gate"]["passed"] is True
    assert "# Offline Phishing Triage Evaluation" in output_report.read_text(
        encoding="utf-8"
    )
