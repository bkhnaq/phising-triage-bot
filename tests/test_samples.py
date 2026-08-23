from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit

import pytest

from email_analysis.email_parser import parse_eml_file

ROOT = Path(__file__).parents[1]
SAMPLES = ROOT / "samples"
SAMPLE_NAMES = (
    "legitimate-en.eml",
    "phishing-en.eml",
    "legitimate-vi.eml",
    "phishing-vi.eml",
    "phishing_test_sample.eml",
)


@pytest.mark.parametrize("name", SAMPLE_NAMES)
def test_sample_is_parseable_and_inert(name: str) -> None:
    path = SAMPLES / name

    parsed = parse_eml_file(str(path))
    raw = path.read_text(encoding="utf-8").lower()

    assert parsed["subject"]
    for url in re.findall(r"https?://[^\s<>\"']+", raw):
        hostname = urlsplit(url.rstrip(".,;:!?)}]")).hostname
        assert hostname is not None
        assert hostname.endswith(".test")


def _run_offline_pipeline(path: Path) -> dict:
    environment = os.environ.copy()
    environment.update(
        {
            "OFFLINE_MODE": "true",
            "LOCAL_AI_ENABLED": "false",
            "TELEGRAM_ENABLED": "false",
            "API_PROTECTION_ENABLED": "false",
        }
    )
    program = """
import json
import sys
from email_analysis.pipeline import PhishingPipeline

result = PhishingPipeline().analyze_file(sys.argv[1])
print(json.dumps({
    'analysis_id': result['analysis_id'],
    'risk': result['risk'],
    'report': result['report'],
}))
"""
    completed = subprocess.run(
        [sys.executable, "-c", program, str(path)],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def test_offline_samples_return_complete_results_and_order_risk() -> None:
    results = {name: _run_offline_pipeline(SAMPLES / name) for name in SAMPLE_NAMES}

    for result in results.values():
        assert result["analysis_id"]
        assert result["risk"]
        assert result["report"]

    assert (
        results["phishing-en.eml"]["risk"]["score"]
        > results["legitimate-en.eml"]["risk"]["score"]
    )
    assert (
        results["phishing-vi.eml"]["risk"]["score"]
        > results["legitimate-vi.eml"]["risk"]["score"]
    )


def test_scoring_architecture_regression_sample_is_high_phishing() -> None:
    result = _run_offline_pipeline(SAMPLES / "phishing_test_sample.eml")
    risk = result["risk"]

    # The regression helper intentionally disables local AI; deterministic score only.
    assert 68 <= risk["score"] <= 74
    assert risk["risk_severity"] == "HIGH"
    assert risk["verdict"] == "PHISHING"
    assert risk["confidence"] >= 0.85
    assert 90 <= risk["data_completeness"] <= 95
    assert "correlation" not in risk["category_scores"]
    assert "Credential-phishing deceptive hyperlink" in result["report"]
    assert "Multi-signal credential phishing confirmation" in result["report"]
    assert "IOC Environment: TEST / LAB" in result["report"]
    assert "Applicable Evidence Coverage" in result["report"]
    assert "NOT_APPLICABLE sources are excluded" in result["report"]
    assert "Other independent evidence retained" not in result["report"]

    effective_total = sum(
        int(detail["effective_contribution"])
        for detail in risk["category_details"].values()
    )
    reconciliation = risk["score_reconciliation"]
    assert effective_total == reconciliation["raw_effective_total"]
    assert (
        reconciliation["pre_calibration_score"]
        - reconciliation["suppressed_by_calibration"]
        == risk["score"]
    )
    assert all(
        detail["items"]
        for category, detail in risk["category_details"].items()
        if category != "ESP detection" and detail["effective_contribution"] > 0
    )
