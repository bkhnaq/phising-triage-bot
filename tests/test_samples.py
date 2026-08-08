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
