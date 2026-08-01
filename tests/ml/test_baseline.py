from __future__ import annotations

import json
from pathlib import Path

import pytest

from ml.prepare_data import prepare_fixture
from ml.train_baseline import train_baseline
from ml.train_baseline import load_split


def test_load_split_uses_shared_email_formatter() -> None:
    data_dir = Path(__file__).parents[1] / "fixtures" / "ml"
    fixture = data_dir / "tiny_emails.jsonl"

    texts, labels, records = load_split(fixture, expected_split=None)

    assert len(texts) == len(labels) == len(records) == 14
    assert texts[0].startswith("Subject: Team lunch\nFrom: hr@example.test")
    assert labels[:3] == [0, 0, 0]
    assert {record.source_split for record in records} == {
        "train",
        "validation",
        "test",
    }


def test_load_split_filters_expected_split(tmp_path: Path) -> None:
    fixture = Path(__file__).parents[1] / "fixtures" / "ml" / "tiny_emails.jsonl"

    texts, labels, records = load_split(fixture, expected_split="validation")

    assert len(texts) == 4
    assert labels == [0, 0, 1, 1]
    assert {record.source_split for record in records} == {"validation"}


def test_tiny_baseline_smoke_exports_reproducible_candidate_files(
    tmp_path: Path,
) -> None:
    pytest.importorskip("sklearn")
    fixture = Path(__file__).parents[1] / "fixtures" / "ml" / "tiny_emails.jsonl"
    data_dir = tmp_path / "data"
    output_dir = tmp_path / "baseline"
    prepare_fixture(fixture, data_dir, seed=42, smoke=True)

    metrics = train_baseline(data_dir, output_dir, seed=42, smoke=True)

    assert metrics["validation"]["macro_f1"] >= 0.5
    assert {
        "baseline.joblib",
        "dataset-manifest.json",
        "metrics.json",
        "test-predictions.jsonl",
        "thresholds.json",
        "validation-predictions.jsonl",
    } <= {path.name for path in output_dir.iterdir()}
    copied_manifest = json.loads(
        (output_dir / "dataset-manifest.json").read_text(encoding="utf-8")
    )
    assert copied_manifest["checksums"]
