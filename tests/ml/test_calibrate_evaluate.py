from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

from ml.calibrate import main as calibrate_main
from ml.calibrate import select_bilingual_thresholds
from ml.calibrate import select_thresholds
from ml.contracts import DecisionThresholds
from ml.evaluate import compute_metrics, evaluate_slices


def test_calibration_respects_false_positive_ceiling() -> None:
    thresholds = select_thresholds(
        y_true=[0, 0, 1, 1],
        probabilities=[0.01, 0.20, 0.70, 0.95],
        max_fpr=0.0,
    )

    assert thresholds.high > 0.20
    assert thresholds.high <= 0.70
    assert 0.20 < thresholds.low < thresholds.high


def test_calibration_maximizes_macro_f1_after_recall_and_fpr_gates() -> None:
    thresholds = select_thresholds(
        y_true=([0] * 10) + ([1] * 10),
        probabilities=([0.05] * 8 + [0.35, 0.36] + [0.30] + [0.80] * 9),
        max_fpr=0.20,
        min_recall=0.90,
    )

    assert thresholds.high > 0.36


def test_calibration_rejects_invalid_or_single_class_inputs() -> None:
    with pytest.raises(ValueError, match="same length"):
        select_thresholds([0], [0.1, 0.2])
    with pytest.raises(ValueError, match="both classes"):
        select_thresholds([1, 1], [0.8, 0.9])
    with pytest.raises(ValueError, match="max_fpr"):
        select_thresholds([0, 1], [0.1, 0.9], max_fpr=1.1)
    with pytest.raises(ValueError, match="min_recall"):
        select_thresholds([0, 1], [0.1, 0.9], min_recall=-0.1)


def test_bilingual_calibration_enforces_each_language_slice() -> None:
    labels = ([0] * 10) + ([1] * 10) + ([0] * 10) + ([1] * 10)
    probabilities = (
        ([0.01] * 9)
        + [0.40]
        + [0.15]
        + ([0.90] * 9)
        + ([0.01] * 8)
        + [0.20, 0.30]
        + [0.25]
        + ([0.90] * 9)
    )
    languages = (["en"] * 20) + (["vi"] * 20)

    thresholds = select_bilingual_thresholds(
        labels,
        probabilities,
        languages,
        min_english_recall=0.90,
        max_english_fpr=0.10,
        min_vietnamese_recall=0.90,
        max_vietnamese_fpr=0.20,
    )

    assert thresholds.high > 0.30


def test_perfect_predictions_have_expected_binary_metrics() -> None:
    metrics = compute_metrics(
        [0, 0, 1, 1],
        [0.05, 0.10, 0.80, 0.90],
        DecisionThresholds(0.2, 0.7),
    )

    assert metrics["confusion_matrix"] == {"tn": 2, "fp": 0, "fn": 0, "tp": 2}
    assert metrics["phishing_precision"] == 1.0
    assert metrics["phishing_recall"] == 1.0
    assert metrics["phishing_f1"] == 1.0
    assert metrics["macro_f1"] == 1.0
    assert metrics["false_positive_rate"] == 0.0
    assert metrics["roc_auc"] == 1.0
    assert metrics["pr_auc"] == 1.0
    assert metrics["brier_score"] == pytest.approx(0.015625)
    assert metrics["confident_coverage"] == 1.0


def test_single_class_metrics_return_null_auc_without_warning() -> None:
    metrics = compute_metrics([0, 0], [0.1, 0.2], DecisionThresholds(0.3, 0.7))

    assert metrics["roc_auc"] is None
    assert metrics["pr_auc"] is None
    assert math.isfinite(float(metrics["brier_score"]))


def test_evaluation_reports_english_vietnamese_and_combined_slices() -> None:
    predictions = [
        {
            "label": "legitimate",
            "language": "en",
            "synthetic": False,
            "phishing_probability": 0.1,
        },
        {
            "label": "phishing",
            "language": "en",
            "synthetic": False,
            "phishing_probability": 0.9,
        },
        {
            "label": "legitimate",
            "language": "vi",
            "synthetic": True,
            "phishing_probability": 0.2,
        },
        {
            "label": "phishing",
            "language": "vi",
            "synthetic": True,
            "phishing_probability": 0.8,
        },
    ]

    result = evaluate_slices(predictions, DecisionThresholds(0.3, 0.7))

    assert set(result) == {"combined", "english", "synthetic_vietnamese"}
    assert result["combined"]["sample_count"] == 4
    assert result["english"]["phishing_recall"] == 1.0
    assert result["synthetic_vietnamese"]["phishing_recall"] == 1.0


def test_calibration_cli_writes_threshold_artifact(tmp_path: Path) -> None:
    predictions = tmp_path / "validation.jsonl"
    predictions.write_text(
        "\n".join(
            json.dumps({"label": label, "phishing_probability": probability})
            for label, probability in (
                ("legitimate", 0.1),
                ("legitimate", 0.2),
                ("phishing", 0.8),
                ("phishing", 0.9),
            )
        )
        + "\n",
        encoding="utf-8",
    )
    output = tmp_path / "thresholds.json"

    assert (
        calibrate_main(
            [
                "--predictions",
                str(predictions),
                "--output",
                str(output),
                "--max-fpr",
                "0",
            ]
        )
        == 0
    )
    saved = json.loads(output.read_text(encoding="utf-8"))
    assert 0.2 < saved["low"] < saved["high"] <= 0.8
    assert saved["calibration"]["max_fpr"] == 0.0
    assert saved["calibration"]["min_recall"] == 0.90
