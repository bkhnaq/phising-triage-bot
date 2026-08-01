"""Dependency-free evaluation for calibrated phishing probabilities."""

from __future__ import annotations

import argparse
import json
import math
from collections.abc import Mapping, Sequence
from pathlib import Path

from ml.contracts import DecisionThresholds


def _validate(
    y_true: Sequence[int], probabilities: Sequence[float]
) -> tuple[list[int], list[float]]:
    if len(y_true) != len(probabilities):
        raise ValueError("labels and probabilities must have the same length")
    labels = [int(value) for value in y_true]
    scores = [float(value) for value in probabilities]
    if set(labels) - {0, 1}:
        raise ValueError("labels must contain only 0 and 1")
    if any(not math.isfinite(value) or not 0.0 <= value <= 1.0 for value in scores):
        raise ValueError("probabilities must be finite values in [0, 1]")
    return labels, scores


def _divide(numerator: int | float, denominator: int | float) -> float:
    return float(numerator / denominator) if denominator else 0.0


def _f1(precision: float, recall: float) -> float:
    return _divide(2 * precision * recall, precision + recall)


def _roc_auc(labels: Sequence[int], scores: Sequence[float]) -> float | None:
    positives = sum(labels)
    negatives = len(labels) - positives
    if not positives or not negatives:
        return None

    ordered = sorted(zip(scores, labels, strict=True), key=lambda item: item[0])
    positive_rank_sum = 0.0
    index = 0
    while index < len(ordered):
        end = index + 1
        while end < len(ordered) and ordered[end][0] == ordered[index][0]:
            end += 1
        average_rank = ((index + 1) + end) / 2.0
        positive_rank_sum += average_rank * sum(
            label for _, label in ordered[index:end]
        )
        index = end
    auc = (positive_rank_sum - (positives * (positives + 1) / 2)) / (
        positives * negatives
    )
    return float(auc)


def _average_precision(labels: Sequence[int], scores: Sequence[float]) -> float | None:
    positives = sum(labels)
    if not positives or positives == len(labels):
        return None
    ordered = sorted(zip(scores, labels, strict=True), reverse=True)
    tp = fp = 0
    previous_recall = 0.0
    area = 0.0
    index = 0
    while index < len(ordered):
        score = ordered[index][0]
        end = index
        while end < len(ordered) and ordered[end][0] == score:
            if ordered[end][1] == 1:
                tp += 1
            else:
                fp += 1
            end += 1
        recall = tp / positives
        precision = tp / (tp + fp)
        area += (recall - previous_recall) * precision
        previous_recall = recall
        index = end
    return float(area)


def _expected_calibration_error(
    labels: Sequence[int], scores: Sequence[float], bins: int = 10
) -> float | None:
    if not labels:
        return None
    total = len(labels)
    error = 0.0
    for bin_index in range(bins):
        lower = bin_index / bins
        upper = (bin_index + 1) / bins
        members = [
            (label, score)
            for label, score in zip(labels, scores, strict=True)
            if lower <= score < upper or (bin_index == bins - 1 and score == 1.0)
        ]
        if not members:
            continue
        accuracy = sum(label for label, _ in members) / len(members)
        confidence = sum(score for _, score in members) / len(members)
        error += (len(members) / total) * abs(accuracy - confidence)
    return error


def compute_metrics(
    y_true: Sequence[int],
    probabilities: Sequence[float],
    thresholds: DecisionThresholds,
) -> dict[str, object]:
    """Compute promotion metrics using the calibrated phishing threshold."""
    labels, scores = _validate(y_true, probabilities)
    tn = fp = fn = tp = 0
    for label, score in zip(labels, scores, strict=True):
        predicted = int(score >= thresholds.high)
        if label == 1 and predicted == 1:
            tp += 1
        elif label == 0 and predicted == 1:
            fp += 1
        elif label == 0:
            tn += 1
        else:
            fn += 1

    phishing_precision = _divide(tp, tp + fp)
    phishing_recall = _divide(tp, tp + fn)
    legitimate_precision = _divide(tn, tn + fn)
    legitimate_recall = _divide(tn, tn + fp)
    phishing_f1 = _f1(phishing_precision, phishing_recall)
    legitimate_f1 = _f1(legitimate_precision, legitimate_recall)
    brier = (
        sum((score - label) ** 2 for label, score in zip(labels, scores, strict=True))
        / len(labels)
        if labels
        else None
    )
    confident = sum(
        score < thresholds.low or score >= thresholds.high for score in scores
    )
    return {
        "sample_count": len(labels),
        "phishing_precision": phishing_precision,
        "phishing_recall": phishing_recall,
        "phishing_f1": phishing_f1,
        "macro_f1": (phishing_f1 + legitimate_f1) / 2,
        "false_positive_rate": _divide(fp, fp + tn),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "roc_auc": _roc_auc(labels, scores),
        "pr_auc": _average_precision(labels, scores),
        "brier_score": brier,
        "expected_calibration_error": _expected_calibration_error(labels, scores),
        "confident_coverage": _divide(confident, len(scores)),
    }


def _label_id(value: object) -> int:
    if value == "legitimate" or value == 0:
        return 0
    if value == "phishing" or value == 1:
        return 1
    raise ValueError(f"unsupported label: {value!r}")


def _probability(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError(f"unsupported probability: {value!r}")
    return float(value)


def evaluate_slices(
    predictions: Sequence[Mapping[str, object]],
    thresholds: DecisionThresholds,
) -> dict[str, dict[str, object]]:
    slices = {
        "combined": list(predictions),
        "english": [
            row for row in predictions if str(row.get("language", "")).lower() == "en"
        ],
        "synthetic_vietnamese": [
            row
            for row in predictions
            if str(row.get("language", "")).lower() == "vi"
            and row.get("synthetic") is True
        ],
    }
    result: dict[str, dict[str, object]] = {}
    for name, rows in slices.items():
        labels = [_label_id(row.get("label")) for row in rows]
        probabilities = [_probability(row.get("phishing_probability")) for row in rows]
        result[name] = compute_metrics(labels, probabilities, thresholds)
    return result


def _read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: row must be an object")
            rows.append(value)
    return rows


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate phishing probabilities.")
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--thresholds", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    threshold_data = _read_json(args.thresholds)
    if not isinstance(threshold_data, Mapping):
        raise SystemExit("threshold file must contain a JSON object")
    metrics = evaluate_slices(
        _read_jsonl(args.predictions),
        DecisionThresholds.from_mapping(threshold_data),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"output": str(args.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
