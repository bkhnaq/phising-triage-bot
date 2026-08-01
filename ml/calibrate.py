"""Select stable legitimate/suspicious/phishing probability thresholds."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections.abc import Sequence
from pathlib import Path

from ml.contracts import DecisionThresholds


def _validated_inputs(
    y_true: Sequence[int], probabilities: Sequence[float]
) -> tuple[list[int], list[float]]:
    if len(y_true) != len(probabilities) or not y_true:
        raise ValueError("labels and probabilities must have the same length")
    labels = [int(value) for value in y_true]
    if set(labels) - {0, 1}:
        raise ValueError("labels must contain only 0 and 1")
    if set(labels) != {0, 1}:
        raise ValueError("calibration requires both classes")
    scores = [float(value) for value in probabilities]
    if any(not math.isfinite(value) or not 0.0 <= value <= 1.0 for value in scores):
        raise ValueError("probabilities must be finite values in [0, 1]")
    return labels, scores


def _f1(tp: int, fp: int, fn: int) -> float:
    denominator = (2 * tp) + fp + fn
    return (2 * tp / denominator) if denominator else 0.0


def _binary_stats(
    labels: Sequence[int], scores: Sequence[float], threshold: float
) -> tuple[float, float, float]:
    tp = fp = tn = fn = 0
    for label, score in zip(labels, scores, strict=True):
        predicted = int(score >= threshold)
        if label == 1 and predicted == 1:
            tp += 1
        elif label == 0 and predicted == 1:
            fp += 1
        elif label == 0:
            tn += 1
        else:
            fn += 1
    recall = tp / (tp + fn)
    fpr = fp / (fp + tn)
    phishing_f1 = _f1(tp, fp, fn)
    legitimate_f1 = _f1(tn, fn, fp)
    return recall, fpr, (phishing_f1 + legitimate_f1) / 2


def _midpoints(values: Sequence[float]) -> list[float]:
    unique = sorted(set(values))
    return [
        (left + right) / 2.0
        for left, right in zip(unique, unique[1:], strict=False)
        if left < right
    ]


def _select_low_threshold(
    labels: Sequence[int],
    scores: Sequence[float],
    high: float,
    max_fnr: float,
) -> float:
    low_candidates = {
        0.0,
        *(
            candidate
            for candidate in _midpoints([*scores, high])
            if 0.0 < candidate < high
        ),
    }
    positive_count = sum(labels)
    negative_count = len(labels) - positive_count
    eligible_low: list[tuple[float, float]] = []
    for candidate in sorted(low_candidates):
        confident_legitimate = [
            label
            for label, score in zip(labels, scores, strict=True)
            if score < candidate
        ]
        true_legitimate = sum(label == 0 for label in confident_legitimate)
        false_legitimate = sum(label == 1 for label in confident_legitimate)
        legitimate_recall = true_legitimate / negative_count
        phishing_miss_rate = false_legitimate / positive_count
        if phishing_miss_rate <= max_fnr:
            eligible_low.append((legitimate_recall, candidate))
    _, low = max(eligible_low, key=lambda item: item)
    return low


def select_thresholds(
    y_true: Sequence[int],
    probabilities: Sequence[float],
    max_fpr: float = 0.05,
    min_recall: float = 0.90,
    max_fnr: float | None = None,
) -> DecisionThresholds:
    """Maximize macro F1 after satisfying recall/FPR safety gates."""
    if not 0.0 <= max_fpr <= 1.0:
        raise ValueError("max_fpr must be in [0, 1]")
    if not 0.0 <= min_recall <= 1.0:
        raise ValueError("min_recall must be in [0, 1]")
    if max_fnr is None:
        max_fnr = max_fpr
    if not 0.0 <= max_fnr <= 1.0:
        raise ValueError("max_fnr must be in [0, 1]")
    labels, scores = _validated_inputs(y_true, probabilities)

    high_candidates = sorted(set(scores) | {1.0})
    eligible_high: list[tuple[float, float, float, float]] = []
    for candidate in high_candidates:
        recall, fpr, macro_f1 = _binary_stats(labels, scores, candidate)
        if fpr <= max_fpr and recall >= min_recall:
            eligible_high.append((macro_f1, recall, -fpr, candidate))
    if not eligible_high:
        raise ValueError("no high threshold satisfies min_recall and max_fpr")
    _, _, _, high = max(eligible_high)
    if high <= 0.0:
        raise ValueError("calibration could not create a non-empty threshold range")
    low = _select_low_threshold(labels, scores, high, max_fnr)
    return DecisionThresholds(low=low, high=high)


def select_bilingual_thresholds(
    y_true: Sequence[int],
    probabilities: Sequence[float],
    languages: Sequence[str],
    *,
    min_english_recall: float = 0.95,
    max_english_fpr: float = 0.05,
    min_vietnamese_recall: float = 0.90,
    max_vietnamese_fpr: float = 0.20,
    max_fnr: float = 0.05,
) -> DecisionThresholds:
    """Optimize equal-weight EN/VI macro F1 after per-language safety gates."""
    if len(languages) != len(y_true):
        raise ValueError("languages and labels must have the same length")
    constraints = {
        "min_english_recall": min_english_recall,
        "max_english_fpr": max_english_fpr,
        "min_vietnamese_recall": min_vietnamese_recall,
        "max_vietnamese_fpr": max_vietnamese_fpr,
        "max_fnr": max_fnr,
    }
    for name, value in constraints.items():
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"{name} must be in [0, 1]")
    labels, scores = _validated_inputs(y_true, probabilities)
    normalized_languages = [str(value).lower() for value in languages]
    if set(normalized_languages) != {"en", "vi"}:
        raise ValueError("bilingual calibration requires en and vi slices")

    slices: dict[str, tuple[list[int], list[float]]] = {}
    for language in ("en", "vi"):
        indexes = [
            index
            for index, value in enumerate(normalized_languages)
            if value == language
        ]
        slices[language] = _validated_inputs(
            [labels[index] for index in indexes],
            [scores[index] for index in indexes],
        )

    eligible: list[tuple[float, float, float, float]] = []
    for candidate in sorted(set(scores) | {1.0}):
        english = _binary_stats(*slices["en"], candidate)
        vietnamese = _binary_stats(*slices["vi"], candidate)
        en_recall, en_fpr, en_macro_f1 = english
        vi_recall, vi_fpr, vi_macro_f1 = vietnamese
        if (
            en_recall >= min_english_recall
            and en_fpr <= max_english_fpr
            and vi_recall >= min_vietnamese_recall
            and vi_fpr <= max_vietnamese_fpr
        ):
            eligible.append(
                (
                    (en_macro_f1 + vi_macro_f1) / 2.0,
                    min(en_recall, vi_recall),
                    -max(en_fpr, vi_fpr),
                    candidate,
                )
            )
    if not eligible:
        raise ValueError("no threshold satisfies bilingual calibration gates")
    _, _, _, high = max(eligible)
    if high <= 0.0:
        raise ValueError("calibration could not create a non-empty threshold range")
    low = _select_low_threshold(labels, scores, high, max_fnr)
    return DecisionThresholds(low=low, high=high)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Calibrate phishing decision thresholds."
    )
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-fpr", type=float, default=0.05)
    parser.add_argument("--min-recall", type=float, default=0.90)
    parser.add_argument("--max-fnr", type=float)
    return parser


def _label_id(value: object) -> int:
    if value == "legitimate" or value == 0:
        return 0
    if value == "phishing" or value == 1:
        return 1
    raise ValueError(f"unsupported label: {value!r}")


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    labels: list[int] = []
    probabilities: list[float] = []
    digest = hashlib.sha256()
    with args.predictions.open("rb") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            digest.update(raw_line)
            if not raw_line.strip():
                continue
            try:
                row = json.loads(raw_line)
                if not isinstance(row, dict):
                    raise ValueError("row must be an object")
                labels.append(_label_id(row.get("label")))
                probabilities.append(float(row["phishing_probability"]))
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise ValueError(
                    f"{args.predictions}:{line_number}: invalid prediction"
                ) from exc
    thresholds = select_thresholds(
        labels,
        probabilities,
        max_fpr=args.max_fpr,
        min_recall=args.min_recall,
        max_fnr=args.max_fnr,
    )
    payload: dict[str, object] = {
        **thresholds.to_dict(),
        "calibration": {
            "max_fpr": args.max_fpr,
            "min_recall": args.min_recall,
            "max_fnr": args.max_fnr if args.max_fnr is not None else args.max_fpr,
            "sample_count": len(labels),
            "validation_predictions_sha256": digest.hexdigest(),
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(thresholds.to_dict(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
