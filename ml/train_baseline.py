"""Train a calibrated word/character TF-IDF phishing baseline."""

from __future__ import annotations

import argparse
import json
import shutil
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ml.calibrate import select_thresholds
from ml.contracts import EmailRecord
from ml.evaluate import compute_metrics, evaluate_slices
from ml.prepare_data import normalize_source_row
from ml.text import format_email_text


def load_split(
    path: Path, expected_split: str | None
) -> tuple[list[str], list[int], list[EmailRecord]]:
    """Load normalized records, accepting the raw smoke fixture as input."""
    texts: list[str] = []
    labels: list[int] = []
    records: list[EmailRecord] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, Mapping):
                raise ValueError(f"{path}:{line_number}: row must be an object")
            if "content_sha256" in value:
                record = EmailRecord.from_mapping(value)
            else:
                split = str(value.get("source_split") or expected_split or "")
                record = normalize_source_row(value, "fixture", split)
            if expected_split is not None and record.source_split != expected_split:
                continue
            texts.append(
                format_email_text(
                    {
                        "subject": record.subject,
                        "sender": record.sender,
                        "body": record.body,
                    }
                )
            )
            labels.append(1 if record.label == "phishing" else 0)
            records.append(record)
    return texts, labels, records


def _build_pipeline(seed: int, smoke: bool) -> Any:
    try:
        from sklearn.calibration import CalibratedClassifierCV
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.pipeline import FeatureUnion, Pipeline
        from sklearn.linear_model import LogisticRegression
    except ImportError as exc:
        raise RuntimeError(
            "scikit-learn is required; install requirements-ml.txt"
        ) from exc

    features = FeatureUnion(
        [
            (
                "word",
                TfidfVectorizer(
                    ngram_range=(1, 2),
                    min_df=1,
                    max_features=2_000 if smoke else 50_000,
                    sublinear_tf=True,
                ),
            ),
            (
                "character",
                TfidfVectorizer(
                    analyzer="char_wb",
                    ngram_range=(3, 5),
                    min_df=1,
                    max_features=4_000 if smoke else 100_000,
                    sublinear_tf=True,
                ),
            ),
        ]
    )
    base = LogisticRegression(
        class_weight="balanced",
        max_iter=500,
        random_state=seed,
        solver="liblinear",
    )
    classifier = CalibratedClassifierCV(estimator=base, method="sigmoid", cv=2)
    return Pipeline([("features", features), ("classifier", classifier)])


def _prediction_rows(
    records: Sequence[EmailRecord], probabilities: Sequence[float]
) -> list[dict[str, object]]:
    return [
        {
            "id": record.id,
            "source_split": record.source_split,
            "language": record.language,
            "synthetic": record.synthetic,
            "label": record.label,
            "phishing_probability": float(probability),
        }
        for record, probability in zip(records, probabilities, strict=True)
    ]


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_jsonl(path: Path, rows: Sequence[Mapping[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(
                json.dumps(
                    row, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                )
                + "\n"
            )


def train_baseline(
    data_dir: Path,
    output_dir: Path,
    *,
    seed: int = 42,
    smoke: bool = False,
    max_fpr: float = 0.05,
) -> dict[str, object]:
    try:
        import joblib
    except ImportError as exc:
        raise RuntimeError("joblib is required; install requirements-ml.txt") from exc

    train_texts, train_labels, _ = load_split(data_dir / "train.jsonl", "train")
    validation_texts, validation_labels, validation_records = load_split(
        data_dir / "validation.jsonl", "validation"
    )
    test_texts, _, test_records = load_split(data_dir / "test.jsonl", "test")
    if set(train_labels) != {0, 1} or min(Counter(train_labels).values()) < 2:
        raise ValueError("training split requires at least two records per class")
    if set(validation_labels) != {0, 1}:
        raise ValueError("validation split requires both classes")

    model = _build_pipeline(seed, smoke)
    model.fit(train_texts, train_labels)
    validation_probabilities = model.predict_proba(validation_texts)[:, 1].tolist()
    test_probabilities = model.predict_proba(test_texts)[:, 1].tolist()
    thresholds = select_thresholds(
        validation_labels, validation_probabilities, max_fpr=max_fpr
    )
    validation_metrics = compute_metrics(
        validation_labels, validation_probabilities, thresholds
    )
    test_predictions = _prediction_rows(test_records, test_probabilities)
    metrics = {
        "schema_version": 1,
        "model": "tfidf-word-char-calibrated-logistic-regression",
        "seed": seed,
        "smoke": smoke,
        "validation": validation_metrics,
        "test": evaluate_slices(test_predictions, thresholds),
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    dataset_manifest = data_dir / "dataset-manifest.json"
    if not dataset_manifest.is_file():
        raise ValueError(f"dataset manifest not found: {dataset_manifest}")
    shutil.copyfile(dataset_manifest, output_dir / "dataset-manifest.json")
    joblib.dump(model, output_dir / "baseline.joblib")
    _write_json(output_dir / "thresholds.json", thresholds.to_dict())
    _write_json(output_dir / "metrics.json", metrics)
    _write_jsonl(
        output_dir / "validation-predictions.jsonl",
        _prediction_rows(validation_records, validation_probabilities),
    )
    _write_jsonl(output_dir / "test-predictions.jsonl", test_predictions)
    return metrics


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Train a calibrated TF-IDF phishing baseline."
    )
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-fpr", type=float, default=0.05)
    parser.add_argument("--smoke", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    metrics = train_baseline(
        args.data_dir,
        args.output_dir,
        seed=args.seed,
        smoke=args.smoke,
        max_fpr=args.max_fpr,
    )
    validation = metrics.get("validation")
    validation_macro_f1 = (
        validation.get("macro_f1") if isinstance(validation, Mapping) else None
    )
    print(
        json.dumps(
            {
                "validation_macro_f1": validation_macro_f1,
                "output_dir": str(args.output_dir),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
