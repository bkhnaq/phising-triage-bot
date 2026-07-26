from __future__ import annotations

import json
from pathlib import Path

import pytest

from ml.promote import (
    build_artifact_manifest,
    evaluate_promotion_gates,
    promote_artifact,
    validate_artifact,
    write_artifact_manifest,
)


def _metrics(
    *,
    english_recall: float = 0.95,
    english_fpr: float = 0.02,
    english_macro_f1: float = 0.94,
    vietnamese_recall: float = 0.90,
) -> dict[str, object]:
    return {
        "test": {
            "english": {
                "sample_count": 100,
                "phishing_recall": english_recall,
                "false_positive_rate": english_fpr,
                "macro_f1": english_macro_f1,
            },
            "synthetic_vietnamese": {
                "sample_count": 40,
                "phishing_recall": vietnamese_recall,
            },
        }
    }


def _make_artifact(
    directory: Path,
    *,
    metrics: dict[str, object] | None = None,
    marker: str | None = None,
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "config.json").write_text(
        json.dumps(
            {
                "model_type": "modernbert",
                "num_labels": 2,
                "id2label": {"0": "legitimate", "1": "phishing"},
            }
        ),
        encoding="utf-8",
    )
    (directory / "tokenizer.json").write_text("{}", encoding="utf-8")
    (directory / "tokenizer_config.json").write_text("{}", encoding="utf-8")
    (directory / "model.safetensors").write_bytes(b"fake-safe-tensors")
    (directory / "thresholds.json").write_text(
        json.dumps({"low": 0.2, "high": 0.8}),
        encoding="utf-8",
    )
    (directory / "metrics.json").write_text(
        json.dumps(metrics or _metrics()), encoding="utf-8"
    )
    (directory / "dataset-manifest.json").write_text(
        json.dumps({"schema_version": 1, "checksums": {"train.jsonl": "a" * 64}}),
        encoding="utf-8",
    )
    if marker is not None:
        (directory / "marker").write_text(marker, encoding="utf-8")
    write_artifact_manifest(directory, model_id="jhu-clsp/mmBERT-small")
    return directory


def _baseline_metrics(macro_f1: float = 0.90) -> dict[str, object]:
    return {"test": {"english": {"macro_f1": macro_f1}}}


def test_valid_artifact_manifest_checks_every_runtime_file(tmp_path: Path) -> None:
    artifact = _make_artifact(tmp_path / "artifact")

    validated = validate_artifact(artifact)

    assert validated.model_id == "jhu-clsp/mmBERT-small"
    assert set(validated.files) >= {
        "config.json",
        "dataset-manifest.json",
        "metrics.json",
        "model.safetensors",
        "thresholds.json",
        "tokenizer.json",
        "tokenizer_config.json",
    }


def test_tampered_artifact_is_rejected(tmp_path: Path) -> None:
    artifact = _make_artifact(tmp_path / "artifact")
    (artifact / "thresholds.json").write_text(
        '{"low":0.1,"high":0.9}', encoding="utf-8"
    )

    with pytest.raises(ValueError, match="checksum"):
        validate_artifact(artifact)


def test_manifest_path_traversal_is_rejected(tmp_path: Path) -> None:
    artifact = _make_artifact(tmp_path / "artifact")
    manifest_path = artifact / "artifact-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["../outside"] = {
        "sha256": "0" * 64,
        "size": 0,
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="unsafe artifact path"):
        validate_artifact(artifact)


def test_reversed_model_label_mapping_is_rejected(tmp_path: Path) -> None:
    artifact = _make_artifact(tmp_path / "artifact")
    (artifact / "config.json").write_text(
        json.dumps(
            {
                "model_type": "modernbert",
                "num_labels": 2,
                "id2label": {"0": "phishing", "1": "legitimate"},
            }
        ),
        encoding="utf-8",
    )
    write_artifact_manifest(artifact, model_id="jhu-clsp/mmBERT-small")

    with pytest.raises(ValueError, match="label 0.*legitimate.*label 1.*phishing"):
        validate_artifact(artifact)


def test_transformers_config_may_derive_num_labels_from_exact_id_mapping(
    tmp_path: Path,
) -> None:
    artifact = _make_artifact(tmp_path / "artifact")
    (artifact / "config.json").write_text(
        json.dumps(
            {
                "model_type": "modernbert",
                "id2label": {"0": "legitimate", "1": "phishing"},
                "label2id": {"legitimate": 0, "phishing": 1},
            }
        ),
        encoding="utf-8",
    )
    write_artifact_manifest(artifact, model_id="jhu-clsp/mmBERT-small")

    validated = validate_artifact(artifact)

    assert validated.model_id == "jhu-clsp/mmBERT-small"


@pytest.mark.parametrize(
    ("metrics", "expected"),
    [
        (_metrics(english_recall=0.89), "English phishing recall"),
        (_metrics(english_fpr=0.051), "English false-positive rate"),
        (_metrics(english_macro_f1=0.89), "English macro F1"),
        (_metrics(vietnamese_recall=0.84), "Vietnamese phishing recall"),
    ],
)
def test_each_failed_quality_gate_has_actionable_reason(
    metrics: dict[str, object], expected: str
) -> None:
    failures = evaluate_promotion_gates(metrics, _baseline_metrics())

    assert any(expected in failure for failure in failures)


def test_failed_quality_gate_does_not_replace_active_artifact(
    tmp_path: Path,
) -> None:
    target = _make_artifact(tmp_path / "active", marker="active")
    candidate = _make_artifact(
        tmp_path / "candidate", metrics=_metrics(english_recall=0.50)
    )

    with pytest.raises(ValueError, match="English phishing recall"):
        promote_artifact(candidate, target, _baseline_metrics())

    assert (target / "marker").read_text(encoding="utf-8") == "active"
    validate_artifact(target)


def test_successful_promotion_atomically_replaces_active_artifact(
    tmp_path: Path,
) -> None:
    target = _make_artifact(tmp_path / "active", marker="old")
    candidate = _make_artifact(tmp_path / "candidate", marker="new")

    promote_artifact(candidate, target, _baseline_metrics())

    assert (target / "marker").read_text(encoding="utf-8") == "new"
    validate_artifact(target)
    assert not list(tmp_path.glob(".active.backup-*"))
    assert not list(tmp_path.glob(".active.staging-*"))


def test_manifest_builder_excludes_manifest_from_recursive_checksum(
    tmp_path: Path,
) -> None:
    artifact = _make_artifact(tmp_path / "artifact")

    manifest = build_artifact_manifest(artifact, model_id="jhu-clsp/mmBERT-small")

    assert "artifact-manifest.json" not in manifest["files"]
