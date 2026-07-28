"""Validate checksummed model artifacts and promote only quality-gated builds."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import shutil
import tempfile
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath

from ml.contracts import ArtifactManifest, DecisionThresholds

_MANIFEST_NAME = "artifact-manifest.json"
_REQUIRED_FILES = frozenset(
    {
        "config.json",
        "dataset-manifest.json",
        "metrics.json",
        "thresholds.json",
        "tokenizer.json",
        "tokenizer_config.json",
    }
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact_files(directory: Path) -> dict[str, Path]:
    files: dict[str, Path] = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"artifact cannot contain symlink: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(directory).as_posix()
        if relative != _MANIFEST_NAME:
            files[relative] = path
    return files


def _require_runtime_files(files: set[str]) -> None:
    missing = sorted(_REQUIRED_FILES - files)
    if missing:
        raise ValueError(f"artifact is missing required files: {missing}")
    if "model.safetensors" not in files and "model.safetensors.index.json" not in files:
        raise ValueError("artifact requires safetensors model weights")


def build_artifact_manifest(directory: Path, model_id: str) -> dict[str, object]:
    """Build checksums for every artifact file except the manifest itself."""
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError(f"artifact directory not found: {directory}")
    files = _artifact_files(directory)
    _require_runtime_files(set(files))
    return {
        "schema_version": 1,
        "model_id": model_id,
        "files": {
            relative: {
                "sha256": _sha256(path),
                "size": path.stat().st_size,
            }
            for relative, path in files.items()
        },
    }


def write_artifact_manifest(directory: Path, model_id: str) -> Path:
    """Write the generated artifact manifest atomically."""
    payload = build_artifact_manifest(directory, model_id)
    destination = directory / _MANIFEST_NAME
    temporary = directory / f".{_MANIFEST_NAME}.tmp"
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)
    return destination


def _json_object(path: Path) -> Mapping[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid JSON artifact file: {path.name}") from exc
    if not isinstance(value, Mapping):
        raise ValueError(f"artifact file must contain a JSON object: {path.name}")
    return value


def _safe_artifact_path(root: Path, relative: str) -> Path:
    if "\\" in relative:
        raise ValueError(f"unsafe artifact path: {relative!r}")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts:
        raise ValueError(f"unsafe artifact path: {relative!r}")
    root_resolved = root.resolve()
    resolved = root.joinpath(*pure.parts).resolve()
    if not resolved.is_relative_to(root_resolved):
        raise ValueError(f"unsafe artifact path: {relative!r}")
    return resolved


def _validate_model_contract(directory: Path, files: set[str]) -> None:
    DecisionThresholds.from_mapping(_json_object(directory / "thresholds.json"))
    config = _json_object(directory / "config.json")
    if config.get("num_labels") not in {None, 2}:
        raise ValueError("model config num_labels must be 2")
    id2label = config.get("id2label")
    if (
        not isinstance(id2label, Mapping)
        or len(id2label) != 2
        or str(id2label.get("0", "")).lower() != "legitimate"
        or str(id2label.get("1", "")).lower() != "phishing"
    ):
        raise ValueError(
            "model config must map label 0 to legitimate and label 1 to phishing"
        )
    label2id = config.get("label2id")
    if label2id is not None and (
        not isinstance(label2id, Mapping)
        or dict(label2id) != {"legitimate": 0, "phishing": 1}
    ):
        raise ValueError(
            "model config label2id must map legitimate to 0 and phishing to 1"
        )
    _json_object(directory / "metrics.json")
    dataset_manifest = _json_object(directory / "dataset-manifest.json")
    if not isinstance(dataset_manifest.get("checksums"), Mapping):
        raise ValueError("dataset manifest requires checksums")

    index_name = "model.safetensors.index.json"
    if index_name in files:
        index = _json_object(directory / index_name)
        weight_map = index.get("weight_map")
        if not isinstance(weight_map, Mapping) or not weight_map:
            raise ValueError("safetensors index requires a weight_map")
        referenced = {str(value) for value in weight_map.values()}
        missing_shards = sorted(referenced - files)
        if missing_shards:
            raise ValueError(f"safetensors index has missing shards: {missing_shards}")


def validate_artifact(directory: Path) -> ArtifactManifest:
    """Validate structure, paths, checksums, and runtime model contract."""
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError(f"artifact directory not found: {directory}")
    manifest_path = directory / _MANIFEST_NAME
    manifest = ArtifactManifest.from_mapping(_json_object(manifest_path))
    _require_runtime_files(set(manifest.files))
    for relative in manifest.files:
        _safe_artifact_path(directory, relative)

    actual_files = set(_artifact_files(directory))
    manifest_files = set(manifest.files)
    if actual_files != manifest_files:
        missing = sorted(manifest_files - actual_files)
        untracked = sorted(actual_files - manifest_files)
        raise ValueError(
            f"artifact file set mismatch; missing={missing}, untracked={untracked}"
        )

    for relative, metadata in manifest.files.items():
        path = _safe_artifact_path(directory, relative)
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"artifact file not found: {relative}")
        if path.stat().st_size != metadata.size:
            raise ValueError(f"artifact checksum metadata size mismatch: {relative}")
        if _sha256(path) != metadata.sha256:
            raise ValueError(f"artifact checksum mismatch: {relative}")
    _validate_model_contract(directory, manifest_files)
    return manifest


def _metric(
    data: Mapping[str, object],
    *path: str,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    current: object = data
    for key in path:
        if not isinstance(current, Mapping) or key not in current:
            raise ValueError(f"missing metric: {'.'.join(path)}")
        current = current[key]
    if isinstance(current, bool) or not isinstance(current, (int, float)):
        raise ValueError(f"metric must be numeric: {'.'.join(path)}")
    value = float(current)
    if not math.isfinite(value):
        raise ValueError(f"metric must be finite: {'.'.join(path)}")
    if minimum is not None and value < minimum:
        raise ValueError(f"metric must be at least {minimum}: {'.'.join(path)}")
    if maximum is not None and value > maximum:
        raise ValueError(f"metric must be at most {maximum}: {'.'.join(path)}")
    return value


def _positive_sample_count(data: Mapping[str, object], *path: str) -> int:
    current: object = data
    for key in path:
        if not isinstance(current, Mapping) or key not in current:
            raise ValueError(f"missing metric: {'.'.join(path)}")
        current = current[key]
    if isinstance(current, bool) or not isinstance(current, int) or current <= 0:
        raise ValueError(
            f"metric must be a positive integer: {'.'.join(path)}"
        )
    return current


def evaluate_promotion_gates(
    metrics: Mapping[str, object],
    baseline_metrics: Mapping[str, object],
    *,
    min_english_recall: float = 0.90,
    max_english_fpr: float = 0.05,
    min_vietnamese_recall: float = 0.85,
    max_vietnamese_fpr: float = 0.20,
) -> list[str]:
    """Return every failed promotion requirement without mutating artifacts."""
    try:
        _positive_sample_count(metrics, "test", "english", "sample_count")
        _positive_sample_count(
            metrics, "test", "synthetic_vietnamese", "sample_count"
        )
        english_recall = _metric(
            metrics,
            "test",
            "english",
            "phishing_recall",
            minimum=0.0,
            maximum=1.0,
        )
        english_fpr = _metric(
            metrics,
            "test",
            "english",
            "false_positive_rate",
            minimum=0.0,
            maximum=1.0,
        )
        english_macro_f1 = _metric(
            metrics,
            "test",
            "english",
            "macro_f1",
            minimum=0.0,
            maximum=1.0,
        )
        vietnamese_recall = _metric(
            metrics,
            "test",
            "synthetic_vietnamese",
            "phishing_recall",
            minimum=0.0,
            maximum=1.0,
        )
        vietnamese_fpr = _metric(
            metrics,
            "test",
            "synthetic_vietnamese",
            "false_positive_rate",
            minimum=0.0,
            maximum=1.0,
        )
        baseline_macro_f1 = _metric(
            baseline_metrics,
            "test",
            "english",
            "macro_f1",
            minimum=0.0,
            maximum=1.0,
        )
    except ValueError as exc:
        return [f"Metrics contract invalid: {exc}"]

    failures: list[str] = []
    if english_recall < min_english_recall:
        failures.append(
            "English phishing recall "
            f"{english_recall:.4f} is below {min_english_recall:.4f}"
        )
    if english_fpr > max_english_fpr:
        failures.append(
            "English false-positive rate "
            f"{english_fpr:.4f} exceeds {max_english_fpr:.4f}"
        )
    if english_macro_f1 < baseline_macro_f1:
        failures.append(
            "English macro F1 "
            f"{english_macro_f1:.4f} is below baseline {baseline_macro_f1:.4f}"
        )
    if vietnamese_recall < min_vietnamese_recall:
        failures.append(
            "Vietnamese phishing recall "
            f"{vietnamese_recall:.4f} is below {min_vietnamese_recall:.4f}"
        )
    if vietnamese_fpr > max_vietnamese_fpr:
        failures.append(
            "Vietnamese false-positive rate "
            f"{vietnamese_fpr:.4f} exceeds {max_vietnamese_fpr:.4f}"
        )
    return failures


def _safe_remove_tree(path: Path, expected_parent: Path) -> None:
    resolved = path.resolve()
    parent = expected_parent.resolve()
    if resolved.parent != parent or not path.name.startswith("."):
        raise ValueError(f"refusing to remove unsafe temporary path: {path}")
    if path.exists():
        shutil.rmtree(path)


def promote_artifact(
    candidate: Path,
    target: Path,
    baseline_metrics: Mapping[str, object],
) -> None:
    """Validate, gate, stage, and atomically replace the active artifact."""
    candidate = candidate.resolve()
    target = target.resolve()
    if candidate == target or target.is_relative_to(candidate):
        raise ValueError("candidate and target must be separate directories")
    validate_artifact(candidate)
    metrics = _json_object(candidate / "metrics.json")
    failures = evaluate_promotion_gates(metrics, baseline_metrics)
    if failures:
        raise ValueError("promotion gates failed: " + "; ".join(failures))

    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{target.name}.staging-", dir=parent))
    backup = parent / f".{target.name}.backup-{uuid.uuid4().hex}"
    moved_active = False
    try:
        shutil.copytree(candidate, staging, dirs_exist_ok=True)
        validate_artifact(staging)
        if target.exists():
            os.replace(target, backup)
            moved_active = True
        os.replace(staging, target)
    except BaseException:
        if staging.exists():
            _safe_remove_tree(staging, parent)
        if moved_active and backup.exists() and not target.exists():
            os.replace(backup, target)
        raise
    if backup.exists():
        _safe_remove_tree(backup, parent)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build or promote checksummed local-AI artifacts."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    manifest = subparsers.add_parser("manifest", help="write artifact manifest")
    manifest.add_argument("--candidate", type=Path, required=True)
    manifest.add_argument("--model-id", required=True)
    promote = subparsers.add_parser("promote", help="quality-gate and publish")
    promote.add_argument("--candidate", type=Path, required=True)
    promote.add_argument("--target", type=Path, required=True)
    promote.add_argument("--baseline-metrics", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "manifest":
        path = write_artifact_manifest(args.candidate, args.model_id)
        print(json.dumps({"manifest": str(path)}, sort_keys=True))
        return 0
    baseline = _json_object(args.baseline_metrics)
    promote_artifact(args.candidate, args.target, baseline)
    print(json.dumps({"promoted": str(args.target)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
