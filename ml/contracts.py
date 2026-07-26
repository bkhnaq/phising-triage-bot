"""Validated, dependency-free contracts shared by ML training and runtime."""

from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass
from typing import Mapping

_LABELS = frozenset({"legitimate", "phishing"})
_SPLITS = frozenset({"train", "validation", "test"})
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _required_string(data: Mapping[str, object], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-empty string")
    return value


@dataclass(frozen=True, slots=True)
class DecisionThresholds:
    """Probability thresholds for the three user-facing verdicts."""

    low: float
    high: float

    def __post_init__(self) -> None:
        if (
            not math.isfinite(self.low)
            or not math.isfinite(self.high)
            or not 0.0 <= self.low < self.high <= 1.0
        ):
            raise ValueError("thresholds must satisfy 0 <= low < high <= 1")

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "DecisionThresholds":
        try:
            low = float(data["low"])  # type: ignore[arg-type]
            high = float(data["high"])  # type: ignore[arg-type]
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("thresholds require numeric low and high values") from exc
        return cls(low=low, high=high)

    def verdict(self, probability: float) -> str:
        probability = float(probability)
        if not math.isfinite(probability):
            raise ValueError("probability must be finite")
        probability = max(0.0, min(1.0, probability))
        if probability < self.low:
            return "legitimate"
        if probability >= self.high:
            return "phishing"
        return "suspicious"

    def to_dict(self) -> dict[str, float]:
        return {"low": self.low, "high": self.high}


@dataclass(frozen=True, slots=True)
class EmailRecord:
    """One normalized labeled email and its provenance."""

    id: str
    source: str
    source_split: str
    source_id: str
    language: str
    subject: str
    sender: str
    body: str
    label: str
    content_sha256: str
    group_id: str
    synthetic: bool

    def __post_init__(self) -> None:
        for field_name in (
            "id",
            "source",
            "source_split",
            "source_id",
            "language",
            "label",
            "content_sha256",
            "group_id",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string")
        if self.source_split not in _SPLITS:
            raise ValueError(
                f"source_split must be one of {sorted(_SPLITS)}, got {self.source_split!r}"
            )
        if self.label not in _LABELS:
            raise ValueError(
                f"label must be one of {sorted(_LABELS)}, got {self.label!r}"
            )
        if not _SHA256_PATTERN.fullmatch(self.content_sha256):
            raise ValueError("content_sha256 must be a lowercase SHA-256 hex digest")
        if not isinstance(self.synthetic, bool):
            raise ValueError("synthetic must be a boolean")

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "EmailRecord":
        synthetic = data.get("synthetic")
        if not isinstance(synthetic, bool):
            raise ValueError("synthetic must be a boolean")
        return cls(
            id=_required_string(data, "id"),
            source=_required_string(data, "source"),
            source_split=_required_string(data, "source_split"),
            source_id=_required_string(data, "source_id"),
            language=_required_string(data, "language"),
            subject=str(data.get("subject") or ""),
            sender=str(data.get("sender") or ""),
            body=str(data.get("body") or ""),
            label=_required_string(data, "label"),
            content_sha256=_required_string(data, "content_sha256"),
            group_id=_required_string(data, "group_id"),
            synthetic=synthetic,
        )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ArtifactFile:
    """Integrity metadata for one file inside a promoted artifact."""

    sha256: str
    size: int

    def __post_init__(self) -> None:
        if not _SHA256_PATTERN.fullmatch(self.sha256):
            raise ValueError("artifact file sha256 must be a lowercase hex digest")
        if isinstance(self.size, bool) or self.size < 0:
            raise ValueError("artifact file size must be a non-negative integer")

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "ArtifactFile":
        sha256 = data.get("sha256")
        size = data.get("size")
        if not isinstance(sha256, str):
            raise ValueError("artifact file sha256 must be a string")
        if isinstance(size, bool) or not isinstance(size, int):
            raise ValueError("artifact file size must be an integer")
        return cls(sha256=sha256, size=size)


@dataclass(frozen=True, slots=True)
class ArtifactManifest:
    """Validated manifest for one immutable model artifact directory."""

    schema_version: int
    model_id: str
    files: dict[str, ArtifactFile]

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported artifact manifest schema_version")
        if not self.model_id.strip():
            raise ValueError("artifact manifest model_id must be non-empty")
        if not self.files:
            raise ValueError("artifact manifest files must be non-empty")

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "ArtifactManifest":
        schema_version = data.get("schema_version")
        model_id = data.get("model_id")
        raw_files = data.get("files")
        if isinstance(schema_version, bool) or not isinstance(schema_version, int):
            raise ValueError("artifact manifest schema_version must be an integer")
        if not isinstance(model_id, str):
            raise ValueError("artifact manifest model_id must be a string")
        if not isinstance(raw_files, Mapping):
            raise ValueError("artifact manifest files must be an object")
        files: dict[str, ArtifactFile] = {}
        for path, metadata in raw_files.items():
            if not isinstance(path, str) or not isinstance(metadata, Mapping):
                raise ValueError("artifact manifest file entry is invalid")
            files[path] = ArtifactFile.from_mapping(metadata)
        return cls(
            schema_version=schema_version,
            model_id=model_id,
            files=files,
        )
