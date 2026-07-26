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
