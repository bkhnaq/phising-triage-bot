"""Normalized evidence objects for scoring and reporting."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class EvidenceItem:
    """A normalized finding emitted by any detector."""

    category: str
    source: str
    entity_type: str
    indicator: str
    severity: str
    confidence: float
    risk_delta: int
    state: str
    summary: str
    details: str = ""
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["confidence"] = round(max(0.0, min(1.0, self.confidence)), 2)
        return data


def make_evidence(
    *,
    category: str,
    source: str,
    entity_type: str,
    indicator: str,
    severity: str,
    confidence: float,
    risk_delta: int,
    state: str,
    summary: str,
    details: str = "",
    tags: list[str] | None = None,
) -> EvidenceItem:
    return EvidenceItem(
        category=category,
        source=source,
        entity_type=entity_type,
        indicator=indicator,
        severity=severity,
        confidence=confidence,
        risk_delta=risk_delta,
        state=state,
        summary=summary,
        details=details,
        tags=tags or [],
    )


def evidence_to_dicts(items: list[EvidenceItem]) -> list[dict[str, Any]]:
    return [item.to_dict() for item in items]
