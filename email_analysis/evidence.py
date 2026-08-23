"""Normalized evidence objects for scoring and reporting."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from scoring.config import Confidence, EvidenceGroup, EvidenceState, Severity


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
    evidence_group: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["confidence"] = round(max(0.0, min(1.0, self.confidence)), 2)
        data["id"] = f"{self.source}:{self.category}:{self.indicator}"[:240]
        data["name"] = self.summary
        data["severity"] = _severity(self.severity).value
        data["confidence_level"] = _confidence_level(self.confidence).value
        data["risk_weight"] = self.risk_delta
        data["raw_score"] = self.risk_delta
        data["evidence_group"] = self.evidence_group or _infer_evidence_group(
            self.category, self.tags
        )
        if self.state == "supporting":
            data["scoring_state"] = EvidenceState.SUPPORTING.value
        elif self.risk_delta > 0 and self.state in {"suspicious", "malicious"}:
            data["scoring_state"] = EvidenceState.ACTIVE.value
        else:
            data["scoring_state"] = EvidenceState.INFORMATIONAL.value
        data["consumed_by"] = None
        data["status"] = {
            "suspicious": "detected",
            "malicious": "detected",
            "clean": "not_detected",
            "unknown": "unknown",
            "none": "not_detected",
            "supporting": "supporting_context",
        }.get(self.state, self.state)
        data["evidence"] = {
            "indicator": self.indicator,
            "details": self.details,
        }
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
    evidence_group: str = "",
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
        evidence_group=evidence_group,
    )


def evidence_to_dicts(items: list[EvidenceItem]) -> list[dict[str, Any]]:
    deduplicated: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in items:
        serialized = item.to_dict()
        evidence_id = str(serialized["id"])
        if evidence_id in seen:
            continue
        seen.add(evidence_id)
        deduplicated.append(serialized)
    return deduplicated


@dataclass(frozen=True)
class Finding:
    """A correlated finding that replaces overlapping primitive evidence."""

    id: str
    name: str
    category: str
    evidence_ids: list[str]
    severity: str
    confidence: str
    contribution: int
    evidence_groups: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["score_contribution"] = self.contribution
        data["risk_score"] = self.contribution
        return data


def _infer_evidence_group(category: str, tags: list[str]) -> str:
    tag_set = set(tags)
    if category == "auth" or "authentication" in tag_set:
        return EvidenceGroup.AUTHENTICATION.value
    if category in {"identity", "relay"} or "alignment" in tag_set:
        return EvidenceGroup.HEADER_ALIGNMENT.value
    if "deceptive_link" in tag_set:
        return EvidenceGroup.URL_DECEPTION.value
    if category in {"credential_harvesting", "landing_page"}:
        return EvidenceGroup.CREDENTIAL_LURE.value
    if category == "content":
        if tag_set & {
            "credential_harvesting",
            "account_verification",
            "password_expiration",
        }:
            return EvidenceGroup.CREDENTIAL_LURE.value
        return EvidenceGroup.SOCIAL_ENGINEERING.value
    if category == "brand_impersonation" or "brand" in tag_set:
        return EvidenceGroup.BRAND_IDENTITY.value
    if category == "threat_intel":
        return EvidenceGroup.THREAT_INTEL.value
    if category == "attachment":
        return EvidenceGroup.ATTACHMENT.value
    if category in {"url", "domain"}:
        return EvidenceGroup.INFRASTRUCTURE.value
    if category == "ai_ml":
        return EvidenceGroup.AI_ML.value
    return EvidenceGroup.SOCIAL_ENGINEERING.value


def _severity(value: str) -> Severity:
    normalized = str(value or "INFO").upper()
    if normalized == "INFORMATIONAL":
        normalized = "INFO"
    try:
        return Severity(normalized)
    except ValueError:
        return Severity.INFO


def _confidence_level(value: float) -> Confidence:
    if value >= 0.80:
        return Confidence.HIGH
    if value >= 0.50:
        return Confidence.MEDIUM
    return Confidence.LOW
