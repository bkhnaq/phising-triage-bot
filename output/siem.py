"""Versioned Wazuh JSON event built exclusively from intrinsic email evidence.

Wazuh supports scalar arrays but not object arrays. Detailed records therefore
use keyed objects; values in observable groups remain simple strings.
"""

from __future__ import annotations

from datetime import datetime, timezone
import math
import re
import uuid

from scoring.config import AuthState

_EMOJI = re.compile("[\U0001f000-\U0001faff\u2600-\u27bf\ufe0e\ufe0f\u200d\u20e3]")
_OBSERVABLE_GROUPS = {
    "url": "urls",
    "domain": "domains",
    "ip": "ips",
    "email": "emails",
    "md5": "hashes",
    "sha1": "hashes",
    "sha256": "hashes",
    "filename": "filenames",
}


def _clean(value):
    if isinstance(value, str):
        return _EMOJI.sub("", value)
    if isinstance(value, dict):
        return {str(key): _clean(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clean(item) for item in value]
    return value


def _confidence(value: object) -> float:
    try:
        number = float(value)  # type: ignore[arg-type]
        return max(0.0, min(1.0, number)) if math.isfinite(number) else 0.0
    except (ValueError, TypeError):
        return 0.0


def suggested_playbook(risk: dict, language: dict | None = None) -> str:
    categories = (language or {}).get("categories", {})
    if risk.get("initial_verdict", risk.get("verdict")) == "PHISHING":
        if "financial" in categories:
            return "payment_fraud"
        return "credential_phishing"
    return (
        "suspicious_email"
        if risk.get("base_score", risk.get("score", 0))
        else "email_review"
    )


def build_siem_event(
    result: dict, *, event_id: str | None = None, timestamp: str | None = None
) -> dict:
    """Build an event; explicit identity/time make serialization reproducible.

    Every new pipeline analysis receives a fresh UUID. Rebuilding/retrying an
    existing result preserves its event identity and original timestamp.
    """
    risk = result.get("risk", {})
    auth = result.get("auth_results", {})
    header = auth.get("forensics", {})
    relay = result.get("header_forensics", {})
    metadata = result.get("email_data", {})
    language = result.get("language_analysis", {})
    categories = language.get("categories", {})
    ai = result.get("ai_verdict", {})
    prior = result.get("siem_event", {})
    identifier = event_id or result.get("event_id") or str(uuid.uuid4())
    uuid.UUID(identifier)

    observables: dict[str, list[str]] = {
        name: [] for name in ("urls", "domains", "ips", "emails", "hashes", "filenames")
    }
    observable_metadata = {}
    records = sorted(
        result.get("observables", []), key=lambda item: (item["type"], item["value"])
    )
    for index, record in enumerate(records):
        kind = str(record["type"])
        group = _OBSERVABLE_GROUPS.get(kind)
        if group is None:
            continue
        value = str(record["value"])
        if value not in observables[group]:
            observables[group].append(value)
        observable_metadata[f"o{index:04d}"] = {
            "type": kind,
            "value": value,
            "environment": str(record.get("environment", "UNKNOWN")).upper(),
            "exportable": bool(record.get("exportable", False)),
            "classification": record.get("classification", "contextual"),
            "source": record.get("label", ""),
            "export_reason": record.get("export_reason", ""),
        }

    deceptive = result.get("url_intelligence", {}).get("deceptive_links", [])
    finding_details = {}
    for index, finding in enumerate(
        risk.get("final_findings", []) + risk.get("cross_category_findings", [])
    ):
        finding_details[f"f{index:03d}"] = {
            key: finding[key]
            for key in (
                "type",
                "summary",
                "category",
                "severity",
                "confidence",
                "status",
                "evidence",
                "evidence_groups",
                "source_findings",
                "consumed_evidence",
                "score_contribution",
            )
            if key in finding
        }
    mismatch_types = sorted(
        {
            str(item.get("type", ""))
            for item in header.get("findings", [])
            if "mismatch" in str(item.get("type", ""))
            or "alignment" in str(item.get("type", ""))
        }
    )
    if any(
        "does not match relay server" in warning
        for warning in relay.get("warnings", [])
    ):
        mismatch_types.append("relay_mismatch")
    keywords = sorted(
        {
            str(item["keyword"])
            for item in result.get("heuristics", {}).get("suspicious_keywords", [])
        }
        | {
            keyword
            for item in result.get("url_intelligence", {}).get(
                "suspicious_endpoints", []
            )
            for keyword in item.get("keywords", [])
        }
    )
    return _clean(
        {
            "schema_version": "1.0",
            "integration": "phishing_bot",
            "event_type": "email_triage",
            "event_id": identifier,
            "timestamp": timestamp
            or prior.get("timestamp")
            or datetime.now(timezone.utc).isoformat(),
            "email": {
                key: str(metadata.get(key) or "")
                for key in (
                    "subject",
                    "from",
                    "to",
                    "date",
                    "message_id",
                    "return_path",
                    "reply_to",
                )
            },
            "authentication": {
                check: AuthState.parse(
                    auth.get(check, {}).get("state")
                    or auth.get(check, {}).get("result")
                ).value
                for check in ("spf", "dkim", "dmarc")
            },
            "header_analysis": {
                **{
                    key: str(header.get(key) or "")
                    for key in (
                        "from_domain",
                        "return_path_domain",
                        "reply_to_domain",
                        "message_id_domain",
                    )
                },
                "origin_ip": str(relay.get("origin_ip") or ""),
                "relay_domains": sorted(
                    {
                        str(hop["server"])
                        for hop in relay.get("relay_chain", [])
                        if hop.get("server")
                    }
                ),
                "received": [str(value) for value in metadata.get("received", [])],
                "mismatches": mismatch_types,
            },
            "url_analysis": {
                "deceptive_link": bool(deceptive),
                "deceptive_links": sorted({str(item["url"]) for item in deceptive}),
                "deceptive_link_details": {
                    f"l{index:03d}": {
                        key: item.get(key, "")
                        for key in (
                            "url",
                            "displayed_url",
                            "displayed_domain",
                            "actual_domain",
                            "state",
                            "deceptive_link",
                            "requires_redirect_validation",
                        )
                    }
                    for index, item in enumerate(deceptive)
                },
                "suspicious_keywords": keywords,
            },
            "content_analysis": {
                "urgency": "urgency" in categories,
                "credential_request": bool(
                    {
                        "credential_harvesting",
                        "account_verification",
                        "password_expiration",
                    }
                    & categories.keys()
                )
                or bool(result.get("credential_harvesting", {}).get("detected")),
                "authority_impersonation": "authority" in categories,
            },
            "ai": {
                "provider": str(ai.get("provider") or "local"),
                "model": str(ai.get("model") or "jhu-clsp/mmBERT-small"),
                "prediction": str(ai.get("verdict") or "unknown"),
                "confidence": _confidence(ai.get("confidence")),
                "role": "supporting_evidence",
                "status": (
                    "UNAVAILABLE"
                    if ai.get("error") or ai.get("verdict", "unknown") == "unknown"
                    else "ANALYZED"
                ),
            },
            "observables": observables,
            "observable_metadata": observable_metadata,
            "correlated_findings": [item["type"] for item in finding_details.values()],
            "finding_details": finding_details,
            "risk": {
                "base_score": int(risk.get("base_score", risk.get("score", 0))),
                "initial_severity": risk.get(
                    "initial_severity", risk.get("risk_severity", "LOW")
                ),
                "initial_verdict": risk.get(
                    "initial_verdict", risk.get("verdict", "BENIGN")
                ),
            },
            "evidence_coverage": {
                "percentage": int(risk.get("data_completeness", 0)),
                "sources": risk.get("evidence_coverage", {}),
            },
            "analysis_environment": result.get("analysis_environment", {}),
            "analysis_limits": result.get("analysis_limits", {}),
            "suggested_playbook": suggested_playbook(risk, language),
            "external_enrichment": {"status": "PENDING", "performed_by": "Shuffle"},
        }
    )
