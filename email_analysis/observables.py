"""Normalized observable classification and safe IOC export metadata."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit, urlunsplit

from email_analysis.domain_utils import registered_domain
from email_analysis.special_use import (
    classify_domain,
    classify_ip,
    is_nonproduction_observable,
)

CLASSIFICATION_PRIORITY = {
    "informational": 0,
    "trusted": 1,
    "contextual": 2,
    "ioc_candidate": 3,
    "suspicious": 4,
    "confirmed_malicious": 5,
}

GROUP_BY_CLASSIFICATION = {
    "confirmed_malicious": "confirmed",
    "suspicious": "suspicious",
    "ioc_candidate": "candidates",
    "contextual": "contextual",
    "trusted": "trusted",
    "informational": "informational",
}


def normalize_observable(value: object, observable_type: str) -> str:
    raw = str(value or "").strip()
    kind = str(observable_type or "").strip().lower()
    if not raw:
        return ""
    if kind == "url":
        parsed = urlsplit(raw)
        if not parsed.scheme or not parsed.hostname:
            return raw
        hostname = parsed.hostname.lower().rstrip(".")
        try:
            port = parsed.port
        except ValueError:
            return raw
        default_port = (parsed.scheme.lower(), port) in {("http", 80), ("https", 443)}
        netloc = hostname if port is None or default_port else f"{hostname}:{port}"
        return urlunsplit(
            (parsed.scheme.lower(), netloc, parsed.path or "", parsed.query, "")
        )
    if kind == "domain":
        return raw.lower().rstrip(".")
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(raw))
        except ValueError:
            return raw
    if kind in {"sha256", "hash"}:
        return raw.lower()
    return raw


def infer_observable_type(label: str, value: object) -> str:
    normalized_label = str(label or "").lower()
    raw = str(value or "").strip()
    if "sha-256" in normalized_label or "sha256" in normalized_label:
        return "sha256"
    if "domain" in normalized_label:
        return "domain"
    if "url" in normalized_label or "://" in raw:
        return "url"
    if "ip" in normalized_label:
        return "ip"
    try:
        ipaddress.ip_address(raw)
        return "ip"
    except ValueError:
        return "indicator"


def _safety_metadata(
    value: str, observable_type: str, classification: str
) -> dict[str, object]:
    nonproduction = is_nonproduction_observable(value, observable_type)
    environment = "test" if nonproduction else "production"
    exportable_class = classification in {
        "confirmed_malicious",
        "suspicious",
        "ioc_candidate",
    }
    exportable = bool(exportable_class and not nonproduction)

    if nonproduction:
        if observable_type == "domain":
            reason = classify_domain(value).classification
        elif observable_type == "url":
            hostname = urlsplit(value).hostname or ""
            domain_result = classify_domain(hostname)
            reason = (
                domain_result.classification
                if domain_result.is_special_use
                else classify_ip(hostname).classification
            )
        else:
            reason = classify_ip(value).classification
    elif classification == "trusted":
        reason = "Trusted or brand infrastructure is not exportable"
    elif classification in {"contextual", "informational"}:
        reason = "Contextual-only observable is not exportable"
    else:
        reason = "Eligible only for analyst-reviewed production export"

    return {
        "environment": environment,
        "exportable": exportable,
        "export_reason": reason,
        "reputation": "NOT_APPLICABLE" if nonproduction else "UNKNOWN",
    }


class ObservableRegistry:
    """Deduplicate observables globally and retain only their highest classification."""

    def __init__(self, maximum: int = 50) -> None:
        self.maximum = maximum
        self._records: dict[tuple[str, str], dict] = {}

    def add(
        self,
        classification: str,
        label: str,
        value: object,
        observable_type: str = "",
    ) -> None:
        normalized_classification = str(classification).lower()
        if normalized_classification not in CLASSIFICATION_PRIORITY:
            raise ValueError(f"Unknown observable classification: {classification}")
        kind = observable_type or infer_observable_type(label, value)
        normalized = normalize_observable(value, kind)
        if not normalized:
            return
        key = (kind, normalized)
        existing = self._records.get(key)
        if existing:
            old_priority = CLASSIFICATION_PRIORITY[str(existing["classification"])]
            new_priority = CLASSIFICATION_PRIORITY[normalized_classification]
            if new_priority < old_priority:
                return
            if new_priority == old_priority:
                if str(label).startswith("Displayed "):
                    existing["label"] = str(label)
                return
        elif len(self._records) >= self.maximum:
            return

        record: dict[str, object] = {
            "type": kind,
            "value": normalized,
            "normalized_key": key,
            "label": str(label),
            "classification": normalized_classification,
        }
        record.update(_safety_metadata(normalized, kind, normalized_classification))
        self._records[key] = record

    def records(self) -> list[dict]:
        return list(self._records.values())

    def grouped(self) -> dict[str, list[dict]]:
        groups: dict[str, list[dict]] = {
            group: [] for group in GROUP_BY_CLASSIFICATION.values()
        }
        for record in self.records():
            group = GROUP_BY_CLASSIFICATION[str(record["classification"])]
            groups[group].append(record)
        return groups


def collect_observables(
    *,
    urls: list[dict],
    attachments: list[dict],
    url_intelligence: dict | None,
    sender_domain: str = "",
    brand_impersonation: dict | None = None,
    vt_url_reports: list[dict] | None = None,
    vt_hash_reports: list[dict] | None = None,
    otx_reports: list[dict] | None = None,
    attachment_risks: list[dict] | None = None,
    origin_ip: str = "",
    ip_reputation: list[dict] | None = None,
) -> list[dict]:
    registry = ObservableRegistry()
    identity_findings = (brand_impersonation or {}).get("sender_identity_mismatch", [])
    suspicious_senders = {
        str(finding.get("sender_domain", "")) for finding in identity_findings
    }
    trusted_roots = {
        registered_domain(str(finding.get("expected_domain", "")))
        for finding in identity_findings
        if finding.get("expected_domain")
    }
    registry.add(
        "ioc_candidate" if sender_domain in suspicious_senders else "contextual",
        "Sender domain",
        sender_domain,
        "domain",
    )
    registry.add("contextual", "Origin IP", origin_ip, "ip")

    for item in urls:
        actual_url = (
            item.get("normalized_url") or item.get("expanded_url") or item.get("url")
        )
        actual_domain = str(
            item.get("actual_domain")
            or item.get("domain")
            or item.get("registered_domain")
            or ""
        )
        is_mismatch = item.get("link_target_comparison") == "mismatch"
        registry.add(
            "contextual",
            "Actual HREF URL" if is_mismatch else "URL",
            actual_url,
            "url",
        )
        registry.add(
            "contextual",
            "Actual HREF domain" if is_mismatch else "URL domain",
            actual_domain,
            "domain",
        )
        displayed_url = item.get("displayed_url")
        displayed_domain = item.get("displayed_domain")
        if displayed_url:
            registry.add("contextual", "Displayed URL", displayed_url, "url")
        if displayed_domain:
            registry.add(
                "contextual", "Displayed URL domain", displayed_domain, "domain"
            )
        root = registered_domain(actual_domain)
        if root in trusted_roots:
            registry.add("trusted", "Brand domain", root, "domain")

    for finding in (url_intelligence or {}).get("deceptive_links", []):
        if int(finding.get("risk_score", 0)) > 0:
            registry.add(
                "ioc_candidate", "Deceptive-link URL", finding.get("url"), "url"
            )
            registry.add(
                "ioc_candidate",
                "Deceptive-link domain",
                finding.get("actual_domain"),
                "domain",
            )
    for finding in (url_intelligence or {}).get("redirect_findings", []):
        if int(finding.get("hops", 0)) > 0 and not finding.get("error"):
            registry.add(
                "contextual",
                "Observed redirect destination",
                finding.get("redirect_destination") or finding.get("final_url"),
                "url",
            )
            registry.add(
                "contextual",
                "Observed redirect domain",
                finding.get("final_domain"),
                "domain",
            )
    for finding in (url_intelligence or {}).get("shortener_findings", []):
        registry.add("contextual", "Expanded URL", finding.get("expanded_url"), "url")
        registry.add(
            "contextual", "Expanded domain", finding.get("expanded_domain"), "domain"
        )

    for report in vt_url_reports or []:
        if int(report.get("malicious", 0)) > 0:
            registry.add(
                "confirmed_malicious", "Known-malicious URL", report.get("url"), "url"
            )
        elif int(report.get("suspicious", 0)) > 0:
            registry.add("suspicious", "Suspicious URL", report.get("url"), "url")
    for report in vt_hash_reports or []:
        if int(report.get("malicious", 0)) > 0:
            registry.add(
                "confirmed_malicious",
                "Known-malicious SHA-256",
                report.get("sha256"),
                "sha256",
            )
    for report in otx_reports or []:
        if int(report.get("pulse_count", 0)) > 0:
            value = report.get("sha256") or report.get("url") or report.get("domain")
            observable_type = (
                "sha256"
                if report.get("sha256")
                else "url" if report.get("url") else "domain"
            )
            registry.add("ioc_candidate", "OTX indicator", value, observable_type)
    for finding in ip_reputation or []:
        registry.add(
            "suspicious" if int(finding.get("risk_score", 0)) > 0 else "contextual",
            "Origin IP reputation",
            finding.get("ip"),
            "ip",
        )

    risky_names = {
        str(finding.get("filename", ""))
        for finding in attachment_risks or []
        if int(finding.get("risk_score", 0)) > 0
    }
    for attachment in attachments:
        classification = (
            "ioc_candidate"
            if attachment.get("filename") in risky_names
            else "contextual"
        )
        registry.add(
            classification,
            "Attachment SHA-256",
            attachment.get("sha256"),
            "sha256",
        )
    return registry.records()


def group_observables(observables: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {
        group: [] for group in GROUP_BY_CLASSIFICATION.values()
    }
    for record in observables:
        group = GROUP_BY_CLASSIFICATION[str(record["classification"])]
        groups[group].append(record)
    return groups
