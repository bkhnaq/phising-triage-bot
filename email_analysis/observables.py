"""Normalized observable classification and safe IOC export metadata."""

from __future__ import annotations

import ipaddress
import re
from email.utils import getaddresses
from urllib.parse import urlsplit

from email_analysis.domain_utils import domain_info, registered_domain
from email_analysis.url_utils import analyze_url
from email_analysis.ip_utils import extract_ip_literals
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
        try:
            return analyze_url(raw).normalized_url
        except (UnicodeError, ValueError):
            return ""
    if kind == "domain":
        return domain_info(raw).ascii_host
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(raw))
        except ValueError:
            return raw
    if kind == "email" and "@" in raw:
        local, domain = raw.rsplit("@", 1)
        return local + "@" + domain_info(domain).ascii_host
    if kind in {"md5", "sha1", "sha256", "hash"}:
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
    environment = "TEST" if nonproduction else "PRODUCTION"
    exportable_class = classification in {
        "confirmed_malicious",
        "suspicious",
        "ioc_candidate",
    }
    exportable = bool(exportable_class and not nonproduction)

    if nonproduction:
        if observable_type in {"domain", "email"}:
            reason = classify_domain(value.rsplit("@", 1)[-1]).classification
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

    def __init__(self, maximum: int | None = None) -> None:
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
        try:
            if kind == "domain" and domain_info(str(value or "")).is_ip:
                kind = "ip"
            normalized = normalize_observable(value, kind)
        except (UnicodeError, ValueError):
            return
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
        elif self.maximum is not None and len(self._records) >= self.maximum:
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
    email_data: dict | None = None,
    header_forensics: dict | None = None,
    lab_mode: bool = False,
) -> list[dict]:
    """Extract intrinsic IOCs; legacy reputation inputs have no effect."""
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
            item.get("url")
        )
        actual_domain = domain_info(str(actual_url or "")).ascii_host
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
        registry.add(classification, "Attachment filename", attachment.get("filename"), "filename")
        for algorithm in ("md5", "sha1", "sha256"):
            registry.add(classification, f"Attachment {algorithm.upper()}", attachment.get(algorithm), algorithm)

    data = email_data or {}
    headers = data.get("headers", [])
    address_headers = [str(value) for name, value in headers if name.lower() in {
        "from", "to", "cc", "bcc", "reply-to", "return-path", "sender"
    }]
    address_headers.extend(str(data.get(key) or "") for key in ("from", "to", "reply_to", "return_path"))
    body = str(data.get("body_text") or "") + " " + str(data.get("body_html") or "")
    addresses = [address for _, address in getaddresses(address_headers) if "@" in address]
    addresses.extend(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", body))
    for address in addresses:
        registry.add("contextual", "Email address", address, "email")
        registry.add("contextual", "Email domain", address.rsplit("@", 1)[-1], "domain")
    for name, value in headers:
        if name.lower() == "message-id" and "@" in str(value):
            registry.add("informational", "Message-ID domain", str(value).rsplit("@", 1)[-1].strip("<> "), "domain")
    for hop in (header_forensics or {}).get("relay_chain", []):
        registry.add("contextual", "Relay IP", hop.get("ip"), "ip")
        registry.add("contextual", "Relay domain", hop.get("server"), "domain")

    # Extract IP literals without resolving any hostname.
    text = body + " " + " ".join(str(value) for _, value in headers)
    for candidate in extract_ip_literals(text):
        registry.add("contextual", "Observed IP", candidate, "ip")
    for record in list(registry.records()):
        if record["type"] in {"domain", "url"}:
            host = urlsplit(str(record["value"])).hostname if record["type"] == "url" else str(record["value"])
            try:
                registry.add("contextual", "URL IP", str(ipaddress.ip_address(host or "")), "ip")
            except ValueError:
                pass
    records = registry.records()
    for record in records:
        if lab_mode:
            record.update(environment="TEST", exportable=False, export_reason="Explicit lab analysis")
        elif record["type"] in {"md5", "sha1", "sha256", "filename"}:
            record.update(environment="UNKNOWN", exportable=False, export_reason="File origin requires downstream assessment")
    return sorted(records, key=lambda item: (str(item["type"]), str(item["value"])))



def group_observables(observables: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {
        group: [] for group in GROUP_BY_CLASSIFICATION.values()
    }
    for record in observables:
        group = GROUP_BY_CLASSIFICATION[str(record["classification"])]
        groups[group].append(record)
    return groups
