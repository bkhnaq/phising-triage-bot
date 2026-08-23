"""Classification helpers for reserved domains and special-use IP addresses."""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit

SPECIAL_USE_SUFFIXES: dict[str, str] = {
    ".test": "Reserved testing domain (.test)",
    ".example": "Reserved documentation domain (.example)",
    ".invalid": "Reserved invalid domain (.invalid)",
    ".localhost": "Reserved loopback domain (.localhost)",
}

DOCUMENTATION_NETWORKS: tuple[
    tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str], ...
] = (
    (ipaddress.ip_network("192.0.2.0/24"), "Documentation / TEST-NET-1"),
    (ipaddress.ip_network("198.51.100.0/24"), "Documentation / TEST-NET-2"),
    (ipaddress.ip_network("203.0.113.0/24"), "Documentation / TEST-NET-3"),
)


@dataclass(frozen=True)
class SpecialUseClassification:
    value: str
    is_special_use: bool
    classification: str
    suffix_or_network: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def classify_domain(domain: str) -> SpecialUseClassification:
    normalized = str(domain or "").strip().lower().rstrip(".")
    for suffix, classification in SPECIAL_USE_SUFFIXES.items():
        bare_suffix = suffix.removeprefix(".")
        if normalized == bare_suffix or normalized.endswith(suffix):
            return SpecialUseClassification(
                value=normalized,
                is_special_use=True,
                classification=classification,
                suffix_or_network=suffix,
            )
    return SpecialUseClassification(normalized, False, "Public DNS domain")


def classify_ip(value: str) -> SpecialUseClassification:
    normalized = str(value or "").strip()
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return SpecialUseClassification(normalized, False, "Invalid IP address")

    for network, classification in DOCUMENTATION_NETWORKS:
        if address in network:
            return SpecialUseClassification(
                value=normalized,
                is_special_use=True,
                classification=classification,
                suffix_or_network=str(network),
            )
    if not address.is_global:
        return SpecialUseClassification(
            value=normalized,
            is_special_use=True,
            classification="Non-public / special-use IP address",
        )
    return SpecialUseClassification(normalized, False, "Public IP address")


def is_reserved_test_domain(domain: str) -> bool:
    return classify_domain(domain).is_special_use


def is_documentation_ip(value: str) -> bool:
    normalized = str(value or "").strip()
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return any(address in network for network, _label in DOCUMENTATION_NETWORKS)


def is_nonproduction_observable(value: str, observable_type: str = "") -> bool:
    """Return True for reserved domains/URLs and documentation/special-use IPs."""
    normalized_type = str(observable_type or "").strip().lower()
    normalized_value = str(value or "").strip()
    if normalized_type == "url" or "://" in normalized_value:
        hostname = urlsplit(normalized_value).hostname or ""
        if is_reserved_test_domain(hostname):
            return True
        try:
            return classify_ip(hostname).is_special_use
        except ValueError:
            return False
    if normalized_type == "ip":
        return classify_ip(normalized_value).is_special_use
    if normalized_type == "domain":
        return is_reserved_test_domain(normalized_value)
    return False
