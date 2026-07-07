"""Shared domain canonicalization helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import importlib
import ipaddress
from typing import Any
from urllib.parse import urlparse

try:
    tldextract: Any | None = importlib.import_module("tldextract")
except ImportError:
    tldextract = None

_EXTRACTOR = (
    tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
    if tldextract is not None
    else None
)


@dataclass(frozen=True)
class DomainInfo:
    """Canonical domain pieces derived with Public Suffix List support."""

    host: str
    ascii_host: str
    unicode_host: str
    registered_domain: str
    suffix: str
    subdomain: str
    base_label: str
    is_ip: bool
    is_punycode: bool

    def to_dict(self) -> dict:
        return asdict(self)


def domain_info(value: str) -> DomainInfo:
    """Return canonical domain metadata for a hostname, netloc, URL, or email domain."""
    host = _extract_host(value)
    is_ip = _is_ip_address(host)
    ascii_host, unicode_host, is_punycode = _idna_forms(host)

    if not ascii_host:
        return DomainInfo("", "", "", "", "", "", "", False, False)

    if is_ip:
        return DomainInfo(
            host=ascii_host,
            ascii_host=ascii_host,
            unicode_host=unicode_host,
            registered_domain=ascii_host,
            suffix="",
            subdomain="",
            base_label=ascii_host,
            is_ip=True,
            is_punycode=is_punycode,
        )

    subdomain, domain, suffix = _split_public_suffix(ascii_host)
    if domain and suffix:
        registered = f"{domain}.{suffix}"
    elif suffix:
        registered = ascii_host
    elif "." in ascii_host:
        registered = ".".join(ascii_host.split(".")[-2:])
    else:
        registered = domain
    return DomainInfo(
        host=ascii_host,
        ascii_host=ascii_host,
        unicode_host=unicode_host,
        registered_domain=registered,
        suffix=suffix,
        subdomain=subdomain,
        base_label=domain or ascii_host.split(".", 1)[0],
        is_ip=False,
        is_punycode=is_punycode,
    )


def registered_domain(value: str) -> str:
    return domain_info(value).registered_domain


def base_label(value: str) -> str:
    return domain_info(value).base_label


def same_registered_domain(left: str, right: str) -> bool:
    left_reg = registered_domain(left)
    right_reg = registered_domain(right)
    return bool(left_reg and right_reg and left_reg == right_reg)


def is_domain_or_subdomain(host: str, candidate_domain: str) -> bool:
    host_info = domain_info(host)
    candidate_info = domain_info(candidate_domain)
    host_ascii = host_info.ascii_host
    candidate_ascii = candidate_info.ascii_host
    if not host_ascii or not candidate_ascii:
        return False
    return host_ascii == candidate_ascii or host_ascii.endswith("." + candidate_ascii)


def any_domain_match(
    host: str, candidates: set[str] | tuple[str, ...] | list[str]
) -> bool:
    return any(is_domain_or_subdomain(host, candidate) for candidate in candidates)


def _extract_host(value: str) -> str:
    raw = (value or "").strip().strip("<>[]()\"'")
    if not raw:
        return ""

    if "://" in raw:
        parsed = urlparse(raw)
        host = parsed.hostname or ""
    elif "/" in raw or "@" in raw:
        parsed = urlparse("//" + raw)
        host = parsed.hostname or raw.rsplit("@", 1)[-1]
    else:
        parsed = urlparse("//" + raw)
        host = parsed.hostname or raw

    return host.strip().lower().rstrip(".")


def _idna_forms(host: str) -> tuple[str, str, bool]:
    if not host:
        return "", "", False

    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        ascii_host = host.lower()

    try:
        unicode_host = ascii_host.encode("ascii").decode("idna").lower()
    except UnicodeError:
        unicode_host = host.lower()

    is_punycode = ascii_host.startswith("xn--") or ".xn--" in ascii_host
    return ascii_host, unicode_host, is_punycode


def _split_public_suffix(host: str) -> tuple[str, str, str]:
    if _EXTRACTOR is not None:
        extracted = _EXTRACTOR(host)
        return extracted.subdomain, extracted.domain, extracted.suffix

    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "ac", "gov"}:
        return ".".join(parts[:-3]), parts[-3], ".".join(parts[-2:])
    if len(parts) >= 2:
        return ".".join(parts[:-2]), parts[-2], parts[-1]
    return "", host, ""


def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
