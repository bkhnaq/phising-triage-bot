"""
IP Reputation Module
--------------------
Checks IP addresses against AbuseIPDB and Spamhaus DNSBL to detect
IPs with a history of malicious activity.

Usage:
    from threat_intel.ip_reputation import check_ip_reputation
    results = check_ip_reputation(["93.184.216.34"])
"""

import logging
import socket
import importlib
from ipaddress import ip_address, AddressValueError
from typing import Any

import requests

try:
    dns_resolver: Any | None = importlib.import_module("dns.resolver")
except ImportError:
    dns_resolver = None

from config.settings import (
    ABUSEIPDB_API_KEY,
    OFFLINE_MODE,
    THREAT_INTEL_CACHE_TTL_SECONDS,
)
from threat_intel.cache import TTLCache

logger = logging.getLogger(__name__)

_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
_ABUSEIPDB_TIMEOUT = 10

# Spamhaus DNS-based blocklists
_SPAMHAUS_ZONES = [
    "zen.spamhaus.org",  # combined SBL + XBL + PBL
]

# Abuse confidence threshold (0-100) — flag if score meets or exceeds this
_ABUSE_CONFIDENCE_THRESHOLD = 50
_DNS_CACHE = TTLCache(THREAT_INTEL_CACHE_TTL_SECONDS)
_ABUSE_CACHE = TTLCache(THREAT_INTEL_CACHE_TTL_SECONDS)
_SPAMHAUS_CACHE = TTLCache(THREAT_INTEL_CACHE_TTL_SECONDS)


def resolve_domain_ip(domain: str) -> str | None:
    """
    Resolve a domain name to its first A-record IP address.

    Returns:
        IP address string, or None if resolution fails.
    """
    # Strip port if present
    host = domain.split(":")[0].strip().lower()
    if not host:
        return None

    if OFFLINE_MODE:
        logger.info("DNS resolution skipped in offline mode for %s", host)
        return None

    found, cached = _DNS_CACHE.get(host)
    if found:
        return cached

    # If it's already an IP, return it directly
    try:
        ip_address(host)
        _DNS_CACHE.set(host, host)
        return host
    except (AddressValueError, ValueError):
        pass

    try:
        answers = socket.getaddrinfo(host, None, socket.AF_INET)
        if answers:
            ip = str(answers[0][4][0])
            _DNS_CACHE.set(host, ip)
            return ip
    except (socket.gaierror, OSError):
        logger.debug("DNS resolution failed for %s", host)
    return None


def _check_abuseipdb(ip: str) -> dict:
    """
    Query AbuseIPDB for an IP's abuse confidence score.

    Returns:
        Dict with keys: ip, abuse_score, is_public, country, isp,
                        total_reports, error.
    """
    result: dict = {
        "ip": ip,
        "abuse_score": 0,
        "is_public": True,
        "country": None,
        "isp": None,
        "total_reports": 0,
        "state": "not_checked",
        "error": None,
    }

    if not ABUSEIPDB_API_KEY:
        result["error"] = "ABUSEIPDB_API_KEY not configured"
        return result

    if OFFLINE_MODE:
        result["error"] = "offline mode enabled"
        return result

    found, cached = _ABUSE_CACHE.get(ip)
    if found:
        return cached

    try:
        resp = requests.get(
            _ABUSEIPDB_URL,
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json",
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": "90",
                "verbose": "",
            },
            timeout=_ABUSEIPDB_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})

        result["abuse_score"] = data.get("abuseConfidenceScore", 0)
        result["is_public"] = data.get("isPublic", True)
        result["country"] = data.get("countryCode")
        result["isp"] = data.get("isp")
        result["total_reports"] = data.get("totalReports", 0)
        result["state"] = (
            "suspicious"
            if result["abuse_score"] >= _ABUSE_CONFIDENCE_THRESHOLD
            else "clean"
        )

    except (requests.RequestException, AttributeError, TypeError, ValueError) as exc:
        result["error"] = str(exc)
        result["state"] = "unavailable"
        logger.error("AbuseIPDB check failed for %s: %s", ip, exc)

    _ABUSE_CACHE.set(ip, result)
    return result


def _check_spamhaus(ip: str) -> dict:
    """
    Check an IP against Spamhaus DNSBL via DNS lookup.

    The check reverses the IP octets and queries the Spamhaus zone.
    A successful DNS response means the IP **is** listed.

    Returns:
        Dict with keys: ip, listed, zone, error.
    """
    result: dict = {
        "ip": ip,
        "listed": False,
        "zone": None,
        "state": "not_checked",
        "error": None,
    }

    if dns_resolver is None:
        result["error"] = "dnspython not installed"
        return result

    if OFFLINE_MODE:
        result["error"] = "offline mode enabled"
        return result

    try:
        parsed = ip_address(ip)
        if parsed.version != 4:
            result["error"] = "IPv6 not supported for DNSBL"
            return result
    except (AddressValueError, ValueError):
        result["error"] = f"invalid IP: {ip}"
        return result

    reversed_ip = ".".join(reversed(ip.split(".")))

    found, cached = _SPAMHAUS_CACHE.get(reversed_ip)
    if found:
        return cached

    for zone in _SPAMHAUS_ZONES:
        query = f"{reversed_ip}.{zone}"
        try:
            dns_resolver.resolve(query, "A")
            # DNS returned a result → IP is listed in this zone
            result["listed"] = True
            result["zone"] = zone
            result["state"] = "suspicious"
            logger.warning("Spamhaus hit: %s listed in %s", ip, zone)
            break
        except (dns_resolver.NXDOMAIN, dns_resolver.NoAnswer):
            # Not listed in this zone
            continue
        except dns_resolver.Timeout:
            result["error"] = f"DNS timeout for {zone}"
            logger.debug("Spamhaus lookup timeout for %s in %s", ip, zone)
        except Exception as exc:
            result["error"] = str(exc)
            result["state"] = "unavailable"
            logger.debug("Spamhaus lookup error for %s: %s", ip, exc)

    if result["state"] == "not_checked" and result["error"] is None:
        result["state"] = "clean"

    _SPAMHAUS_CACHE.set(reversed_ip, result)
    return result


def check_ip_reputation(domains: list[str]) -> list[dict]:
    """
    Resolve domains to IPs and check their reputation via AbuseIPDB
    and Spamhaus DNSBL.

    Args:
        domains: List of domain strings extracted from email URLs.

    Returns:
        List of finding dicts, each containing:
            domain, ip, abuseipdb (sub-dict), spamhaus (sub-dict),
            blacklisted (bool), risk_score (int).
    """
    findings: list[dict] = []
    checked_ips: set[str] = set()

    for domain in domains:
        ip = resolve_domain_ip(domain)
        if not ip or ip in checked_ips:
            continue
        checked_ips.add(ip)

        abuse = _check_abuseipdb(ip)
        spamhaus = _check_spamhaus(ip)

        blacklisted = (
            abuse["abuse_score"] >= _ABUSE_CONFIDENCE_THRESHOLD or spamhaus["listed"]
        )

        finding: dict = {
            "domain": domain,
            "ip": ip,
            "abuseipdb": abuse,
            "spamhaus": spamhaus,
            "blacklisted": blacklisted,
            "risk_score": 20 if blacklisted else 0,
        }

        if blacklisted:
            logger.warning(
                "Blacklisted IP: %s (domain: %s, abuse_score=%d, spamhaus=%s)",
                ip,
                domain,
                abuse["abuse_score"],
                spamhaus["listed"],
            )

        findings.append(finding)

    return findings
