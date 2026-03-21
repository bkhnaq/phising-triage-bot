"""
IP Reputation Module
--------------------
Checks IP addresses against AbuseIPDB and Spamhaus DNSBL to detect
IPs with a history of malicious activity.

Usage:
    from threat_intel.ip_reputation import check_ip_reputation
    results = check_ip_reputation(["93.184.216.34"])
"""

import dns.resolver
import logging
import socket
from ipaddress import ip_address, AddressValueError

import requests

from config.settings import ABUSEIPDB_API_KEY

logger = logging.getLogger(__name__)

_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
_ABUSEIPDB_TIMEOUT = 10

# Spamhaus DNS-based blocklists
_SPAMHAUS_ZONES = [
    "zen.spamhaus.org",  # combined SBL + XBL + PBL
]

# Abuse confidence threshold (0-100) — flag if score meets or exceeds this
_ABUSE_CONFIDENCE_THRESHOLD = 50


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

    # If it's already an IP, return it directly
    try:
        ip_address(host)
        return host
    except (AddressValueError, ValueError):
        pass

    try:
        answers = socket.getaddrinfo(host, None, socket.AF_INET)
        if answers:
            return str(answers[0][4][0])
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
        "error": None,
    }

    if not ABUSEIPDB_API_KEY:
        result["error"] = "ABUSEIPDB_API_KEY not configured"
        return result

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

    except requests.RequestException as exc:
        result["error"] = str(exc)
        logger.error("AbuseIPDB check failed for %s: %s", ip, exc)

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
        "error": None,
    }

    try:
        parsed = ip_address(ip)
        if parsed.version != 4:
            result["error"] = "IPv6 not supported for DNSBL"
            return result
    except (AddressValueError, ValueError):
        result["error"] = f"invalid IP: {ip}"
        return result

    reversed_ip = ".".join(reversed(ip.split(".")))

    for zone in _SPAMHAUS_ZONES:
        query = f"{reversed_ip}.{zone}"
        try:
            dns.resolver.resolve(query, "A")
            # DNS returned a result → IP is listed in this zone
            result["listed"] = True
            result["zone"] = zone
            logger.warning("Spamhaus hit: %s listed in %s", ip, zone)
            break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            # Not listed in this zone
            continue
        except dns.resolver.Timeout:
            result["error"] = f"DNS timeout for {zone}"
            logger.debug("Spamhaus lookup timeout for %s in %s", ip, zone)
        except Exception as exc:
            result["error"] = str(exc)
            logger.debug("Spamhaus lookup error for %s: %s", ip, exc)

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
