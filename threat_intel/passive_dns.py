"""
Passive DNS Module
------------------
Queries SecurityTrails API to discover how many domains are hosted on a
given IP address.  An IP hosting a large number of domains (especially
freshly registered or suspicious ones) is a strong phishing indicator.

Usage:
    from threat_intel.passive_dns import check_passive_dns
    findings = check_passive_dns(["93.184.216.34"])
"""

import logging

import requests

from config.settings import SECURITYTRAILS_API_KEY

logger = logging.getLogger(__name__)

_BASE_URL = "https://api.securitytrails.com/v1"
_TIMEOUT = 15
# Flag IPs hosting more than this many domains as suspicious
_DOMAIN_COUNT_THRESHOLD = 50


def _query_securitytrails(ip: str) -> dict:
    """
    Query SecurityTrails for domains hosted on a given IP.

    Returns:
        Dict with keys: ip, domain_count, sample_domains, error.
    """
    result: dict = {
        "ip": ip,
        "domain_count": 0,
        "sample_domains": [],
        "error": None,
    }

    if not SECURITYTRAILS_API_KEY:
        result["error"] = "SECURITYTRAILS_API_KEY not configured"
        return result

    try:
        resp = requests.get(
            f"{_BASE_URL}/domains/list",
            headers={
                "APIKEY": SECURITYTRAILS_API_KEY,
                "Accept": "application/json",
            },
            params={"include_ips": "false", "scroll": "false", "filter": f"ipv4={ip}"},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        result["domain_count"] = data.get("record_count", 0)
        records = data.get("records", [])
        # Keep a small sample of domain names for the report
        result["sample_domains"] = [
            r.get("hostname", "") for r in records[:10] if r.get("hostname")
        ]

    except requests.RequestException as exc:
        result["error"] = str(exc)
        logger.error("SecurityTrails lookup failed for IP %s: %s", ip, exc)

    return result


def check_passive_dns(ip_findings: list[dict]) -> list[dict]:
    """
    For each IP already resolved by the IP reputation module, query
    SecurityTrails to count the number of domains hosted on that IP.

    Args:
        ip_findings: List of dicts from ``ip_reputation.check_ip_reputation()``,
                     each containing at least an ``ip`` key.

    Returns:
        List of finding dicts with keys:
            ip, domain_count, sample_domains, suspicious, risk_score, error.
    """
    findings: list[dict] = []
    checked: set[str] = set()

    for entry in ip_findings:
        ip = entry.get("ip", "")
        if not ip or ip in checked:
            continue
        checked.add(ip)

        st = _query_securitytrails(ip)

        suspicious = st["domain_count"] >= _DOMAIN_COUNT_THRESHOLD
        risk_score = 20 if suspicious else 0

        finding: dict = {
            "ip": ip,
            "domain_count": st["domain_count"],
            "sample_domains": st["sample_domains"],
            "suspicious": suspicious,
            "risk_score": risk_score,
            "error": st["error"],
        }

        if suspicious:
            logger.warning(
                "Passive DNS: IP %s hosts %d domain(s) – suspicious",
                ip,
                st["domain_count"],
            )

        findings.append(finding)

    return findings
