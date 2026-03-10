"""
AlienVault OTX Checker Module
------------------------------
Queries the AlienVault OTX DirectConnect API for threat intelligence on
domains, URLs, and file hashes.

Docs: https://otx.alienvault.com/assets/s/v2/api/docs/

Usage:
    from threat_intel.alienvault_checker import check_domain, check_file_hash
    domain_report = check_domain("example.com")
    hash_report   = check_file_hash("<sha256>")
"""

import logging

import requests

from config.settings import ALIENVAULT_OTX_API_KEY

logger = logging.getLogger(__name__)

_BASE_URL = "https://otx.alienvault.com/api/v1"
_TIMEOUT = 15  # seconds


def _get_headers() -> dict:
    return {"X-OTX-API-KEY": ALIENVAULT_OTX_API_KEY}


def check_domain(domain: str) -> dict:
    """
    Look up a domain on AlienVault OTX.

    Args:
        domain: Domain name to check (e.g., "evil-site.com").

    Returns:
        Dict with keys: domain, pulse_count, pulses, error.
    """
    result: dict = {
        "domain": domain,
        "pulse_count": 0,
        "pulses": [],
        "error": None,
    }

    if not ALIENVAULT_OTX_API_KEY:
        result["error"] = "ALIENVAULT_OTX_API_KEY not configured"
        logger.warning(result["error"])
        return result

    try:
        resp = requests.get(
            f"{_BASE_URL}/indicators/domain/{domain}/general",
            headers=_get_headers(),
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        result["pulse_count"] = data.get("pulse_info", {}).get("count", 0)
        # Keep only the first 5 pulse names for brevity
        pulses = data.get("pulse_info", {}).get("pulses", [])
        result["pulses"] = [p.get("name", "") for p in pulses[:5]]

    except requests.RequestException as exc:
        result["error"] = str(exc)
        logger.error("OTX domain check failed for %s: %s", domain, exc)

    return result


def check_file_hash(sha256: str) -> dict:
    """
    Look up a file hash on AlienVault OTX.

    Args:
        sha256: SHA-256 hex digest of the file.

    Returns:
        Dict with keys: sha256, pulse_count, pulses, error.
    """
    result: dict = {
        "sha256": sha256,
        "pulse_count": 0,
        "pulses": [],
        "error": None,
    }

    if not ALIENVAULT_OTX_API_KEY:
        result["error"] = "ALIENVAULT_OTX_API_KEY not configured"
        logger.warning(result["error"])
        return result

    try:
        resp = requests.get(
            f"{_BASE_URL}/indicators/file/{sha256}/general",
            headers=_get_headers(),
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        result["pulse_count"] = data.get("pulse_info", {}).get("count", 0)
        pulses = data.get("pulse_info", {}).get("pulses", [])
        result["pulses"] = [p.get("name", "") for p in pulses[:5]]

    except requests.RequestException as exc:
        result["error"] = str(exc)
        logger.error("OTX hash check failed for %s: %s", sha256, exc)

    return result
