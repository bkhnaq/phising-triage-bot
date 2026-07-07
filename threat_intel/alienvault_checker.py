"""
AlienVault OTX Checker Module
------------------------------
Queries the AlienVault OTX DirectConnect API for threat intelligence on
domains, URLs, and file hashes.

Docs: https://otx.alienvault.com/assets/s/v2/api/docs/

Usage:
    from threat_intel.alienvault_checker import check_domain, check_url, check_file_hash
    domain_report = check_domain("example.com")
    url_report    = check_url("https://example.com/login")
    hash_report   = check_file_hash("<sha256>")
"""

import logging
from urllib.parse import quote

import requests

from config.settings import (
    ALIENVAULT_OTX_API_KEY,
    OFFLINE_MODE,
    THREAT_INTEL_CACHE_TTL_SECONDS,
)
from threat_intel.cache import TTLCache

logger = logging.getLogger(__name__)

_BASE_URL = "https://otx.alienvault.com/api/v1"
_TIMEOUT = 15  # seconds
_DOMAIN_CACHE = TTLCache(THREAT_INTEL_CACHE_TTL_SECONDS)
_URL_CACHE = TTLCache(THREAT_INTEL_CACHE_TTL_SECONDS)
_HASH_CACHE = TTLCache(THREAT_INTEL_CACHE_TTL_SECONDS)


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
        "state": "not_checked",
        "error": None,
    }

    if not ALIENVAULT_OTX_API_KEY:
        result["error"] = "ALIENVAULT_OTX_API_KEY not configured"
        logger.warning(result["error"])
        return result

    if OFFLINE_MODE:
        result["error"] = "offline mode enabled"
        logger.info("OTX domain check skipped in offline mode for %s", domain)
        return result

    found, cached = _DOMAIN_CACHE.get(domain)
    if found:
        return cached

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
        result["state"] = _otx_state(result)

    except (requests.RequestException, AttributeError, TypeError, ValueError) as exc:
        result["error"] = str(exc)
        result["state"] = "unavailable"
        logger.error("OTX domain check failed for %s: %s", domain, exc)

    _DOMAIN_CACHE.set(domain, result)
    return result


def check_url(url: str) -> dict:
    """
    Look up a URL on AlienVault OTX.

    Args:
        url: URL to check (e.g., "https://evil-site.com/login").

    Returns:
        Dict with keys: url, pulse_count, pulses, error.
    """
    result: dict = {
        "url": url,
        "pulse_count": 0,
        "pulses": [],
        "state": "not_checked",
        "error": None,
    }

    if not ALIENVAULT_OTX_API_KEY:
        result["error"] = "ALIENVAULT_OTX_API_KEY not configured"
        logger.warning(result["error"])
        return result

    if OFFLINE_MODE:
        result["error"] = "offline mode enabled"
        logger.info("OTX URL check skipped in offline mode for %s", url)
        return result

    found, cached = _URL_CACHE.get(url)
    if found:
        return cached

    try:
        encoded_url = quote(url, safe="")
        resp = requests.get(
            f"{_BASE_URL}/indicators/url/{encoded_url}/general",
            headers=_get_headers(),
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        result["pulse_count"] = data.get("pulse_info", {}).get("count", 0)
        pulses = data.get("pulse_info", {}).get("pulses", [])
        result["pulses"] = [p.get("name", "") for p in pulses[:5]]
        result["state"] = _otx_state(result)

    except (requests.RequestException, AttributeError, TypeError, ValueError) as exc:
        result["error"] = str(exc)
        result["state"] = "unavailable"
        logger.error("OTX URL check failed for %s: %s", url, exc)

    _URL_CACHE.set(url, result)
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
        "state": "not_checked",
        "error": None,
    }

    if not ALIENVAULT_OTX_API_KEY:
        result["error"] = "ALIENVAULT_OTX_API_KEY not configured"
        logger.warning(result["error"])
        return result

    if OFFLINE_MODE:
        result["error"] = "offline mode enabled"
        logger.info("OTX hash check skipped in offline mode for %s", sha256)
        return result

    found, cached = _HASH_CACHE.get(sha256)
    if found:
        return cached

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
        result["state"] = _otx_state(result)

    except (requests.RequestException, AttributeError, TypeError, ValueError) as exc:
        result["error"] = str(exc)
        result["state"] = "unavailable"
        logger.error("OTX hash check failed for %s: %s", sha256, exc)

    _HASH_CACHE.set(sha256, result)
    return result


def _otx_state(result: dict) -> str:
    return "suspicious" if int(result.get("pulse_count", 0)) > 0 else "clean"
