"""
VirusTotal Checker Module
-------------------------
Queries the VirusTotal v3 API to check URLs and file hashes.

Docs: https://docs.virustotal.com/reference/overview

Usage:
    from threat_intel.virustotal_checker import check_url, check_file_hash
    url_report  = check_url("https://example.com")
    hash_report = check_file_hash("<sha256>")
"""

import logging

import requests

from config.settings import (
    OFFLINE_MODE,
    THREAT_INTEL_CACHE_TTL_SECONDS,
    VIRUSTOTAL_API_KEY,
)
from threat_intel.cache import TTLCache

logger = logging.getLogger(__name__)

_BASE_URL = "https://www.virustotal.com/api/v3"
_TIMEOUT = 15  # seconds
_URL_CACHE = TTLCache(THREAT_INTEL_CACHE_TTL_SECONDS)
_HASH_CACHE = TTLCache(THREAT_INTEL_CACHE_TTL_SECONDS)


def _get_headers() -> dict:
    return {"x-apikey": VIRUSTOTAL_API_KEY}


def check_url(url: str) -> dict:
    """
    Submit a URL to VirusTotal and return the analysis summary.

    Args:
        url: The URL to scan.

    Returns:
        Dict with keys: url, malicious, suspicious, harmless, undetected, error.
    """
    result = {
        "url": url,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "state": "not_checked",
        "error": None,
    }

    if not VIRUSTOTAL_API_KEY:
        result["error"] = "VIRUSTOTAL_API_KEY not configured"
        logger.warning(result["error"])
        return result

    if OFFLINE_MODE:
        result["error"] = "offline mode enabled"
        logger.info("VirusTotal URL check skipped in offline mode for %s", url)
        return result

    found, cached = _URL_CACHE.get(url)
    if found:
        return cached

    try:
        # URL identifier used by VT v3 is base64url of the URL
        import base64

        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        resp = requests.get(
            f"{_BASE_URL}/urls/{url_id}",
            headers=_get_headers(),
            timeout=_TIMEOUT,
        )

        if resp.status_code == 404:
            # URL not yet scanned – submit it
            resp = requests.post(
                f"{_BASE_URL}/urls",
                headers=_get_headers(),
                data={"url": url},
                timeout=_TIMEOUT,
            )
            resp.raise_for_status()
            result["state"] = "submitted_for_analysis"
            result["error"] = "submitted_for_analysis"
            return result

        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        result["malicious"] = stats.get("malicious", 0)
        result["suspicious"] = stats.get("suspicious", 0)
        result["harmless"] = stats.get("harmless", 0)
        result["undetected"] = stats.get("undetected", 0)
        result["state"] = _vt_state(result)

    except (
        requests.RequestException,
        AttributeError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        result["error"] = str(exc)
        result["state"] = "unavailable"
        logger.error("VirusTotal URL check failed for %s: %s", url, exc)

    _URL_CACHE.set(url, result)
    return result


def check_file_hash(sha256: str) -> dict:
    """
    Look up a file hash on VirusTotal.

    Args:
        sha256: SHA-256 hex digest of the file.

    Returns:
        Dict with keys: sha256, malicious, suspicious, harmless, undetected, error.
    """
    result = {
        "sha256": sha256,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "state": "not_checked",
        "error": None,
    }

    if not VIRUSTOTAL_API_KEY:
        result["error"] = "VIRUSTOTAL_API_KEY not configured"
        logger.warning(result["error"])
        return result

    if OFFLINE_MODE:
        result["error"] = "offline mode enabled"
        logger.info("VirusTotal hash check skipped in offline mode for %s", sha256)
        return result

    found, cached = _HASH_CACHE.get(sha256)
    if found:
        return cached

    try:
        resp = requests.get(
            f"{_BASE_URL}/files/{sha256}",
            headers=_get_headers(),
            timeout=_TIMEOUT,
        )
        if resp.status_code == 404:
            result["state"] = "not_found"
            result["error"] = "not_found"
            return result

        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        result["malicious"] = stats.get("malicious", 0)
        result["suspicious"] = stats.get("suspicious", 0)
        result["harmless"] = stats.get("harmless", 0)
        result["undetected"] = stats.get("undetected", 0)
        result["state"] = _vt_state(result)

    except (
        requests.RequestException,
        AttributeError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        result["error"] = str(exc)
        result["state"] = "unavailable"
        logger.error("VirusTotal hash check failed for %s: %s", sha256, exc)

    _HASH_CACHE.set(sha256, result)
    return result


def _vt_state(result: dict) -> str:
    if int(result.get("malicious", 0)) > 0:
        return "malicious"
    if int(result.get("suspicious", 0)) > 0:
        return "suspicious"
    return "clean"
