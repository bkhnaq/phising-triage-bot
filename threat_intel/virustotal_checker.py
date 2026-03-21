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

from config.settings import VIRUSTOTAL_API_KEY

logger = logging.getLogger(__name__)

_BASE_URL = "https://www.virustotal.com/api/v3"
_TIMEOUT = 15  # seconds


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
        "error": None,
    }

    if not VIRUSTOTAL_API_KEY:
        result["error"] = "VIRUSTOTAL_API_KEY not configured"
        logger.warning(result["error"])
        return result

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
            result["error"] = "submitted_for_analysis"
            return result

        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        result["malicious"] = stats.get("malicious", 0)
        result["suspicious"] = stats.get("suspicious", 0)
        result["harmless"] = stats.get("harmless", 0)
        result["undetected"] = stats.get("undetected", 0)

    except requests.RequestException as exc:
        result["error"] = str(exc)
        logger.error("VirusTotal URL check failed for %s: %s", url, exc)

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
        "error": None,
    }

    if not VIRUSTOTAL_API_KEY:
        result["error"] = "VIRUSTOTAL_API_KEY not configured"
        logger.warning(result["error"])
        return result

    try:
        resp = requests.get(
            f"{_BASE_URL}/files/{sha256}",
            headers=_get_headers(),
            timeout=_TIMEOUT,
        )
        if resp.status_code == 404:
            result["error"] = "not_found"
            return result

        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        result["malicious"] = stats.get("malicious", 0)
        result["suspicious"] = stats.get("suspicious", 0)
        result["harmless"] = stats.get("harmless", 0)
        result["undetected"] = stats.get("undetected", 0)

    except requests.RequestException as exc:
        result["error"] = str(exc)
        logger.error("VirusTotal hash check failed for %s: %s", sha256, exc)

    return result
