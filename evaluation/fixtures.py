"""Deterministic provider and model fixtures used by the evaluation runner."""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
from unittest.mock import patch
from urllib.parse import urlparse

from scoring.config import ThreatIntelStatus


def _vt_report(indicator: str, kind: str, *, is_hash: bool = False) -> dict:
    key = "sha256" if is_hash else "url"
    result = {
        key: indicator,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "state": "clean",
        "status": ThreatIntelStatus.CLEAN.value,
        "data": {},
        "error": None,
    }
    if kind == "malicious":
        result.update(
            malicious=7,
            suspicious=1,
            harmless=2,
            undetected=10,
            state="malicious",
            status=ThreatIntelStatus.MALICIOUS.value,
        )
    elif kind == "suspicious":
        result.update(
            suspicious=3,
            harmless=2,
            undetected=15,
            state="suspicious",
            status=ThreatIntelStatus.SUSPICIOUS.value,
        )
    elif kind == "unavailable":
        result.update(
            state="unavailable",
            status=ThreatIntelStatus.UNAVAILABLE.value,
            error="deterministic provider-unavailable fixture",
            data=None,
        )
    return result


def _otx_report(indicator: str, kind: str, *, indicator_type: str) -> dict:
    result = {
        indicator_type: indicator,
        "pulse_count": 0,
        "pulses": [],
        "state": "clean",
        "status": ThreatIntelStatus.CLEAN.value,
        "data": {"pulse_count": 0, "pulses": []},
        "error": None,
    }
    if kind == "malicious":
        result.update(
            pulse_count=2,
            pulses=["Offline phishing regression", "Credential theft fixture"],
            state="malicious",
            status=ThreatIntelStatus.MALICIOUS.value,
        )
        result["data"] = {
            "pulse_count": result["pulse_count"],
            "pulses": result["pulses"],
        }
    elif kind == "unavailable":
        result.update(
            state="unavailable",
            status=ThreatIntelStatus.UNAVAILABLE.value,
            error="deterministic provider-unavailable fixture",
            data=None,
        )
    return result


def _ai_report(kind: str) -> dict:
    fixtures = {
        "phishing_high": ("phishing", 0.98, 10),
        "suspicious": ("suspicious", 0.72, 2),
        "legitimate": ("legitimate", 0.97, 0),
        "unavailable": ("unknown", 0.0, 0),
    }
    verdict, confidence, risk_score = fixtures.get(kind, ("legitimate", 0.95, 0))
    return {
        "verdict": verdict,
        "confidence": confidence,
        "reasons": [f"Deterministic {kind} evaluation fixture"],
        "risk_score": risk_score,
        "error": "deterministic unavailable fixture" if kind == "unavailable" else None,
        "provider": "evaluation-fixture",
        "model": "offline-deterministic-v1",
        "phishing_probability": confidence if verdict == "phishing" else 1 - confidence,
        "fallback_used": False,
    }


@contextmanager
def deterministic_fixtures(sample: dict):
    """Patch every external enrichment boundary for exactly one sample."""
    fixtures = sample.get("fixtures") or {}
    vt_url_kind = str(fixtures.get("vt_url", "clean"))
    vt_hash_kind = str(fixtures.get("vt_hash", "clean"))
    otx_kind = str(fixtures.get("otx", "clean"))
    ai_kind = str(fixtures.get("ai", "legitimate"))
    qr_url = str(fixtures.get("qr_url", ""))

    def vt_url(url: str) -> dict:
        return _vt_report(url, vt_url_kind)

    def vt_hash(sha256: str) -> dict:
        return _vt_report(sha256, vt_hash_kind, is_hash=True)

    def otx_url(url: str) -> dict:
        return _otx_report(url, otx_kind, indicator_type="url")

    def otx_domain(domain: str) -> dict:
        return _otx_report(domain, otx_kind, indicator_type="domain")

    def otx_hash(sha256: str) -> dict:
        return _otx_report(sha256, otx_kind, indicator_type="sha256")

    def ai_classifier(_email: dict, _urls: list[dict], _findings: list[str]) -> dict:
        return _ai_report(ai_kind)

    def qr_scanner(attachments: list[dict]) -> list[dict]:
        if not qr_url or not attachments:
            return []
        return [
            {
                "filename": attachments[0].get("filename", "security-qr.png"),
                "qr_data": qr_url,
                "qr_type": "QRCODE",
                "url": qr_url,
                "domain": urlparse(qr_url).hostname,
                "risk_score": 15,
            }
        ]

    with ExitStack() as stack:
        for module_name in (
            "config.settings",
            "email_analysis.domain_intelligence",
            "email_analysis.header_forensics",
            "email_analysis.landing_page_analyzer",
            "email_analysis.url_intelligence",
            "threat_intel.ip_reputation",
            "threat_intel.passive_dns",
        ):
            stack.enter_context(patch(f"{module_name}.OFFLINE_MODE", True))
        stack.enter_context(patch("threat_intel.virustotal_checker.check_url", vt_url))
        stack.enter_context(
            patch("threat_intel.virustotal_checker.check_file_hash", vt_hash)
        )
        stack.enter_context(patch("threat_intel.alienvault_checker.check_url", otx_url))
        stack.enter_context(
            patch("threat_intel.alienvault_checker.check_domain", otx_domain)
        )
        stack.enter_context(
            patch("threat_intel.alienvault_checker.check_file_hash", otx_hash)
        )
        stack.enter_context(
            patch("threat_intel.ip_reputation.check_ip_reputation", lambda _domains: [])
        )
        stack.enter_context(
            patch("threat_intel.passive_dns.check_passive_dns", lambda _items: [])
        )
        stack.enter_context(
            patch("email_analysis.ai_classifier.classify_email", ai_classifier)
        )
        stack.enter_context(
            patch("email_analysis.qr_code_analyzer.scan_attachments_for_qr", qr_scanner)
        )
        yield
