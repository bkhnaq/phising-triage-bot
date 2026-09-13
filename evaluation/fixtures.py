"""Deterministic provider and model fixtures used by the evaluation runner."""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
from unittest.mock import patch
from urllib.parse import urlparse


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
    """Inject deterministic AI/QR fixtures for one intrinsic-analysis sample."""
    fixtures = sample.get("fixtures") or {}
    ai_kind = str(fixtures.get("ai", "legitimate"))
    qr_url = str(fixtures.get("qr_url", ""))

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
        stack.enter_context(
            patch("email_analysis.ai_classifier.classify_email", ai_classifier)
        )
        stack.enter_context(
            patch("email_analysis.qr_code_analyzer.scan_attachments_for_qr", qr_scanner)
        )
        yield
