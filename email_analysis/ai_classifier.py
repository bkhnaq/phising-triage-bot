"""
AI Phishing Classifier Module
------------------------------
Uses Groq API to classify an email as phishing or legitimate,
complementing the existing rule-based detections.

The classifier sends a structured prompt containing email metadata, body
excerpt, and extracted URLs to the LLM and parses a JSON verdict back.

Falls back gracefully when the API key is not configured — the rest of the
pipeline continues to work with rule-based scoring only.

Usage:
    from email_analysis.ai_classifier import classify_email
    result = classify_email(email_data, urls)
"""

import html
import json
import logging
import math
import re
from collections.abc import Mapping

import requests

from config.settings import (
    AI_GROQ_FALLBACK,
    GROQ_API_KEY,
    GROQ_MODEL,
    LOCAL_AI_ENABLED,
    OFFLINE_MODE,
)
from email_analysis.local_ai_classifier import classify_email_local

logger = logging.getLogger(__name__)

# Groq API configuration
_GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
_TIMEOUT = 30
_MAX_BODY_CHARS = 2000  # Truncate body to keep token usage low
_MAX_URLS = 5
_ALLOWED_VERDICTS = {"phishing", "suspicious", "legitimate"}
_EMAIL_PATTERN = re.compile(
    r"(?P<local>[A-Za-z0-9._%+-]+)@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)

_SYSTEM_PROMPT = """
You are a senior SOC email security analyst.

Analyse the provided email data and determine whether the email is phishing.

Consider the following signals:

• Sender spoofing
• Brand impersonation
• Suspicious URLs
• Credential harvesting language
• Urgency or threats
• Financial requests

Return ONLY valid JSON:

{
"verdict": "phishing" | "suspicious" | "legitimate",
"confidence": 0.0-1.0,
"reasons": ["clear technical explanation"]
}
"""


def _base_result(
    *,
    error: str | None = None,
    provider: str = "none",
    model: str | None = None,
) -> dict:
    return {
        "verdict": "unknown",
        "confidence": 0.0,
        "reasons": [],
        "risk_score": 0,
        "error": error,
        "provider": provider,
        "model": model,
        "phishing_probability": None,
        "fallback_used": False,
    }


def _normalize_result(result: dict) -> dict:
    normalized = _base_result()
    normalized.update({key: result[key] for key in normalized if key in result})
    return normalized


def classify_email(
    email_data: dict,
    urls: list[dict] | None = None,
    rule_findings: list[str] | None = None,
) -> dict:
    """Return one final AI verdict using local inference before Groq."""
    url_items = urls or []
    finding_items = rule_findings or []

    if not LOCAL_AI_ENABLED:
        if OFFLINE_MODE:
            return _base_result(error="offline mode enabled")
        return _normalize_result(
            _classify_with_groq(email_data, url_items, finding_items)
        )

    try:
        local_result = _normalize_result(classify_email_local(email_data, url_items))
    except (MemoryError, OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.warning("Local AI call failed (%s)", type(exc).__name__)
        local_result = _base_result(
            error="local model unavailable",
            provider="local",
        )

    local_verdict = str(local_result.get("verdict", "")).lower()
    if local_verdict in {"legitimate", "phishing"}:
        return local_result
    if OFFLINE_MODE:
        return local_result

    if local_verdict == "suspicious":
        if not AI_GROQ_FALLBACK:
            return local_result
        groq_result = _normalize_result(
            _classify_with_groq(email_data, url_items, finding_items)
        )
        if groq_result["error"] is None and groq_result["verdict"] in _ALLOWED_VERDICTS:
            groq_result["fallback_used"] = True
            return groq_result
        local_result["fallback_used"] = True
        fallback_error = str(groq_result.get("error") or "unknown error")
        local_result["error"] = f"Groq fallback failed: {fallback_error}"
        return local_result

    groq_result = _normalize_result(
        _classify_with_groq(email_data, url_items, finding_items)
    )
    groq_result["fallback_used"] = True
    return groq_result


def _classify_with_groq(
    email_data: dict,
    urls: list[dict],
    rule_findings: list[str],
) -> dict:
    """
    Send email content to an LLM for phishing classification.

    Args:
        email_data: Parsed email dict (from email_parser.parse_eml_file).
        urls:       Extracted URL dicts (from url_extractor.extract_urls).
        rule_findings: Optional rule-based findings from existing detectors.

    Returns:
        Dict with keys:
            verdict    – "phishing", "suspicious", or "legitimate"
            confidence – float 0.0–1.0
            reasons    – list of human-readable reason strings
            risk_score – int (25 if phishing, 10 if suspicious, 0 otherwise)
            error      – error string or None
    """
    result = _base_result(provider="groq", model=GROQ_MODEL)

    if not GROQ_API_KEY:
        result["error"] = "GROQ_API_KEY not configured"
        logger.info("AI classifier skipped: no API key")
        return result

    if OFFLINE_MODE:
        result["error"] = "offline mode enabled"
        logger.info("AI classifier skipped: offline mode enabled")
        return result

    # Build the analysis prompt
    user_content = _build_prompt(email_data, urls, rule_findings)

    try:
        resp = requests.post(
            _GROQ_URL,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {GROQ_API_KEY}",
            },
            json={
                "model": GROQ_MODEL,
                "messages": [
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": user_content},
                ],
                "temperature": 0.0,
                "max_tokens": 300,
            },
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()

        reply = _extract_groq_reply(resp.json())

        parsed = _parse_llm_response(reply)

        verdict = str(parsed.get("verdict", "")).strip().lower()
        if verdict not in _ALLOWED_VERDICTS:
            result["error"] = f"Unexpected verdict value: {verdict or 'missing'}"
            verdict = "unknown"

        result["verdict"] = verdict
        result["confidence"] = _safe_confidence(parsed.get("confidence", 0.0))

        raw_reasons = parsed.get("reasons", [])
        if isinstance(raw_reasons, list):
            result["reasons"] = [str(r).strip() for r in raw_reasons if str(r).strip()]
        else:
            result["reasons"] = []

        # Map verdict → risk score
        if result["verdict"] == "phishing":
            result["risk_score"] = 25
        elif result["verdict"] == "suspicious":
            result["risk_score"] = 10

        logger.info(
            "AI classifier: %s (confidence=%.2f, score=%d)",
            result["verdict"],
            result["confidence"],
            result["risk_score"],
        )

    except requests.Timeout as exc:
        result["error"] = "API timeout"
        logger.error("AI classifier timeout (%s)", type(exc).__name__)
    except requests.RequestException as exc:
        result["error"] = "API request failed"
        logger.error("AI classifier request failed (%s)", type(exc).__name__)
    except (TypeError, ValueError, KeyError, IndexError, json.JSONDecodeError) as exc:
        result["error"] = "Response parse error"
        logger.error("AI classifier parse error (%s)", type(exc).__name__)

    return result


def _build_prompt(email_data: dict, urls: list[dict], rule_findings: list[str]) -> str:
    """Build the user prompt with metadata, rule findings, and body excerpt."""
    body = email_data.get("body_text") or email_data.get("body_html") or ""
    body = _strip_html(body)
    body = mask_email(body)

    # Truncate to limit tokens
    if len(body) > _MAX_BODY_CHARS:
        body = body[:_MAX_BODY_CHARS] + "\n[truncated]"

    # Keep only a small URL sample to avoid oversized prompts
    limited_urls = urls[:_MAX_URLS]
    url_items = [
        mask_email(str(u.get("url", ""))) for u in limited_urls if u.get("url")
    ]
    if url_items:
        url_list = "\n".join(f"  - {u}" for u in url_items)
        if len(urls) > _MAX_URLS:
            url_list += f"\n  - ... ({len(urls) - _MAX_URLS} more URL(s) omitted)"
    else:
        url_list = "  (none)"

    findings_items = [
        mask_email(str(f).strip()) for f in rule_findings if str(f).strip()
    ]
    findings_list = (
        "\n".join(f"  - {f}" for f in findings_items) if findings_items else "  (none)"
    )

    return (
        f"Subject: {mask_email(str(email_data.get('subject', 'N/A')))}\n"
        f"From: {mask_email(str(email_data.get('from', 'N/A')))}\n"
        f"To: {mask_email(str(email_data.get('to', 'N/A')))}\n"
        f"Date: {str(email_data.get('date', 'N/A'))}\n\n"
        f"URLs found:\n{url_list}\n\n"
        f"Rule-based findings:\n{findings_list}\n\n"
        f"Body:\n{body}"
    )


def mask_email(address: str) -> str:
    """Mask email addresses in a string to reduce PII exposure."""
    if not address:
        return ""

    def _repl(match: re.Match[str]) -> str:
        return f"{match.group('local')}@***"

    return _EMAIL_PATTERN.sub(_repl, address)


def _strip_html(text: str) -> str:
    """Remove simple HTML tags and normalize whitespace."""
    if not text:
        return ""
    cleaned = re.sub(r"<[^>]+>", " ", text)
    cleaned = html.unescape(cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip()


def _safe_confidence(value: object) -> float:
    """Convert confidence to float and clamp it to [0.0, 1.0]."""
    if not isinstance(value, (int, float, str)):
        return 0.0

    try:
        conf = float(value)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(conf):
        return 0.0
    if conf < 0.0:
        return 0.0
    if conf > 1.0:
        return 1.0
    return conf


def _extract_groq_reply(data: object) -> str:
    """Validate the upstream response shape before extracting message text."""
    if not isinstance(data, Mapping):
        raise ValueError("Groq response must be an object")
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ValueError("Groq response choices must be a non-empty list")
    choice = choices[0]
    if not isinstance(choice, Mapping):
        raise ValueError("Groq response choice must be an object")
    message = choice.get("message")
    if not isinstance(message, Mapping):
        raise ValueError("Groq response message must be an object")
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise ValueError("Groq response content must be a non-empty string")
    return content.strip()


def _parse_llm_response(text: str) -> dict:
    """
    Parse the LLM response, extracting JSON even if wrapped in markdown or text.

    Returns:
        Parsed dict with verdict, confidence, and reasons.
    """
    # Strip markdown fences if present
    cleaned = re.sub(r"^```(?:json)?\s*", "", text, flags=re.MULTILINE)
    cleaned = re.sub(r"\s*```\s*$", "", cleaned, flags=re.MULTILINE)

    # Try direct JSON parse first
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, Mapping):
        return dict(parsed)
    if parsed is not None:
        raise ValueError("LLM response JSON must be an object")

    # LLM may wrap JSON in explanatory text — extract the JSON object
    json_match = re.search(r"\{[^{}]*\"verdict\"[^{}]*\}", cleaned, re.DOTALL)
    if json_match:
        parsed = json.loads(json_match.group(0))
        if isinstance(parsed, Mapping):
            return dict(parsed)
        raise ValueError("LLM response JSON must be an object")

    # Fallback: try to find any {...} block
    brace_match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if brace_match:
        parsed = json.loads(brace_match.group(0))
        if isinstance(parsed, Mapping):
            return dict(parsed)
        raise ValueError("LLM response JSON must be an object")

    raise ValueError("No valid JSON found in response")
