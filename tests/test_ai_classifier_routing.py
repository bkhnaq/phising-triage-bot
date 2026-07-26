from __future__ import annotations

import math

import pytest

from email_analysis import ai_classifier as ai

_RESULT_KEYS = {
    "verdict",
    "confidence",
    "reasons",
    "risk_score",
    "error",
    "provider",
    "model",
    "phishing_probability",
    "fallback_used",
}


def _result(
    verdict: str,
    *,
    provider: str = "local",
    error: str | None = None,
    probability: float | None = 0.5,
) -> dict[str, object]:
    return {
        "verdict": verdict,
        "confidence": 0.9,
        "reasons": [f"{provider} reason"],
        "risk_score": (
            25 if verdict == "phishing" else 10 if verdict == "suspicious" else 0
        ),
        "error": error,
        "provider": provider,
        "model": "local-model" if provider == "local" else "groq-model",
        "phishing_probability": probability,
        "fallback_used": False,
    }


@pytest.fixture(autouse=True)
def _online_local_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ai, "LOCAL_AI_ENABLED", True)
    monkeypatch.setattr(ai, "AI_GROQ_FALLBACK", True)
    monkeypatch.setattr(ai, "OFFLINE_MODE", False)


@pytest.mark.parametrize("verdict", ["legitimate", "phishing"])
def test_confident_local_result_does_not_call_groq(
    monkeypatch: pytest.MonkeyPatch, verdict: str
) -> None:
    monkeypatch.setattr(
        ai,
        "classify_email_local",
        lambda _email, _urls: _result(verdict),
    )

    def forbidden_groq(*_args: object) -> dict[str, object]:
        raise AssertionError("Groq must not be called for confident local results")

    monkeypatch.setattr(ai, "_classify_with_groq", forbidden_groq)

    routed = ai.classify_email({"subject": "hello"})

    assert routed["provider"] == "local"
    assert routed["verdict"] == verdict
    assert set(routed) == _RESULT_KEYS


def test_uncertain_local_result_falls_back_to_groq(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        ai,
        "classify_email_local",
        lambda _email, _urls: _result("suspicious"),
    )
    monkeypatch.setattr(
        ai,
        "_classify_with_groq",
        lambda *_args: _result("phishing", provider="groq", probability=None),
    )

    routed = ai.classify_email({"subject": "hello"})

    assert routed["provider"] == "groq"
    assert routed["verdict"] == "phishing"
    assert routed["fallback_used"] is True
    assert routed["phishing_probability"] is None


def test_failed_groq_fallback_preserves_uncertain_local_verdict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        ai,
        "classify_email_local",
        lambda _email, _urls: _result("suspicious", probability=0.55),
    )
    monkeypatch.setattr(
        ai,
        "_classify_with_groq",
        lambda *_args: _result(
            "unknown",
            provider="groq",
            error="API request failed",
            probability=None,
        ),
    )

    routed = ai.classify_email({"subject": "hello"})

    assert routed["provider"] == "local"
    assert routed["verdict"] == "suspicious"
    assert routed["phishing_probability"] == 0.55
    assert routed["fallback_used"] is True
    assert routed["error"] == "Groq fallback failed: API request failed"


def test_fallback_disabled_returns_uncertain_local_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ai, "AI_GROQ_FALLBACK", False)
    monkeypatch.setattr(
        ai,
        "classify_email_local",
        lambda _email, _urls: _result("suspicious"),
    )

    def forbidden_groq(*_args: object) -> dict[str, object]:
        raise AssertionError("fallback is disabled")

    monkeypatch.setattr(ai, "_classify_with_groq", forbidden_groq)

    assert ai.classify_email({})["provider"] == "local"


def test_offline_uncertain_local_result_never_calls_groq(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ai, "OFFLINE_MODE", True)
    monkeypatch.setattr(
        ai,
        "classify_email_local",
        lambda _email, _urls: _result("suspicious"),
    )

    def forbidden_groq(*_args: object) -> dict[str, object]:
        raise AssertionError("offline mode must never call Groq")

    monkeypatch.setattr(ai, "_classify_with_groq", forbidden_groq)

    routed = ai.classify_email({})

    assert routed["verdict"] == "suspicious"
    assert routed["provider"] == "local"


def test_local_unavailable_uses_existing_groq_path_even_if_fallback_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ai, "AI_GROQ_FALLBACK", False)
    monkeypatch.setattr(
        ai,
        "classify_email_local",
        lambda _email, _urls: _result(
            "unknown", error="local model artifact not found", probability=None
        ),
    )
    monkeypatch.setattr(
        ai,
        "_classify_with_groq",
        lambda *_args: _result("legitimate", provider="groq", probability=None),
    )

    routed = ai.classify_email({})

    assert routed["verdict"] == "legitimate"
    assert routed["provider"] == "groq"
    assert routed["fallback_used"] is True


def test_offline_and_local_unavailable_returns_without_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ai, "OFFLINE_MODE", True)
    monkeypatch.setattr(
        ai,
        "classify_email_local",
        lambda _email, _urls: _result(
            "unknown", error="local model artifact not found", probability=None
        ),
    )

    def forbidden_groq(*_args: object) -> dict[str, object]:
        raise AssertionError("offline mode must never call Groq")

    monkeypatch.setattr(ai, "_classify_with_groq", forbidden_groq)

    routed = ai.classify_email({})

    assert routed["verdict"] == "unknown"
    assert routed["provider"] == "local"
    assert routed["error"] == "local model artifact not found"


def test_disabled_local_ai_keeps_groq_only_behavior(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ai, "LOCAL_AI_ENABLED", False)

    def forbidden_local(*_args: object) -> dict[str, object]:
        raise AssertionError("disabled local AI must not be called")

    monkeypatch.setattr(ai, "classify_email_local", forbidden_local)
    monkeypatch.setattr(
        ai,
        "_classify_with_groq",
        lambda *_args: _result("legitimate", provider="groq", probability=None),
    )

    routed = ai.classify_email({})

    assert routed["verdict"] == "legitimate"
    assert routed["provider"] == "groq"
    assert routed["fallback_used"] is False


def test_disabled_local_ai_in_offline_mode_returns_complete_unknown_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ai, "LOCAL_AI_ENABLED", False)
    monkeypatch.setattr(ai, "OFFLINE_MODE", True)

    routed = ai.classify_email({})

    assert set(routed) == _RESULT_KEYS
    assert routed["verdict"] == "unknown"
    assert routed["provider"] == "none"
    assert routed["error"] == "offline mode enabled"


def test_groq_result_preserves_old_fields_and_adds_provider_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ai, "GROQ_API_KEY", "configured")

    class Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {
                "choices": [
                    {
                        "message": {
                            "content": (
                                '{"verdict":"phishing","confidence":0.95,'
                                '"reasons":["credential link"]}'
                            )
                        }
                    }
                ]
            }

    monkeypatch.setattr(ai.requests, "post", lambda *_args, **_kwargs: Response())

    result = ai._classify_with_groq({}, [], [])

    assert set(result) == _RESULT_KEYS
    assert result["verdict"] == "phishing"
    assert result["confidence"] == 0.95
    assert result["risk_score"] == 25
    assert result["provider"] == "groq"
    assert result["model"] == ai.GROQ_MODEL
    assert result["phishing_probability"] is None


@pytest.mark.parametrize("value", ["nan", "inf", "-inf", float("nan")])
def test_non_finite_groq_confidence_is_safely_zero(value: object) -> None:
    confidence = ai._safe_confidence(value)

    assert confidence == 0.0
    assert math.isfinite(confidence)
