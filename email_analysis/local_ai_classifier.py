"""Safe, optional local inference for the bilingual phishing classifier."""

from __future__ import annotations

import json
import logging
import math
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from config import settings
from ml.contracts import DecisionThresholds
from ml.promote import validate_artifact
from ml.text import format_email_text

logger = logging.getLogger(__name__)

LOCAL_AI_ENABLED = getattr(settings, "LOCAL_AI_ENABLED", True)
LOCAL_AI_MODEL_DIR = getattr(
    settings, "LOCAL_AI_MODEL_DIR", "artifacts/models/phishing-mmbert"
)
LOCAL_AI_MAX_LENGTH = getattr(settings, "LOCAL_AI_MAX_LENGTH", 1024)

_LOAD_LOCK = threading.Lock()
_INFERENCE_LOCK = threading.Lock()


class _ProbabilityBackend(Protocol):
    def predict_probability(self, text: str) -> float: ...


@dataclass(frozen=True, slots=True)
class _LoadedState:
    identity: tuple[str, int, int]
    backend: _ProbabilityBackend
    thresholds: DecisionThresholds
    model_id: str


_loaded_state: _LoadedState | None = None


def _base_result(error: str | None = None) -> dict[str, object]:
    return {
        "verdict": "unknown",
        "confidence": 0.0,
        "reasons": [],
        "risk_score": 0,
        "error": error,
        "provider": "local",
        "model": None,
        "phishing_probability": None,
        "fallback_used": False,
    }


def reset_local_model_cache() -> None:
    """Release this process's cached backend so an artifact can be reloaded."""
    global _loaded_state
    with _LOAD_LOCK:
        _loaded_state = None


class _TransformersBackend:
    def __init__(self, directory: Path, max_length: int) -> None:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self._torch = torch
        self._max_length = max_length
        self._device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self._tokenizer = AutoTokenizer.from_pretrained(
            str(directory),
            local_files_only=True,
            trust_remote_code=False,
        )
        self._model = AutoModelForSequenceClassification.from_pretrained(
            str(directory),
            local_files_only=True,
            trust_remote_code=False,
            use_safetensors=True,
        )
        self._model.to(self._device)
        self._model.eval()

    def predict_probability(self, text: str) -> float:
        encoded = self._tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=self._max_length,
            padding=False,
        )
        encoded = {name: tensor.to(self._device) for name, tensor in encoded.items()}
        with self._torch.inference_mode():
            logits = self._model(**encoded).logits
        if logits.shape[-1] == 1:
            return float(self._torch.sigmoid(logits[0, 0]).item())
        if logits.shape[-1] == 2:
            return float(self._torch.softmax(logits, dim=-1)[0, 1].item())
        raise ValueError("local model must emit one or two logits")


def _load_transformers_backend(directory: Path, max_length: int) -> _ProbabilityBackend:
    return _TransformersBackend(directory, max_length)


def _identity(directory: Path) -> tuple[str, int, int]:
    manifest = directory / "artifact-manifest.json"
    stat = manifest.stat()
    return (str(directory.resolve()), stat.st_size, stat.st_mtime_ns)


def _load_state(directory: Path, max_length: int) -> _LoadedState:
    global _loaded_state
    identity = _identity(directory)
    with _LOAD_LOCK:
        if _loaded_state is not None and _loaded_state.identity == identity:
            return _loaded_state
        manifest = validate_artifact(directory)
        thresholds_payload = json.loads(
            (directory / "thresholds.json").read_text(encoding="utf-8")
        )
        if not isinstance(thresholds_payload, dict):
            raise ValueError("threshold artifact must be an object")
        state = _LoadedState(
            identity=identity,
            backend=_load_transformers_backend(directory, max_length),
            thresholds=DecisionThresholds.from_mapping(thresholds_payload),
            model_id=manifest.model_id,
        )
        _loaded_state = state
        return state


def _success_result(probability: float, state: _LoadedState) -> dict[str, object]:
    probability = float(probability)
    if not math.isfinite(probability):
        raise ValueError("model probability must be finite")
    probability = max(0.0, min(1.0, probability))
    verdict = state.thresholds.verdict(probability)
    confidence = (
        probability
        if verdict == "phishing"
        else (
            1.0 - probability
            if verdict == "legitimate"
            else max(probability, 1.0 - probability)
        )
    )
    risk_score = 25 if verdict == "phishing" else 10 if verdict == "suspicious" else 0
    return {
        "verdict": verdict,
        "confidence": confidence,
        "reasons": [
            "Local bilingual classifier phishing probability: " f"{probability:.1%}"
        ],
        "risk_score": risk_score,
        "error": None,
        "provider": "local",
        "model": state.model_id,
        "phishing_probability": probability,
        "fallback_used": False,
    }


def classify_email_local(
    email_data: dict,
    urls: list[dict] | None = None,
) -> dict[str, object]:
    """Classify locally or return a stable, sanitized unavailable result."""
    if not LOCAL_AI_ENABLED:
        return _base_result("local AI disabled")
    directory = Path(LOCAL_AI_MODEL_DIR)
    if not directory.is_dir():
        return _base_result("local model artifact not found")
    if (
        isinstance(LOCAL_AI_MAX_LENGTH, bool)
        or not isinstance(LOCAL_AI_MAX_LENGTH, int)
        or LOCAL_AI_MAX_LENGTH <= 0
    ):
        return _base_result("local AI configuration invalid")

    try:
        state = _load_state(directory, LOCAL_AI_MAX_LENGTH)
    except ImportError:
        logger.info("Local AI unavailable: optional dependencies are not installed")
        return _base_result("local AI dependencies unavailable")
    except (json.JSONDecodeError, ValueError) as exc:
        logger.warning("Local AI artifact validation failed (%s)", type(exc).__name__)
        return _base_result("local model artifact invalid")
    except (OSError, RuntimeError) as exc:
        logger.warning("Local AI model loading failed (%s)", type(exc).__name__)
        return _base_result("local model load failed")

    try:
        text = format_email_text(
            email_data,
            urls,
            max_chars=max(4000, LOCAL_AI_MAX_LENGTH * 12),
        )
        with _INFERENCE_LOCK:
            probability = state.backend.predict_probability(text)
        return _success_result(probability, state)
    except (
        ArithmeticError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
    ) as exc:
        logger.warning("Local AI inference failed (%s)", type(exc).__name__)
        result = _base_result("local model inference failed")
        result["model"] = state.model_id
        return result
