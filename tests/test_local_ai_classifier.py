from __future__ import annotations

import json
from pathlib import Path

import pytest

from email_analysis import local_ai_classifier as local
from ml.promote import write_artifact_manifest


def _artifact(directory: Path, *, low: float = 0.2, high: float = 0.8) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "config.json").write_text(
        json.dumps(
            {
                "model_type": "modernbert",
                "num_labels": 2,
                "id2label": {"0": "legitimate", "1": "phishing"},
            }
        ),
        encoding="utf-8",
    )
    (directory / "tokenizer.json").write_text("{}", encoding="utf-8")
    (directory / "tokenizer_config.json").write_text("{}", encoding="utf-8")
    (directory / "model.safetensors").write_bytes(b"fake")
    (directory / "thresholds.json").write_text(
        json.dumps({"low": low, "high": high}), encoding="utf-8"
    )
    (directory / "metrics.json").write_text(
        json.dumps(
            {
                "test": {
                    "english": {
                        "phishing_recall": 1.0,
                        "false_positive_rate": 0.0,
                        "macro_f1": 1.0,
                    },
                    "synthetic_vietnamese": {"phishing_recall": 1.0},
                }
            }
        ),
        encoding="utf-8",
    )
    (directory / "dataset-manifest.json").write_text(
        json.dumps({"checksums": {"train.jsonl": "a" * 64}}),
        encoding="utf-8",
    )
    (directory / "training-metadata.json").write_text(
        json.dumps(
            {
                "config": {
                    "model_id": "jhu-clsp/mmBERT-small",
                    "model_revision": (
                        "abc32620dd4f6ab06f5fbe905dc25f310618e09f"
                    ),
                }
            }
        ),
        encoding="utf-8",
    )
    write_artifact_manifest(directory)
    return directory


class _Backend:
    def __init__(self, probability: float) -> None:
        self.probability = probability

    def predict_probability(self, text: str) -> float:
        return (
            self.probability
            if "Subject:" in text and "Body:" in text
            else 1.0 - self.probability
        )


class _CapturingBackend(_Backend):
    def __init__(self, probability: float) -> None:
        super().__init__(probability)
        self.text: str | None = None

    def predict_probability(self, text: str) -> float:
        self.text = text
        return super().predict_probability(text)


@pytest.fixture(autouse=True)
def _clean_local_cache() -> None:
    local.reset_local_model_cache()
    yield
    local.reset_local_model_cache()


def test_runtime_default_context_matches_calibrated_training_context() -> None:
    assert local.LOCAL_AI_MAX_LENGTH == 512


def test_disabled_local_ai_returns_stable_result(monkeypatch) -> None:
    monkeypatch.setattr(local, "LOCAL_AI_ENABLED", False)

    result = local.classify_email_local({"subject": "Hello", "body_text": "World"})

    assert result == {
        "verdict": "unknown",
        "confidence": 0.0,
        "reasons": [],
        "risk_score": 0,
        "error": "local AI disabled",
        "provider": "local",
        "model": None,
        "phishing_probability": None,
        "fallback_used": False,
    }


def test_missing_artifact_returns_stable_unavailable_result(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(local, "LOCAL_AI_ENABLED", True)
    monkeypatch.setattr(local, "LOCAL_AI_MODEL_DIR", str(tmp_path / "missing"))

    result = local.classify_email_local({"subject": "Hello", "body_text": "World"})

    assert result["verdict"] == "unknown"
    assert result["provider"] == "local"
    assert result["error"] == "local model artifact not found"
    assert result["model"] is None


@pytest.mark.parametrize(
    ("probability", "verdict", "risk_score"),
    [
        (0.199, "legitimate", 0),
        (0.2, "suspicious", 10),
        (0.799, "suspicious", 10),
        (0.8, "phishing", 25),
    ],
)
def test_local_probability_maps_through_artifact_thresholds(
    monkeypatch,
    tmp_path: Path,
    probability: float,
    verdict: str,
    risk_score: int,
) -> None:
    artifact = _artifact(tmp_path / "artifact")
    monkeypatch.setattr(local, "LOCAL_AI_ENABLED", True)
    monkeypatch.setattr(local, "LOCAL_AI_MODEL_DIR", str(artifact))
    monkeypatch.setattr(
        local,
        "_load_transformers_backend",
        lambda _directory, _max_length: _Backend(probability),
    )

    result = local.classify_email_local(
        {"subject": "Verify account", "body_text": "Open the portal."},
        [{"url": "https://portal.example.test/login"}],
    )

    assert result["verdict"] == verdict
    assert result["risk_score"] == risk_score
    assert result["provider"] == "local"
    assert result["model"] == "jhu-clsp/mmBERT-small"
    assert result["phishing_probability"] == pytest.approx(probability)
    assert result["error"] is None


def test_loaded_model_is_reused_for_later_inference(
    monkeypatch, tmp_path: Path
) -> None:
    artifact = _artifact(tmp_path / "artifact")
    monkeypatch.setattr(local, "LOCAL_AI_ENABLED", True)
    monkeypatch.setattr(local, "LOCAL_AI_MODEL_DIR", str(artifact))
    backend = _Backend(0.9)
    loaded = False

    def load_once(_directory: Path, _max_length: int) -> _Backend:
        nonlocal loaded
        if loaded:
            raise AssertionError("model loaded twice")
        loaded = True
        return backend

    monkeypatch.setattr(local, "_load_transformers_backend", load_once)

    first = local.classify_email_local({"subject": "One", "body_text": "Body"})
    second = local.classify_email_local({"subject": "Two", "body_text": "Body"})

    assert first["verdict"] == second["verdict"] == "phishing"


def test_runtime_uses_training_balanced_context_for_long_email(
    monkeypatch, tmp_path: Path
) -> None:
    artifact = _artifact(tmp_path / "artifact")
    backend = _CapturingBackend(0.9)
    monkeypatch.setattr(local, "LOCAL_AI_ENABLED", True)
    monkeypatch.setattr(local, "LOCAL_AI_MODEL_DIR", str(artifact))
    monkeypatch.setattr(local, "LOCAL_AI_MAX_LENGTH", 512)
    monkeypatch.setattr(
        local,
        "_load_transformers_backend",
        lambda _directory, _max_length: backend,
    )
    body = "SAFE-HEAD " + ("middle " * 2_000) + " PHISHING-TAIL"

    result = local.classify_email_local({"subject": "Notice", "body_text": body})

    assert result["verdict"] == "phishing"
    assert backend.text is not None
    assert len(backend.text) == 2_048
    assert backend.text.startswith("Subject: Notice")
    assert backend.text.endswith("PHISHING-TAIL")
    assert "[...]" in backend.text


def test_missing_optional_dependencies_do_not_escape_runtime(
    monkeypatch, tmp_path: Path
) -> None:
    artifact = _artifact(tmp_path / "artifact")
    monkeypatch.setattr(local, "LOCAL_AI_ENABLED", True)
    monkeypatch.setattr(local, "LOCAL_AI_MODEL_DIR", str(artifact))

    def unavailable(_directory: Path, _max_length: int) -> _Backend:
        raise ImportError("torch is missing")

    monkeypatch.setattr(local, "_load_transformers_backend", unavailable)

    result = local.classify_email_local({"subject": "Hello", "body_text": "World"})

    assert result["verdict"] == "unknown"
    assert result["error"] == "local AI dependencies unavailable"
    assert "torch is missing" not in str(result)


def test_invalid_artifact_and_inference_failure_are_sanitized(
    monkeypatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    artifact = _artifact(tmp_path / "artifact")
    monkeypatch.setattr(local, "LOCAL_AI_ENABLED", True)
    monkeypatch.setattr(local, "LOCAL_AI_MODEL_DIR", str(artifact))
    (artifact / "thresholds.json").write_text("{}", encoding="utf-8")

    invalid = local.classify_email_local({"subject": "Hello", "body_text": "World"})

    assert invalid["error"] == "local model artifact invalid"
    assert "threshold" not in str(invalid)

    artifact = _artifact(tmp_path / "artifact")
    local.reset_local_model_cache()

    class FailingBackend:
        def predict_probability(self, _text: str) -> float:
            raise RuntimeError("secret inference details")

    monkeypatch.setattr(
        local,
        "_load_transformers_backend",
        lambda _directory, _max_length: FailingBackend(),
    )
    failed = local.classify_email_local({"subject": "Hello", "body_text": "World"})

    assert failed["error"] == "local model inference failed"
    assert "secret inference details" not in str(failed)
    assert "secret inference details" not in caplog.text


def test_oversized_metadata_cannot_escape_as_formatter_exception(
    monkeypatch, tmp_path: Path
) -> None:
    artifact = _artifact(tmp_path / "artifact")
    monkeypatch.setattr(local, "LOCAL_AI_ENABLED", True)
    monkeypatch.setattr(local, "LOCAL_AI_MODEL_DIR", str(artifact))
    monkeypatch.setattr(
        local,
        "_load_transformers_backend",
        lambda _directory, _max_length: _Backend(0.9),
    )

    result = local.classify_email_local({"subject": "x" * 20_000, "body_text": "body"})

    assert result["verdict"] == "unknown"
    assert result["error"] == "local model inference failed"
