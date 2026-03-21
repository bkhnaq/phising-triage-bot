import sys
import types
from pathlib import Path

from fastapi.testclient import TestClient


def _client_with_auth(monkeypatch, api_key: str = "test-key"):
    from config import settings as app_settings
    from api import routes

    monkeypatch.setattr(app_settings, "API_PROTECTION_ENABLED", True)
    monkeypatch.setattr(app_settings, "API_KEY", api_key)
    monkeypatch.setattr(app_settings, "ENV", "prod")
    monkeypatch.setattr(routes, "API_PROTECTION_ENABLED", True)
    monkeypatch.setattr(routes, "API_KEY", api_key)
    monkeypatch.setattr(routes, "ENV", "prod")
    routes._rate_limit_buckets.clear()
    return TestClient(routes.app), routes


def test_upload_path_traversal_protection(monkeypatch, tmp_path: Path) -> None:
    from bot import telegram_handler

    monkeypatch.setattr(telegram_handler, "UPLOAD_DIR", str(tmp_path))

    path = telegram_handler._safe_upload_path("../../secret.eml", prefix="tg")

    assert path.parent == tmp_path.resolve()
    assert ".." not in path.name
    assert "secret.eml" in path.name


def test_analyze_file_cleans_up_temporary_upload(monkeypatch, tmp_path: Path) -> None:
    client, routes = _client_with_auth(monkeypatch)
    monkeypatch.setattr(routes, "UPLOAD_DIR", str(tmp_path))

    fake_pipeline_module = types.ModuleType("email_analysis.pipeline")

    class FakePipeline:
        def analyze_file(self, eml_path: str) -> dict:
            assert Path(eml_path).exists()
            return {
                "risk": {"score": 5, "verdict": "LOW"},
                "report": "ok",
                "email_data": {},
                "auth_results": {},
                "ai_verdict": {},
                "urls": [],
                "attachments": [],
            }

    setattr(fake_pipeline_module, "PhishingPipeline", FakePipeline)
    monkeypatch.setitem(sys.modules, "email_analysis.pipeline", fake_pipeline_module)

    response = client.post(
        "/analyze_file",
        headers={"X-API-Key": "test-key"},
        files={"file": ("mail.eml", b"From: a@b.com\n\nHello", "message/rfc822")},
    )

    assert response.status_code == 200
    assert list(tmp_path.glob("*")) == []


def test_split_message_keeps_markdown_fences_balanced() -> None:
    from bot.telegram_handler import _split_message

    long_code_block = "```python\n" + ("print('x')\n" * 800) + "```\n"
    text = f"Start\n\n{long_code_block}\nEnd"

    chunks = _split_message(text, max_len=500)

    assert len(chunks) > 1
    for chunk in chunks:
        assert chunk.count("```") % 2 == 0


def test_request_id_and_error_envelope_consistent(monkeypatch) -> None:
    client, _routes = _client_with_auth(monkeypatch)

    health = client.get("/health")
    assert health.status_code == 200
    assert "request_id" in health.json()
    assert "X-Request-ID" in health.headers

    unauthorized = client.post(
        "/analyze_email",
        headers={"X-API-Key": "wrong-key"},
        json={"email_raw": "From: a@b.com\n\nTest"},
    )
    payload = unauthorized.json()

    assert unauthorized.status_code == 401
    assert payload["success"] is False
    assert isinstance(payload.get("request_id"), str)
    assert set(payload["error"].keys()) >= {"code", "message"}


def test_rate_limit_returns_429(monkeypatch) -> None:
    client, routes = _client_with_auth(monkeypatch)

    monkeypatch.setattr(routes, "RATE_LIMIT_MAX_REQUESTS", 1)
    monkeypatch.setattr(routes, "RATE_LIMIT_WINDOW_SECONDS", 60)
    routes._rate_limit_buckets.clear()

    first = client.post(
        "/analyze_email",
        headers={"X-API-Key": "test-key"},
        json={},
    )
    second = client.post(
        "/analyze_email",
        headers={"X-API-Key": "test-key"},
        json={},
    )

    assert first.status_code == 422
    assert second.status_code == 429
    assert second.json()["error"]["code"] == "rate_limited"
