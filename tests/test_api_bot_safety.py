import asyncio
from collections import deque
import sys
import time
import types
import importlib
import json
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

TestClient = importlib.import_module("starlette.testclient").TestClient
Request = importlib.import_module("starlette.requests").Request


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


class RecordingUpload:
    def __init__(self, content: bytes, filename: str = "mail.eml") -> None:
        self.filename = filename
        self.read_sizes: list[int] = []
        self.remaining = content
        self.closed = False

    async def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        if not self.remaining:
            return b""
        if size == -1:
            chunk, self.remaining = self.remaining, b""
            return chunk
        chunk, self.remaining = self.remaining[:size], self.remaining[size:]
        return chunk

    async def close(self) -> None:
        self.closed = True


def test_upload_path_traversal_protection(monkeypatch, tmp_path: Path) -> None:
    from bot import telegram_handler

    monkeypatch.setattr(telegram_handler, "UPLOAD_DIR", str(tmp_path))

    path = telegram_handler._safe_upload_path("../../secret.eml", prefix="tg")

    assert path.parent == tmp_path.resolve()
    assert ".." not in path.name
    assert "secret.eml" in path.name


def test_downloaded_file_size_is_checked(tmp_path: Path) -> None:
    from bot.telegram_handler import _validate_downloaded_size

    path = tmp_path / "mail.eml"
    path.write_bytes(b"123456")

    with pytest.raises(ValueError, match="too large"):
        _validate_downloaded_size(path, 5)


def test_analysis_keeps_event_loop_responsive(monkeypatch, tmp_path: Path) -> None:
    from bot import telegram_handler as handler

    class FakeTelegramFile:
        async def download_to_drive(self, path: str) -> None:
            Path(path).write_bytes(b"From: a@example.test\n\nHello")

    class FakeDocument:
        file_name = "mail.eml"
        file_size = 32

        async def get_file(self) -> FakeTelegramFile:
            return FakeTelegramFile()

    class FakeMessage:
        document = FakeDocument()

        def __init__(self) -> None:
            self.replies: list[str] = []

        async def reply_text(self, text: str, **_kwargs) -> None:
            self.replies.append(text)

    message = FakeMessage()
    update = SimpleNamespace(
        message=message,
        effective_chat=SimpleNamespace(id=42),
    )
    path = tmp_path / "mail.eml"
    events: list[str] = []

    def slow_analysis(_path: str, analysis_id: str) -> str:
        events.append("analysis-start")
        time.sleep(0.15)
        events.append("analysis-end")
        return "report"

    monkeypatch.setattr(handler, "ALLOWED_CHAT_IDS", [])
    monkeypatch.setattr(handler, "_safe_upload_path", lambda *_args, **_kwargs: path)
    monkeypatch.setattr(handler, "_run_analysis", slow_analysis)

    async def scenario() -> None:
        analysis = asyncio.create_task(handler.handle_document(update, None))
        while "analysis-start" not in events:
            await asyncio.sleep(0)
        await asyncio.sleep(0.02)
        events.append("heartbeat")
        await analysis

    asyncio.run(scenario())

    assert events.index("heartbeat") < events.index("analysis-end")
    assert message.replies[-1] == "report"
    assert not path.exists()


def test_downloaded_oversize_is_rejected_before_analysis_and_cleaned(
    monkeypatch, tmp_path: Path
) -> None:
    from bot import telegram_handler as handler

    class FakeTelegramFile:
        async def download_to_drive(self, path: str) -> None:
            Path(path).write_bytes(b"123456")

    class FakeDocument:
        file_name = "mail.eml"
        file_size = 5

        async def get_file(self) -> FakeTelegramFile:
            return FakeTelegramFile()

    class FakeMessage:
        document = FakeDocument()

        def __init__(self) -> None:
            self.replies: list[str] = []

        async def reply_text(self, text: str, **_kwargs) -> None:
            self.replies.append(text)

    message = FakeMessage()
    update = SimpleNamespace(message=message, effective_chat=SimpleNamespace(id=42))
    path = tmp_path / "mail.eml"
    analysis_calls: list[str] = []

    def record_analysis(_path: str, analysis_id: str) -> str:
        analysis_calls.append(_path)
        return "report"

    monkeypatch.setattr(handler, "ALLOWED_CHAT_IDS", [])
    monkeypatch.setattr(handler, "MAX_UPLOAD_SIZE_BYTES", 5)
    monkeypatch.setattr(handler, "_safe_upload_path", lambda *_args, **_kwargs: path)
    monkeypatch.setattr(handler, "_run_analysis", record_analysis)

    asyncio.run(handler.handle_document(update, None))

    assert analysis_calls == []
    assert "File too large" in message.replies[-1]
    assert not path.exists()


def test_download_failure_is_sanitized_and_cleans_temporary_file(
    monkeypatch, tmp_path: Path
) -> None:
    from bot import telegram_handler as handler

    class FakeTelegramFile:
        async def download_to_drive(self, path: str) -> None:
            Path(path).write_bytes(b"partial")
            raise RuntimeError("sensitive-token")

    class FakeDocument:
        file_name = "mail.eml"
        file_size = 1

        async def get_file(self) -> FakeTelegramFile:
            return FakeTelegramFile()

    class FakeMessage:
        document = FakeDocument()

        def __init__(self) -> None:
            self.replies: list[str] = []

        async def reply_text(self, text: str, **_kwargs) -> None:
            self.replies.append(text)

    message = FakeMessage()
    update = SimpleNamespace(message=message, effective_chat=SimpleNamespace(id=42))
    path = tmp_path / "mail.eml"

    monkeypatch.setattr(handler, "ALLOWED_CHAT_IDS", [])
    monkeypatch.setattr(handler, "_safe_upload_path", lambda *_args, **_kwargs: path)

    asyncio.run(handler.handle_document(update, None))

    assert message.replies[-1] == "❌ Analysis failed. Check bot logs for details."
    assert "sensitive-token" not in message.replies[-1]
    assert not path.exists()


def test_get_file_failure_is_sanitized_and_cleans_temporary_file(
    monkeypatch, tmp_path: Path
) -> None:
    from bot import telegram_handler as handler

    class FakeDocument:
        file_name = "mail.eml"
        file_size = 1

        async def get_file(self) -> None:
            raise RuntimeError("sensitive-token")

    class FakeMessage:
        document = FakeDocument()

        def __init__(self) -> None:
            self.replies: list[str] = []

        async def reply_text(self, text: str, **_kwargs) -> None:
            self.replies.append(text)

    message = FakeMessage()
    update = SimpleNamespace(message=message, effective_chat=SimpleNamespace(id=42))
    path = tmp_path / "mail.eml"

    monkeypatch.setattr(handler, "ALLOWED_CHAT_IDS", [])
    monkeypatch.setattr(handler, "_safe_upload_path", lambda *_args, **_kwargs: path)

    asyncio.run(handler.handle_document(update, None))

    assert message.replies[-1] == "❌ Analysis failed. Check bot logs for details."
    assert "sensitive-token" not in message.replies[-1]
    assert not path.exists()


def test_analysis_value_error_is_sanitized_as_generic_failure(
    monkeypatch, tmp_path: Path
) -> None:
    from bot import telegram_handler as handler

    class FakeTelegramFile:
        async def download_to_drive(self, path: str) -> None:
            Path(path).write_bytes(b"message")

    class FakeDocument:
        file_name = "mail.eml"
        file_size = 1

        async def get_file(self) -> FakeTelegramFile:
            return FakeTelegramFile()

    class FakeMessage:
        document = FakeDocument()

        def __init__(self) -> None:
            self.replies: list[str] = []

        async def reply_text(self, text: str, **_kwargs) -> None:
            self.replies.append(text)

    def fail_analysis(_path: str, analysis_id: str) -> str:
        raise ValueError("sensitive-token")

    message = FakeMessage()
    update = SimpleNamespace(message=message, effective_chat=SimpleNamespace(id=42))
    path = tmp_path / "mail.eml"

    monkeypatch.setattr(handler, "ALLOWED_CHAT_IDS", [])
    monkeypatch.setattr(handler, "_safe_upload_path", lambda *_args, **_kwargs: path)
    monkeypatch.setattr(handler, "_run_analysis", fail_analysis)

    asyncio.run(handler.handle_document(update, None))

    assert message.replies[-1] == "❌ Analysis failed. Check bot logs for details."
    assert "sensitive-token" not in message.replies[-1]
    assert not path.exists()


def test_analyze_file_cleans_up_temporary_upload(monkeypatch, tmp_path: Path) -> None:
    client, routes = _client_with_auth(monkeypatch)
    monkeypatch.setattr(routes, "UPLOAD_DIR", str(tmp_path))

    fake_pipeline_module = types.ModuleType("email_analysis.pipeline")

    class FakePipeline:
        def __init__(self, *args, **kwargs):
            pass

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


def test_analyze_file_too_large_returns_413(monkeypatch, tmp_path: Path) -> None:
    client, routes = _client_with_auth(monkeypatch)
    monkeypatch.setattr(routes, "UPLOAD_DIR", str(tmp_path))
    monkeypatch.setattr(routes, "MAX_UPLOAD_SIZE_BYTES", 5)

    response = client.post(
        "/analyze_file",
        headers={"X-API-Key": "test-key"},
        files={"file": ("mail.eml", b"From: a@b.com\n\nHello", "message/rfc822")},
    )

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "http_error"
    assert list(tmp_path.glob("*")) == []


def test_analyze_file_streams_upload_and_cleans_up(monkeypatch, tmp_path: Path) -> None:
    client, routes = _client_with_auth(monkeypatch)
    client.close()
    monkeypatch.setattr(routes, "UPLOAD_DIR", str(tmp_path))
    monkeypatch.setattr(routes, "MAX_UPLOAD_SIZE_BYTES", 5)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/analyze_file",
        "headers": [],
    }
    upload = RecordingUpload(b"123456")

    with pytest.raises(routes.HTTPException) as caught:
        asyncio.run(routes.analyze_file(Request(scope), upload))

    assert caught.value.status_code == 413
    assert upload.read_sizes
    assert -1 not in upload.read_sizes
    assert upload.closed is True
    assert list(tmp_path.glob("*")) == []


def test_analyze_file_closes_upload_when_filename_is_invalid(monkeypatch) -> None:
    client, routes = _client_with_auth(monkeypatch)
    client.close()
    upload = RecordingUpload(b"", filename="mail.txt")
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/analyze_file",
        "headers": [],
    }

    with pytest.raises(routes.HTTPException) as caught:
        asyncio.run(routes.analyze_file(Request(scope), upload))

    assert caught.value.status_code == 400
    assert upload.read_sizes == []
    assert upload.closed is True


def test_analyze_file_closes_upload_when_path_creation_fails(monkeypatch) -> None:
    client, routes = _client_with_auth(monkeypatch)
    client.close()
    upload = RecordingUpload(b"")
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/analyze_file",
        "headers": [],
    }

    def reject_path(_filename: str, prefix: str) -> Path:
        assert prefix == "api"
        raise routes.HTTPException(status_code=400, detail="Invalid upload path")

    monkeypatch.setattr(routes, "_safe_upload_path", reject_path)

    with pytest.raises(routes.HTTPException) as caught:
        asyncio.run(routes.analyze_file(Request(scope), upload))

    assert caught.value.status_code == 400
    assert upload.read_sizes == []
    assert upload.closed is True


def test_analysis_failure_does_not_expose_exception_details(monkeypatch) -> None:
    client, _routes = _client_with_auth(monkeypatch)
    fake_pipeline_module = types.ModuleType("email_analysis.pipeline")

    class FailingPipeline:
        def __init__(self, *args, **kwargs):
            pass

        def analyze_raw(self, email_raw: str) -> dict:
            raise RuntimeError("sensitive-token")

    setattr(fake_pipeline_module, "PhishingPipeline", FailingPipeline)
    monkeypatch.setitem(sys.modules, "email_analysis.pipeline", fake_pipeline_module)

    response = client.post(
        "/analyze_email",
        headers={"X-API-Key": "test-key"},
        json={"email_raw": "From: a@b.com\n\nHello"},
    )

    assert response.status_code == 500
    assert response.json()["error"] == {
        "code": "http_error",
        "message": "Analysis failed",
    }
    assert "sensitive-token" not in response.text


def test_unhandled_exception_is_sanitized_and_logged(caplog) -> None:
    from api import routes

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/probe",
        "headers": [],
        "query_string": b"",
        "server": ("testserver", 80),
        "client": ("testclient", 50000),
        "scheme": "http",
        "root_path": "",
        "http_version": "1.1",
    }
    try:
        raise RuntimeError("sensitive-token")
    except RuntimeError as exc:
        error = exc

    with caplog.at_level(logging.ERROR, logger=routes.__name__):
        response = asyncio.run(
            routes.unhandled_exception_handler(Request(scope), error)
        )

    payload = json.loads(response.body)
    assert response.status_code == 500
    assert payload["error"] == {
        "code": "internal_error",
        "message": "Internal server error",
    }
    assert "sensitive-token" not in response.body.decode()
    assert caplog.records[-1].exc_info is not None
    assert caplog.records[-1].exc_info[1] is error
    assert error.__traceback__ is not None
    assert caplog.records[-1].exc_info[2] is error.__traceback__


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


def test_validation_error_does_not_echo_email_input(monkeypatch) -> None:
    client, _routes = _client_with_auth(monkeypatch)

    response = client.post(
        "/analyze_email",
        headers={"X-API-Key": "test-key"},
        json={"email_raw": {"secret": "do-not-echo"}},
    )

    assert response.status_code == 422
    assert "do-not-echo" not in response.text


def test_raw_email_model_rejects_content_over_character_limit() -> None:
    from api import routes

    with pytest.raises(ValidationError):
        routes.EmailAnalysisRequest(email_raw="x" * (routes.MAX_RAW_EMAIL_CHARS + 1))


def test_api_key_authentication_uses_constant_time_comparison(monkeypatch) -> None:
    client, routes = _client_with_auth(monkeypatch)
    compared: list[tuple[str, str]] = []

    def accept_with_recording(provided_key: str, configured_key: str) -> bool:
        compared.append((provided_key, configured_key))
        return True

    monkeypatch.setattr(routes.secrets, "compare_digest", accept_with_recording)

    response = client.post(
        "/analyze_email",
        headers={"X-API-Key": "different-key"},
        json={},
    )

    assert response.status_code == 422
    assert compared == [("different-key", "test-key")]


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


def test_rate_limit_state_is_bounded(monkeypatch) -> None:
    client, routes = _client_with_auth(monkeypatch)
    client.close()
    monkeypatch.setattr(routes, "RATE_LIMIT_MAX_CLIENTS", 2)
    routes._rate_limit_buckets.update(
        {
            "old-a": deque([0.0]),
            "old-b": deque([0.0]),
            "old-c": deque([0.0]),
        }
    )

    routes._prune_rate_limit_buckets(1_000.0)

    assert len(routes._rate_limit_buckets) <= 2


def test_rate_limit_evicts_oldest_bucket_before_allocating_new_client(
    monkeypatch,
) -> None:
    client, routes = _client_with_auth(monkeypatch)
    client.close()
    monkeypatch.setattr(routes, "RATE_LIMIT_MAX_CLIENTS", 2)
    monkeypatch.setattr(routes, "RATE_LIMIT_WINDOW_SECONDS", 1_000)
    routes._rate_limit_buckets.update(
        {
            "oldest": deque([10.0]),
            "newer": deque([20.0]),
        }
    )

    assert routes._is_rate_limited("new-client", 30.0) is False

    assert set(routes._rate_limit_buckets) == {"newer", "new-client"}
