import asyncio
import json


def test_streamed_body_over_limit_returns_413() -> None:
    from api.body_limit import RequestBodyLimitMiddleware

    sent: list[dict] = []
    incoming = [
        {"type": "http.request", "body": b"123", "more_body": True},
        {"type": "http.request", "body": b"456", "more_body": False},
    ]

    async def receive() -> dict:
        return incoming.pop(0)

    async def send(message: dict) -> None:
        sent.append(message)

    async def downstream(_scope, wrapped_receive, downstream_send) -> None:
        while (message := await wrapped_receive()).get("more_body", False):
            pass
        await downstream_send(
            {"type": "http.response.start", "status": 204, "headers": []}
        )
        await downstream_send({"type": "http.response.body", "body": b""})

    middleware = RequestBodyLimitMiddleware(downstream, max_body_size=5)
    scope = {"type": "http", "method": "POST", "path": "/", "headers": []}

    asyncio.run(middleware(scope, receive, send))

    assert sent[0]["status"] == 413
    payload = json.loads(sent[1]["body"])
    assert payload["success"] is False
    assert isinstance(payload["request_id"], str)
    assert set(payload["error"]) >= {"code", "message"}


def test_declared_body_over_limit_short_circuits() -> None:
    from api.body_limit import RequestBodyLimitMiddleware

    sent: list[dict] = []
    called = False

    async def receive() -> dict:
        raise AssertionError("body must not be read")

    async def send(message: dict) -> None:
        sent.append(message)

    async def downstream(_scope, _receive, _send) -> None:
        nonlocal called
        called = True

    middleware = RequestBodyLimitMiddleware(downstream, max_body_size=5)
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "headers": [(b"content-length", b"6")],
    }

    asyncio.run(middleware(scope, receive, send))

    assert sent[0]["status"] == 413
    assert called is False


def test_over_limit_body_discards_buffered_downstream_response() -> None:
    from api.body_limit import RequestBodyLimitMiddleware

    sent: list[dict] = []
    incoming = [
        {"type": "http.request", "body": b"123", "more_body": True},
        {"type": "http.request", "body": b"456", "more_body": False},
    ]

    async def receive() -> dict:
        return incoming.pop(0)

    async def send(message: dict) -> None:
        sent.append(message)

    async def downstream(_scope, wrapped_receive, downstream_send) -> None:
        await wrapped_receive()
        await downstream_send(
            {"type": "http.response.start", "status": 204, "headers": []}
        )
        await downstream_send(
            {
                "type": "http.response.body",
                "body": b"partial",
                "more_body": True,
            }
        )
        await wrapped_receive()

    middleware = RequestBodyLimitMiddleware(downstream, max_body_size=5)
    scope = {"type": "http", "method": "POST", "path": "/", "headers": []}

    asyncio.run(middleware(scope, receive, send))

    assert sent[0]["status"] == 413
    assert all(message.get("status") != 204 for message in sent)
    assert all(message.get("body") != b"partial" for message in sent)


def test_non_http_scope_is_forwarded_unchanged() -> None:
    from api.body_limit import RequestBodyLimitMiddleware

    called = False

    async def receive() -> dict:
        return {"type": "websocket.disconnect"}

    async def send(_message: dict) -> None:
        pass

    async def downstream(scope, downstream_receive, downstream_send) -> None:
        nonlocal called
        called = True
        assert scope["type"] == "websocket"
        assert downstream_receive is receive
        assert downstream_send is send

    middleware = RequestBodyLimitMiddleware(downstream, max_body_size=5)

    asyncio.run(middleware({"type": "websocket"}, receive, send))

    assert called is True
