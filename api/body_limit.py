"""ASGI middleware for bounding HTTP request bodies."""

from collections import deque
import uuid

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class RequestBodyLimitMiddleware:
    """Reject HTTP request bodies that exceed a configured byte limit."""

    def __init__(self, app: ASGIApp, max_body_size: int) -> None:
        self.app = app
        self.max_body_size = max_body_size

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        if self._declared_length_exceeds_limit(scope):
            await self._send_too_large(scope, receive, send)
            return

        buffered: deque[Message] = deque()
        received = 0
        while True:
            message = await receive()
            buffered.append(message)

            if message["type"] == "http.disconnect":
                break
            if message["type"] != "http.request":
                continue

            received += len(message.get("body", b""))
            if received > self.max_body_size:
                await self._send_too_large(scope, receive, send)
                return
            if not message.get("more_body", False):
                break

        async def replay_receive() -> Message:
            if buffered:
                return buffered.popleft()
            return await receive()

        await self.app(scope, replay_receive, send)

    def _declared_length_exceeds_limit(self, scope: Scope) -> bool:
        for name, value in scope.get("headers", []):
            if name.lower() != b"content-length":
                continue
            try:
                declared_length = int(value)
            except ValueError:
                continue
            if declared_length > self.max_body_size:
                return True
        return False

    async def _send_too_large(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        state = scope.setdefault("state", {})
        request_id = state.get("request_id")
        if not isinstance(request_id, str) or not request_id:
            request_id = str(uuid.uuid4())
            state["request_id"] = request_id

        response = JSONResponse(
            status_code=413,
            headers={"X-Request-ID": request_id},
            content={
                "success": False,
                "request_id": request_id,
                "error": {
                    "code": "http_error",
                    "message": (
                        "Request body exceeds maximum allowed size "
                        f"({self.max_body_size} bytes)"
                    ),
                },
            },
        )
        await response(scope, receive=receive, send=send)
