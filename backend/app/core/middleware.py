"""Pure ASGI middleware (streaming-safe): request context/access log and body size limit."""

import json
import logging
import re
import time
import uuid
from typing import Any

from starlette.exceptions import HTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.metrics import observe_request

logger = logging.getLogger("app.access")
_REQUEST_ID = re.compile(r"[A-Za-z0-9._-]{8,64}")


class RequestContextMiddleware:
    """Assigns a request id, adds security headers and writes one structured access log line.

    Logged: method, path (no query string), status, duration, request id, API key id. Not
    logged: client IP, headers, query strings, bodies.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        incoming = _header(scope, b"x-request-id")
        request_id = incoming if incoming and _REQUEST_ID.fullmatch(incoming) else uuid.uuid4().hex
        state = scope.setdefault("state", {})
        state["request_id"] = request_id
        started = time.perf_counter()
        status = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                headers = list(message.get("headers", []))
                names = {name.lower() for name, _ in headers}
                headers.append((b"x-request-id", request_id.encode()))
                headers.append((b"x-content-type-options", b"nosniff"))
                if b"cache-control" not in names:
                    headers.append((b"cache-control", b"no-store"))
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            observe_request(_route_template(scope), scope["method"], status, started)
            logger.info(
                "request",
                extra={
                    "request_id": request_id,
                    "method": scope["method"],
                    "path": scope["path"],
                    "status": status,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 1),
                    "key_id": state.get("key_id"),
                },
            )


class _BodyTooLarge(HTTPException):
    """Raised from ``receive``. An HTTPException, so FastAPI's body parser re-raises it as is
    (instead of turning it into a 400) and the exception handler renders a 413."""

    def __init__(self) -> None:
        super().__init__(status_code=413, detail="request body too large")


class BodySizeLimitMiddleware:
    """Rejects request bodies over ``max_bytes`` with 413, by Content-Length or while streaming."""

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = _header(scope, b"content-length")
        if declared is not None:
            if not declared.isdigit():
                await _send_error(send, 400, "invalid Content-Length")
                return
            if int(declared) > self.max_bytes:
                await _send_error(send, 413, "request body too large")
                return

        received = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _BodyTooLarge
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _BodyTooLarge:
            if response_started:
                raise
            await _send_error(send, 413, "request body too large")


def _route_template(scope: Scope) -> str | None:
    """The matched route as a template, e.g. /v1/signatures/delta; None when nothing matched.

    Routes of included routers carry their path relative to the router, so the prefix is recovered
    from the request path: everything before the route's own (parameter-filled) path.
    """
    route = scope.get("route")
    if route is None:
        return None
    path: str = scope["path"]
    params = scope.get("path_params") or {}
    relative: str = getattr(route, "path_format", None) or getattr(route, "path", "")
    try:
        filled = relative.format(**{key: str(value) for key, value in params.items()})
    except (KeyError, IndexError, ValueError):
        return relative
    if filled and path.endswith(filled):
        return path[: len(path) - len(filled)] + relative
    return relative


def _header(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers", []):
        if key.lower() == name:
            return value.decode("latin-1")
    return None


async def _send_error(send: Send, status: int, detail: str) -> None:
    body = json.dumps({"detail": detail}).encode()
    headers: list[Any] = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
        (b"connection", b"close"),
    ]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})
