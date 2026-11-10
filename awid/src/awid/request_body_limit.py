"""Refuse a request body over a limit with 413.

A declared Content-Length over the limit is refused before the app runs. A
body sent without one is counted as the app reads it: the read that passes
the limit raises RequestBodyTooLarge, which a FastAPI or Starlette app
answers as 413 and which this middleware answers itself when it surfaces
from a layer that does not. Nothing is buffered here, so a route that
streams its body under a tighter limit of its own keeps doing so.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger(__name__)

TOO_LARGE = "Request body too large"


class RequestBodyTooLarge(HTTPException):
    def __init__(self) -> None:
        super().__init__(status_code=413, detail=TOO_LARGE)


class RequestBodyLimitMiddleware:
    """`logged_path` writes the request path that a refusal's log line shows; it is given the
    decoded path. The default drops a query or fragment, escapes what is not printable and caps
    the length (_logged_path). A host whose paths carry secrets of its own (invite codes, tokens)
    passes its rule for those; a rule that raises is replaced by the default for that line, so a
    refusal is a 413 whatever the rule does."""

    def __init__(
        self, app: ASGIApp, *, max_body_bytes: int, logged_path: Callable[[str], str] | None = None,
    ) -> None:
        if max_body_bytes < 1:
            raise ValueError("max_body_bytes must be positive")
        self.app = app
        self.max_body_bytes = max_body_bytes
        self.logged_path = logged_path or _logged_path

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = _declared_length(scope)
        if declared is not None and declared > self.max_body_bytes:
            # Answered before the app runs, so this is the request's only record.
            logger.warning(
                "Request body too large: %s %s declared %d bytes, limit %d",
                scope["method"], self._path_for_log(scope["path"]), declared, self.max_body_bytes,
            )
            await _too_large(scope, receive, send)
            return

        received = 0
        refused = False

        async def counted_receive() -> Message:
            nonlocal received, refused
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body_bytes:
                    if not refused:
                        refused = True
                        logger.warning(
                            "Request body too large: %s %s received %d bytes, limit %d",
                            scope["method"], self._path_for_log(scope["path"]), received, self.max_body_bytes,
                        )
                    raise RequestBodyTooLarge()
            return message

        started = False

        async def marking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, counted_receive, marking_send)
        except RequestBodyTooLarge:
            if started:
                raise
            await _too_large(scope, receive, send)

    def _path_for_log(self, path: str) -> str:
        try:
            return self.logged_path(path)
        except Exception:
            return _logged_path(path)


LOGGED_PATH_MAX = 256


def _logged_path(path: str) -> str:
    """The request path as a log line shows it: without a query or fragment, with
    every character that is not printable, and the backslash, written as its
    escape (a decoded ``%0A`` shows as ``\\n``), and at most LOGGED_PATH_MAX
    characters, then an ellipsis.

    ASGI decodes the path, so an encoded ``?`` or ``#`` appears in it and
    whatever follows is dropped as a query string would be.
    """
    shown = "".join(
        char if char.isprintable() and char != "\\" else repr(char)[1:-1]
        for char in path.split("?", 1)[0].split("#", 1)[0]
    )
    return shown if len(shown) <= LOGGED_PATH_MAX else shown[:LOGGED_PATH_MAX] + "…"


def _declared_length(scope: Scope) -> int | None:
    for name, value in scope["headers"]:
        if name.lower() == b"content-length":
            try:
                return int(value)
            except ValueError:
                return None
    return None


async def _too_large(scope: Scope, receive: Receive, send: Send) -> None:
    await JSONResponse({"detail": TOO_LARGE}, status_code=413)(scope, receive, send)
