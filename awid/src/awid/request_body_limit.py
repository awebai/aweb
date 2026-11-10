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

from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger(__name__)

TOO_LARGE = "Request body too large"


class RequestBodyTooLarge(HTTPException):
    def __init__(self) -> None:
        super().__init__(status_code=413, detail=TOO_LARGE)


class RequestBodyLimitMiddleware:
    def __init__(self, app: ASGIApp, *, max_body_bytes: int) -> None:
        if max_body_bytes < 1:
            raise ValueError("max_body_bytes must be positive")
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = _declared_length(scope)
        if declared is not None and declared > self.max_body_bytes:
            # Answered before the app runs, so this is the request's only record.
            logger.warning(
                "Request body too large: %s declared %d bytes, limit %d",
                scope["method"], declared, self.max_body_bytes,
            )
            await _too_large(scope, receive, send)
            return

        received = 0

        async def counted_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body_bytes:
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
