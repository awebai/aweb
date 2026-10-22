"""Presentation capability privacy at Folio's HTTP and access-log boundaries."""

from __future__ import annotations

import logging
import re

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_PRESENT_TOKEN = re.compile(r"^(/(?:v1/)?present/)[^/]+")


class PresentAccessFilter(logging.Filter):
    """Sanitize Uvicorn's request-target argument before any handler formats it.

    This changes only the log record, never the ASGI target used by routing and
    signature verification. Queries can contain record filters, so none are logged.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple) and len(record.args) == 5:
            client, method, target, version, status = record.args
            if isinstance(target, str):
                path = target.split("?", 1)[0]
                # Records link IDs are public identifiers, not legacy bearer tokens.
                if not path.startswith("/present/links/"):
                    path = _PRESENT_TOKEN.sub(r"\1[redacted]", path)
                record.args = (client, method, path, version, status)
        return True


def install_access_filter() -> None:
    logger = logging.getLogger("uvicorn.access")
    if not any(isinstance(item, PresentAccessFilter) for item in logger.filters):
        logger.addFilter(PresentAccessFilter())


class PresentationPrivacy:
    """Apply private response headers to every presentation route/refusal."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope["path"].startswith("/present/"):
            await self.app(scope, receive, send)
            return

        async def private_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["Cache-Control"] = "no-store"
                headers["Referrer-Policy"] = "no-referrer"
            await send(message)

        await self.app(scope, receive, private_send)
