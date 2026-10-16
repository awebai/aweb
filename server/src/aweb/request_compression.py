"""Bounded HTTP request decoding before body hashes, logging and authentication.

Public embedding API: use RequestDecompressionFastAPI in place of FastAPI, or
wrap a completed ASGI stack in RequestDecompressionMiddleware. Both leave plain
requests unchanged. Nesting is safe: the outer decoder removes the coding.
"""

from __future__ import annotations

import logging
import zlib

from fastapi import FastAPI
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger(__name__)
GZIP_REQUEST_LIMIT = 1024 * 1024


class _DecodeRefusal(Exception):
    def __init__(self, status: int, detail: str):
        self.status = status
        self.detail = detail


class RequestDecompressionMiddleware:
    """Decode gzip with separate hard caps on compressed and decoded bytes.

    The cap applies only to gzip. Clients must send larger bodies plain to
    preserve the existing uncapped plain-body API. Signed body hashes cover
    decoded bytes, never the compressed transport representation.
    """

    def __init__(self, app: ASGIApp, *, max_body_bytes: int = GZIP_REQUEST_LIMIT):
        if max_body_bytes < 1:
            raise ValueError("max_body_bytes must be positive")
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        started = False

        async def advertised_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                # Set rather than append: nested OSS/embedding apps advertise once.
                message = dict(message)
                message["headers"] = [
                    (k, v) for k, v in message.get("headers", [])
                    if k.lower() != b"accept-encoding"
                ] + [(b"accept-encoding", b"gzip")]
                started = True
            await send(message)

        async def refuse(status: int, detail: str) -> None:
            await PlainTextResponse(detail, status_code=status)(scope, receive, advertised_send)

        try:
            codings = [v.strip().lower() for k, v in scope["headers"] if k.lower() == b"content-encoding"]
            if not codings or codings == [b"identity"]:
                await self.app(scope, receive, advertised_send)
                return
            if codings != [b"gzip"]:
                raise _DecodeRefusal(415, "Unsupported Content-Encoding")

            body = await self._decode(receive)
            if body is None:  # Client disconnected before completing the upload.
                return
            scope = dict(scope)
            scope["headers"] = [
                (k, v) for k, v in scope["headers"]
                if k.lower() not in {b"content-encoding", b"content-length", b"transfer-encoding"}
            ] + [(b"content-length", str(len(body)).encode("ascii"))]
            replayed = False

            async def decoded_receive() -> Message:
                nonlocal replayed
                if not replayed:
                    replayed = True
                    return {"type": "http.request", "body": body, "more_body": False}
                return await receive()

            await self.app(scope, decoded_receive, advertised_send)
        except _DecodeRefusal as exc:
            await refuse(exc.status, exc.detail)
        except Exception:
            # This wrapper sits outside framework error handling. Preserve a
            # bounded response even if the decoder itself has an internal bug.
            # Never log a request body or header here.
            logger.exception("Request processing failed at decompression boundary")
            if not started:
                await refuse(500, "Internal server error")

    async def _decode(self, receive: Receive) -> bytes | None:
        decoder = zlib.decompressobj(wbits=31)
        decoded = bytearray()
        compressed_size = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return None
            data = message.get("body", b"")
            compressed_size += len(data)
            if compressed_size > self.max_body_bytes:
                raise _DecodeRefusal(413, "Compressed request body too large")
            while data:
                if decoder.eof:
                    # RFC 1952 permits concatenated members. All share one cap.
                    decoder = zlib.decompressobj(wbits=31)
                try:
                    chunk = decoder.decompress(data, self.max_body_bytes - len(decoded) + 1)
                except zlib.error as exc:
                    raise _DecodeRefusal(400, "Invalid gzip request body") from exc
                if len(decoded) + len(chunk) > self.max_body_bytes:
                    raise _DecodeRefusal(413, "Decoded request body too large")
                decoded.extend(chunk)
                data = decoder.unused_data if decoder.eof else decoder.unconsumed_tail
            if not message.get("more_body", False):
                if not decoder.eof:
                    raise _DecodeRefusal(400, "Invalid gzip request body")
                return bytes(decoded)


class RequestDecompressionFastAPI(FastAPI):
    """FastAPI with decoding and advertisement outside its entire error stack.

    add_middleware alone sits inside ServerErrorMiddleware and misses its 500
    responses. Wrapping the completed stack also precedes user middleware added
    by embedding hosts, regardless of registration order.
    """

    def build_middleware_stack(self) -> ASGIApp:
        return RequestDecompressionMiddleware(super().build_middleware_stack())
