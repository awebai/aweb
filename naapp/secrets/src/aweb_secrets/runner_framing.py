"""Bounded runner transport framing; no authentication or effect authority.

The service receives exact bytes and performs all final verification. In
particular, a header parsed here is not an authenticated runner request.
"""

import logging
import re
import traceback

from aweb_naapp.runtime.team_auth import raw_request_target
from fastapi import HTTPException, Request, Response
from fastapi.responses import JSONResponse

from aweb_secrets.runner_protocol import RunnerRefused, parse_request
from aweb_secrets.runner_types import RunnerReply

MAX_RESULT_FRAME = 6 * 16 * 1024 * 1024 + 1024
_NO_STORE = {"Cache-Control": "no-store"}
_JSON_MEDIA = re.compile(
    r'application/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?', re.IGNORECASE
)
_STATUSES = {
    "runner_request_invalid": 400,
    "runner_request_binding_mismatch": 400,
    "runner_result_invalid": 400,
    "runner_unknown": 401,
    "runner_dispatch_unknown": 404,
    "runner_request_stale": 409,
    "runner_request_replayed": 409,
    "runner_dispatch_state_conflict": 409,
    "runner_result_conflict": 409,
    "runner_reconciliation_required": 409,
    "runner_request_too_large": 413,
    "runner_unavailable": 503,
}
logger = logging.getLogger(__name__)


class _FramingRefused(HTTPException):
    def __init__(self, status: int = 400) -> None:
        code = "runner_request_too_large" if status == 413 else "runner_request_invalid"
        super().__init__(status, detail={"code": code}, headers=_NO_STORE)


def _request_head(request: Request) -> tuple[str, str]:
    """Validate bounded framing/header shape without reading the body."""
    media = request.headers.getlist("content-type")
    if (
        len(media) != 1
        or not _JSON_MEDIA.fullmatch(media[0].strip())
        or "content-encoding" in request.headers
    ):
        raise _FramingRefused(415)
    if request.method != "POST" or request.scope.get("query_string"):
        raise _FramingRefused()
    headers = request.headers.getlist("x-aweb-secrets-runner-request")
    if len(headers) != 1:
        raise _FramingRefused()
    header = headers[0]
    parse_request(header)  # Shape only, never a current-key or nonce check.
    try:
        target = raw_request_target(request)
    except HTTPException:
        raise _FramingRefused() from None
    return header, target


def _declared_length(request: Request, *, limit: int) -> int | None:
    lengths = request.headers.getlist("content-length")
    if not lengths:
        return None
    if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdecimal():
        raise _FramingRefused()
    # Compare before int conversion, including arbitrarily many leading zeros.
    length = lengths[0].lstrip("0") or "0"
    bound = str(limit)
    if len(length) > len(bound) or len(length) == len(bound) and length > bound:
        raise _FramingRefused(413)
    return int(length)


async def _read_body(request: Request, *, limit: int) -> bytes:
    if type(limit) is not int or not 0 < limit <= MAX_RESULT_FRAME:
        raise ValueError("invalid runner frame limit")
    declared = _declared_length(request, limit=limit)
    raw = bytearray()
    async for chunk in request.stream():
        if len(chunk) > limit - len(raw):
            raise _FramingRefused(413)
        raw.extend(chunk)
    if declared is not None and declared != len(raw):
        raise _FramingRefused()
    return bytes(raw)


def _error(status: int, code: str) -> JSONResponse:
    return JSONResponse({"detail": {"code": code}}, status_code=status, headers=_NO_STORE)


def _log_failure(error: Exception) -> None:
    # Exception messages and locals can contain raw streams/credentials. Retain
    # the real exception class and its call sites, without formatting either.
    frames = [(f.filename, f.lineno, f.name) for f in traceback.extract_tb(error.__traceback__)]
    logger.error("Runner dependency failure: %s; frames=%s", type(error).__name__, frames)


def _runner_refusal(refused: RunnerRefused) -> JSONResponse:
    status = _STATUSES.get(refused.code)
    if status is None:
        _log_failure(refused)
        return _error(503, "runner_unavailable")
    return _error(status, refused.code)


def _runner_reply(reply: RunnerReply, *, operation: str) -> Response:
    if reply.status == 204 and reply.body is None:
        return Response(status_code=204, headers=_NO_STORE)
    if (
        operation == "claim"
        and reply.status == 200
        and isinstance(reply.body, bytes)
        and 0 < len(reply.body) <= 1024 * 1024
    ):
        return Response(reply.body, media_type="application/json", headers=_NO_STORE)
    raise ValueError("invalid runner service reply")
