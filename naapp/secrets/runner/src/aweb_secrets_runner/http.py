"""Bounded outbound TLS transport; assignments still require S0 verification."""

from __future__ import annotations

import asyncio
import math
import re
import ssl
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType

import httpx

from .errors import Refused
from .journal import MAX_RESULT_BYTES
from .protocol import ID, MAX_BODY, origin_is_valid, parse_json, public_key, sign_request
from .state import Identity

REFUSALS = {
    400: {"runner_request_invalid", "runner_request_binding_mismatch", "runner_result_invalid"},
    401: {"runner_unknown"},
    404: {"runner_dispatch_unknown"},
    409: {
        "runner_request_stale",
        "runner_request_replayed",
        "runner_dispatch_state_conflict",
        "runner_result_conflict",
        "runner_reconciliation_required",
    },
    413: {"runner_request_too_large"},
    415: {"runner_request_invalid"},
    503: {"runner_unavailable"},
}


def _now() -> datetime:
    return datetime.now(UTC)


def _dispatch_path(dispatch_id: str, operation: str) -> str:
    if not re.fullmatch("dsp_" + ID, dispatch_id):
        raise Refused("runner_request_invalid")
    return f"/runner/v1/dispatches/{dispatch_id}/{operation}"


def _json_media(value: str) -> bool:
    parts = [part.strip().lower() for part in value.split(";")]
    return parts == ["application/json"] or parts == ["application/json", "charset=utf-8"]


class RunnerHTTP:
    """One scoped client, no redirects/proxies/cookies, one fresh signature per send.

    This transport makes one attempt. Its caller owns durable reporting/retry
    policy and must verify and journal every returned assignment before opening
    credentials. A timeout cannot establish whether the server committed.
    """

    def __init__(
        self,
        identity: Identity,
        *,
        ca_file: Path | None = None,
        deadline_s: float = 40,
        clock: Callable[[], datetime] = _now,
    ):
        if identity.runner_id is None or identity.service_kid is None:
            raise Refused("runner_unregistered")
        try:
            public_key(identity.service_kid)
            if (
                not origin_is_valid(identity.origin)
                or not re.fullmatch("rnr_" + ID, identity.runner_id)
                or not math.isfinite(deadline_s)
                or not 0 < deadline_s <= 40
            ):
                raise ValueError("configuration")
            tls = ssl.create_default_context(cafile=ca_file)
        except (ValueError, OSError):
            raise Refused("runner_configuration_invalid") from None
        self._identity = identity
        self._runner_id = identity.runner_id
        self._clock = clock
        self._deadline_s = deadline_s
        self._lock = asyncio.Lock()
        self._client = httpx.AsyncClient(
            verify=tls,
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(connect=5, read=35, write=10, pool=5),
            limits=httpx.Limits(max_connections=1, max_keepalive_connections=1),
        )

    async def __aenter__(self) -> RunnerHTTP:
        await self._client.__aenter__()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self._client.__aexit__(exc_type, exc, tb)

    async def claim(self) -> bytes | None:
        return await self._post("/runner/v1/claim", b"{}", assignment=True)

    async def started(self, dispatch_id: str) -> None:
        await self._post(_dispatch_path(dispatch_id, "started"), b"{}")

    async def result(self, dispatch_id: str, body: bytes) -> None:
        if type(body) is not bytes or not 0 < len(body) <= MAX_RESULT_BYTES:
            raise Refused("runner_result_invalid")
        # Do not parse or re-encode: the server deduplicates the exact saved body.
        await self._post(_dispatch_path(dispatch_id, "result"), body)

    async def _post(self, path: str, body: bytes, *, assignment: bool = False) -> bytes | None:
        try:
            # HTTPX read timeouts bound inactivity, not a dribbling response's
            # total duration. This deadline also bounds pool/serialization waits.
            async with asyncio.timeout(self._deadline_s), self._lock:
                header = sign_request(
                    self._identity.signing_key,
                    origin=self._identity.origin,
                    runner_id=self._runner_id,
                    method="POST",
                    path=path,
                    body=body,
                    now=self._clock(),
                )
                self._client.cookies.clear()
                try:
                    async with self._client.stream(
                        "POST",
                        self._identity.origin + path,
                        content=body,
                        headers={
                            "X-AWEB-Secrets-Runner-Request": header,
                            "Content-Type": "application/json",
                            "Accept-Encoding": "identity",
                            "Cache-Control": "no-store",
                        },
                    ) as response:
                        return await self._response(response, assignment=assignment)
                finally:
                    self._client.cookies.clear()
        except (httpx.HTTPError, TimeoutError, OSError):
            raise Refused("runner_unavailable") from None

    async def _response(self, response: httpx.Response, *, assignment: bool) -> bytes | None:
        if (
            "no-store"
            not in {
                token.strip().lower()
                for token in response.headers.get("cache-control", "").split(",")
            }
            or "content-encoding" in response.headers
        ):
            raise Refused("runner_response_invalid")
        status = response.status_code
        if status != 204 and not _json_media(response.headers.get("content-type", "")):
            raise Refused("runner_response_invalid")
        if status == 200 and assignment:
            limit = MAX_BODY
        elif status == 204:
            limit = 0
        elif status in REFUSALS:
            limit = 4096
        else:
            raise Refused("runner_response_invalid")
        try:
            length = response.headers.get("content-length")
            if length is not None and (not length.isdecimal() or int(length) > limit):
                raise Refused("runner_response_invalid")
            raw = bytearray()
            async for chunk in response.aiter_raw():
                if len(raw) + len(chunk) > limit:
                    raise Refused("runner_response_invalid")
                raw.extend(chunk)
            if status == 204:
                return None
            if status == 200:
                return bytes(raw)
            error = parse_json(bytes(raw))
            if (
                isinstance(error, dict)
                and set(error) == {"detail"}
                and isinstance(error["detail"], dict)
                and set(error["detail"]) == {"code"}
                and isinstance(error["detail"]["code"], str)
                and error["detail"]["code"] in REFUSALS[status]
            ):
                raise Refused(error["detail"]["code"])
        except (ValueError, TypeError, RecursionError):
            pass
        raise Refused("runner_response_invalid")
