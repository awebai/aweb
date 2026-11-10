"""The handoff's own B3 registration: public output, with no designation."""

import base64
import hashlib
import hmac
import json
import re
import secrets
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from aweb_naapp.console import ConsoleRoute, LoginLimiter, require_json
from aweb_naapp.console.handoff_store import HandoffStore
from aweb_naapp.console.handoff_wire import HandoffWireRefused, verify_console_request
from aweb_naapp.runtime.approvals.request import parse_request_json
from aweb_naapp.runtime.passkeys import RelyingParty, WebAuthnRefused, verify_registration
from aweb_naapp.runtime.passkeys.webauthn import registration_options

_BROWSER = "__Host-console-handoff"
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")


def _hash(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _token(value: Any) -> str:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise HTTPException(403, "handoff_refused")
    if _b64(base64.urlsafe_b64decode(value + "=")) != value:
        raise HTTPException(403, "handoff_refused")
    return value


def _id(value: str) -> UUID:
    try:
        parsed = UUID(value)
        if str(parsed) != value:
            raise ValueError()
        return parsed
    except ValueError:
        raise HTTPException(403, "handoff_refused") from None


def _scope(row) -> dict[str, str]:
    value = row["public_scope"]
    return json.loads(value) if isinstance(value, str) else dict(value)


def credential_handoff_router(
    *,
    store: HandoffStore,
    rp: RelyingParty,
    admits: Callable[[dict[str, str]], Awaitable[bool]],
    limiter: LoginLimiter,
    session_result: Callable[[str, Request], Awaitable[dict | None]] | None = None,
) -> APIRouter:
    """The registration half of the handoff; `admits` checks the app namespace.

    This callback admits a public registration target, never a role or session.
    The public credential must subsequently be bound by a verified owner act.
    """

    async def limited(request: Request) -> None:
        try:
            await limiter.admit(request, "console.handoff")
        except HTTPException as exc:
            if exc.status_code != 429:
                raise
            raise HTTPException(429, "handoff_rate_limited", headers=exc.headers) from None

    router = APIRouter(route_class=ConsoleRoute, dependencies=[Depends(limited)])

    async def row_for(handoff_id: str):
        row = await store.db.fetch_one(
            "SELECT * FROM {{tables.console_handoffs}} WHERE handoff_id=$1 "
            "AND purpose='credential' AND expires_at>clock_timestamp() "
            "AND completed_at IS NULL AND released_at IS NULL",
            _id(handoff_id),
        )
        if row is None or not await admits(_scope(row)):
            raise HTTPException(403, "handoff_refused")
        return row

    async def browser_row(handoff_id: str, request: Request):
        row = await row_for(handoff_id)
        if request.headers.get("origin") != rp.origin:
            raise HTTPException(403, "handoff_refused")
        browser = request.cookies.get(_BROWSER, "")
        csrf = request.headers.get("X-CSRF-Token", "")
        if (
            row["browser_sha256"] is None
            or row["csrf_sha256"] is None
            or not hmac.compare_digest(_hash(browser), bytes(row["browser_sha256"]))
            or not hmac.compare_digest(_hash(csrf), bytes(row["csrf_sha256"]))
        ):
            raise HTTPException(403, "handoff_refused")
        return row

    async def body(request: Request, fields: set[str]) -> dict[str, Any]:
        raw = await request.body()
        if len(raw) > 64 * 1024:
            raise HTTPException(403, "handoff_refused")
        try:
            value = parse_request_json(raw)
            if set(value) != fields:
                raise ValueError()
            return value
        except (ValueError, TypeError, RecursionError):
            raise HTTPException(403, "handoff_refused") from None

    @router.get("/handoff/{handoff_id}/credential")
    async def state(handoff_id: str, request: Request, response: Response):
        row = await row_for(handoff_id)
        browser = request.cookies.get(_BROWSER) or secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        updated = await store.db.fetch_value(
            "UPDATE {{tables.console_handoffs}} SET browser_sha256=$2,csrf_sha256=$3 "
            "WHERE handoff_id=$1 AND expires_at>clock_timestamp() AND completed_at IS NULL "
            "AND (browser_sha256 IS NULL OR browser_sha256=$2) RETURNING handoff_id",
            _id(handoff_id),
            _hash(browser),
            _hash(csrf),
        )
        if updated is None:
            raise HTTPException(403, "handoff_refused")
        response.set_cookie(
            _BROWSER, browser, secure=True, httponly=True, samesite="strict", path="/", max_age=600
        )
        return {"scope": _scope(row), "csrf_token": csrf}

    @router.post("/handoff/{handoff_id}/credential/options", dependencies=[Depends(require_json)])
    async def options(handoff_id: str, request: Request):
        await body(request, set())
        row = await browser_row(handoff_id, request)
        challenge = secrets.token_bytes(32)
        updated = await store.db.fetch_value(
            "UPDATE {{tables.console_handoffs}} SET challenge=$2 WHERE handoff_id=$1 "
            "AND browser_sha256=$3 AND csrf_sha256=$4 AND completed_at IS NULL "
            "AND expires_at>clock_timestamp() RETURNING handoff_id",
            _id(handoff_id),
            _b64(challenge),
            row["browser_sha256"],
            row["csrf_sha256"],
        )
        if updated is None:
            raise HTTPException(403, "handoff_refused")
        principal = _scope(row)["principal"]
        return registration_options(
            rp=rp, subject=principal, display_name=principal, challenge=challenge, timeout=300000
        )

    @router.post("/handoff/{handoff_id}/credential/complete", dependencies=[Depends(require_json)])
    async def complete(handoff_id: str, request: Request):
        value = await body(request, {"credential"})
        row = await browser_row(handoff_id, request)
        # Claim and consume the challenge before verification, including failed
        # assertions. An id or pre-existing console cookie cannot supply a result.
        challenge = await store.db.fetch_value(
            "UPDATE {{tables.console_handoffs}} SET challenge=NULL WHERE handoff_id=$1 "
            "AND challenge=$2 AND browser_sha256=$3 AND csrf_sha256=$4 "
            "AND expires_at>clock_timestamp() AND completed_at IS NULL RETURNING $2::text",
            _id(handoff_id),
            row["challenge"],
            row["browser_sha256"],
            row["csrf_sha256"],
        )
        if challenge is None:
            raise HTTPException(403, "handoff_refused")
        try:
            verified = verify_registration(
                value["credential"],
                challenge=base64.urlsafe_b64decode(challenge + "=" * (-len(challenge) % 4)),
                rp=rp,
            )
        except WebAuthnRefused:
            raise HTTPException(403, "handoff_refused") from None
        credential = {
            "credential_id": _b64(verified.credential_id),
            "public_key": _b64(verified.public_key),
            "rp_id": rp.rp_id,
        }
        code = secrets.token_urlsafe(32)
        updated = await store.db.fetch_value(
            "UPDATE {{tables.console_handoffs}} SET credential=$2::jsonb,code_sha256=$3,completed_at=clock_timestamp() "
            "WHERE handoff_id=$1 AND completed_at IS NULL AND expires_at>clock_timestamp() "
            "RETURNING handoff_id",
            _id(handoff_id),
            json.dumps(credential),
            _hash(code),
        )
        if updated is None:
            raise HTTPException(403, "handoff_refused")
        return {
            "redirect_uri": row["redirect_uri"]
            + "?"
            + urlencode({"handoff_id": handoff_id, "code": code})
        }

    @router.post("/handoffs/{handoff_id}/result", dependencies=[Depends(require_json)])
    async def result(handoff_id: str, request: Request):
        if session_result is not None:
            answer = await session_result(handoff_id, request)
            if answer is not None:
                return answer
        value = await body(request, {"v", "code", "verifier"})
        if type(value["v"]) is not int or value["v"] != 1:
            raise HTTPException(403, "handoff_refused")
        code, verifier = _token(value["code"]), _token(value["verifier"])
        async with store.db.transaction() as tx:
            row = await tx.fetch_one(
                "SELECT * FROM {{tables.console_handoffs}} WHERE handoff_id=$1 FOR UPDATE",
                _id(handoff_id),
            )
            if (
                row is None
                or row["purpose"] != "credential"
                or row["completed_at"] is None
                or row["released_at"] is not None
                or row["expires_at"] <= datetime.now(UTC)
            ):
                raise HTTPException(403, "handoff_refused")
            try:
                await verify_console_request(
                    request,
                    origin=rp.origin,
                    client_key=row["client_key"],
                    domain="handoff-result",
                    subject_field="handoff_id",
                    subject=handoff_id,
                    now=datetime.now(UTC),
                )
            except HandoffWireRefused:
                raise HTTPException(403, "handoff_refused") from None
            if not hmac.compare_digest(
                _hash(code), bytes(row["code_sha256"])
            ) or not hmac.compare_digest(_hash(verifier), bytes(row["verifier_sha256"])):
                raise HTTPException(403, "handoff_refused")
            await tx.execute(
                "UPDATE {{tables.console_handoffs}} SET released_at=clock_timestamp() WHERE handoff_id=$1",
                _id(handoff_id),
            )
            credential = row["credential"]
            if isinstance(credential, str):
                credential = json.loads(credential)
        await store.prune()
        return {"purpose": "credential", "credential": credential}

    return router
