"""Bounded, member-signed API starts; ceremonies never follow from an id."""

import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from typing import Annotated, Any
from uuid import UUID, uuid4

from awid.did import public_key_from_did, strict_ed25519_point, validate_stable_id
from fastapi import APIRouter, Depends, HTTPException, Request
from pgdbm import AsyncDatabaseManager
from pgdbm.core import TransactionManager

from aweb_naapp.console import ConsoleRoute, LoginLimiter, require_json
from aweb_naapp.console.handoff_authority import PublicScope
from aweb_naapp.console.handoff_wire import HandoffWireRefused, loopback_redirect
from aweb_naapp.runtime.approvals.request import parse_request_json
from aweb_naapp.runtime.team_auth import Principal

_START_REQUIRED = {
    "v",
    "purpose",
    "client_key",
    "return",
    "verifier_sha256",
    "scope",
}
_ROLE = re.compile(r"[a-z][a-z0-9_-]*(?:\.[a-z0-9][a-z0-9_-]*)+")
_DIGEST = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class HandoffStart:
    purpose: str
    client_key: str
    redirect_uri: str
    verifier_sha256: bytes
    scope: PublicScope
    client_hostname: str


def parse_start(body: Any) -> HandoffStart:
    """The loopback profile; unsupported fallback cannot start a session."""
    try:
        if (
            not isinstance(body, dict)
            or not _START_REQUIRED <= set(body)
            or set(body) - (_START_REQUIRED | {"client_hostname", "redirect_uri"})
            or type(body["v"]) is not int
            or body["v"] != 1
            or body["purpose"] not in ("credential", "session")
            or body["return"] not in ("loopback", "user_code")
            or (body["return"] == "loopback" and "redirect_uri" not in body)
            or (body["return"] == "user_code" and "redirect_uri" in body)
        ):
            raise ValueError()
        key = body["client_key"]
        if not isinstance(key, str) or not strict_ed25519_point(public_key_from_did(key)):
            raise ValueError()
        digest = body["verifier_sha256"]
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
            raise ValueError()
        scope = body["scope"]
        if not isinstance(scope, dict) or set(scope) != {"installation_id", "role", "principal"}:
            raise ValueError()
        if not all(isinstance(value, str) for value in scope.values()):
            raise ValueError()
        if str(UUID(scope["installation_id"])) != scope["installation_id"]:
            raise ValueError()
        if _ROLE.fullmatch(scope["role"]) is None or len(scope["role"].encode()) > 64:
            raise ValueError()
        validate_stable_id(scope["principal"])
        hostname = body.get("client_hostname", "")
        if (
            not isinstance(hostname, str)
            or len(hostname) > 255
            or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in hostname)
            or (body["return"] == "user_code" and not hostname)
        ):
            raise ValueError()
    except (ValueError, TypeError, KeyError) as exc:
        raise HandoffWireRefused("handoff_invalid") from exc
    if body["return"] == "user_code":
        if body["purpose"] == "session":
            raise HandoffWireRefused("fallback_unavailable")
        raise HandoffWireRefused("handoff_invalid")
    # Preserve the distinct fixed redirect refusal, without reflecting its URI.
    redirect = loopback_redirect(body["redirect_uri"])
    return HandoffStart(
        body["purpose"],
        key,
        redirect,
        bytes.fromhex(digest),
        PublicScope(scope["installation_id"], scope["role"], scope["principal"]),
        hostname,
    )


class HandoffStore:
    def __init__(self, db: AsyncDatabaseManager) -> None:
        self.db = db

    async def create(
        self, start: HandoffStart, *, tx: TransactionManager | None = None
    ) -> dict[str, str]:
        handoff_id = uuid4()
        expiry = await (tx or self.db).fetch_value(
            "INSERT INTO {{tables.console_handoffs}} "
            "(handoff_id,purpose,client_key,redirect_uri,verifier_sha256,public_scope,client_hostname,expires_at) "
            "VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,clock_timestamp()+INTERVAL '10 minutes') RETURNING expires_at",
            handoff_id,
            start.purpose,
            start.client_key,
            start.redirect_uri,
            start.verifier_sha256,
            json.dumps(asdict(start.scope)),
            start.client_hostname,
        )
        return {
            "handoff_id": str(handoff_id),
            "expires_at": expiry.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        }


def handoff_start_router(
    *,
    store: HandoffStore,
    limiter: LoginLimiter,
    principal: Callable[[Request], Awaitable[Principal]],
    session_start: Callable[[HandoffStart, Principal, Request], Awaitable[dict[str, str]]]
    | None = None,
) -> APIRouter:
    """Mount on the API origin, with the runtime's verified principal dependency.

    The supplied dependency authenticates team-auth, including the current
    exact DID/key binding. It grants no role or passkey authority.
    """
    router = APIRouter(route_class=ConsoleRoute, dependencies=[Depends(require_json)])

    @router.post("/handoffs", status_code=201)
    async def start(
        request: Request, signer: Annotated[Principal, Depends(principal)]
    ) -> dict[str, str]:
        try:
            await limiter.admit(request, "console.handoff")
        except HTTPException as exc:
            if exc.status_code != 429:
                raise
            raise HTTPException(429, "handoff_rate_limited", headers=exc.headers) from None
        raw = await request.body()
        if len(raw) > 16 * 1024:
            raise HTTPException(status_code=400, detail="handoff_invalid")
        try:
            value = parse_request_json(raw)
            parsed = parse_start(value)
        except (ValueError, UnicodeError, RecursionError) as exc:
            code = str(exc) if isinstance(exc, HandoffWireRefused) else "handoff_invalid"
            raise HTTPException(
                status_code=409 if code == "fallback_unavailable" else 400, detail=code
            ) from None
        if not signer.did_aw_registry_verified or parsed.scope.principal != signer.did_aw:
            raise HTTPException(403, "scope_not_signer")
        if parsed.purpose == "session":
            if session_start is None:
                raise HTTPException(403, "role_not_held")
            return await session_start(parsed, signer, request)
        return await store.create(parsed)

    return router
