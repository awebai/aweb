"""Reader governance over HTTP (audit-substrate.md §B5).

On logs' agent origin, ``POST /v1/reader-slots`` issues a pending reader slot
(:mod:`aweb_logs.readers`) to a member the installation grants
``logs.readers``, for the contact the owner will designate. A slot grants
nothing: only the owner act that names it designates a reader. Slots are
rate-limited per member.

On logs' console origin, the owner's signed acts designate and revoke readers.
"""

import base64
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from aweb_naapp import ratelimit
from aweb_naapp.console import ConsoleRoute, exact_body, require_json, text_field
from aweb_naapp.hooks.strictjson import Refused
from aweb_naapp.runtime.authorization import Authorization
from aweb_naapp.runtime.credential_audit import GovernanceUnavailable
from aweb_naapp.runtime.installation import InstallationFence, InstallationRefused
from fastapi import APIRouter, Depends, HTTPException, Request

from aweb_logs.readers import ReaderDesignations, ReaderDirectory, ReaderRefused

logger = logging.getLogger(__name__)

SLOT_BUCKET = "logs.reader_slots.member"
SLOT_LIMIT = 20
SLOT_WINDOW = timedelta(hours=1)


async def _json_object(request: Request) -> dict[str, Any]:
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type != "application/json":
        raise HTTPException(status_code=415, detail="json_required")
    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(status_code=400, detail="request_invalid") from None
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="request_invalid")
    return body


def reader_slot_router(
    directory: ReaderDirectory,
    *,
    authorized: Callable[..., Awaitable[Authorization]],
    fence: InstallationFence,
    limit: int = SLOT_LIMIT,
    window: timedelta = SLOT_WINDOW,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> APIRouter:
    """``POST /v1/reader-slots``. Mount only on the agent origin, with the
    runtime's team-auth dependency for the manifest's ``reader-slot`` tool."""
    router = APIRouter()

    @router.post("/v1/reader-slots")
    async def issue(
        request: Request, auth: Annotated[Authorization, Depends(authorized)]
    ) -> dict[str, str]:
        body = await _json_object(request)
        contact = body.get("contact_sha256")
        if set(body) != {"contact_sha256"} or not isinstance(contact, str):
            raise HTTPException(status_code=400, detail="request_invalid")
        now = clock()
        charge = ratelimit.Charge(
            bucket=SLOT_BUCKET,
            key=auth.principal.did_key,
            capacity=limit,
            window_s=int(window.total_seconds()),
        )
        try:
            await fence.refresh(auth.grant.team_id)
            async with directory.db.transaction() as tx:
                admitted = await fence.admit(tx, auth.grant)
                decision = await ratelimit.take(tx, [charge], now=now)
                if decision.throttled:
                    raise HTTPException(
                        status_code=429,
                        detail="reader_slots_rate_limited",
                        headers={"Retry-After": str(decision.retry_after_s)},
                    )
                slot = await directory.create_slot(
                    tx,
                    installation_id=admitted.installation_id,
                    team_id=admitted.team_id,
                    contact_sha256=contact,
                )
        except InstallationRefused as refused:
            raise HTTPException(status_code=refused.status, detail=refused.code) from None
        except ValueError:
            raise HTTPException(status_code=400, detail="request_invalid") from None
        try:
            await ratelimit.sweep(directory.db, now=now, limit=16)
        except Exception as error:
            logger.warning("reader slot bucket sweep failed: %s", type(error).__name__)
        return {"scope": slot.scope, "expires_at": slot.expires_at.isoformat()}

    return router


def _signed_act(body: dict[str, Any]) -> tuple[bytes, str]:
    try:
        signing = base64.b64decode(text_field(body, "signing"), validate=True)
    except ValueError:
        raise HTTPException(status_code=400, detail="request_invalid") from None
    return signing, text_field(body, "signature")


def reader_governance_router(designations: ReaderDesignations, *, prefix: str = "") -> APIRouter:
    """``POST /readers/designations`` and ``POST /readers/revocations``, under
    ``prefix``. Mount only on logs' console origin.

    The endpoints are anonymous: the owner's signed act is the only authority.
    An act that names no pending slot or current reader exactly is refused
    with 403 ``owner_required``, never echoing the request; a governance event
    that cannot be recorded, or an installation that cannot be admitted,
    refuses the change with its code.
    """
    router = APIRouter(prefix=prefix, route_class=ConsoleRoute)

    async def governed(change: Awaitable[Any]) -> None:
        try:
            await change
        except ReaderRefused as refused:
            raise HTTPException(status_code=403, detail=refused.code) from None
        except InstallationRefused as refused:
            raise HTTPException(status_code=refused.status, detail=refused.code) from None
        except (GovernanceUnavailable, Refused) as refused:
            raise HTTPException(status_code=503, detail=refused.code) from None

    @router.post("/readers/designations", dependencies=[Depends(require_json)])
    async def designate(request: Request) -> dict[str, str]:
        body = await exact_body(request, {"signing", "signature", "scope", "contact"})
        signing, signature = _signed_act(body)
        scope = text_field(body, "scope")
        await governed(
            designations.designate(
                signing=signing,
                signature=signature,
                scope=scope,
                contact=text_field(body, "contact"),
            )
        )
        return {"scope": scope}

    @router.post("/readers/revocations", dependencies=[Depends(require_json)])
    async def revoke(request: Request) -> dict[str, str]:
        body = await exact_body(request, {"signing", "signature", "scope"})
        signing, signature = _signed_act(body)
        scope = text_field(body, "scope")
        await governed(designations.revoke(signing=signing, signature=signature, scope=scope))
        return {"scope": scope}

    return router
