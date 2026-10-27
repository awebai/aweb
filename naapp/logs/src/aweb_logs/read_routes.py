"""The reader's API on logs' console origin, and the reader slots members ask
for on its agent origin (audit-substrate.md §B5).

Every route needs a console session: a passkey login by a designated reader
(:mod:`aweb_logs.readers`). The session's scope names the one team it reads;
no request parameter can name another. The console origin refuses team-auth
outright (``split_origins``), so a member signature, an MCP identity or a
hosted session never reaches these routes.

- ``GET /v1/events``: the team's events, newest first. Query parameters are
  the exact-match filters of :class:`aweb_logs.read_store.EventFilter`, plus
  ``limit`` and ``cursor``.
- ``GET /v1/tail``: the events after ``after``, oldest first; without
  ``after``, the position to follow from.
- ``GET /v1/verify``: the integrity report of one chain epoch (the current one
  unless ``chain_epoch`` is given). ``POST /v1/verify`` also checks receipts
  and checkpoints given as ``{"signing": <base64>, "signature": <base64>}``.
  Verify returns no event content.

On the agent origin, ``POST /v1/reader-slots`` issues a pending reader slot
(:mod:`aweb_logs.readers`) to a member the installation grants
``logs.readers``, for the contact the owner will designate. A slot grants
nothing: only the owner act that names it designates a reader. Slots are
rate-limited per member.

On logs' console origin, the owner's signed acts designate and revoke readers.
"""

import base64
import binascii
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from aweb_naapp import ratelimit
from aweb_naapp.console import (
    ConsoleRoute,
    ConsoleSession,
    ConsoleSessions,
    exact_body,
    require_json,
    text_field,
)
from aweb_naapp.hooks.strictjson import Refused
from aweb_naapp.runtime.authorization import Authorization
from aweb_naapp.runtime.credential_audit import GovernanceUnavailable
from aweb_naapp.runtime.installation import InstallationFence, InstallationRefused
from fastapi import APIRouter, Depends, HTTPException, Request
from pgdbm import AsyncDatabaseManager

from aweb_logs.ledger import verify_epoch
from aweb_logs.read_store import DEFAULT_LIMIT, EventFilter, InvalidRead, Page, query, tail
from aweb_logs.readers import Reader, ReaderDesignations, ReaderDirectory, ReaderRefused

logger = logging.getLogger(__name__)

_PAGING = ("limit", "cursor", "after")
_MAX_ARTEFACTS = 1000
SLOT_BUCKET = "logs.reader_slots.member"
SLOT_LIMIT = 20
SLOT_WINDOW = timedelta(hours=1)


class ReaderReads:
    """What the reader routes read with: the database, the console sessions,
    the reader directory and logs' own receipt and checkpoint did:keys."""

    def __init__(
        self,
        db: AsyncDatabaseManager,
        *,
        sessions: ConsoleSessions,
        directory: ReaderDirectory,
        chain_keys: frozenset[str],
    ) -> None:
        self.db = db
        self.sessions = sessions
        self.directory = directory
        self.chain_keys = chain_keys


def reader_read_router(reads: ReaderReads) -> APIRouter:
    """The reader routes. Mount only on the console (human) origin."""
    router = APIRouter(route_class=ConsoleRoute)

    async def current_reader(
        session: Annotated[ConsoleSession, Depends(reads.sessions.current)],
    ) -> Reader:
        reader = await reads.directory.reader(session.scope)
        if reader is None:
            raise HTTPException(status_code=401, detail="console_session_required")
        return reader

    @router.get("/v1/events")
    async def events(
        request: Request, reader: Annotated[Reader, Depends(current_reader)]
    ) -> dict[str, Any]:
        where, paging = _read_query(request, allowed=("limit", "cursor"))
        page = await _read(
            query(
                reads.db,
                reader.team_id,
                where,
                limit=_limit(paging),
                before=paging.get("cursor"),
            )
        )
        return {"events": page.events, "next_cursor": page.next_cursor}

    @router.get("/v1/tail")
    async def follow(
        request: Request, reader: Annotated[Reader, Depends(current_reader)]
    ) -> dict[str, Any]:
        where, paging = _read_query(request, allowed=("limit", "after"))
        page = await _read(
            tail(reads.db, reader.team_id, where, after=paging.get("after"), limit=_limit(paging))
        )
        return {"events": page.events, "next_cursor": page.next_cursor}

    @router.get("/v1/verify")
    async def verify(
        reader: Annotated[Reader, Depends(current_reader)], chain_epoch: int | None = None
    ) -> dict[str, Any]:
        return await _verify(reads, reader, chain_epoch, receipts=[], checkpoints=[])

    @router.post("/v1/verify")
    async def verify_artefacts(
        request: Request, reader: Annotated[Reader, Depends(current_reader)]
    ) -> dict[str, Any]:
        body = await _json_object(request)
        if not set(body) <= {"chain_epoch", "receipts", "checkpoints"}:
            raise HTTPException(status_code=400, detail="request_invalid")
        chain_epoch = body.get("chain_epoch")
        if chain_epoch is not None and (
            not isinstance(chain_epoch, int) or isinstance(chain_epoch, bool)
        ):
            raise HTTPException(status_code=400, detail="request_invalid")
        return await _verify(
            reads,
            reader,
            chain_epoch,
            receipts=_artefacts(body.get("receipts", [])),
            checkpoints=_artefacts(body.get("checkpoints", [])),
        )

    return router


def _read_query(
    request: Request, *, allowed: tuple[str, ...]
) -> tuple[EventFilter, dict[str, str]]:
    items = request.query_params.multi_items()
    names = [name for name, _ in items]
    if len(names) != len(set(names)):
        raise HTTPException(status_code=400, detail=InvalidRead.code)
    paging = {name: value for name, value in items if name in _PAGING}
    if not set(paging) <= set(allowed):
        raise HTTPException(status_code=400, detail=InvalidRead.code)
    try:
        where = EventFilter.from_query({n: v for n, v in items if n not in _PAGING})
    except InvalidRead:
        raise HTTPException(status_code=400, detail=InvalidRead.code) from None
    return where, paging


def _limit(paging: dict[str, str]) -> int:
    text = paging.get("limit")
    if text is None:
        return DEFAULT_LIMIT
    if not text.isdigit() or text != str(int(text)):
        raise HTTPException(status_code=400, detail=InvalidRead.code)
    return int(text)


async def _read(page: Any) -> Page:
    try:
        result: Page = await page
    except InvalidRead:
        raise HTTPException(status_code=400, detail=InvalidRead.code) from None
    return result


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


def _artefacts(value: Any) -> list[tuple[bytes, str]]:
    if not isinstance(value, list) or len(value) > _MAX_ARTEFACTS:
        raise HTTPException(status_code=400, detail="request_invalid")
    artefacts = []
    for item in value:
        if (
            not isinstance(item, dict)
            or set(item) != {"signing", "signature"}
            or not isinstance(item["signing"], str)
            or not isinstance(item["signature"], str)
        ):
            raise HTTPException(status_code=400, detail="request_invalid")
        try:
            signing = base64.b64decode(item["signing"], validate=True)
        except (binascii.Error, ValueError):
            raise HTTPException(status_code=400, detail="request_invalid") from None
        artefacts.append((signing, item["signature"]))
    return artefacts


async def _verify(
    reads: ReaderReads,
    reader: Reader,
    chain_epoch: int | None,
    *,
    receipts: list[tuple[bytes, str]],
    checkpoints: list[tuple[bytes, str]],
) -> dict[str, Any]:
    if chain_epoch is None:
        chain_epoch = await reads.db.fetch_value(
            "SELECT chain_epoch FROM {{tables.chain_heads}} WHERE team_id = $1", reader.team_id
        )
        if chain_epoch is None:
            raise HTTPException(status_code=404, detail="no_chain")
    try:
        report = await verify_epoch(
            reads.db,
            reader.team_id,
            chain_epoch,
            receipt_keys=reads.chain_keys,
            checkpoint_keys=reads.chain_keys,
            receipts=receipts,
            checkpoints=checkpoints,
        )
    except LookupError:
        raise HTTPException(status_code=404, detail="no_chain") from None
    return {"chain_epoch": chain_epoch, **report}


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
