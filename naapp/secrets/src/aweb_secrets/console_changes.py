"""Human-only canonical drafts and fresh passkey confirmation, through B2/B3.

Draft envelope authority comes from S4 plus authoritative F6, never browser
scope/team/generation fields. Decisions and effects are separate transactions:
B3 verifies the fresh APPROVE assertion, then the sole ChangeSets.confirm
consumes that retained decision with its existing forest/B2/revision order.
No LOGIN credential lock is acquired late in that effect transaction. S4
checks the exact login on request entry; passkey retirement also voids its B2
decisions. A confirmation releases protected results only to its deciding owner.

This first HTTP slice exposes backend_credential changes only, whose required
proof-bound governance recording is implemented by ChangeSets. Other record
forms and their complete governance projection follow on this same writer.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

from aweb_naapp.console import ConsoleRoute, ConsoleSession
from aweb_naapp.hooks.producer import Registrations
from aweb_naapp.roles import hold_role
from aweb_naapp.runtime.approvals import ApprovalRefused, Approvals, Assurance, Decision
from aweb_naapp.runtime.installation import AdmittedInstallation, InstallationRefused
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pgdbm import TransactionManager

from aweb_secrets.change import ChangeRefused
from aweb_secrets.change_sets import ChangeSets, Confirmation
from aweb_secrets.console import OwnerConsole, _body, _require_json, _text
from aweb_secrets.console_results import owner_confirmation_result
from aweb_secrets.custody import SealContext
from aweb_secrets.owners import OWNER_ROLE, owner_scope
from aweb_secrets.revisions import config_revision

AfterCommit = Callable[[str, str, tuple[str, ...]], Awaitable[None]]
_LOG = logging.getLogger(__name__)


class ConsoleChanges:
    """Composition shares the console, B2, sole writer and hook registrations."""

    def __init__(
        self,
        *,
        console: OwnerConsole,
        changes: ChangeSets,
        approvals: Approvals,
        registrations: Registrations,
        after_commit: AfterCommit,
    ) -> None:
        self.console = console
        self.changes = changes
        self.approvals = approvals
        self.registrations = registrations
        self.after_commit = after_commit

    async def _installation(self, installation_id: str) -> AdmittedInstallation:
        admitted = await self.console.installation(installation_id)
        if admitted.installation_id != installation_id:
            raise HTTPException(403, "owner_required")
        return admitted

    @staticmethod
    def _supported(items: Any) -> None:
        if not isinstance(items, list):
            raise HTTPException(400, "request_invalid")
        if any(
            not isinstance(item, dict) or item.get("kind") != "backend_credential" for item in items
        ):
            raise HTTPException(409, "change_kind_not_applicable")

    @staticmethod
    def _unexpired(current: ConsoleSession) -> None:
        if current.expires_at <= datetime.now(UTC):
            raise HTTPException(401, "console_session_required")

    async def _owner(
        self,
        tx: TransactionManager,
        current: ConsoleSession,
        admitted: AdmittedInstallation,
    ) -> None:
        await self.console.fence.check(tx, admitted)
        owner = await self.console.directory.owner_of(tx, current.scope)
        if (
            owner is None
            or owner.team_id != admitted.team_id
            or current.scope
            != owner_scope(admitted.installation_id, admitted.team_id, owner.principal_did)
            or not await hold_role(tx, owner, OWNER_ROLE)
        ):
            raise HTTPException(403, "owner_required")
        self._unexpired(current)

    async def _row(
        self, tx: TransactionManager, admitted: AdmittedInstallation, change_id: str
    ) -> Any:
        row = await tx.fetch_one(
            "SELECT approval_id,request,state FROM {{tables.change_sets}}"
            " WHERE change_id=$1 AND installation_id=$2 AND team_id=$3",
            change_id,
            admitted.installation_id,
            admitted.team_id,
        )
        if row is None:
            raise HTTPException(404, "change_unknown")
        change = (
            json.loads(row["request"]) if isinstance(row["request"], str) else dict(row["request"])
        )
        self._supported(change["changes"])
        return row

    async def draft(
        self, current: ConsoleSession, installation_id: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        admitted = await self._installation(installation_id)
        self._supported(body["changes"])
        if not isinstance(body["sealed"], list):
            raise HTTPException(400, "request_invalid")
        sealed = []
        for value in body["sealed"]:
            if (
                not isinstance(value, dict)
                or set(value) != {"secret_id", "version"}
                or not isinstance(value["secret_id"], str)
                or type(value["version"]) is not int
                or value["version"] <= 0
            ):
                raise HTTPException(400, "request_invalid")
            sealed.append(
                SealContext(
                    admitted.installation_id, admitted.team_id, value["secret_id"], value["version"]
                )
            )
        issued = datetime.now(UTC).replace(microsecond=0)
        async with self.console.db.transaction() as tx:
            await self._owner(tx, current, admitted)
            if not await self.console.passkeys.login_evidence_is_current(
                current.scope,
                current.subject,
                current.evidence_ref,
                tx=tx,
            ):
                raise HTTPException(401, "console_session_required")
            change = {
                "v": 1,
                "type": "aweb.secrets.change",
                "change_id": "chg_" + uuid.uuid4().hex,
                "installation_id": admitted.installation_id,
                "install_generation": admitted.generation,
                "team_id": admitted.team_id,
                "drafter": {"via": "console", "scope": current.scope, "subject": current.subject},
                "base_revision": await config_revision(tx, admitted.installation_id),
                "changes": body["changes"],
                "reason": body["reason"],
                "issued_at": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "expires_at": (issued + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            pending = await self.changes.draft(tx, change, sealed=sealed)
            await self.console.fence.check(tx, admitted)
            self._unexpired(current)
        await self.approvals.deliver(pending)
        return {
            "change_id": change["change_id"],
            "approval_id": pending.approval.approval_id,
            "state": "pending",
        }

    async def read(
        self, current: ConsoleSession, installation_id: str, change_id: str
    ) -> dict[str, Any]:
        admitted = await self._installation(installation_id)
        async with self.console.db.transaction() as tx:
            await self._owner(tx, current, admitted)
            row = await self._row(tx, admitted, change_id)
        # This is the persisted frozen projection, not a reconstruction from live records.
        change = (
            json.loads(row["request"]) if isinstance(row["request"], str) else dict(row["request"])
        )
        return {"change": change, "approval_id": row["approval_id"], "state": row["state"]}

    async def _candidate(
        self, current: ConsoleSession, installation_id: str, change_id: str, token: str
    ) -> str:
        admitted = await self._installation(installation_id)
        async with self.console.db.transaction() as tx:
            await self._owner(tx, current, admitted)
            row = await self._row(tx, admitted, change_id)
        linked = await self.approvals.open_link(token)
        candidate = linked.approval.candidate(current.subject)
        if (
            linked.approval.approval_id != row["approval_id"]
            or candidate is None
            or candidate.scope != current.scope
        ):
            raise HTTPException(403, "owner_required")
        return row["approval_id"]

    async def options(
        self, current: ConsoleSession, installation_id: str, change_id: str, token: str
    ) -> Mapping[str, Any]:
        approval_id = await self._candidate(current, installation_id, change_id, token)
        return await self.approvals.challenge(
            approval_id,
            Decision.APPROVE,
            Assurance.PASSKEY,
            link_token=token,
        )

    async def approve(
        self, current: ConsoleSession, installation_id: str, change_id: str, body: dict[str, Any]
    ) -> dict[str, str]:
        if not isinstance(body["assertion"], dict):
            raise HTTPException(400, "request_invalid")
        approval_id = await self._candidate(
            current, installation_id, change_id, _text(body, "token")
        )
        # B3 verifies in its own transaction. Holding the login credential here
        # would block verification's update of that same credential. This only
        # records a decision; confirm rechecks current role/F6 and consumes it.
        approved = await self.approvals.decide(
            approval_id,
            Decision.APPROVE,
            Assurance.PASSKEY,
            body["assertion"],
            link_token=body["token"],
        )
        if approved.decided_by is None or (
            approved.decided_by.scope,
            approved.decided_by.subject,
        ) != (current.scope, current.subject):
            raise HTTPException(403, "owner_required")
        return {"approval_id": approval_id, "state": approved.state.value}

    async def confirm(
        self, current: ConsoleSession, installation_id: str, change_id: str
    ) -> Confirmation:
        admitted = await self._installation(installation_id)
        # The shared resolver may do network I/O. Fetch before authority locks.
        view = await self.registrations.view(admitted.team_id, "post-governance-hook")
        async with self.console.db.transaction() as tx:
            await self._owner(tx, current, admitted)
            row = await self._row(tx, admitted, change_id)
            approval = await self.approvals.get(row["approval_id"])
            if approval is None or approval.decided_by is None:
                raise HTTPException(409, "change_not_approved")
            if (approval.decided_by.scope, approval.decided_by.subject) != (
                current.scope,
                current.subject,
            ):
                raise HTTPException(403, "owner_required")
            confirmation = await self.changes.confirm(
                tx,
                change_id,
                operation_id="confirm-" + change_id,
                fence=self.console.fence,
                admitted=admitted,
                governance_view=view,
            )
            await self.console.fence.check(tx, admitted)
            self._unexpired(current)
        await self.changes.deliver(confirmation)
        try:
            await self.after_commit(
                confirmation.installation_id, confirmation.team_id, confirmation.affected_secret_ids
            )
        except Exception:
            # Authority already moved. Eviction is cleanup; never replay the effect.
            _LOG.warning("post-confirmation cache cleanup unavailable")
        return confirmation


@asynccontextmanager
async def _errors(console: OwnerConsole, current: ConsoleSession) -> AsyncIterator[None]:
    try:
        yield
    except HTTPException as refused:
        if refused.status_code == 401:
            await console.sessions.close(current)
            response = Response()
            console.sessions.clear_cookie(response)
            raise HTTPException(
                401,
                "console_session_required",
                headers={"Set-Cookie": response.headers["set-cookie"]},
            ) from None
        raise
    except InstallationRefused as refused:
        raise HTTPException(refused.status, refused.code) from None
    except LookupError:
        raise HTTPException(403, "owner_required") from None
    except ChangeRefused as refused:
        # Parser messages can contain submitted text. Codes never do.
        raise HTTPException(409, refused.code) from None
    except ApprovalRefused:
        raise HTTPException(409, "approval_refused") from None


def console_changes_router(services: ConsoleChanges, *, prefix: str = "") -> APIRouter:
    """Mount alongside the shared console only on the human origin."""
    router = APIRouter(prefix=prefix, route_class=ConsoleRoute)
    root = "/installations/{installation_id}/change-sets"

    @router.post(root, status_code=201, dependencies=[Depends(_require_json)])
    async def draft(installation_id: str, request: Request):
        current = await services.console.sessions.current(request)
        body = await _body(request, {"changes", "sealed", "reason"})
        async with _errors(services.console, current):
            return await services.draft(current, installation_id, body)

    @router.get(root + "/{change_id}")
    async def read(installation_id: str, change_id: str, request: Request):
        current = await services.console.sessions.current(request)
        async with _errors(services.console, current):
            return await services.read(current, installation_id, change_id)

    @router.post(root + "/{change_id}/approval-options", dependencies=[Depends(_require_json)])
    async def options(installation_id: str, change_id: str, request: Request):
        current = await services.console.sessions.current(request)
        body = await _body(request, {"token"})
        async with _errors(services.console, current):
            return await services.options(current, installation_id, change_id, _text(body, "token"))

    @router.post(root + "/{change_id}/approve", dependencies=[Depends(_require_json)])
    async def approve(installation_id: str, change_id: str, request: Request):
        current = await services.console.sessions.current(request)
        body = await _body(request, {"token", "assertion"})
        async with _errors(services.console, current):
            return await services.approve(current, installation_id, change_id, body)

    @router.post(root + "/{change_id}/confirm", dependencies=[Depends(_require_json)])
    async def confirm(installation_id: str, change_id: str, request: Request):
        current = await services.console.sessions.current(request)
        await _body(request, set())
        async with _errors(services.console, current):
            confirmation = await services.confirm(current, installation_id, change_id)
            # Recheck S4 after commit before releasing one-time runner codes.
            current = await services.console.sessions.current(request)
            return await owner_confirmation_result(
                services.console.db, services.console.directory, confirmation, current
            )

    return router
