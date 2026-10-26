"""Owner reconciliation pages; reads, decisions and settlement stay separate."""

from contextlib import asynccontextmanager
from dataclasses import asdict
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from urllib.parse import quote

import asyncpg
from aweb_naapp.console import ConsoleRoute, ConsoleSession
from aweb_naapp.dispatch import State
from aweb_naapp.roles import hold_role
from aweb_naapp.runtime.approvals import ApprovalRefused, Approvals, ApprovalState, Assurance
from aweb_naapp.runtime.installation import InstallationRefused
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, Response

from aweb_secrets.console import OwnerConsole, _body, _require_json, _text
from aweb_secrets.console_reconciliation.authority import ConsoleReconciliationFence
from aweb_secrets.console_ui import _login_redirect, _page, console_page
from aweb_secrets.console_use_approvals import _decision, _proof
from aweb_secrets.owners import OWNER_ROLE, owner_scope
from aweb_secrets.reconciliation_policy import reconciliation_request
from aweb_secrets.reconciliation_reads import ReconciliationReads
from aweb_secrets.reconciliation_service import ReconciliationControls, ReconciliationRefused
from aweb_secrets.use_audit import UseAuditUnavailable

_ROOT = "/reconciliation-approvals"
_ASSETS = Path(__file__).parent


@asynccontextmanager
async def _refusals():
    try:
        yield
    except ApprovalRefused:
        raise HTTPException(409, "approval_refused") from None
    except (InstallationRefused, ReconciliationRefused) as refused:
        raise HTTPException(refused.status, refused.code) from None
    except UseAuditUnavailable as refused:
        raise HTTPException(503, refused.code) from None
    except asyncpg.LockNotAvailableError:
        # Each failed transaction has unwound. Earlier committed mint/delivery
        # work stays committed; the browser must check status, never replay.
        raise HTTPException(503, "approval_busy") from None


class ConsoleReconciliation:
    def __init__(
        self,
        *,
        console: OwnerConsole,
        reads: ReconciliationReads,
        controls: ReconciliationControls,
        approvals: Approvals,
    ) -> None:
        self.console, self.reads, self.controls, self.approvals = (
            console,
            reads,
            controls,
            approvals,
        )

    async def _scope(self, scope):
        row = await self.console.db.fetch_one(
            "SELECT installation_id,team_id FROM {{tables.owner_principals}} WHERE scope=$1",
            scope,
        )
        if row is None:
            raise HTTPException(403, "owner_required")
        admitted = await self.console.installation(row["installation_id"])
        if (admitted.installation_id, admitted.team_id) != (row["installation_id"], row["team_id"]):
            raise HTTPException(403, "owner_required")
        return admitted

    async def _end(self, tx, current, admitted):
        # Read the exact persisted session again without acquiring B3 locks.
        row = await tx.fetch_one(
            "SELECT scope,subject,evidence_ref,expires_at,closed_at"
            " FROM {{tables.console_sessions}} WHERE token_sha256=$1",
            current.token_sha256,
        )
        if (
            row is None
            or row["closed_at"] is not None
            or (row["scope"], row["subject"], row["evidence_ref"], row["expires_at"])
            != (current.scope, current.subject, current.evidence_ref, current.expires_at)
        ):
            raise HTTPException(401, "console_session_required")
        await self.console.fence.check(tx, admitted)
        if current.expires_at <= datetime.now(UTC):
            raise HTTPException(401, "console_session_required")

    async def _owner(self, tx, current, admitted):
        await self.console.fence.check(tx, admitted)
        owner = await self.console.directory.owner_of(tx, current.scope)
        if (
            owner is None
            or owner.team_id != admitted.team_id
            or owner_scope(admitted.installation_id, owner.team_id, owner.principal_did)
            != current.scope
            or not await hold_role(tx, owner, OWNER_ROLE)
        ):
            raise HTTPException(403, "owner_required")
        await self._end(tx, current, admitted)

    async def record(self, current: ConsoleSession, reconcile_ref):
        admitted = await self._scope(current.scope)
        async with self.console.db.transaction() as tx:
            await self._owner(tx, current, admitted)
            view = await self.reads.get(tx, scope=admitted, reconcile_ref=reconcile_ref)
            if view is None:
                raise HTTPException(404, "reconciliation_not_found")
            await self._end(tx, current, admitted)
        return view

    async def status(self, current, approval_id):
        admitted = await self._scope(current.scope)
        async with self.console.db.transaction() as tx:
            await self._owner(tx, current, admitted)
            status = await self.controls.status(tx, scope=admitted, approval_id=approval_id)
            if status is None:
                raise HTTPException(404, "reconciliation_not_found")
            if (status.control.owner_scope, status.control.owner_subject) != (
                current.scope,
                current.subject,
            ):
                raise HTTPException(403, "owner_required")
            await self._end(tx, current, admitted)
        return status

    async def mint(self, current, reconcile_ref, outcome):
        admitted = await self._scope(current.scope)
        async with self.console.db.transaction() as tx:
            pending = await self.controls.mint(
                tx,
                reconcile_ref=reconcile_ref,
                outcome=outcome,
                fence=ConsoleReconciliationFence(
                    console=self.console, current=current, scope=admitted
                ),
            )
        await self.approvals.deliver(pending)
        # A separate checked transaction owns token release. PendingApproval is
        # internal throughout and is never passed to a response serializer.
        async with self.console.db.transaction() as tx:
            presentation = await self.controls.present(
                tx,
                pending=pending,
                fence=ConsoleReconciliationFence(
                    console=self.console, current=current, scope=admitted
                ),
            )
        return asdict(presentation)

    async def settle(self, current, approval_id):
        admitted = await self._scope(current.scope)
        async with self.console.db.transaction() as tx:
            receipt = await self.controls.settle(
                tx,
                approval_id=approval_id,
                fence=ConsoleReconciliationFence(
                    console=self.console, current=current, scope=admitted
                ),
            )
        return asdict(receipt)

    async def _linked(self, token):
        linked = await self.approvals.open_link(token)
        [candidate] = linked.approval.candidates
        admitted = await self._scope(candidate.scope)
        async with self.console.db.transaction() as tx:
            await self.console.fence.check(tx, admitted)
            status = await self.controls.status(
                tx, scope=admitted, approval_id=linked.approval.approval_id
            )
            if status is None or (status.control.owner_scope, status.control.owner_subject) != (
                candidate.scope,
                candidate.subject,
            ):
                raise HTTPException(409, "approval_refused")
            await self.console.fence.check(tx, admitted)
        return linked, status, admitted

    async def signin_scope(self, token):
        linked, _, _ = await self._linked(token)
        return {"scope": linked.approval.candidates[0].scope}

    async def _candidate(self, current, token):
        linked, status, admitted = await self._linked(token)
        if (status.control.owner_scope, status.control.owner_subject) != (
            current.scope,
            current.subject,
        ):
            raise HTTPException(403, "owner_required")
        await self.status(current, linked.approval.approval_id)
        return linked.approval.approval_id, status, admitted

    async def options(self, current, token, decision=None):
        approval_id, _, _ = await self._candidate(current, token)
        if decision is None:
            return await self.approvals.view_challenge(
                approval_id, Assurance.PASSKEY, link_token=token
            )
        return await self.approvals.challenge(
            approval_id, decision, Assurance.PASSKEY, link_token=token
        )

    async def view(self, current, token, proof):
        approval_id, status, _ = await self._candidate(current, token)
        viewed = await self.approvals.view(approval_id, Assurance.PASSKEY, proof, link_token=token)
        c = status.control
        if viewed.request != reconciliation_request(
            c.original,
            control_id=c.control_id,
            outcome=c.outcome,
            owner_scope=c.owner_scope,
            owner_subject=c.owner_subject,
        ):
            raise HTTPException(409, "approval_refused")
        return asdict(await self.status(current, approval_id))

    async def decide(self, current, token, proof, decision):
        approval_id, _, admitted = await self._candidate(current, token)
        # No credential-holding caller fence spans B3's fresh decision verify.
        # The dedicated shared control audit is local and has no target gate.
        async with self.console.db.transaction() as tx:
            await self._owner(tx, current, admitted)
            approval = await self.approvals.decide(
                approval_id, decision, Assurance.PASSKEY, proof, link_token=token, tx=tx
            )
            await self._end(tx, current, admitted)
        return {
            "approval_id": approval_id,
            "state": approval.state.value,
            "status_path": "/reconciliation-controls/" + quote(approval_id, safe=""),
        }


def _facts(original, *, outcome=None):
    rows = [
        ("Request reference", original.reconcile_ref),
        ("Request ID", original.request_id),
        ("Agent", original.requested_by),
        ("Dispatch ID", original.dispatch_id),
        ("Operation", original.operation_id),
        ("Job", original.job_id),
        ("Runner", original.runner_id),
        ("Chosen outcome", outcome),
    ]
    rows.extend(
        ("Secret version", f"{r.secret_ref or r.secret_id} · {r.version}")
        for r in original.resources
    )
    return (
        '<dl class="reconciliation-facts">'
        + "".join(
            f"<dt>{escape(name)}</dt><dd>{escape(str(value))}</dd>"
            for name, value in rows
            if value is not None
        )
        + "</dl>"
    )


def _assets():
    return (
        '<link rel="stylesheet" href="/console-reconciliation/reconciliation.css">'
        '<script src="/console-reconciliation/reconciliation.js" defer></script>'
    )


def console_reconciliation_router(*, services: ConsoleReconciliation) -> APIRouter:
    """Human app only, alongside the shared S4 shell and custody entry router."""
    router = APIRouter(route_class=ConsoleRoute)

    @router.get("/reconciliations/{reconcile_ref}", response_class=HTMLResponse)
    async def record_page(reconcile_ref: str, request: Request):
        try:
            current = await services.console.sessions.current(request)
        except HTTPException as refused:
            return _login_redirect(refused)
        async with _refusals():
            view = await services.record(current, reconcile_ref)
        body = "<h1>Resolve an uncertain outcome</h1>" + _facts(view.original)
        body += f"<p>Recorded state: {escape(view.state.value)}</p>"
        if view.state is State.OUTCOME_UNKNOWN:
            endpoint = "/reconciliations/" + quote(reconcile_ref, safe="") + "/controls"
            body += (
                "<p>Choose the outcome to record. Review and approve that choice with your passkey, "
                "then confirm settlement. The original operation will stay closed.</p>"
                f'<form id="reconciliation-choice" action="{escape(endpoint, quote=True)}" method="post">'
                '<label for="outcome">Outcome to record</label><select id="outcome" name="outcome">'
                '<option value="completed">Completed</option><option value="failed">Failed</option>'
                '<option value="unknown-closed">Close with outcome unknown</option></select>'
                '<button type="submit">Review this outcome</button></form>'
            )
        body += '<p id="reconciliation-status" role="status" tabindex="-1"></p>' + _assets()
        return console_page(title="Resolve an uncertain outcome", body_html=body, session=current)

    @router.get("/reconciliations/{reconcile_ref}/record")
    async def record_json(reconcile_ref: str, request: Request):
        current = await services.console.sessions.current(request)
        async with _refusals():
            return asdict(await services.record(current, reconcile_ref))

    @router.post(
        "/reconciliations/{reconcile_ref}/controls",
        dependencies=[Depends(_require_json)],
        status_code=201,
    )
    async def mint(reconcile_ref: str, request: Request):
        current = await services.console.sessions.current(request)
        body = await _body(request, {"outcome"})
        async with _refusals():
            return await services.mint(current, reconcile_ref, _text(body, "outcome"))

    @router.get("/reconciliation-controls/{approval_id}", response_class=HTMLResponse)
    async def control_page(approval_id: str, request: Request):
        try:
            current = await services.console.sessions.current(request)
        except HTTPException as refused:
            return _login_redirect(refused)
        async with _refusals():
            status = await services.status(current, approval_id)
        body = "<h1>Settlement status</h1>" + _facts(
            status.control.original, outcome=status.control.outcome
        )
        body += f"<p>Approval: {escape(status.approval_state.value)}. Original outcome: {escape(status.original_state.value)}.</p>"
        if (
            status.approval_state is ApprovalState.APPROVED
            and status.original_state is State.OUTCOME_UNKNOWN
        ):
            endpoint = "/reconciliation-controls/" + quote(approval_id, safe="") + "/settle"
            body += (
                f'<button id="settle-outcome" data-endpoint="{escape(endpoint, quote=True)}" type="button">'
                "Confirm settlement</button>"
            )
        body += (
            '<p id="reconciliation-status" role="status" tabindex="-1"></p><dl id="settlement-receipt"></dl>'
            + _assets()
        )
        return console_page(title="Settlement status", body_html=body, session=current)

    @router.get("/reconciliation-controls/{approval_id}/status")
    async def control_status(approval_id: str, request: Request):
        current = await services.console.sessions.current(request)
        async with _refusals():
            return asdict(await services.status(current, approval_id))

    @router.post(
        "/reconciliation-controls/{approval_id}/settle", dependencies=[Depends(_require_json)]
    )
    async def settle(approval_id: str, request: Request):
        current = await services.console.sessions.current(request)
        await _body(request, set())
        async with _refusals():
            return await services.settle(current, approval_id)

    @router.get(_ROOT, response_class=HTMLResponse)
    async def approval_page(request: Request):
        body = (
            '<div id="reconciliation-approval"><h1>Review an outcome</h1>'
            '<p id="reconciliation-status" role="status" tabindex="-1">Open your personal approval link to continue.</p>'
            '<button id="view-outcome" type="button" disabled>Review with your passkey</button>'
            '<section id="outcome-review" hidden><h2>Outcome for approval</h2><dl id="outcome-facts"></dl>'
            "<p>Approval records your chosen outcome. Confirm settlement in the next step to close the original record.</p>"
            '<button id="approve-outcome" type="button">Approve with your passkey</button> '
            '<button id="reject-outcome" type="button" class="secondary">Reject with your passkey</button></section>'
            '<a id="settlement-link" hidden>View settlement status</a></div>'
        ) + _assets()
        try:
            current = await services.console.sessions.current(request)
        except HTTPException as refused:
            if refused.status_code != 401:
                raise
            response = _page("Review an outcome", body)
            response.headers.update(refused.headers or {})
            return response
        return console_page(title="Review an outcome", body_html=body, session=current)

    @router.post(_ROOT + "/sign-in", dependencies=[Depends(_require_json)])
    async def signin(request: Request):
        body = await _body(request, {"token"})
        async with _refusals():
            return await services.signin_scope(_text(body, "token"))

    @router.post(_ROOT + "/view-options", dependencies=[Depends(_require_json)])
    async def view_options(request: Request):
        current = await services.console.sessions.current(request)
        body = await _body(request, {"token"})
        async with _refusals():
            return await services.options(current, _text(body, "token"))

    @router.post(_ROOT + "/view", dependencies=[Depends(_require_json)])
    async def view(request: Request):
        current = await services.console.sessions.current(request)
        body = await _body(request, {"token", "assertion"})
        async with _refusals():
            return await services.view(current, _text(body, "token"), _proof(body))

    @router.post(_ROOT + "/decision-options", dependencies=[Depends(_require_json)])
    async def decision_options(request: Request):
        current = await services.console.sessions.current(request)
        body = await _body(request, {"token", "decision"})
        async with _refusals():
            return await services.options(current, _text(body, "token"), _decision(body))

    @router.post(_ROOT + "/decide", dependencies=[Depends(_require_json)])
    async def decide(request: Request):
        current = await services.console.sessions.current(request)
        body = await _body(request, {"token", "assertion", "decision"})
        async with _refusals():
            return await services.decide(
                current, _text(body, "token"), _proof(body), _decision(body)
            )

    @router.get("/console-reconciliation/reconciliation.js")
    async def script_asset():
        return Response((_ASSETS / "reconciliation.js").read_text(), media_type="text/javascript")

    @router.get("/console-reconciliation/reconciliation.css")
    async def style_asset():
        return Response((_ASSETS / "reconciliation.css").read_text(), media_type="text/css")

    return router
