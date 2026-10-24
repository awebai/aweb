"""Human use/run approval review and decisions; these routes never dispatch.

Custody owns /approvals and dispatches personal links to /use-approvals or
/run-approvals. B2 owns frozen requests, eligibility and first-decision wins;
B3 owns distinct VIEW, APPROVE and REJECT proofs. S4 supplies the same live
console session and tab CSRF checks as the rest of the human console.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from aweb_naapp.console import ConsoleRoute, ConsoleSession
from aweb_naapp.runtime.approvals import Approvals, Assurance, Decision
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, Response

from aweb_secrets.console import OwnerConsole, _body, _require_json, _text
from aweb_secrets.console_changes import _errors
from aweb_secrets.console_ui import _page, console_page
from aweb_secrets.run_approvals import run_approval_view
from aweb_secrets.run_plan import RunPlanRefused
from aweb_secrets.use_approval import UseApprovalRefused, use_approval_view

Kind = Literal["use", "run"]
_ASSETS = Path(__file__).parent


class ConsoleUseApprovals:
    def __init__(self, *, console: OwnerConsole, approvals: Approvals) -> None:
        self.console, self.approvals = console, approvals

    async def _linked(self, token: str, kind: Kind):
        linked = await self.approvals.open_link(token)
        # Table names are fixed code, never interpolated request input.
        table = "use_approvals" if kind == "use" else "run_slot_approvals"
        row = await self.console.db.fetch_one(
            "SELECT installation_id,team_id,request FROM {{tables."
            + table
            + "}} WHERE approval_id=$1",
            linked.approval.approval_id,
        )
        if row is None:
            raise HTTPException(404, "approval_unknown")
        frozen = json.loads(row["request"])
        admitted = await self.console.installation(row["installation_id"])
        if (
            admitted.installation_id != row["installation_id"]
            or admitted.team_id != row["team_id"]
            or (frozen["installation_id"], frozen["team_id"], frozen["install_generation"])
            != (admitted.installation_id, admitted.team_id, admitted.generation)
            or frozen["type"] != "aweb.secrets.use-approval"
            or frozen["action"] != ("broker" if kind == "use" else "run_job")
        ):
            raise HTTPException(409, "approval_unavailable")
        async with self.console.db.transaction() as tx:
            await self.console.fence.check(tx, admitted)
        return linked, admitted, frozen

    async def signin_scope(self, token: str, *, kind: Kind) -> dict[str, str]:
        """A personal sign-in locator, without disclosing any request terms."""
        linked, _, _ = await self._linked(token, kind)
        [candidate] = linked.approval.candidates
        return {"scope": candidate.scope}

    async def _candidate(self, current: ConsoleSession, token: str, kind: Kind):
        linked, admitted, frozen = await self._linked(token, kind)
        [candidate] = linked.approval.candidates
        if (candidate.scope, candidate.subject) != (current.scope, current.subject):
            raise HTTPException(403, "approver_required")
        if current.expires_at <= datetime.now(UTC):
            raise HTTPException(401, "console_session_required")
        return linked.approval.approval_id, admitted, frozen

    async def options(
        self, current: ConsoleSession, token: str, *, kind: Kind, decision: Decision | None
    ):
        approval_id, _, _ = await self._candidate(current, token, kind)
        if decision is None:
            return await self.approvals.view_challenge(
                approval_id, Assurance.PASSKEY, link_token=token
            )
        return await self.approvals.challenge(
            approval_id, decision, Assurance.PASSKEY, link_token=token
        )

    async def view(self, current: ConsoleSession, token: str, proof: dict, *, kind: Kind):
        approval_id, admitted, frozen = await self._candidate(current, token, kind)
        linked = await self.approvals.view(approval_id, Assurance.PASSKEY, proof, link_token=token)
        if linked.request != frozen:
            raise HTTPException(409, "approval_unavailable")
        async with self.console.db.transaction() as tx:
            await self.console.fence.check(tx, admitted)
            if current.expires_at <= datetime.now(UTC):
                raise HTTPException(401, "console_session_required")
            if kind == "run":
                view = await run_approval_view(
                    tx,
                    installation_id=admitted.installation_id,
                    team_id=admitted.team_id,
                    approval_id=approval_id,
                )
                if view is None:
                    raise HTTPException(409, "approval_unavailable")
            else:
                view = use_approval_view(linked.request)
        return {
            "approval_id": approval_id,
            "state": linked.approval.state.value,
            "view": asdict(view),
        }

    async def decide(
        self, current: ConsoleSession, token: str, proof: dict, *, kind: Kind, decision: Decision
    ):
        approval_id, admitted, _ = await self._candidate(current, token, kind)
        # No LOGIN credential lock spans B3 verification (its separate tx updates
        # that credential). The final decision uses B2's caller-tx seam so F6
        # stays held through the decision and its audit, never through dispatch.
        async with self.console.db.transaction() as tx:
            await self.console.fence.check(tx, admitted)
            approved = await self.approvals.decide(
                approval_id, decision, Assurance.PASSKEY, proof, link_token=token, tx=tx
            )
            if current.expires_at <= datetime.now(UTC):
                raise HTTPException(401, "console_session_required")
        return {"approval_id": approval_id, "state": approved.state.value}


def _decision(body: dict[str, Any]) -> Decision:
    try:
        return Decision(_text(body, "decision"))
    except ValueError:
        raise HTTPException(400, "request_invalid") from None


def _proof(body: dict[str, Any]) -> dict:
    if not isinstance(body["assertion"], dict):
        raise HTTPException(400, "request_invalid")
    return body["assertion"]


def _router(services: ConsoleUseApprovals, kind: Kind) -> APIRouter:
    router = APIRouter(route_class=ConsoleRoute)
    root = "/use-approvals" if kind == "use" else "/run-approvals"
    title = "Review a secret use" if kind == "use" else "Review a job credential"
    script = '<script src="/console-use-approvals/approvals.js" defer></script>'
    content = (
        f'<div id="use-approval" data-root="{root}"><h1>{title}</h1>'
        '<p id="approval-status" role="status" aria-live="polite">'
        "Open the approval link sent to your registered contact.</p>"
        '<button id="view-request" type="button" disabled>Review with your passkey</button>'
        '<section id="request-review" hidden><h2>Request for approval</h2>'
        '<dl id="request-facts"></dl><div id="request-action"></div>'
        '<h2>Reason supplied by the requester (untrusted)</h2><pre id="request-reason"></pre>'
        "<p>Approving records your decision. The agent must resubmit the request to continue.</p>"
        '<button id="approve-request" type="button">Approve with your passkey</button> '
        '<button id="reject-request" class="secondary" type="button">Reject with your passkey</button>'
        "</section></div>" + script
    )

    @router.get(root, response_class=HTMLResponse)
    async def page(request: Request) -> Response:
        try:
            current = await services.console.sessions.current(request)
        except HTTPException as refused:
            if refused.status_code != 401:
                raise
            result = _page(title, content)
            result.headers.update(refused.headers or {})
            return result
        return console_page(title=title, body_html=content, session=current)

    @router.post(root + "/sign-in", dependencies=[Depends(_require_json)])
    async def signin(request: Request):
        body = await _body(request, {"token"})
        # A sign-in hint needs no authenticated session, just like /login/options.
        from aweb_naapp.runtime.approvals import ApprovalRefused
        from aweb_naapp.runtime.installation import InstallationRefused

        try:
            return await services.signin_scope(_text(body, "token"), kind=kind)
        except ApprovalRefused:
            raise HTTPException(409, "approval_refused") from None
        except InstallationRefused as refused:
            raise HTTPException(refused.status, refused.code) from None
        except LookupError:
            raise HTTPException(409, "approval_unavailable") from None

    @router.post(root + "/view-options", dependencies=[Depends(_require_json)])
    async def view_options(request: Request):
        current = await services.console.sessions.current(request)
        body = await _body(request, {"token"})
        async with _errors(services.console, current):
            return await services.options(current, _text(body, "token"), kind=kind, decision=None)

    @router.post(root + "/view", dependencies=[Depends(_require_json)])
    async def view(request: Request):
        current = await services.console.sessions.current(request)
        body = await _body(request, {"token", "assertion"})
        async with _errors(services.console, current):
            try:
                return await services.view(current, _text(body, "token"), _proof(body), kind=kind)
            except (UseApprovalRefused, RunPlanRefused):
                raise HTTPException(409, "approval_unavailable") from None

    @router.post(root + "/decision-options", dependencies=[Depends(_require_json)])
    async def decision_options(request: Request):
        current = await services.console.sessions.current(request)
        body = await _body(request, {"token", "decision"})
        async with _errors(services.console, current):
            return await services.options(
                current, _text(body, "token"), kind=kind, decision=_decision(body)
            )

    @router.post(root + "/decide", dependencies=[Depends(_require_json)])
    async def decide(request: Request):
        current = await services.console.sessions.current(request)
        body = await _body(request, {"token", "decision", "assertion"})
        async with _errors(services.console, current):
            return await services.decide(
                current, _text(body, "token"), _proof(body), kind=kind, decision=_decision(body)
            )

    if kind == "use":

        @router.get("/console-use-approvals/approvals.js")
        async def script_asset() -> Response:
            return Response((_ASSETS / "approvals.js").read_text(), media_type="text/javascript")

    return router


def console_use_approvals_router(*, services: ConsoleUseApprovals) -> APIRouter:
    """Human-only /use-approvals page and ceremonies; mount with run router."""
    return _router(services, "use")


def console_run_approvals_router(*, services: ConsoleUseApprovals) -> APIRouter:
    """Human-only /run-approvals page and ceremonies; mount with use router."""
    return _router(services, "run")
