"""Owner-scoped configured access: which agent can use which secret, and on what terms.

Read-only. One REPEATABLE READ transaction holds the owner's F6, OWNER, LOGIN
and S4 authority before any configuration read, reads custody's confirmed
candidates for each configured principal with that principal's own secrets
roles, and ends with the live F6 and session-expiry checks. Coverage is
admission's own predicate. A listed row is configured access with its
conditions, never a promise that a future request will be admitted.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from typing import Any
from urllib.parse import quote

import asyncpg
from aweb_naapp.console import ConsoleRoute, ConsoleSession
from aweb_naapp.roles import PrincipalKey, hold_role, members_of, roles_of
from aweb_naapp.runtime.installation import AdmittedInstallation
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from pgdbm.core import TransactionManager

from aweb_secrets import access_reads, records
from aweb_secrets.admission import use_coverage_refusal
from aweb_secrets.console import OwnerConsole
from aweb_secrets.console_changes import _errors
from aweb_secrets.console_ui import _login_redirect, console_page
from aweb_secrets.grant import is_secrets_role
from aweb_secrets.owners import OWNER_ROLE, owner_scope
from aweb_secrets.principal_display import observed_principal_alias, principal_html
from aweb_secrets.revisions import config_revision
from aweb_secrets.run_planner import run_grant_covers_job

_ASSETS = Path(__file__).parent
OWNER_DEFINED_ROLE = "secrets.role."


@dataclass(frozen=True)
class UseAccess:
    """One named operation pin, or the open request when operation_id is None."""

    operation_id: str | None
    side_effect: str | None
    refusal: str | None

    @property
    def writes(self) -> bool:
        """Usable and not declared read-only: an open request declares no effect, so it may write."""
        return self.refusal is None and self.side_effect != "none"


@dataclass(frozen=True)
class RunAccess:
    """One job pin; covering it is never permission for a whole run."""

    job_id: str
    covered: bool
    source_refusal: str | None


@dataclass(frozen=True)
class Conditions:
    approval: str
    approve_only: bool
    approvers: Sequence[str]
    rate: Sequence[Mapping[str, Any]]
    windows: Mapping[str, Any] | None
    attestation: Mapping[str, Any] | None


@dataclass(frozen=True)
class GrantAccess:
    grant_id: str
    secret_id: str
    secret_ref: str
    sensitive: bool
    via_role: str | None
    uses: tuple[UseAccess, ...]
    runs: tuple[RunAccess, ...]
    conditions: Conditions | None

    @property
    def usable(self) -> bool:
        return any(u.refusal is None for u in self.uses) or any(r.covered for r in self.runs)

    @property
    def writes(self) -> bool:
        return any(u.writes for u in self.uses)


@dataclass(frozen=True)
class AgentAccess:
    principal_did: str
    alias: str | None
    grants: tuple[GrantAccess, ...]

    @property
    def flags(self) -> tuple[str, ...]:
        sensitive = any(g.sensitive and g.usable for g in self.grants)
        writes = any(g.writes for g in self.grants)
        return tuple(f for f, on in (("sensitive", sensitive), ("write", writes)) if on)


@dataclass(frozen=True)
class AccessView:
    installation_id: str
    team_id: str
    revision: int
    secret_ref: str | None
    agents: tuple[AgentAccess, ...]


def _grant_access(candidate: access_reads.GrantAccessCandidate) -> GrantAccess:
    secret, grant, policy = candidate.secret, candidate.grant, candidate.policy
    sensitivity = secret.record.sensitivity
    enabled = secret.state == "active" and secret.active_version is not None

    def refusal(operation_id: str | None, current) -> str | None:
        if not enabled:
            return "secret_disabled"
        if policy is None:
            return "policy_unavailable"
        return use_coverage_refusal(
            grant, policy, operation_id=operation_id, operation=current, sensitivity=sensitivity
        )

    uses: list[UseAccess] = []
    if grant.capability == "use":
        if grant.open_request:
            uses.append(UseAccess(None, None, refusal(None, None)))
        for pin in candidate.operations:
            side_effect = None if pin.current is None else pin.current.after["side_effect"]
            uses.append(
                UseAccess(pin.operation_id, side_effect, refusal(pin.operation_id, pin.current))
            )
    runs = tuple(
        RunAccess(
            pin.job_id,
            enabled
            and policy is not None
            and pin.current is not None
            and run_grant_covers_job(grant, pin.current),
            pin.source_refusal,
        )
        for pin in candidate.jobs
        if grant.capability == "run"
    )
    conditions = (
        None
        if policy is None
        else Conditions(
            approval=policy.body["approval"],
            approve_only=secret.record.approve_only,
            approvers=tuple(policy.body["approvers"]),
            rate=tuple(policy.body["rate"]),
            windows=policy.body["windows"],
            attestation=policy.body["requires_attestation"],
        )
    )
    return GrantAccess(
        grant_id=grant.grant_id,
        secret_id=secret.record.secret_id,
        secret_ref=secret.record.ref,
        sensitive=sensitivity == "sensitive",
        via_role=grant.subject_role,
        uses=tuple(uses),
        runs=runs,
        conditions=conditions,
    )


class ConsoleAccess:
    def __init__(self, *, console: OwnerConsole) -> None:
        self.console = console

    async def view(self, current: ConsoleSession, *, secret_ref: str | None = None) -> AccessView:
        installation_id = await self.console.db.fetch_value(
            "SELECT installation_id FROM {{tables.owner_principals}} WHERE scope=$1", current.scope
        )
        if installation_id is None:
            raise HTTPException(403, "owner_required")
        admitted = await self.console.installation(installation_id)
        try:
            async with self.console.db.transaction() as tx:
                await tx.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                await self._hold(tx, current, admitted, installation_id)
                secret_id = None
                if secret_ref is not None:
                    stored = await records.secret_by_ref(
                        tx, installation_id, admitted.team_id, secret_ref, lock=False
                    )
                    if stored is None:
                        raise HTTPException(404, "secret_not_found")
                    secret_id = stored.record.secret_id
                agents = await self._agents(tx, admitted, secret_id)
                revision = await config_revision(tx, installation_id)
                await self.console.fence.check(tx, admitted)
                # No awaited work follows the final live F6 and S4 deadline samples.
                if current.expires_at <= datetime.now(UTC):
                    raise HTTPException(401, "console_session_required")
        except asyncpg.SerializationError:
            # A narrowing committed after this snapshot. A fresh request reads it.
            raise HTTPException(409, "access_changed", headers={"Retry-After": "0"}) from None
        return AccessView(installation_id, admitted.team_id, revision, secret_ref, agents)

    async def _hold(
        self,
        tx: TransactionManager,
        current: ConsoleSession,
        admitted: AdmittedInstallation,
        installation_id: str,
    ) -> None:
        """F6, then OWNER, then the exact LOGIN credential, then the S4 session row."""
        await self.console.fence.check(tx, admitted)
        owner = await self.console.directory.owner_of(tx, current.scope)
        if (
            owner is None
            or owner.team_id != admitted.team_id
            or admitted.installation_id != installation_id
            or current.scope != owner_scope(installation_id, admitted.team_id, owner.principal_did)
            or not await hold_role(tx, owner, OWNER_ROLE)
        ):
            raise HTTPException(403, "owner_required")
        if not await self.console.passkeys.login_evidence_is_current(
            current.scope, current.subject, current.evidence_ref, tx=tx
        ):
            raise HTTPException(401, "console_session_required")
        row = await tx.fetch_one(
            "SELECT scope,subject,evidence_ref,expires_at,closed_at"
            " FROM {{tables.console_sessions}} WHERE token_sha256=$1 FOR SHARE",
            current.token_sha256,
        )
        if (
            row is None
            or row["closed_at"] is not None
            or (row["scope"], row["subject"], row["evidence_ref"], row["expires_at"])
            != (current.scope, current.subject, current.evidence_ref, current.expires_at)
        ):
            raise HTTPException(401, "console_session_required")

    async def _agents(
        self, tx: TransactionManager, admitted: AdmittedInstallation, secret_id: str | None
    ) -> tuple[AgentAccess, ...]:
        subjects = await access_reads.configured_subjects(tx, admitted, secret_id=secret_id)
        principals = set(subjects.direct_principals)
        for role in subjects.roles:
            principals.update(m.principal_did for m in await members_of(tx, admitted.team_id, role))
        agents = []
        for principal_did in sorted(principals):
            key = PrincipalKey(team_id=admitted.team_id, principal_did=principal_did)
            roles = [role for role in await roles_of(tx, key) if is_secrets_role(role)]
            confirmed = await access_reads.confirmed_access(
                tx, admitted, principal_did=principal_did, roles=roles, secret_id=secret_id
            )
            if not confirmed.candidates:
                continue
            alias = await observed_principal_alias(
                tx, team_id=admitted.team_id, principal_did=principal_did
            )
            grants = tuple(_grant_access(candidate) for candidate in confirmed.candidates)
            agents.append(AgentAccess(principal_did, alias, grants))
        # Flagged agents first, so the riskiest access is the first thing seen.
        return tuple(sorted(agents, key=lambda a: (-len(a.flags), a.principal_did)))


_FLAGS = {"write": "Can write", "sensitive": "Sensitive secret"}
_REFUSALS = {
    "operation_not_allowed": "not usable: this operation's current definition is not granted",
    "open_request_not_allowed": "not usable: open requests are not allowed here",
    "token_issuing_denied": "not usable: it issues tokens this policy denies",
    "secret_disabled": "not usable: the secret is disabled",
    "policy_unavailable": "not usable: its policy cannot be read",
}


def _flags(flags: Sequence[str]) -> str:
    return "".join(
        f'<span class="flag flag-{escape(flag, quote=True)}">{escape(_FLAGS[flag])}</span>'
        for flag in flags
    )


def _use(agent: AgentAccess, grant: GrantAccess, use: UseAccess) -> str:
    attributes = (
        f' data-principal-did="{escape(agent.principal_did, quote=True)}"'
        f' data-grant-id="{escape(grant.grant_id, quote=True)}"'
        f' data-covered="{"true" if use.refusal is None else "false"}"'
    )
    if use.operation_id is None:
        name = "Any request"
    else:
        name = f"<code>{escape(use.operation_id)}</code>"
        attributes += f' data-operation-id="{escape(use.operation_id, quote=True)}"'
    if use.side_effect is not None:
        attributes += f' data-side-effect="{escape(use.side_effect, quote=True)}"'
    if use.refusal is not None:
        detail = escape(_REFUSALS.get(use.refusal, "not usable"))
    elif use.side_effect is None:
        detail = '<span class="flag flag-write">May write (effect not declared)</span>'
    elif use.writes:
        detail = f'<span class="flag flag-write">Writes ({escape(use.side_effect)})</span>'
    else:
        detail = "read-only"
    return f'<li class="access-use"{attributes}>{name} — {detail}</li>'


def _run(agent: AgentAccess, grant: GrantAccess, run: RunAccess) -> str:
    detail = (
        "can run" if run.covered else "not usable: this job's current definition is not granted"
    )
    if run.covered and run.source_refusal is not None:
        detail += " (a required credential is missing)"
    return (
        f'<li class="access-run" data-principal-did="{escape(agent.principal_did, quote=True)}"'
        f' data-grant-id="{escape(grant.grant_id, quote=True)}"'
        f' data-job-id="{escape(run.job_id, quote=True)}"'
        f' data-covered="{"true" if run.covered else "false"}">'
        f"Job <code>{escape(run.job_id)}</code> — {escape(detail)}</li>"
    )


def _conditions(conditions: Conditions | None) -> str:
    if conditions is None:
        return ""
    approval = (
        "every use needs approval"
        if conditions.approval == "per_use" or conditions.approve_only
        else "none"
    )
    items = [("Approval", approval)]
    if conditions.rate:
        items.append(
            (
                "Rate limit",
                "; ".join(
                    f"{r['capacity']} per {r['window_s']} s"
                    f" ({'per agent' if r['per'] == 'principal_secret' else 'all agents'})"
                    for r in conditions.rate
                ),
            )
        )
    if conditions.windows is not None:
        ranges = "; ".join(
            f"{', '.join(w['days'])} {w['from']}–{w['to']}" for w in conditions.windows["ranges"]
        )
        items.append(("Allowed times", f"{ranges} ({conditions.windows['time_zone']})"))
    if conditions.attestation is not None:
        items.append(("Attestation", "required"))
    return (
        '<dl class="access-conditions">'
        + "".join(f"<dt>{escape(k)}</dt><dd>{escape(v)}</dd>" for k, v in items)
        + "</dl>"
    )


def _remove_member(view: AccessView, agent: AgentAccess, role: str) -> str:
    """Containment's remove-role-member: this agent leaves an owner-defined role, others stay."""
    return (
        '<button type="button" class="access-remove-member secondary"'
        f' data-role="{escape(role, quote=True)}"'
        f' data-principal-did="{escape(agent.principal_did, quote=True)}"'
        f' data-installation-id="{escape(view.installation_id, quote=True)}">'
        f"Remove this agent from the role {escape(role)}</button>"
    )


def _grant(view: AccessView, agent: AgentAccess, grant: GrantAccess, *, removable: bool) -> str:
    role = (
        "" if grant.via_role is None else f' data-via-role="{escape(grant.via_role, quote=True)}"'
    )
    origin = (
        "Granted directly to this agent"
        if grant.via_role is None
        else f"Through the role <code>{escape(grant.via_role)}</code>"
    )
    revoke_label = (
        "Revoke this grant"
        if grant.via_role is None
        else "Revoke this grant for everyone in the role"
    )
    href = "/access/secrets/" + quote(grant.secret_ref, safe="")
    sensitive = '<span class="flag flag-sensitive">Sensitive</span>' if grant.sensitive else ""
    return (
        f'<article class="access-grant" data-principal-did="{escape(agent.principal_did, quote=True)}"'
        f' data-grant-id="{escape(grant.grant_id, quote=True)}"'
        f' data-secret-id="{escape(grant.secret_id, quote=True)}"{role}>'
        f'<h3><a href="{escape(href, quote=True)}">{escape(grant.secret_ref)}</a> {sensitive}</h3>'
        f'<p class="access-origin">{origin} · grant <code>{escape(grant.grant_id)}</code></p>'
        "<ul>"
        + "".join(_use(agent, grant, use) for use in grant.uses)
        + "".join(_run(agent, grant, run) for run in grant.runs)
        + "</ul>"
        + _conditions(grant.conditions)
        + '<div class="access-actions">'
        + f'<button type="button" class="access-revoke secondary"'
        f' data-grant-id="{escape(grant.grant_id, quote=True)}"'
        f' data-installation-id="{escape(view.installation_id, quote=True)}">'
        f"{escape(revoke_label)}</button>"
        + (_remove_member(view, agent, grant.via_role) if removable and grant.via_role else "")
        + "</div></article>"
    )


def _render(view: AccessView) -> str:
    if view.secret_ref is None:
        heading = "<h1>Access</h1>"
        intro = "Which agents can use your team’s secrets, and on what terms."
    else:
        heading = f"<h1>Access to <code>{escape(view.secret_ref)}</code></h1>"
        intro = 'Which agents can use this secret. <a href="/access">All access</a>'
    parts = [
        heading,
        f"<p>{intro}</p>",
        '<p class="access-note">This is the confirmed configuration'
        f" (revision {view.revision}). Every request is still checked when it is made,"
        " including approvals, rate limits and allowed times.</p>",
        '<p id="notice" role="status"></p>',
    ]
    if not view.agents:
        parts.append('<p id="access-empty">No agent can use these secrets.</p>')
    for agent in view.agents:
        # One removal per owner-defined role ends every grant the agent holds through it.
        # The owner role is left to the owner designation and retirement ceremonies.
        roles = [g.via_role for g in agent.grants]
        removable = [
            g.via_role is not None
            and g.via_role.startswith(OWNER_DEFINED_ROLE)
            and roles.index(g.via_role) == i
            for i, g in enumerate(agent.grants)
        ]
        label = principal_html(
            principal_did=agent.principal_did, alias=agent.alias, team_id=view.team_id
        )
        parts.append(
            f'<section class="access-agent" data-principal-did="{escape(agent.principal_did, quote=True)}"'
            f' data-flags="{escape(" ".join(agent.flags), quote=True)}">'
            f'<h2>{label}</h2><p class="access-flags">{_flags(agent.flags)}</p>'
            + "".join(
                _grant(view, agent, grant, removable=r)
                for grant, r in zip(agent.grants, removable, strict=True)
            )
            + "</section>"
        )
    parts.append('<link rel="stylesheet" href="/console-access/access.css">')
    parts.append('<script src="/console-access/access.js" defer></script>')
    return "".join(parts)


def console_access_router(*, services: ConsoleAccess) -> APIRouter:
    """Human app only; inject the same OwnerConsole the other owner pages use."""
    router = APIRouter(route_class=ConsoleRoute)

    async def page(request: Request, secret_ref: str | None) -> Response:
        try:
            current = await services.console.sessions.current(request)
        except HTTPException as refused:
            return _login_redirect(refused)
        async with _errors(services.console, current):
            view = await services.view(current, secret_ref=secret_ref)
        title = "Access" if secret_ref is None else f"Access to {secret_ref}"
        return console_page(title=title, body_html=_render(view), session=current)

    @router.get("/access", response_class=HTMLResponse)
    async def agents(request: Request) -> Response:
        return await page(request, None)

    @router.get("/access/secrets/{secret_ref}", response_class=HTMLResponse)
    async def secret(request: Request, secret_ref: str) -> Response:
        return await page(request, secret_ref)

    @router.get("/console-access/access.css")
    async def style() -> Response:
        return Response((_ASSETS / "access.css").read_text(), media_type="text/css")

    @router.get("/console-access/access.js")
    async def script() -> Response:
        return Response((_ASSETS / "access.js").read_text(), media_type="text/javascript")

    return router
