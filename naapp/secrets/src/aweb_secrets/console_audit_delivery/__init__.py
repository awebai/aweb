"""Owner-scoped audit delivery faults: stalled audit targets and undelivered events.

Read-only. Core's registration views are fetched before the transaction, as
admission fetches them. One REPEATABLE READ transaction then holds the owner's
F6, OWNER, LOGIN and S4 authority before reading this team's hook outbox, and
ends with the live F6 and session-expiry checks. A target's backlog comes from
the kit reader the admission gate decides from, so the page shows the same
condition that refuses uses and widening changes.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from html import escape
from pathlib import Path
from typing import Literal

import asyncpg
from aweb_naapp.console import ConsoleRoute, ConsoleSession
from aweb_naapp.hooks.producer import (
    HOOKS_CHANNEL,
    Backlog,
    Registrations,
    RegistrationView,
    hook_backlog,
    owed_registrations,
)
from aweb_naapp.hooks.strictjson import Refused
from aweb_naapp.outbox import UndeliveredEvent, undelivered_critical_events
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, Response

from aweb_secrets.console import OwnerConsole
from aweb_secrets.console_access import hold_owner, owner_installation
from aweb_secrets.console_changes import _errors
from aweb_secrets.console_ui import _login_redirect, console_page, recovery_page

_ASSETS = Path(__file__).parent

# Each hook secrets produces: its records, one record, and what its gate refuses.
HOOKS = {
    "post-secret-use-hook": ("Secret use records", "Secret use record", "Secret uses"),
    "post-governance-hook": ("Change records", "Change record", "Changes that widen access"),
}

Admission = Literal["open", "refused", "unavailable"]


@dataclass(frozen=True)
class TargetHealth:
    backlog: Backlog
    stalled: bool


@dataclass(frozen=True)
class HookHealth:
    hook: str
    admission: Admission
    targets: tuple[TargetHealth, ...]


@dataclass(frozen=True)
class AuditDeliveryView:
    hooks: tuple[HookHealth, ...]
    undelivered: tuple[UndeliveredEvent, ...]
    target_labels: dict[str, str]


class ConsoleAuditDelivery:
    def __init__(
        self,
        *,
        console: OwnerConsole,
        registrations: Registrations,
        max_backlog_age: timedelta,
    ) -> None:
        if max_backlog_age <= timedelta(0):
            raise ValueError("max_backlog_age must be positive")
        self.console = console
        self.registrations = registrations
        self.max_backlog_age = max_backlog_age

    async def view(self, current: ConsoleSession) -> AuditDeliveryView:
        installation_id, admitted = await owner_installation(self.console, current)
        # Core's views may refresh over the network: read them before any lock.
        views = {hook: await self.registrations.view(admitted.team_id, hook) for hook in HOOKS}
        try:
            async with self.console.db.transaction() as tx:
                await tx.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                await hold_owner(self.console, tx, current, admitted, installation_id)
                hooks = tuple(
                    [await self._health(tx, admitted.team_id, hook, views[hook]) for hook in HOOKS]
                )
                undelivered = await undelivered_critical_events(
                    tx, channel=HOOKS_CHANNEL, team_id=admitted.team_id
                )
                await self.console.fence.check(tx, admitted)
                # No awaited work follows the final live F6 and S4 deadline samples.
                if current.expires_at <= datetime.now(UTC):
                    raise HTTPException(401, "console_session_required")
        except asyncpg.SerializationError:
            raise HTTPException(
                409, "audit_delivery_changed", headers={"Retry-After": "0"}
            ) from None
        labels = {
            r.binding_id: r.origin + r.path
            for view in views.values()
            if view is not None
            for r in view.registrations
        }
        return AuditDeliveryView(hooks, tuple(reversed(undelivered)), labels)

    async def _health(
        self, tx, team_id: str, hook: str, view: RegistrationView | None
    ) -> HookHealth:
        now = datetime.now(UTC)
        try:
            owed = owed_registrations(hook, team_id, now, now, view)
        except Refused:
            return HookHealth(hook, "unavailable", ())
        backlog = await hook_backlog(tx, team_id=team_id, hook=hook, registrations=owed)
        now = datetime.now(UTC)
        targets = tuple(
            TargetHealth(b, not b.is_current(now, self.max_backlog_age)) for b in backlog
        )
        admission: Admission = "refused" if all(t.stalled for t in targets) else "open"
        return HookHealth(hook, admission, targets)


def _time(moment: datetime) -> str:
    moment = moment.astimezone(UTC)
    return f'<time datetime="{moment.isoformat()}">{moment.strftime("%Y-%m-%d %H:%M")} UTC</time>'


def _admission(hook: HookHealth) -> str:
    _, _, blocks = HOOKS[hook.hook]
    if hook.admission == "open":
        return f'<p class="audit-admission">{escape(blocks)} are being recorded.</p>'
    reason = (
        "no audit target is available"
        if hook.admission == "unavailable"
        else "every audit target has stalled"
    )
    return (
        f'<p class="audit-admission"><span class="pill stop">Refused</span> '
        f"{escape(blocks)} are refused: {reason}.</p>"
    )


def _target(view: AuditDeliveryView, target: TargetHealth) -> str:
    binding = target.backlog.registration.binding_id
    label = view.target_labels.get(binding, binding)
    oldest = target.backlog.oldest_owed_at
    if oldest is None:
        state = "Up to date."
    else:
        state = f"Oldest record waiting since {_time(oldest)}."
    stalled = '<span class="pill stop">Stalled</span> ' if target.stalled else ""
    return (
        f'<li class="audit-target" data-binding-id="{escape(binding, quote=True)}"'
        f' data-stalled="{"true" if target.stalled else "false"}">'
        f"{stalled}<code>{escape(label)}</code> <span>{state}</span></li>"
    )


_ENDINGS = {
    "cancelled": "Cancelled before it was delivered",
    "rejected": "Rejected by the target",
    "conflict": "Conflicted with the target's copy",
}


def _undelivered(view: AuditDeliveryView, event: UndeliveredEvent) -> str:
    _, record, _ = HOOKS.get(event.kind, ("", event.kind, ""))
    deliveries = (
        "".join(
            f'<li class="audit-delivery" data-binding-id="{escape(d.target_id, quote=True)}"'
            f' data-state="{escape(d.state, quote=True)}"'
            f' data-acknowledged="{"true" if d.acknowledged else "false"}">'
            f"<code>{escape(view.target_labels.get(d.target_id, d.target_id))}</code>: "
            f"{escape(_ENDINGS.get(d.state, d.state))}"
            + (", accepted as lost by an operator" if d.acknowledged else "")
            + ".</li>"
            for d in event.deliveries
        )
        or '<li class="audit-delivery">No audit target was owed it.</li>'
    )
    return (
        f'<li class="audit-undelivered" data-event-id="{escape(str(event.event_id), quote=True)}">'
        f'<p><span class="pill stop">Not delivered</span> {escape(record)},'
        f" {_time(event.occurred_at)} <code>{escape(str(event.event_id))}</code></p>"
        f"<ul>{deliveries}</ul></li>"
    )


def _render(view: AuditDeliveryView) -> str:
    parts = [
        "<h1>Audit delivery</h1>",
        "<p>Whether your team’s audit targets are receiving secrets’ records.</p>",
        '<p class="audit-note">A record a target has not acknowledged keeps waiting for it.'
        " When every target of a kind of record has waited too long, secrets refuses"
        " what it records until one catches up.</p>",
    ]
    for hook in view.hooks:
        records, _, _ = HOOKS[hook.hook]
        parts.append(
            f'<section class="audit-hook" data-hook="{escape(hook.hook, quote=True)}"'
            f' data-admission="{hook.admission}">'
            f"<h2>{escape(records)}</h2>{_admission(hook)}"
        )
        if hook.targets:
            parts.append("<ul>" + "".join(_target(view, t) for t in hook.targets) + "</ul>")
        parts.append("</section>")
    parts.append('<section class="audit-faults"><h2>Records never delivered</h2>')
    if view.undelivered:
        parts.append("<ul>" + "".join(_undelivered(view, e) for e in view.undelivered) + "</ul>")
    else:
        parts.append(
            '<p class="audit-undelivered-none">Every record has been delivered or is still being sent.</p>'
        )
    parts.append("</section>")
    parts.append('<link rel="stylesheet" href="/console-audit-delivery/audit.css">')
    return "".join(parts)


_RECOVERIES = {
    "audit_delivery_changed": (
        "Audit delivery changed while this page was loading.",
        "/audit-delivery",
        "Reload audit delivery",
    ),
}


def _recovery(refused: HTTPException) -> Response:
    if refused.status_code == 401:
        return _login_redirect(refused)
    if refused.detail not in _RECOVERIES:
        raise refused
    message, href, label = _RECOVERIES[refused.detail]
    return recovery_page(refused, message=message, action_href=href, action_label=label)


def console_audit_delivery_router(*, services: ConsoleAuditDelivery) -> APIRouter:
    """Human app only; inject the same OwnerConsole the other owner pages use."""
    router = APIRouter(route_class=ConsoleRoute)

    @router.get("/audit-delivery", response_class=HTMLResponse)
    async def page(request: Request) -> Response:
        try:
            current = await services.console.sessions.current(request)
        except HTTPException as refused:
            return _login_redirect(refused)
        try:
            async with _errors(services.console, current):
                view = await services.view(current)
        except HTTPException as refused:
            return _recovery(refused)
        return console_page(title="Audit delivery", body_html=_render(view), session=current)

    @router.get("/console-audit-delivery/audit.css")
    async def style() -> Response:
        return Response((_ASSETS / "audit.css").read_text(), media_type="text/css")

    return router
