"""Owner-scoped activity presentation on the app's operational read service."""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import asdict
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode
from uuid import UUID

from aweb_naapp.console import ConsoleRoute, ConsoleSession
from aweb_naapp.roles import hold_role
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, Response

from aweb_secrets.activity_service import ActivityCursor, ActivityPage, ActivityReads
from aweb_secrets.console import OwnerConsole
from aweb_secrets.console_changes import _errors
from aweb_secrets.console_ui import _login_redirect, console_page, recovery_page
from aweb_secrets.owners import OWNER_ROLE, owner_scope
from aweb_secrets.principal_display import principal_html

_LABELS = (
    ("secret_ref", "Secret"),
    ("secret_id", "Secret ID"),
    ("request_id", "Request ID"),
    ("request_ref", "Request reference"),
    ("dispatch_id", "Dispatch ID"),
    ("operation_id", "Operation"),
    ("operation_digest", "Operation digest"),
    ("job_id", "Job"),
    ("job_digest", "Job digest"),
    ("runner_id", "Runner"),
    ("approval_id", "Approval ID"),
    ("approval_ref", "Approval reference"),
    ("install_generation", "Installation generation"),
    ("refusal_code", "Refusal code"),
)


def _encode(cursor: ActivityCursor) -> str:
    raw = json.dumps([cursor.occurred_at.isoformat(), str(cursor.event_id)]).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _decode(cursor: str | None) -> ActivityCursor | None:
    if cursor is None:
        return None
    try:
        if not cursor or len(cursor) > 512:
            raise ValueError
        raw = base64.b64decode(cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True)
        value = json.loads(raw)
        if not isinstance(value, list) or len(value) != 2:
            raise ValueError
        at, event_id = value
        if not isinstance(at, str) or not isinstance(event_id, str):
            raise ValueError
        occurred = datetime.fromisoformat(at)
        if occurred.tzinfo is None:
            raise ValueError
        return ActivityCursor(occurred_at=occurred, event_id=UUID(event_id))
    except (ValueError, TypeError, binascii.Error):
        raise HTTPException(400, "activity_cursor_invalid") from None


class ConsoleActivity:
    def __init__(self, *, console: OwnerConsole, reads: ActivityReads) -> None:
        self.console, self.reads = console, reads

    async def page(
        self, current: ConsoleSession, *, before: str | None, limit: int
    ) -> tuple[ActivityPage, str]:
        """The page and the owner-checked installation's team, its agents' display context."""
        if not 1 <= limit <= 100:
            raise HTTPException(400, "activity_limit_invalid")
        cursor = _decode(before)
        installation_id = await self.console.db.fetch_value(
            "SELECT installation_id FROM {{tables.owner_principals}} WHERE scope=$1", current.scope
        )
        if installation_id is None:
            raise HTTPException(403, "owner_required")
        admitted = await self.console.installation(installation_id)
        async with self.console.db.transaction() as tx:
            await self.console.fence.check(tx, admitted)
            owner = await self.console.directory.owner_of(tx, current.scope)
            if (
                owner is None
                or owner.team_id != admitted.team_id
                or admitted.installation_id != installation_id
                or current.scope
                != owner_scope(installation_id, admitted.team_id, owner.principal_did)
                or not await hold_role(tx, owner, OWNER_ROLE)
            ):
                raise HTTPException(403, "owner_required")
            result = await self.reads.page(
                tx,
                installation_id=installation_id,
                team_id=admitted.team_id,
                before=cursor,
                limit=limit,
            )
            await self.console.fence.check(tx, admitted)
            if current.expires_at <= datetime.now(UTC):
                raise HTTPException(401, "console_session_required")
        return result, admitted.team_id


def _escaped(value: object) -> str | None:
    return None if value is None else escape(str(value))


def _render(page: ActivityPage, limit: int, team_id: str) -> str:
    parts = ["<h1>Activity</h1><p>Recorded secret uses and job outcomes for your team.</p>"]
    if not page.entries:
        parts.append('<p id="activity-empty">No activity in this page.</p>')
    for entry in page.entries:
        data: dict[str, Any] = asdict(entry)
        label = entry.action.replace("_", " ").capitalize()
        correlation = "".join(
            f' data-{name.replace("_", "-")}="{escape(str(data[name]), quote=True)}"'
            for name in ("request_id", "job_id", "dispatch_id")
            if data.get(name) is not None
        )
        parts.append(
            f'<article class="activity-entry" data-event-id="{escape(str(entry.event_id), quote=True)}"{correlation}><h2>{escape(label)}</h2><dl>'
        )
        agent = (
            None
            if entry.principal_did is None
            else principal_html(
                principal_did=entry.principal_did, alias=entry.principal_alias, team_id=team_id
            )
        )
        for name, value in (
            ("Time", _escaped(entry.occurred_at.isoformat())),
            ("Outcome", _escaped(entry.outcome)),
            ("Agent", agent),
            *((label, _escaped(data.get(field))) for field, label in _LABELS),
        ):
            if value is not None:
                parts.append(f"<dt>{escape(name)}</dt><dd>{value}</dd>")
        parts.append("</dl>")
        if entry.outcome == "outcome_unknown" and entry.request_ref is not None:
            target = "/reconciliations/" + quote(entry.request_ref, safe="")
            parts.append(f'<a href="{escape(target, quote=True)}">Resolve uncertain outcome</a>')
        parts.append("</article>")
    if page.next_cursor is not None:
        url = "/activity?" + urlencode({"before": _encode(page.next_cursor), "limit": limit})
        parts.append(f'<a rel="next" href="{escape(url, quote=True)}">Older activity</a>')
    parts.append('<link rel="stylesheet" href="/console-activity/activity.css">')
    return "".join(parts)


def console_activity_router(*, services: ConsoleActivity) -> APIRouter:
    """Human app only; inject the same OwnerConsole and app-owned ActivityReads."""
    router = APIRouter(route_class=ConsoleRoute)

    @router.get("/activity", response_class=HTMLResponse)
    async def page(request: Request, before: str | None = None, limit: str = "50"):
        try:
            current = await services.console.sessions.current(request)
            count = _limit(limit)
            async with _errors(services.console, current):
                result, team_id = await services.page(current, before=before, limit=count)
        except HTTPException as refused:
            if refused.status_code == 401:
                return _login_redirect(refused)
            return recovery_page(
                refused,
                message=(
                    "Activity link is invalid."
                    if refused.status_code == 400
                    else "Activity could not be loaded."
                ),
                action_href="/activity",
                action_label="View activity",
            )
        return console_page(
            title="Activity", body_html=_render(result, count, team_id), session=current
        )

    @router.get("/activity/events")
    async def events(request: Request, before: str | None = None, limit: str = "50"):
        current = await services.console.sessions.current(request)
        async with _errors(services.console, current):
            result, _ = await services.page(current, before=before, limit=_limit(limit))
        return {
            "entries": [asdict(entry) for entry in result.entries],
            "next_cursor": None if result.next_cursor is None else _encode(result.next_cursor),
        }

    @router.get("/console-activity/activity.css")
    async def style():
        return Response((Path(__file__).parent / "activity.css").read_text(), media_type="text/css")

    return router


def _limit(value: str) -> int:
    try:
        count = int(value)
    except ValueError:
        raise HTTPException(400, "activity_limit_invalid") from None
    if not 1 <= count <= 100:
        raise HTTPException(400, "activity_limit_invalid")
    return count
