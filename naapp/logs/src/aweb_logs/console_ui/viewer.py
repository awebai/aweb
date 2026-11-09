"""The reader's viewer on logs' console origin (audit-substrate.md §B5, §B8).

A reader signed in with its passkey browses its team's events, follows new
ones as they are recorded and reads the integrity report, all through the
console session :class:`aweb_logs.read_routes.ReaderReads` resolves. Pages
are rendered on the server; every value inserted is escaped. The follow page
fetches server-rendered fragments of new events, so one renderer draws every
event.

- ``GET /events``: the events matching the exact filters in the query, newest
  first, with a link to older ones.
- ``GET /follow``: the events recorded after the page loaded, oldest first.
  Its script polls ``GET /follow/events?after=<position>``.
- ``GET /integrity``: the report of one chain epoch.

Each event says how it was recorded. An agent's own client events are marked
agent-reported, never shown as mediated fact (§B8). The integrity page keeps
what logs' signed chain proves apart from what this logs server observed of
delivery, which is unsigned and never a proof of completeness.
"""

import json
import re
from datetime import UTC, datetime, timedelta
from html import escape
from importlib.resources import files
from typing import Any
from urllib.parse import urlencode

from aweb_naapp.console import ConsoleRoute, ConsoleSession
from aweb_naapp.console.browser import ConsoleShell, login_redirect
from aweb_naapp.hooks import envelope as hook_envelope
from aweb_naapp.hooks.producer import VIEW_MAX_AGE
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, Response

from aweb_logs.read_routes import ReaderReads, read_limit, read_page, read_query
from aweb_logs.read_store import (
    DEFAULT_LIMIT,
    MEDIATIONS,
    REFERENCES,
    RESULT_STATUSES,
    EventFilter,
    InvalidRead,
    query,
    tail,
)

_MEDIATION_LABELS = {
    "server": "Server",
    "registry_observed": "Registry observed",
    "client": "Agent-reported",
}
_RESULT_LABELS = {
    "success": "Success",
    "denied": "Denied",
    "failed": "Failed",
    "outcome_unknown": "Outcome unknown",
}
_TEXT_FILTERS = (
    ("event_type", "Event type"),
    ("actor", "Actor DID"),
    ("trace_id", "Trace"),
    ("app_id", "App"),
    ("event_id", "Event ID"),
    ("operation_id", "Operation"),
    ("job_id", "Job"),
    ("dispatch_id", "Dispatch"),
    ("approval_id", "Approval"),
    ("grant_id", "Grant"),
    ("secret_id", "Secret"),
    ("occurred_from", "Occurred from"),
    ("occurred_to", "Occurred to"),
)
_SELECT_FILTERS: tuple[tuple[str, str, tuple[str, ...], dict[str, str]], ...] = (
    ("mediation", "Recorded by", MEDIATIONS, _MEDIATION_LABELS),
    ("result_status", "Result", RESULT_STATUSES, _RESULT_LABELS),
    ("hook", "Hook", tuple(hook_envelope.HOOKS), {}),
)
_FORM_FIELDS = {name: label for name, label, *_ in _SELECT_FILTERS} | dict(_TEXT_FILTERS)
_DATE_FIELDS = ("occurred_from", "occurred_to")
_DATE_HELP = "In UTC: a day, as 2026-11-09, or a moment, as 2026-11-09T14:30:00Z."
_DATE_ERROR = "This is not a day or a moment written as shown."
# A UTC day, or a moment to the minute, second or millisecond (events are
# recorded to the millisecond, so a finer moment is refused, never rounded),
# with an optional Z.
_UTC_WRITTEN = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,3}))?)?)?Z?"
)
_FOLLOW_INTERVAL_MS = 2000
_SCRIPTS = ("follow", "filters")

_NAV = (
    '<nav class="viewer-nav" aria-label="Log">'
    '<a href="/events">Events</a><a href="/follow">Follow</a>'
    '<a href="/integrity">Integrity</a></nav>'
)
_RECORDING = (
    '<details class="reading-guide"><summary>How events are recorded</summary>'
    "<p><strong>Server</strong> events were recorded by the server or app that"
    " carried out the action. <strong>Registry observed</strong> events record"
    " membership changes the server saw in the registry."
    " <strong>Agent-reported</strong> events come from an agent’s own client:"
    " they say what the agent reports it did. No server mediated them, and an"
    " agent can leave them out.</p>"
    f'<p id="revocation-window" data-seconds="{int(VIEW_MAX_AGE.total_seconds())}">'
    "After your team revokes this log, producers can still deliver up to"
    f" {int(VIEW_MAX_AGE.total_seconds())} seconds of further redacted activity"
    " to it.</p></details>"
)


def _attr(value: object) -> str:
    return escape(str(value), quote=True)


def _filter_href(name: str, value: object) -> str | None:
    """A link to the events whose ``name`` is ``value``, when that is a filter
    a reader may ask for."""
    if not isinstance(value, str):
        return None
    try:
        EventFilter.from_query({name: value})
    except InvalidRead:
        return None
    return "/events?" + urlencode({name: value})


def _linked(name: str, value: object, text: str | None = None) -> str:
    shown = escape(text if text is not None else str(value))
    href = _filter_href(name, value)
    if href is None:
        return shown
    return f'<a href="{_attr(href)}" data-filter="{_attr(name)}">{shown}</a>'


def _value(value: object) -> str:
    if isinstance(value, str):
        return escape(value)
    return f"<code>{escape(json.dumps(value, sort_keys=True))}</code>"


def _row(term: str, value_html: str, **data: object) -> str:
    attributes = "".join(f' data-{name.replace("_", "-")}="{_attr(v)}"' for name, v in data.items())
    return f"<div><dt>{escape(term)}</dt><dd{attributes}>{value_html}</dd></div>"


def _position(event: dict[str, Any]) -> str:
    return f' data-chain-epoch="{_attr(event["chain_epoch"])}" data-team-seq="{_attr(event["team_seq"])}"'


def _purged_event(event: dict[str, Any]) -> str:
    return (
        f'<article class="event purged"{_position(event)} data-purged>'
        f'<div class="event-head"><h2>Content purged</h2>'
        f'<span class="event-seq">#{escape(str(event["team_seq"]))}</span></div>'
        '<dl class="event-facts">'
        + _row("Received", escape(event["received_at"]))
        + _row("Hook", escape(event["hook"]))
        + _row("Producer", escape(event["producer_origin"]))
        + _row("Purged by", escape(event["purge_act"]), purge_act=event["purge_act"])
        + "</dl></article>"
    )


def _actor(actor: dict[str, Any]) -> str:
    did = actor.get("did_aw") or actor.get("did_key")
    if did is None:
        return escape(actor.get("alias") or "")
    alias = actor.get("alias")
    linked = _linked("actor", did, alias if alias else did)
    return linked if not alias else f'{linked} <span class="did">{escape(did)}</span>'


def _producer(producer: dict[str, Any]) -> str:
    named = producer.get("app_id") or producer.get("origin") or ""
    return escape(f"{producer['kind']} · {named}" if named else producer["kind"])


def render_event(event: dict[str, Any]) -> str:
    """One event as the viewer shows it, every value escaped."""
    if event["purged"]:
        return _purged_event(event)
    mediation = event["mediation"]
    reported = " data-agent-reported" if mediation == "client" else ""
    title = event["event_type"] or event["hook"]
    facts = [
        _row(
            "Occurred",
            f'<time datetime="{_attr(event["occurred_at"])}">{escape(event["occurred_at"])}</time>',
        ),
        _row(
            "Result",
            escape(_RESULT_LABELS.get(event["result_status"], event["result_status"])),
            result_status=event["result_status"],
        ),
        _row("Producer", _producer(event["producer"])),
        _row("Trace", _linked("trace_id", event["trace_id"])),
    ]
    actor = _actor(event["actor"])
    if actor:
        facts.insert(2, _row("Actor", actor))
    payload = event["payload"]
    facts += [
        _row(name.replace("_", " ").capitalize(), _linked(name, payload[name]))
        for name in REFERENCES
        if name in payload
    ]
    payload_rows = "".join(_row(name, _value(value)) for name, value in sorted(payload.items()))
    note = (
        '<p class="agent-reported-note" data-agent-reported>Reported by the agent’s own'
        " client. No server mediated it.</p>"
        if mediation == "client"
        else ""
    )
    return (
        f'<article class="event" data-event-id="{_attr(event["event_id"])}"'
        f' data-mediation="{_attr(mediation)}"{_position(event)}>'
        f'<div class="event-head"><h2>{escape(title)}</h2>'
        f'<span class="mediation mediation-{_attr(mediation)}"{reported}>'
        f"{escape(_MEDIATION_LABELS[mediation])}</span>"
        f'<span class="event-seq">#{escape(str(event["team_seq"]))}</span></div>'
        f'{note}<dl class="event-facts">{"".join(facts)}</dl>'
        f'<details class="payload" data-payload><summary>Payload</summary>'
        f'<dl class="event-facts">{payload_rows}</dl></details></article>'
    )


def _events_list(events: list[dict[str, Any]], **data: str) -> str:
    attributes = "".join(f' data-{name}="{_attr(value)}"' for name, value in data.items())
    items = "".join(f"<li>{render_event(event)}</li>" for event in events)
    return f'<ol class="events"{attributes}>{items}</ol>'


def _described(name: str, errors: dict[str, str]) -> tuple[str, str]:
    """The attributes tying a filter's control to its format help and to the
    reason its value was refused, and those notes."""
    notes = []
    if name in _DATE_FIELDS:
        notes.append((f"filter-{name}-help", "field-help", _DATE_HELP))
    if name in errors:
        notes.append((f"filter-{name}-error", "field-error", errors[name]))
    attributes = ""
    if notes:
        attributes += f' aria-describedby="{" ".join(ident for ident, _, _ in notes)}"'
    if name in errors:
        attributes += ' aria-invalid="true"'
    rendered = "".join(
        f'<p id="{ident}" class="{kind}">{escape(text)}</p>' for ident, kind, text in notes
    )
    return attributes, rendered


def _filters(
    raw: dict[str, str],
    *,
    action: str,
    limit: str | None,
    errors: dict[str, str] | None = None,
) -> str:
    """The filter form, holding the values the reader submitted; ``errors``
    names each field whose value was refused."""
    errors = errors or {}
    fields = []
    for name, label, options, labels in _SELECT_FILTERS:
        attributes, notes = _described(name, errors)
        chosen = raw.get(name)
        rendered = ['<option value="">Any</option>'] + [
            f'<option value="{_attr(option)}"{" selected" if option == chosen else ""}>'
            f"{escape(labels.get(option, option))}</option>"
            for option in options
        ]
        fields.append(
            f'<div class="filter-field"><label for="filter-{name}">{escape(label)}</label>'
            f'<select id="filter-{name}" name="{name}"{attributes}>{"".join(rendered)}</select>'
            f"{notes}</div>"
        )
    for name, label in _TEXT_FILTERS:
        attributes, notes = _described(name, errors)
        fields.append(
            f'<div class="filter-field"><label for="filter-{name}">{escape(label)}</label>'
            f'<input id="filter-{name}" name="{name}" value="{_attr(raw.get(name, ""))}"'
            f' autocomplete="off" spellcheck="false"{attributes}>{notes}</div>'
        )
    if limit is not None:
        fields.append(f'<input type="hidden" name="limit" value="{_attr(limit)}">')
    active = bool(errors) or any(value for name, value in raw.items())
    return (
        f'<form id="filters" method="get" action="{_attr(action)}">'
        f"<details{' open' if active else ''}><summary>Filter</summary>"
        f'<div class="filter-fields">{"".join(fields)}</div>'
        '<div class="filter-actions"><button type="submit">Apply</button>'
        f'<a href="{_attr(action)}">Clear</a></div></details></form>'
    )


def _chain_epoch(value: str) -> int:
    """A chain epoch as the reader wrote it, in plain decimal digits; anything
    else is refused. :meth:`ReaderReads.verify` refuses one out of range."""
    if not (value.isascii() and value.isdigit() and len(value) <= 10) or value != str(int(value)):
        raise HTTPException(status_code=400, detail=InvalidRead.code)
    return int(value)


class UnusableFilters(Exception):
    """Filter values from the form that cannot be used, each with the reason
    shown beside its field."""

    def __init__(self, errors: dict[str, str]) -> None:
        super().__init__(sorted(errors))
        self.errors = errors


def _utc(written: str, *, end: bool) -> str | None:
    """The canonical instant a reader wrote as a UTC day or moment; a day alone
    is its first instant, or its last when it ``end``s a range."""
    match = _UTC_WRITTEN.fullmatch(written) if written.isascii() else None
    if match is None:
        return None
    year, month, day, hour, minute, second, fraction = match.groups()
    try:
        moment = datetime(
            int(year),
            int(month),
            int(day),
            int(hour or 0),
            int(minute or 0),
            int(second or 0),
            int((fraction or "0").ljust(3, "0")) * 1000,
            tzinfo=UTC,
        )
        if hour is None and end:
            moment += timedelta(days=1, milliseconds=-1)
    except (ValueError, OverflowError):
        return None
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _usable(items: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """``items`` with each date written in its canonical form, or
    :class:`UnusableFilters` naming every form field whose value cannot be used.
    Names and paging the form does not offer are left to :func:`read_query`."""
    usable: list[tuple[str, str]] = []
    errors: dict[str, str] = {}
    for name, value in items:
        if name in _DATE_FIELDS:
            canonical = _utc(value, end=name == "occurred_to")
            if canonical is None:
                errors[name] = _DATE_ERROR
                continue
            value = canonical
        elif name in _FORM_FIELDS:
            try:
                EventFilter.from_query({name: value})
            except InvalidRead:
                errors[name] = f"No {_FORM_FIELDS[name].lower()} can have this value."
                continue
        usable.append((name, value))
    if errors:
        raise UnusableFilters(errors)
    return usable


def _filled(request: Request) -> list[tuple[str, str]]:
    """The query's parameters, without the empty fields a submitted filter form
    leaves."""
    return [(name, value) for name, value in request.query_params.multi_items() if value != ""]


def _query_string(values: dict[str, str]) -> str:
    return "?" + urlencode(values) if values else ""


class Viewer:
    """The viewer's pages, in ``shell``'s brand, over ``reads``."""

    def __init__(self, shell: ConsoleShell, reads: ReaderReads) -> None:
        self.shell = shell
        self.reads = reads

    def refused(self, error: HTTPException) -> Response:
        if error.status_code == 401:
            return login_redirect(error)
        if error.status_code == 404:
            return self.shell.recovery_page(
                error,
                message="Nothing to show here.",
                action_href="/integrity",
                action_label="Open the current integrity report",
            )
        return self.shell.recovery_page(
            error,
            message="This filter cannot be used.",
            action_href="/events",
            action_label="Show all events",
        )

    def refused_form(
        self,
        session: ConsoleSession,
        title: str,
        raw: dict[str, str],
        refused: UnusableFilters,
        *,
        action: str,
        limit: str | None,
    ) -> Response:
        """The page's filter form again, as the reader submitted it, with each
        refused field marked and the first focused; nothing is read."""
        body = (
            f'<div class="heading"><h1>{escape(title)}</h1>{_NAV}</div>{_RECORDING}'
            + _filters(raw, action=action, limit=limit, errors=refused.errors)
            # Runs after the shell's console.js has shown the content, so focus can land.
            + '<script src="/logs-viewer/filters.js" defer></script>'
        )
        response = self.shell.console_page(title=title, body_html=body, session=session)
        response.status_code = 400
        return response

    async def events(self, request: Request) -> Response:
        try:
            session, reader = await self.reads.session(request)
            items = _filled(request)
            raw = {name: value for name, value in items if name not in ("limit", "cursor")}
            try:
                usable = _usable(items)
            except UnusableFilters as refused:
                return self.refused_form(
                    session,
                    "Events",
                    raw,
                    refused,
                    action="/events",
                    limit=dict(items).get("limit"),
                )
            where, paging = read_query(usable, allowed=("limit", "cursor"))
            page = await read_page(
                query(
                    self.reads.db,
                    reader.team_id,
                    where,
                    limit=read_limit(paging),
                    before=paging.get("cursor"),
                )
            )
        except HTTPException as error:
            return self.refused(error)
        kept = raw | ({"limit": paging["limit"]} if "limit" in paging else {})
        older = (
            f'<a id="older" class="pager" href="/events{_attr(_query_string(kept | {"cursor": page.next_cursor}))}">Older events</a>'
            if page.next_cursor is not None
            else ""
        )
        listing = (
            _events_list(page.events) if page.events else '<p id="no-events">No events match.</p>'
        )
        body = (
            f'<div class="heading"><h1>Events</h1>{_NAV}</div>{_RECORDING}'
            + _filters(raw, action="/events", limit=paging.get("limit"))
            + f'<p class="follow-link"><a href="/follow{_attr(_query_string(raw))}">Follow new events</a></p>'
            + listing
            + older
        )
        return self.shell.console_page(title="Events", body_html=body, session=session)

    async def follow(self, request: Request) -> Response:
        try:
            session, reader = await self.reads.session(request)
            items = _filled(request)
            try:
                usable = _usable(items)
            except UnusableFilters as refused:
                return self.refused_form(
                    session, "Follow", dict(items), refused, action="/follow", limit=None
                )
            where, _ = read_query(usable, allowed=())
            head = await read_page(tail(self.reads.db, reader.team_id, where))
        except HTTPException as error:
            return self.refused(error)
        raw = dict(items)
        source = "/follow/events" + _query_string(raw)
        body = (
            f'<div class="heading"><h1>Follow</h1>{_NAV}</div>{_RECORDING}'
            + _filters(raw, action="/follow", limit=None)
            + f'<div id="follow" data-state="live" data-after="{_attr(head.next_cursor)}" data-source="{_attr(source)}"'
            f' data-interval="{_FOLLOW_INTERVAL_MS}">'
            '<p id="follow-status" role="status" aria-live="polite">'
            "Waiting for new events…</p>"
            '<ol id="followed" class="events"></ol>'
            '<p id="follow-ended" hidden>Following stopped. '
            '<a href="/follow">Sign in again to continue</a>.</p>'
            '<p id="follow-failed" hidden>New events could not be loaded. '
            "Reload the page to try again.</p></div>"
            '<script src="/logs-viewer/follow.js" defer></script>'
        )
        return self.shell.console_page(title="Follow", body_html=body, session=session)

    async def follow_events(self, request: Request) -> Response:
        _, reader = await self.reads.session(request)
        try:
            usable = _usable(_filled(request))
        except UnusableFilters:
            raise HTTPException(status_code=400, detail=InvalidRead.code) from None
        where, paging = read_query(usable, allowed=("after",))
        if "after" not in paging:
            raise HTTPException(status_code=400, detail=InvalidRead.code)
        page = await read_page(
            tail(self.reads.db, reader.team_id, where, after=paging["after"], limit=DEFAULT_LIMIT)
        )
        more = {"more": "true"} if len(page.events) == DEFAULT_LIMIT else {}
        return HTMLResponse(_events_list(page.events, after=page.next_cursor or "", **more))

    async def integrity(self, request: Request) -> Response:
        try:
            session, reader = await self.reads.session(request)
            epoch = request.query_params.get("chain_epoch")
            chain_epoch = None
            if epoch is not None:
                chain_epoch = _chain_epoch(epoch)
            report = await self.reads.verify(reader, chain_epoch, receipts=[], checkpoints=[])
        except HTTPException as error:
            return self.refused(error)
        body = (
            f'<div class="heading"><h1>Integrity</h1>{_NAV}</div>'
            f"<p>Chain epoch {escape(str(report['chain_epoch']))}.</p>"
            + _chain_section(report)
            + _observed_section(report)
            + _TAKE_AWAY
        )
        return self.shell.console_page(title="Integrity", body_html=body, session=session)


# The whole log, to check away from this server: the bundle carries the signed
# events and the receipts and checkpoints logs keeps, and verifies with no
# server against keys the holder trusts (docs/logs-chain.md).
_TAKE_AWAY = (
    '<section id="take-away" class="integrity">'
    "<h2>Keep a copy</h2>"
    "<p>Download your team’s whole log: its signed events and the receipts and"
    " checkpoints this server keeps. It can be checked with no server, against"
    " keys you trust. A copy you keep is what shows, later, that events it holds"
    " were removed from this server.</p>"
    '<p><a id="export" href="/v1/export" download>Download the log</a></p></section>'
)


def _chain_section(report: dict[str, Any]) -> str:
    intact = report["intact"]
    parts = [
        f'<section id="chain" class="integrity integrity-chain" data-intact="{"true" if intact else "false"}">'
        "<h2>Signed chain</h2>"
        "<p>Recomputed from the signed events this log keeps. This checks the log"
        " against itself; the receipts or checkpoints you keep are what show events"
        " removed after the last one kept.</p>"
    ]
    if intact:
        parts.append('<p class="verdict verdict-ok">The chain is intact.</p>')
    else:
        parts.append('<p class="verdict verdict-bad">The chain is not intact.</p>')
    first_break = report.get("first_break")
    if first_break is not None:
        parts.append(
            f'<p data-first-break="{_attr(first_break["team_seq"])}">First break at event'
            f" #{escape(str(first_break['team_seq']))}: {escape(first_break['reason'])}.</p>"
        )
    if report["missing"]:
        parts.append(
            "<h3>Missing events</h3><ul>"
            + "".join(
                f'<li data-missing-range data-from="{_attr(first)}" data-to="{_attr(last)}">'
                f"#{escape(str(first))} to #{escape(str(last))}</li>"
                for first, last in report["missing"]
            )
            + "</ul>"
        )
    if report["purged"]:
        parts.append(
            "<h3>Purged content</h3><ul>"
            + "".join(
                f'<li data-purged-range data-from="{_attr(p["from"])}" data-to="{_attr(p["to"])}"'
                f' data-act="{_attr(p["act"])}">#{escape(str(p["from"]))} to'
                f" #{escape(str(p['to']))}, purged by {escape(p['act'])}</li>"
                for p in report["purged"]
            )
            + "</ul>"
        )
    if report["contradicted"]:
        parts.append(
            "<h3>Contradicted receipts and checkpoints</h3><ul>"
            + "".join(
                f"<li data-contradicted>{escape(c['artefact'])} {escape(str(c['index']))}:"
                f" {escape(c['reason'])}</li>"
                for c in report["contradicted"]
            )
            + "</ul>"
        )
    parts.append("</section>")
    return "".join(parts)


def _producer_named(context: dict[str, Any]) -> str:
    producer = context["producer"]
    return escape(f"{producer.get('app_id') or producer['origin']} · {context['hook']}")


def _observed_section(report: dict[str, Any]) -> str:
    delivery = report["delivery"]
    parts = [
        f'<section id="observed" class="integrity integrity-observed" data-scope="{_attr(delivery["scope"])}">'
        "<h2>Delivery observed by this logs server</h2>"
        "<p>These findings are this server’s own observations. They are not signed,"
        " and finding no gap does not prove that every event was delivered.</p>"
    ]
    if not (
        delivery["gaps"]
        or delivery["sequence_conflicts"]
        or delivery["unassessed"]
        or report["conflicts"]
    ):
        parts.append("<p data-no-findings>No gaps or conflicts observed.</p>")
    if delivery["gaps"]:
        parts.append(
            "<h3>Gaps</h3><ul>"
            + "".join(
                f'<li data-gap data-from="{_attr(g["from"])}" data-to="{_attr(g["to"])}">'
                f"{_producer_named(g)}: sequence {escape(str(g['from']))} to"
                f" {escape(str(g['to']))} not received</li>"
                for g in delivery["gaps"]
            )
            + "</ul>"
        )
    if delivery["sequence_conflicts"]:
        parts.append(
            "<h3>Reused sequence numbers</h3><ul>"
            + "".join(
                f'<li data-sequence-conflict="{_attr(c["seq"])}">{_producer_named(c)}: sequence'
                f" {escape(str(c['seq']))} used by {len(c['event_ids'])} events</li>"
                for c in delivery["sequence_conflicts"]
            )
            + "</ul>"
        )
    if delivery["unassessed"]:
        parts.append(
            f'<p data-unassessed="{len(delivery["unassessed"])}">'
            f"{len(delivery['unassessed'])} events could not be assessed for delivery.</p>"
        )
    if report["conflicts"]:
        parts.append(
            "<h3>Refused conflicting deliveries</h3><ul>"
            + "".join(
                f'<li data-conflict="{_attr(c["fault_id"])}">Event #{escape(str(c["team_seq"]))}:'
                f" {escape(c['kind'])}, {escape(c['recorded_at'])}</li>"
                for c in report["conflicts"]
            )
            + "</ul>"
        )
    parts.append("</section>")
    return "".join(parts)


def viewer_router(shell: ConsoleShell, reads: ReaderReads) -> APIRouter:
    """The viewer's pages and script. Mount only on the console (human) origin."""
    viewer = Viewer(shell, reads)
    router = APIRouter(route_class=ConsoleRoute)
    router.add_api_route("/events", viewer.events, methods=["GET"], response_class=HTMLResponse)
    router.add_api_route("/follow", viewer.follow, methods=["GET"], response_class=HTMLResponse)
    router.add_api_route(
        "/follow/events", viewer.follow_events, methods=["GET"], response_class=HTMLResponse
    )
    router.add_api_route(
        "/integrity", viewer.integrity, methods=["GET"], response_class=HTMLResponse
    )

    @router.get("/logs-viewer/{name}.js")
    async def script(name: str) -> Response:
        if name not in _SCRIPTS:
            raise HTTPException(status_code=404)
        return Response(
            files(__package__).joinpath(f"{name}.js").read_text(), media_type="text/javascript"
        )

    return router
