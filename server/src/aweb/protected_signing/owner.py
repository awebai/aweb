"""The owner's one page: requests waiting for them, what happened, agents
added without asking, the current bounds and who can approve.

Reads only. Every approval and denial still goes through the shared signer's
exact-act routes with the person's own passkey.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from html import escape
from urllib.parse import quote

from fastapi import HTTPException, Query, Request

from aweb_naapp.runtime.protected_signer import SignerRefused
from aweb_naapp.runtime.protected_signer.admission_policy import AdmissionPolicy
from aweb_naapp.runtime.protected_signer.catalog import OPERATIONS

from awid.identity_observation import IdentityObservationRefused, observe_identity_binding, observe_identity_kind

from .admission import _registry, admission_counts

HISTORY_LIMIT = 50


def _json(value):
    return json.loads(value) if isinstance(value, (str, bytes)) else value


def _stamp(value):
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z") if value is not None else None


async def _component_for(composition, scope):
    """The provisioned binding whose approver scope the session holds."""
    for component in getattr(composition, "components", (composition,)):
        async with component.db.transaction() as tx:
            row = await component.authority.binding(tx)
        if row is not None and row["b3_scope"] == scope:
            return component
    raise SignerRefused("scope_refused")


def _owner_initiable():
    spec = OPERATIONS.get(("team.agent.remove", "owner_approved"))
    return spec is not None and spec.owner_initiable


def _asked_at(request):
    """When a request was asked: a frozen artifact's issue time, or for an
    intent the start of its issuance window, which is when it was prepared."""
    artifact = request.get("artifact") or {}
    return artifact.get("issued_at") or (artifact.get("issuance_window") or {}).get("not_before")


def _rendered(request):
    """The operation definition's question and the requester's frozen name."""
    spec = OPERATIONS.get((request.get("operation"), request.get("variant", "default")))
    if spec is None:
        return request.get("operation"), None
    try:
        rendered = spec.display.render(request)
    except SignerRefused:
        return request.get("operation"), None
    named = rendered.get("requester")
    return rendered["title"], named if named != request.get("requester") else None


_COLUMNS = (
    "operation_id,handoff_id,requester,request,digest,approval_id,expires_at,initiator_subject,initiator_scope,"
    "result IS NOT NULL AS committed,signed_result IS NOT NULL AS signed,refusal_code,committed_at,"
    "(SELECT r.suppressed FROM {{tables.protected_signer_notice_reservations}} r "
    "WHERE r.operation_id=o.operation_id) AS notice_suppressed"
)
# Each state class the page lists, stated exactly as its partial index's
# predicate (migration 009), so each page reads only its own class: open
# (waiting, or unsigned past its expiry), signed but unconfirmed, and final.
# Approval-less rows are bounded admissions, listed under added agents instead.
_OPEN = "approval_id IS NOT NULL AND result IS NULL AND refusal_code IS NULL AND signed_result IS NULL"
_UNRESOLVED = "approval_id IS NOT NULL AND result IS NULL AND refusal_code IS NULL AND signed_result IS NOT NULL"
_FINAL = "approval_id IS NOT NULL AND (result IS NOT NULL OR refusal_code IS NOT NULL)"
_AFTER = "AND ($3::timestamptz IS NULL OR (expires_at, operation_id) < ($3::timestamptz, $4::text)) "
_ORDER = "ORDER BY expires_at DESC, operation_id DESC LIMIT $5"


def _page(state: str, extra: str = "") -> str:
    return ("SELECT " + _COLUMNS + " FROM {{tables.protected_signer_operations}} o "
            "WHERE scope=$1::jsonb AND " + state + " " + extra + _AFTER + _ORDER)


# One page of one list for one scope, newest expiry first, after an optional
# (expires_at, operation_id) cursor. History merges two bounded pages, each
# through its own index: final outcomes, and unsigned requests past expiry
# ($2, the reader's now). The unresolved list never expires into history: it
# may already be applied ($2 is typed but unused there).
LISTS = {
    "pending": _page(_OPEN, "AND expires_at > $2::timestamptz "),
    "unresolved": _page(_UNRESOLVED, "AND $2::timestamptz IS NOT NULL "),
    "history": "SELECT * FROM ((" + _page(_FINAL, "AND $2::timestamptz IS NOT NULL ") + ") UNION ALL ("
               + _page(_OPEN, "AND expires_at <= $2::timestamptz ") + ")) h " + _ORDER,
}


async def final_operations(composition, *, scope: str, operation_ids: list[str]) -> list[str]:
    """Of ``operation_ids``, those whose stored outcome in this scope is final:
    committed or refused. An expiry the clock alone shows, a signed but
    unconfirmed row, another scope's row or an unknown id is not."""
    c = await _component_for(composition, scope)
    rows = await c.db.fetch_all(
        "SELECT operation_id FROM {{tables.protected_signer_operations}} "
        "WHERE scope=$1::jsonb AND operation_id = ANY($2::text[]) "
        "AND (result IS NOT NULL OR refusal_code IS NOT NULL)",
        json.dumps(c.context.fields()), operation_ids)
    final = {row["operation_id"] for row in rows}
    return [i for i in operation_ids if i in final]


def _cursor(row) -> str:
    return row["expires_at"].astimezone(UTC).isoformat() + "|" + row["operation_id"]


def _after(cursor: str | None):
    if not cursor:
        return None, None
    expires, _, operation_id = cursor.partition("|")
    try:
        at = datetime.fromisoformat(expires)
        operation_id = str(uuid.UUID(operation_id))
    except ValueError:
        return None, None
    # A time without an offset names no instant.
    return (at, operation_id) if at.utcoffset() is not None else (None, None)


async def owner_view(composition, *, scope: str, subject: str, now: datetime | None = None,
                     page: int = HISTORY_LIMIT, cursors: dict[str, str] | None = None) -> dict:
    """``subject`` is the signed-in approver: the page names them and marks
    the decisions they made, even when the scope has other approvers. Each
    list is one page after its cursor in ``cursors``; ``view["more"]`` holds
    the cursor of the next page of each, or None."""
    c = await _component_for(composition, scope)
    context = c.context
    now = datetime.now(UTC) if now is None else now
    fields = json.dumps(context.fields())
    lists, more = {}, {}
    for name, query in LISTS.items():
        expires, operation_id = _after((cursors or {}).get(name))
        rows = await c.db.fetch_all(query, fields, now, expires, operation_id, page + 1)
        lists[name], more[name] = rows[:page], (_cursor(rows[page - 1]) if len(rows) > page else None)
    pending, unresolved, history = [], [], []
    approvers = await _approvers(c, scope)
    for row in [*lists["pending"], *lists["unresolved"], *lists["history"]]:
        request = _json(row["request"])
        title, named = _rendered(request)
        # A request this signed-in approver started from the owner page is theirs.
        requested_by_you = row["initiator_subject"] == subject and row["initiator_scope"] == scope
        if requested_by_you:
            named = "you"
        entry = {"operation_id": row["operation_id"], "operation": request["operation"],
            "requester": row["requester"], "digest": row["digest"],
            "asked_at": _asked_at(request), "title": title, "requester_name": named,
            "approval_id": row["approval_id"], "requested_by_you": requested_by_you}
        if row["committed"]:
            history.append({**entry, "state": "committed", "at": _stamp(row["committed_at"])})
        elif row["refusal_code"] is not None:
            history.append({**entry, "state": "refused", "code": row["refusal_code"], "at": None})
        elif row["signed"]:
            # Signed but not confirmed: it may already be applied, so it is
            # never "expired" and no longer waits for a decision (the
            # signer's own receipt says unknown, external_effect_unresolved).
            unresolved.append({**entry, "state": "unresolved", "handoff_id": row["handoff_id"], "at": None})
        elif row["expires_at"] <= now:
            history.append({**entry, "state": "expired", "at": _stamp(row["expires_at"])})
        else:
            pending.append({**entry, "handoff_id": row["handoff_id"], "expires_at": _stamp(row["expires_at"]),
                # Past its requester's notice budget nobody was mailed: it waits here only.
                **({"notice": "not_mailed"} if row["notice_suppressed"] else {})})
    view = {
        "authority": {"kind": context.authority_kind, "id": context.authority_id, "domain": context.authority_domain,
            "human": context.human_id},
        "pending": pending,
        "unresolved": await _deciders(c, unresolved, subject),
        "history": await _deciders(c, history, subject),
        "more": more,
        "admitted": [],
        "admitted_removed": 0,
        "roots": [],
        "policy": None,
        "approvers": approvers,
        "you": next((a["contact"] for a in approvers if a["subject"] == subject), None),
        "members": [],
        "owner_initiable": context.authority_kind == "team_controller" and _owner_initiable(),
        # Names where this tab keeps a removal it started: the same for one
        # approver of one team on one signer, and no identifier in clear.
        "storage_scope": "s-" + hashlib.sha256(
            "\n".join((context.service_id, context.authority_kind, context.authority_id, scope, subject)).encode()
        ).hexdigest()[:16],
    }
    for item in [*pending, *view["unresolved"], *view["history"]]:
        del item["approval_id"]
    for approver in approvers:
        del approver["subject"]
    if context.authority_kind == "team_controller":
        await _admissions(c, view, now)
        await _members(c, view)
        _name_requesters([*view["pending"], *view["unresolved"], *view["history"]], view["members"])
    return view


def _name_requesters(entries, members):
    """A requester the team knows by identity or key is named by its alias."""
    names = {}
    for member in members or []:
        for key in (member["member_did_aw"], member["member_did_key"]):
            if key:
                names[key] = member["alias"]
    for entry in entries:
        entry["requester_name"] = (
            "you" if entry.get("requested_by_you") is True
            else names.get(entry["requester"]) or entry.get("requester_name")
        )


async def _admissions(c, view, now):
    context = c.context
    row = await c.db.fetch_one(
        "SELECT policy FROM {{tables.protected_admission_policies}} WHERE service_id=$1", context.service_id
    )
    if row is None:
        return
    policy = AdmissionPolicy.from_fields(_json(row["policy"]), service_id=context.service_id).fields()
    if context.authority_id not in policy["teams"]:
        return
    view["policy"] = policy
    # Agents still added or being added, which the policy bounds; the removed
    # ones, which only grow, are counted, never read row by row.
    admitted = await c.db.fetch_all(
        "SELECT operation_id,root_id,certificate_id,child_id,child_key,admitted_at,state "
        "FROM {{tables.protected_root_admissions}} "
        "WHERE service_id=$1 AND team_id=$2 AND state <> 'removed' ORDER BY admitted_at DESC",
        context.service_id, context.authority_id,
    )
    view["admitted_removed"] = await c.db.fetch_value(
        "SELECT count(*) FROM {{tables.protected_root_admissions}} "
        "WHERE service_id=$1 AND team_id=$2 AND state = 'removed'",
        context.service_id, context.authority_id,
    )
    requests = {row["operation_id"]: _json(row["request"]) for row in await c.db.fetch_all(
        "SELECT operation_id,request FROM {{tables.protected_signer_operations}} WHERE operation_id = ANY($1::text[])",
        [row["operation_id"] for row in admitted])}
    for row in admitted:
        subject = requests.get(row["operation_id"], {}).get("subject", {})
        view["admitted"].append({"root_id": row["root_id"], "alias": subject.get("member_alias"),
            "certificate_id": row["certificate_id"], "child_id": row["child_id"], "child_key": row["child_key"],
            "admitted_at": _stamp(row["admitted_at"]),
            "state": row["state"]})
    # Every root with an agent still added, or an admission inside its rate
    # window, whose count still bounds it.
    window = policy["bounds"]["rate_window_seconds"]
    roots = await c.db.fetch_all(
        "SELECT DISTINCT root_id FROM {{tables.protected_root_admissions}} "
        "WHERE service_id=$1 AND team_id=$2 AND (state <> 'removed' OR admitted_at > $3)",
        context.service_id, context.authority_id, now - timedelta(seconds=window),
    )
    async with c.db.transaction() as tx:
        for root_id in sorted(row["root_id"] for row in roots):
            counts = await admission_counts(tx, service_id=context.service_id, team_id=context.authority_id,
                root_id=root_id, window_seconds=window, now=now)
            view["roots"].append({"root_id": root_id, "active": counts["active"], "in_window": counts["in_window"],
                "next_at": _stamp(counts["next_at"])})


_JOINED = {"active": "signer", "reserved": "signer_reserved", "removed": "signer_removed"}


async def _members(c, view):
    """Every current member of the team, whoever added it: its kind and
    whether this signer admitted it. None when the registry cannot say."""
    name, domain = c.context.authority_id.split(":", 1)
    client = getattr(c.registry, "client", c.registry)
    try:
        records = await _registry(client.list_team_certificates_fresh(domain, name, active_only=True))
    except SignerRefused:
        view["members"] = None
        return
    # One member key may hold several certificates; only this signer's exact
    # record of a certificate says anything about how it joined, and then
    # with the state recorded. Without one, nothing about its origin is known.
    recorded = {row["certificate_id"]: row["state"] for row in await c.db.fetch_all(
        "SELECT certificate_id,state FROM {{tables.protected_root_admissions}} "
        "WHERE service_id=$1 AND team_id=$2 AND certificate_id = ANY($3::text[])",
        c.context.service_id, c.context.authority_id, [record.certificate_id for record in records],
    )}
    for record in records:
        view["members"].append({"alias": record.alias, "kind": await _member_kind(c, record),
            "joined": _JOINED.get(recorded.get(record.certificate_id), "unrecorded"),
            "member_did_aw": record.member_did_aw or None, "member_did_key": record.member_did_key,
            "certificate_id": record.certificate_id})


async def _member_kind(c, record):
    """What the registry says this member is, for reading only: "agent",
    "human", "kind not verified", or "not checked" when evidence is
    unavailable. Removal decides eligibility again, under its own rules."""
    if record.identity_scope == "local":
        return "agent"
    if not record.member_did_aw:
        return "kind not verified"
    # Observed for the certificate's own member key: what the identity's
    # current key proves says nothing about a certificate for another key.
    try:
        binding = await observe_identity_binding(c.registry, did_aw=record.member_did_aw,
            did_key=record.member_did_key)
        kind = (await observe_identity_kind(c.registry, binding)).result
    except IdentityObservationRefused as error:
        return "kind not verified" if error.code == "identity_binding_mismatch" else "not checked"
    except SignerRefused:
        return "not checked"
    if kind["outcome"] == "unavailable":
        return "not checked"
    if kind["identity_valid"] is True and kind["kind"] in ("agent", "human"):
        return kind["kind"]
    return "kind not verified"


async def _deciders(c, history, subject):
    """Mark each decision the signed-in approver made, in one read for the
    page. The approval records which approver decided; the audit names only
    the governed human, the same for every approver of the scope."""
    store = c.signer.store
    decided = {row["approval_id"]: row for row in await store.db.fetch_all(
        "SELECT approval_id,decided_subject,decided_at FROM {{tables.approvals}} WHERE approval_id = ANY($1::text[])",
        [item["approval_id"] for item in history],
    )} if history else {}
    for item in history:
        approval = decided.get(item["approval_id"])
        item["decided_by_you"] = approval is not None and approval["decided_subject"] == subject
        # A refused or unresolved request is dated by the approver's decision;
        # without one it has no time to show, never its expiry.
        if item["state"] in ("refused", "unresolved"):
            item["at"] = _stamp(approval["decided_at"]) if approval is not None and approval["decided_at"] else None
    return history


async def _approvers(c, scope):
    approvers = []
    for row in await c.db.fetch_all(
        "SELECT subject,contact FROM {{tables.passkey_approvers}} WHERE scope=$1 AND superseded_at IS NULL", scope
    ):
        passkeys = await c.db.fetch_all(
            "SELECT credential_id,created_at FROM {{tables.passkey_credentials}} "
            "WHERE subject=$1 AND revoked_at IS NULL ORDER BY created_at",
            row["subject"],
        )
        approvers.append({"subject": row["subject"], "contact": row["contact"], "passkeys": [
            {"key_id": hashlib.sha256(bytes(p["credential_id"])).hexdigest()[:8], "added_at": _stamp(p["created_at"])}
            for p in passkeys]})
    return approvers


def _when(stamp):
    """A stored UTC time as the page shows it: date, time and zone."""
    if stamp is None:
        return ""
    return datetime.fromisoformat(stamp.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M UTC")


def _time(stamp, *, date_only=False):
    """A time marked for the console script to show in the viewer's zone;
    without script it reads as UTC."""
    text = _when(stamp)[:10] if date_only else _when(stamp)
    mark = 'data-local="date"' if date_only else "data-local"
    return f'<time datetime="{escape(stamp, quote=True)}" {mark}>{escape(text)}</time>'


def _window(seconds):
    return {3600: "hour", 86400: "day"}.get(seconds, f"{seconds} seconds")


_OUTCOMES = {"committed": "Approved", "expired": "Expired, nobody decided",
    "unresolved": "Approved, not confirmed yet"}
_REFUSALS = {"human_refused": "Denied"}
_REMOVABLE_KINDS = ("agent", "kind not verified")
_KINDS = {"agent": "agent", "human": "person", "kind not verified": "agent or person not confirmed",
    "not checked": "could not be checked right now"}
# Said only when this signer's own record knows it. A removal is recorded only
# after the registry confirms the certificate revoked, so a still-listed
# member with that record was removed earlier but is still listed.
_JOINED_TEXT = {"signer": ", added by the root agent", "signer_reserved": ", being added by the root agent",
    "signer_removed": ", removed earlier but still listed"}


def _technical(rows):
    """Identifiers, one step away from the sentences."""
    cells = "".join(f"<dt>{escape(label)}</dt><dd>{escape(str(value))}</dd>" for label, value in rows)
    return f"<details><summary>Technical details</summary><dl>{cells}</dl></details>"


def _team_name(team_id):
    return team_id.partition(":")[0]


def _older(view: dict, listing: str, text: str) -> str:
    """The link to the next page of one list, when it has one."""
    cursor = (view.get("more") or {}).get(listing)
    if not cursor:
        return ""
    href = "/older?list=" + quote(listing, safe="") + "&after=" + quote(cursor, safe="")
    return f'<p><a data-older="{escape(listing, quote=True)}" href="{escape(href, quote=True)}">{escape(text)}</a></p>'


def owner_page_html(view: dict) -> str:
    """The owner page's HTML from owner_view. Every value is escaped. Each
    request reads as its operation definition's own question."""
    e = lambda value: escape(str(value), quote=True)  # noqa: E731
    authority = view["authority"]
    team = authority["kind"] == "team_controller"
    title = f"Approvals for team {_team_name(authority['id'])}" if team else "Your own approvals"
    parts = [f"<h1>{e(title)}</h1>"]
    if view["you"]:
        parts.append(f"<p>Signed in as {e(view['you'])}</p>")
    parts.append('<form id="logout"><button class="btn secondary" type="submit">Sign out</button></form>')
    parts.append("<h2>Waiting for you</h2>")
    if view["pending"]:
        parts.append('<ul class="owner-list">')
        for item in view["pending"]:
            asked = f", asked {_time(item['asked_at'])}" if item.get("asked_at") else ""
            parts.append(
                f'<li><a href="/handoff/{e(item["handoff_id"])}">{e(item["title"])}</a>'
                f'<p>Requested by {e(item.get("requester_name") or item["requester"])}{asked}</p>'
                f'<p>Expires {_time(item["expires_at"])}</p>'
                + ('<p data-notice="not-mailed">Not mailed: its requester is over the notice budget.</p>'
                    if item.get("notice") == "not_mailed" else "")
                + _technical([("Requested by", item["requester"]), ("Operation", item["operation"]),
                    ("Digest", item["digest"])]) + "</li>"
            )
        parts.append("</ul>")
        parts.append(_older(view, "pending", "Older requests waiting for you"))
    else:
        parts.append("<p>Nothing is waiting for you.</p>")
    if team:
        bounds = (view["policy"] or {}).get("bounds")
        parts.append("<h2>Agents added without asking you</h2>")
        for number, root in enumerate(view["roots"], start=1):
            if bounds:
                name = "The root agent" if len(view["roots"]) == 1 else f"Root agent {number}"
                parts.append(
                    f'<p>{name}: {root["active"]} of {bounds["max_active"]} at a time, '
                    f'{root["in_window"]} of {bounds["max_per_window"]} in the last {_window(bounds["rate_window_seconds"])}.</p>'
                    + _technical([(name, root["root_id"])])
                )
        if view["admitted"]:
            parts.append('<ul class="owner-list">')
            for agent in view["admitted"]:
                state = {"active": "member", "reserved": "being added", "removed": "removed"}.get(agent["state"], agent["state"])
                parts.append(
                    f'<li>{e(agent["alias"] or "unnamed agent")}: {e(state)}, added {_time(agent["admitted_at"])}'
                    + _technical([("Added by", agent["root_id"]), ("Agent key", agent["child_key"])]) + "</li>"
                )
            parts.append("</ul>")
        elif not view.get("admitted_removed"):
            parts.append("<p>No agents have been added yet.</p>")
        if view.get("admitted_removed"):
            removed = view["admitted_removed"]
            parts.append(f"<p>{removed} {'agent' if removed == 1 else 'agents'} added this way "
                         f"{'was' if removed == 1 else 'were'} removed later; they are not listed.</p>")
        parts.append("<h2>Team members</h2>")
        if view["members"] is None:
            parts.append("<p>The member list could not be read right now. Reload to try again.</p>")
        elif view["members"]:
            removable = view.get("owner_initiable", False)
            if removable:
                parts.append(
                    f'<ul class="owner-list" id="owner-members" data-team-id="{e(authority["id"])}" '
                    f'data-storage-scope="{e(view["storage_scope"])}">'
                )
            else:
                parts.append('<ul class="owner-list">')
            for member in view["members"]:
                kind = _KINDS.get(member["kind"], member["kind"])
                joined = _JOINED_TEXT.get(member["joined"], "")
                # Offered only for kinds the signer can remove on an owner's
                # approval: never a verified human, nor a member whose kind
                # could not be checked (unavailable evidence never authorizes).
                remove = (
                    f'<button type="button" class="btn secondary" data-remove-certificate="{e(member["certificate_id"])}">'
                    f'Remove {e(member["alias"])}…</button>'
                    if removable and member["kind"] in _REMOVABLE_KINDS else ""
                )
                parts.append(
                    f'<li>{e(member["alias"])}: {e(kind)}{joined}{remove}'
                    + _technical([("Identity", member["member_did_aw"] or "none"), ("Key", member["member_did_key"]),
                        ("Certificate", member["certificate_id"])]) + "</li>"
                )
            parts.append("</ul>")
            if removable:
                parts.append('<p id="owner-remove-status" role="status" aria-live="polite"></p>'
                    '<script src="/owner-ui/owner.js" defer></script>')
        else:
            parts.append("<p>No members.</p>")
        parts.append("<h2>Current limits</h2>")
        if bounds:
            policy = view["policy"]
            teams = ", ".join(_team_name(t) for t in policy["teams"])
            parts.append(
                f'<p>A root agent may have {bounds["max_active"]} agents at a time in {e(teams)}, '
                f'and add at most {bounds["max_per_window"]} per {_window(bounds["rate_window_seconds"])}. '
                "They join as ordinary members.</p>"
                + _technical([("Policy", f'version {policy["version"]}, {policy["digest"]}')])
            )
        else:
            parts.append("<p>This team has no admission policy on this signer.</p>")
    parts.append("<h2>History</h2>")
    if view.get("unresolved") or view["history"]:
        parts.append('<ul class="owner-list">')
        for item in [*view.get("unresolved", []), *view["history"]]:
            outcome = _OUTCOMES.get(item["state"]) or _REFUSALS.get(item.get("code"), "Not completed")
            if item.get("decided_by_you") and item["state"] not in ("expired", "unresolved"):
                outcome += " by you"
            # A stored final state lets the page forget a removal it saved.
            final = f' data-final-operation="{e(item["operation_id"])}"' if item["state"] in ("committed", "refused") else ""
            # A removed member may have vanished from the active listing. Its
            # existing handoff still permits authenticated receipt-only recovery.
            reopen = (
                f'<p><a href="/handoff/{e(quote(str(item["handoff_id"]), safe=""))}">Check this request</a></p>'
                if item["state"] == "unresolved" and item.get("handoff_id") else ""
            )
            decision_time = (
                f'<p>Decided {_time(item["at"])}.</p>'
                if item["state"] == "unresolved" and item["at"] else ""
            )
            parts.append(
                f'<li{final}>{e(outcome)}{", " + _time(item["at"]) if item["at"] and item["state"] != "unresolved" else ""}: {e(item["title"])}'
                + decision_time + reopen + _technical([("Requested by", item["requester"]), ("Operation", item["operation"]),
                    ("Digest", item["digest"])]) + "</li>"
            )
        parts.append("</ul>")
        parts.append(_older(view, "unresolved", "Older requests approved but not confirmed"))
        parts.append(_older(view, "history", "Older history"))
    else:
        parts.append("<p>Nothing has happened yet.</p>")
    parts.append('<h2>Who can approve</h2><ul class="owner-list">')
    for approver in view["approvers"]:
        keys = "".join(
            f'<p>Passkey added {_time(p["added_at"], date_only=True)}</p>' + _technical([("Passkey", p["key_id"])])
            for p in approver["passkeys"]
        ) or "<p>No passkey yet</p>"
        parts.append(f'<li>{e(approver["contact"] or "no notice address")}{keys}</li>')
    parts.append("</ul>")
    return "".join(parts)


def owner_router(composition, *, sessions, csrf_key):
    """GET / is the signed-in owner's page; GET /login?scope= signs them in."""
    from .bootstrap import protected_shell

    async def home(session):
        return owner_page_html(await owner_view(composition, scope=session.scope, subject=session.subject))

    shell = protected_shell(csrf_key)
    router = shell.router(sessions=sessions, home_title="Approvals", home=home)

    @router.get("/older")
    async def older(request: Request, listing: str = Query("", alias="list"), after: str = ""):
        """The same page with one list at the page after ``after``, so every
        retained request stays reachable; the other lists show their first
        page. A malformed list name or cursor is refused."""
        from aweb_naapp.console.browser import login_redirect

        if listing not in LISTS or _after(after) == (None, None):
            raise HTTPException(400, "request_invalid")
        try:
            session = await sessions.current(request)
            body_html = owner_page_html(await owner_view(
                composition, scope=session.scope, subject=session.subject, cursors={listing: after}))
        except HTTPException as error:
            return login_redirect(error)
        return shell.console_page(title="Approvals", body_html=body_html, session=session)

    @router.get("/owner-ui/owner.js")
    async def script():
        from importlib.resources import files

        from fastapi import Response

        return Response(files("aweb.protected_signing").joinpath("owner.js").read_text(), media_type="text/javascript")

    return router
