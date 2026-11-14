"""The owner's one page: requests waiting for them, what happened, agents
added without asking, the current bounds and who can approve.

Reads only. Every approval and denial still goes through the shared signer's
exact-act routes with the person's own passkey.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from html import escape

from aweb_naapp.runtime.protected_signer import SignerRefused
from aweb_naapp.runtime.protected_signer.admission_policy import AdmissionPolicy
from aweb_naapp.runtime.protected_signer.catalog import OPERATIONS

from .admission import admission_counts

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


def _title(request):
    """The operation definition's own question for this frozen request."""
    spec = OPERATIONS.get((request.get("operation"), request.get("variant", "default")))
    if spec is None:
        return request.get("operation")
    try:
        return spec.display.render(request)["title"]
    except SignerRefused:
        return request.get("operation")


async def owner_view(composition, *, scope: str, subject: str, now: datetime | None = None) -> dict:
    """``subject`` is the signed-in approver: the page names them and marks
    the decisions they made, even when the scope has other approvers."""
    c = await _component_for(composition, scope)
    context = c.context
    now = datetime.now(UTC) if now is None else now
    fields = context.fields()
    rows = await c.db.fetch_all(
        "SELECT operation_id,handoff_id,requester,request,digest,approval_id,expires_at,"
        "result IS NOT NULL AS committed,signed_result IS NOT NULL AS signed,refusal_code,committed_at "
        "FROM {{tables.protected_signer_operations}} "
        "ORDER BY expires_at DESC"
    )
    pending, history, requests = [], [], {}
    approvers = await _approvers(c, scope)
    for row in rows:
        request = _json(row["request"])
        requests[row["operation_id"]] = request
        if request.get("scope") != fields:
            continue
        entry = {"operation_id": row["operation_id"], "operation": request["operation"],
            "requester": row["requester"], "digest": row["digest"],
            "asked_at": request.get("artifact", {}).get("issued_at"), "title": _title(request),
            "approval_id": row["approval_id"]}
        if row["approval_id"] is None:
            # Bounded unattended work (admissions) is listed under added agents.
            continue
        if row["committed"]:
            history.append({**entry, "state": "committed", "at": _stamp(row["committed_at"])})
        elif row["refusal_code"] is not None:
            history.append({**entry, "state": "refused", "code": row["refusal_code"], "at": _stamp(row["expires_at"])})
        elif row["signed"]:
            # Signed but not confirmed: it may already be applied, so it is
            # never "expired" and no longer waits for a decision (the
            # signer's own receipt says unknown, external_effect_unresolved).
            history.append({**entry, "state": "unresolved", "at": _stamp(row["expires_at"])})
        elif row["expires_at"] <= now:
            history.append({**entry, "state": "expired", "at": _stamp(row["expires_at"])})
        else:
            pending.append({**entry, "handoff_id": row["handoff_id"], "expires_at": _stamp(row["expires_at"])})
    view = {
        "authority": {"kind": context.authority_kind, "id": context.authority_id, "domain": context.authority_domain,
            "human": context.human_id},
        "pending": pending,
        "history": await _deciders(c, history[:HISTORY_LIMIT], subject),
        "admitted": [],
        "roots": [],
        "policy": None,
        "approvers": approvers,
        "you": next((a["contact"] for a in approvers if a["subject"] == subject), None),
    }
    for item in [*pending, *view["history"]]:
        del item["approval_id"]
    for approver in approvers:
        del approver["subject"]
    if context.authority_kind == "team_controller":
        await _admissions(c, view, requests, now)
    return view


async def _admissions(c, view, requests, now):
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
    admitted = await c.db.fetch_all(
        "SELECT operation_id,root_id,child_id,child_key,admitted_at,state FROM {{tables.protected_root_admissions}} "
        "WHERE service_id=$1 AND team_id=$2 ORDER BY admitted_at DESC",
        context.service_id, context.authority_id,
    )
    for row in admitted:
        subject = requests.get(row["operation_id"], {}).get("subject", {})
        view["admitted"].append({"root_id": row["root_id"], "alias": subject.get("member_alias"),
            "child_id": row["child_id"], "child_key": row["child_key"], "admitted_at": _stamp(row["admitted_at"]),
            "state": row["state"]})
    async with c.db.transaction() as tx:
        for root_id in sorted({row["root_id"] for row in admitted}):
            counts = await admission_counts(tx, service_id=context.service_id, team_id=context.authority_id,
                root_id=root_id, window_seconds=policy["bounds"]["rate_window_seconds"], now=now)
            view["roots"].append({"root_id": root_id, "active": counts["active"], "in_window": counts["in_window"],
                "next_at": _stamp(counts["next_at"])})


async def _deciders(c, history, subject):
    """Mark each decision the signed-in approver made. The approval records
    which approver decided; the audit names only the governed human, the same
    for every approver of the scope."""
    for item in history:
        approval = await c.signer.store.get(item["approval_id"])
        decider = approval.decided_by if approval is not None else None
        item["decided_by_you"] = decider is not None and decider.subject == subject
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
    "unresolved": "Signed; whether it took effect is not confirmed yet"}
_REFUSALS = {"human_refused": "Denied"}


def _technical(rows):
    """Identifiers, one step away from the sentences."""
    cells = "".join(f"<dt>{escape(label)}</dt><dd>{escape(str(value))}</dd>" for label, value in rows)
    return f"<details><summary>Technical details</summary><dl>{cells}</dl></details>"


def _team_name(team_id):
    return team_id.partition(":")[0]


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
                f'<p>Requested by {e(item["requester"])}{asked}</p>'
                f'<p>Expires {_time(item["expires_at"])}</p>'
                + _technical([("Operation", item["operation"]), ("Digest", item["digest"])]) + "</li>"
            )
        parts.append("</ul>")
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
        else:
            parts.append("<p>No agents have been added yet.</p>")
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
    if view["history"]:
        parts.append('<ul class="owner-list">')
        for item in view["history"]:
            outcome = _OUTCOMES.get(item["state"]) or _REFUSALS.get(item.get("code"), "Not completed")
            if item.get("decided_by_you") and item["state"] not in ("expired", "unresolved"):
                outcome += " by you"
            parts.append(
                f'<li>{e(outcome)}, {_time(item["at"])}: {e(item["title"])}'
                + _technical([("Requested by", item["requester"]), ("Operation", item["operation"]),
                    ("Digest", item["digest"])]) + "</li>"
            )
        parts.append("</ul>")
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

    return protected_shell(csrf_key).router(sessions=sessions, home_title="Approvals", home=home)
