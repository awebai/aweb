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


async def owner_view(composition, *, scope: str, now: datetime | None = None) -> dict:
    c = await _component_for(composition, scope)
    context = c.context
    now = datetime.now(UTC) if now is None else now
    fields = context.fields()
    rows = await c.db.fetch_all(
        "SELECT operation_id,handoff_id,requester,request,digest,approval_id,expires_at,"
        "result IS NOT NULL AS committed,refusal_code,committed_at FROM {{tables.protected_signer_operations}} "
        "ORDER BY expires_at DESC"
    )
    pending, history, requests = [], [], {}
    for row in rows:
        request = _json(row["request"])
        requests[row["operation_id"]] = request
        if request.get("scope") != fields:
            continue
        entry = {"operation_id": row["operation_id"], "operation": request["operation"],
            "requester": row["requester"], "digest": row["digest"]}
        if row["committed"]:
            history.append({**entry, "state": "committed", "at": _stamp(row["committed_at"])})
        elif row["refusal_code"] is not None:
            history.append({**entry, "state": "refused", "code": row["refusal_code"], "at": _stamp(row["expires_at"])})
        elif row["expires_at"] <= now:
            history.append({**entry, "state": "expired", "at": _stamp(row["expires_at"])})
        elif row["approval_id"] is not None:
            pending.append({**entry, "handoff_id": row["handoff_id"], "expires_at": _stamp(row["expires_at"])})
    view = {
        "authority": {"kind": context.authority_kind, "id": context.authority_id, "domain": context.authority_domain,
            "human": context.human_id},
        "pending": pending,
        "history": history[:HISTORY_LIMIT],
        "admitted": [],
        "roots": [],
        "policy": None,
        "approvers": await _approvers(c, scope),
    }
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
        approvers.append({"contact": row["contact"], "passkeys": [
            {"key_id": hashlib.sha256(bytes(p["credential_id"])).hexdigest()[:8], "added_at": _stamp(p["created_at"])}
            for p in passkeys]})
    return approvers


def _when(stamp):
    """A stored UTC time as the page shows it: date, time and zone."""
    if stamp is None:
        return ""
    return datetime.fromisoformat(stamp.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M UTC")


def _window(seconds):
    return {3600: "hour", 86400: "day"}.get(seconds, f"{seconds} seconds")


_OUTCOMES = {"committed": "Approved", "expired": "Expired, nobody decided"}
_REFUSALS = {"human_refused": "Denied"}


def owner_page_html(view: dict) -> str:
    """The owner page's HTML from owner_view. Every value is escaped; the
    request wording comes from each operation's display definition once it
    exists, so until then a request names who asked and when it expires."""
    e = lambda value: escape(str(value), quote=True)  # noqa: E731
    parts = ["<h1>Protected signing</h1>", "<h2>Waiting for you</h2>"]
    if view["pending"]:
        parts.append("<ul class=\"owner-list\">")
        for item in view["pending"]:
            parts.append(
                f'<li><a href="/handoff/{e(item["handoff_id"])}">Review this request</a> '
                f'<span>expires {e(_when(item["expires_at"]))}</span>'
                f'<details><summary>Technical details</summary><dl><dt>Operation</dt><dd>{e(item["operation"])}</dd>'
                f'<dt>Requested by</dt><dd>{e(item["requester"])}</dd>'
                f'<dt>Digest</dt><dd>{e(item["digest"])}</dd></dl></details></li>'
            )
        parts.append("</ul>")
    else:
        parts.append("<p>Nothing is waiting for you.</p>")
    if view["authority"]["kind"] == "team_controller":
        parts.append("<h2>Agents added without asking you</h2>")
        bounds = (view["policy"] or {}).get("bounds")
        for number, root in enumerate(view["roots"], start=1):
            if bounds:
                parts.append(
                    f'<p>Root agent {number}: {root["active"]} of {bounds["max_active"]} at a time, '
                    f'{root["in_window"]} of {bounds["max_per_window"]} in the last {_window(bounds["rate_window_seconds"])}.</p>'
                    f'<details><summary>Technical details</summary><dl><dt>Root agent {number}</dt>'
                    f'<dd>{e(root["root_id"])}</dd></dl></details>'
                )
        if view["admitted"]:
            parts.append("<ul class=\"owner-list\">")
            for agent in view["admitted"]:
                state = {"active": "member", "reserved": "being added", "removed": "removed"}.get(agent["state"], agent["state"])
                parts.append(
                    f'<li>{e(agent["alias"] or "unnamed agent")}: {e(state)}, added {e(_when(agent["admitted_at"]))}'
                    f'<details><summary>Technical details</summary><dl><dt>Added by</dt><dd>{e(agent["root_id"])}</dd>'
                    f'<dt>Agent key</dt><dd>{e(agent["child_key"])}</dd></dl></details></li>'
                )
            parts.append("</ul>")
        else:
            parts.append("<p>No agents have been added yet.</p>")
        parts.append("<h2>Current limits</h2>")
        if bounds:
            policy = view["policy"]
            parts.append(
                f'<p>A root may have {bounds["max_active"]} agents at a time in {e(", ".join(policy["teams"]))}, '
                f'and add at most {bounds["max_per_window"]} per {_window(bounds["rate_window_seconds"])}. '
                "They join as ordinary members. Changing these limits needs its own approval.</p>"
                f'<details><summary>Technical details</summary><dl><dt>Policy</dt><dd>version {e(policy["version"])}, '
                f'{e(policy["digest"])}</dd></dl></details>'
            )
        else:
            parts.append("<p>This team has no admission policy on this signer.</p>")
    parts.append("<h2>History</h2>")
    if view["history"]:
        parts.append("<ul class=\"owner-list\">")
        for item in view["history"]:
            outcome = _OUTCOMES.get(item["state"]) or _REFUSALS.get(item.get("code"), "Not completed")
            parts.append(
                f'<li>{e(outcome)}, {e(_when(item["at"]))}'
                f'<details><summary>Technical details</summary><dl><dt>Operation</dt><dd>{e(item["operation"])}</dd>'
                f'<dt>Requested by</dt><dd>{e(item["requester"])}</dd>'
                f'<dt>Digest</dt><dd>{e(item["digest"])}</dd></dl></details></li>'
            )
        parts.append("</ul>")
    else:
        parts.append("<p>Nothing has happened yet.</p>")
    parts.append("<h2>Who can approve</h2><ul class=\"owner-list\">")
    for approver in view["approvers"]:
        keys = ", ".join(f'passkey {e(p["key_id"])} added {e(_when(p["added_at"])[:10])}' for p in approver["passkeys"])
        parts.append(f'<li>{e(approver["contact"] or "no notice address")}: {keys or "no passkey yet"}</li>')
    parts.append("</ul>")
    return "".join(parts)


def owner_router(composition, *, sessions, csrf_key):
    """GET / is the signed-in owner's page; GET /login?scope= signs them in."""
    from .bootstrap import protected_shell

    async def home(session):
        return owner_page_html(await owner_view(composition, scope=session.scope))

    return protected_shell(csrf_key).router(sessions=sessions, home_title="Protected signing", home=home)
