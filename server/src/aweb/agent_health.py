"""The agent health object the dashboard renders (docs/agent-health.md, "Reading").

Every dashboard surface reads health from this one computation. A stored
status is shown as its publisher signed it; staleness is computed again on
every read, because nothing fires when valid_until passes. An agent without a
host report gets aweb's own observations, worded as observations.
"""

from __future__ import annotations

from datetime import datetime, timedelta
import json
import logging
from typing import Any

from aweb.agent_status import stored_status_document
from aweb.identity_grant_status import effective_grant_status
from aweb.presence import list_agent_presences_by_workspace_ids

logger = logging.getLogger(__name__)

NOT_REPORTED_TEXT = "Its server hasn't reported yet"

# An open GET /v1/events/stream refreshes its agent's listening record about
# every LISTENING_REFRESH_SECONDS; the agent is listening while the newest
# refresh is at most LISTENING_WINDOW_SECONDS old. The record outlives the
# window so "not listening since" stays answerable.
LISTENING_REFRESH_SECONDS = 30
LISTENING_WINDOW_SECONDS = 120
LISTENING_RECORD_TTL_SECONDS = 7 * 24 * 3600


def _listening_key(agent_id) -> str:
    return f"events-stream:{agent_id}"


def _timestamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


async def record_stream_listening(redis, agent_id, *, now: datetime) -> None:
    """Record that the agent's event stream is open now. Never raises."""
    if redis is None:
        return
    key = _listening_key(agent_id)
    try:
        since = now
        raw = await redis.get(key)
        if raw:
            record = json.loads(raw)
            if now - _parse(record["last"]) <= timedelta(seconds=LISTENING_WINDOW_SECONDS):
                since = _parse(record["since"])
        await redis.set(
            key,
            json.dumps({"since": _timestamp(since), "last": _timestamp(now)}),
            ex=LISTENING_RECORD_TTL_SECONDS,
        )
    except Exception:
        logger.warning("Failed to record the event stream for agent %s", agent_id, exc_info=True)


def _not_reported() -> dict[str, Any]:
    return {
        "source": "host",
        "reachable": "unknown",
        "reason_text": NOT_REPORTED_TEXT,
        "fixing_by": None,
        "fixing_text": None,
        "observed_at": None,
        "valid_until": None,
        "stale": False,
        "verified": False,
        "signed_payload": None,
        "signature": None,
    }


def _reported(signed_payload: str, signature: str, *, now: datetime) -> dict[str, Any]:
    document = stored_status_document(signed_payload)
    reason = document.get("reason") or {}
    fixing = document.get("fixing") or {}
    valid_until = datetime.fromisoformat(document["valid_until"].replace("Z", "+00:00"))
    return {
        "source": "host",
        "reachable": document["reachable"],
        "reason_text": reason.get("text"),
        "fixing_by": fixing.get("by"),
        "fixing_text": fixing.get("text"),
        "observed_at": document["observed_at"],
        "valid_until": document["valid_until"],
        "stale": now > valid_until,
        "verified": True,
        "signed_payload": signed_payload,
        "signature": signature,
    }


def _listening(raw: str | None, *, now: datetime) -> tuple[bool, str | None]:
    if not raw:
        return False, None
    record = json.loads(raw)
    if now - _parse(record["last"]) <= timedelta(seconds=LISTENING_WINDOW_SECONDS):
        return True, record["since"]
    return False, record["last"]


async def _listening_records(redis, agent_ids: list) -> list[str | None]:
    if redis is None or not agent_ids:
        return [None] * len(agent_ids)
    try:
        return await redis.mget([_listening_key(agent_id) for agent_id in agent_ids])
    except Exception:
        logger.warning("Failed to read event stream records", exc_info=True)
        return [None] * len(agent_ids)


async def _presence_last_seen(redis, workspace_ids: list) -> dict[str, datetime]:
    """Newest Redis heartbeat presence per workspace."""
    if redis is None or not workspace_ids:
        return {}
    try:
        records = await list_agent_presences_by_workspace_ids(redis, [str(w) for w in workspace_ids])
    except Exception:
        logger.warning("Failed to read heartbeat presence", exc_info=True)
        return {}
    return {
        record["workspace_id"]: _parse(record["last_seen"])
        for record in records
        if record.get("workspace_id") and record.get("last_seen")
    }


async def _connections(db, request, *, team_id: str, agent_ids: list, now: datetime) -> dict[str, str]:
    """The grant connection enum per grant seat (identity-grant-status.v1).

    A seat is active if any of its non-revoked grants is active; otherwise it
    takes the status of its newest grant.
    """
    rows = await db.fetch_all(
        """
        SELECT g.subject_agent_id, g.team_id, g.issued_at, g.expires_at, g.revoked_at,
               g.issued_by_certificate_id,
               a.status AS subject_status, a.deleted_at AS subject_deleted_at
        FROM {{tables.identity_session_grants}} g
        JOIN {{tables.agents}} a ON a.agent_id = g.subject_agent_id
        WHERE g.team_id = $1 AND g.subject_agent_id = ANY($2::uuid[])
        ORDER BY g.subject_agent_id, g.issued_at DESC
        """,
        team_id,
        agent_ids,
    )
    connections: dict[str, str] = {}
    for row in rows:
        agent_id = str(row["subject_agent_id"])
        if connections.get(agent_id) == "active":
            continue
        if agent_id in connections and row["revoked_at"] is not None:
            continue
        status, _ = await effective_grant_status(request, row, now)
        if agent_id not in connections or status == "active":
            connections[agent_id] = status
    return connections


def _observed_by_aweb(row) -> bool:
    """No host and no report, or a host that is no longer an active member."""
    if row["host_did"] is None:
        return row["signed_payload"] is None
    return not row["host_active"]


def _observed(row, *, listening_raw, presence, connection, now: datetime) -> dict[str, Any]:
    listening, listening_since = _listening(listening_raw, now=now)
    seen = [row["workspace_last_seen_at"], row["grant_last_seen_at"]]
    seen += [presence[str(w)] for w in row["workspace_ids"] or [] if str(w) in presence]
    seen = [value for value in seen if value is not None]
    return {
        "source": "aweb",
        "listening": listening,
        "listening_since": listening_since,
        "last_active": _timestamp(max(seen)) if seen else None,
        "connection": connection,
    }


async def agent_health(
    db,
    redis,
    request,
    *,
    team_id: str,
    agent_ids: list,
    now: datetime,
    show_connection: bool,
) -> dict[str, dict[str, Any]]:
    """Return each agent's health object, keyed by agent_id as a string.

    A designated host that is no longer an active member of the team speaks
    for no one, so its agent falls back to aweb's own observations. The grant
    connection is shown only to verified dashboard readers (show_connection).
    """
    if not agent_ids:
        return {}
    rows = await db.fetch_all(
        """
        SELECT a.agent_id, h.host_did,
               EXISTS (
                   SELECT 1 FROM {{tables.agents}} m
                   WHERE m.team_id = a.team_id AND m.did_key = h.host_did AND m.deleted_at IS NULL
               ) AS host_active,
               s.signed_payload, s.signature,
               (SELECT max(w.last_seen_at) FROM {{tables.workspaces}} w
                WHERE w.agent_id = a.agent_id AND w.deleted_at IS NULL) AS workspace_last_seen_at,
               (SELECT array_agg(w.workspace_id) FROM {{tables.workspaces}} w
                WHERE w.agent_id = a.agent_id AND w.deleted_at IS NULL) AS workspace_ids,
               (SELECT max(l.last_seen_at) FROM {{tables.identity_grant_liveness}} l
                WHERE l.subject_agent_id = a.agent_id AND l.team_id = a.team_id) AS grant_last_seen_at
        FROM {{tables.agents}} a
        LEFT JOIN {{tables.agent_status_hosts}} h ON h.agent_id = a.agent_id
        LEFT JOIN {{tables.agent_status}} s ON s.agent_id = a.agent_id
        WHERE a.team_id = $1 AND a.agent_id = ANY($2::uuid[])
        """,
        team_id,
        agent_ids,
    )
    observed_rows = [row for row in rows if _observed_by_aweb(row)]
    observed_ids = [row["agent_id"] for row in observed_rows]
    listening_raw = dict(zip([str(i) for i in observed_ids], await _listening_records(redis, observed_ids)))
    presence = await _presence_last_seen(
        redis, [w for row in observed_rows for w in row["workspace_ids"] or []],
    )
    connections = (
        await _connections(db, request, team_id=team_id, agent_ids=observed_ids, now=now)
        if show_connection and observed_ids else {}
    )

    health = {}
    for row in rows:
        agent_id = str(row["agent_id"])
        if _observed_by_aweb(row):
            health[agent_id] = _observed(
                row,
                listening_raw=listening_raw.get(agent_id),
                presence=presence,
                connection=connections.get(agent_id),
                now=now,
            )
        elif row["signed_payload"] is not None:
            health[agent_id] = _reported(row["signed_payload"], row["signature"], now=now)
        else:
            health[agent_id] = _not_reported()
    return health
