"""The agent health object the dashboard renders (docs/agent-health.md, "Reading").

Every dashboard surface reads health from this one computation. A stored
status is shown as its publisher signed it; staleness is computed again on
every read, because nothing fires when valid_until passes.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from aweb.agent_status import stored_status_document

NOT_REPORTED_TEXT = "Its server hasn't reported yet"


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


async def agent_health(db, *, team_id: str, agent_ids: list, now: datetime) -> dict[str, dict[str, Any]]:
    """Return each agent's health object, keyed by agent_id as a string.

    A designated host that is no longer an active member of the team speaks
    for no one, so its agent falls back to aweb's own observations.
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
               s.signed_payload, s.signature
        FROM {{tables.agents}} a
        LEFT JOIN {{tables.agent_status_hosts}} h ON h.agent_id = a.agent_id
        LEFT JOIN {{tables.agent_status}} s ON s.agent_id = a.agent_id
        WHERE a.team_id = $1 AND a.agent_id = ANY($2::uuid[])
        """,
        team_id,
        agent_ids,
    )
    health = {}
    for row in rows:
        if row["host_did"] is not None and not row["host_active"]:
            health[str(row["agent_id"])] = {"source": "aweb"}
        elif row["signed_payload"] is not None:
            health[str(row["agent_id"])] = _reported(row["signed_payload"], row["signature"], now=now)
        elif row["host_did"] is not None:
            health[str(row["agent_id"])] = _not_reported()
        else:
            health[str(row["agent_id"])] = {"source": "aweb"}
    return health
