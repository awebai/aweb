"""MCP tools for agent listing and heartbeat."""

from __future__ import annotations

import json
from uuid import UUID

from aweb.mcp.auth import get_auth
from aweb.presence import (
    DEFAULT_PRESENCE_TTL_SECONDS,
    list_agent_presences_by_ids,
    update_agent_presence,
)


async def list_agents(db_infra, redis) -> str:
    """List all agents in the authenticated project."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")

    rows = await aweb_db.fetch_all(
        """
        SELECT agent_id, alias, human_name, agent_type, access_mode,
               did, custody, lifetime, status
        FROM {{tables.agents}}
        WHERE project_id = $1 AND deleted_at IS NULL AND agent_type != 'human'
        ORDER BY alias
        """,
        UUID(auth.project_id),
    )

    agent_ids = [str(r["agent_id"]) for r in rows]
    presences = await list_agent_presences_by_ids(redis, agent_ids)
    presence_map = {p["agent_id"]: p for p in presences}

    agents = []
    for r in rows:
        aid = str(r["agent_id"])
        p = presence_map.get(aid)
        agents.append(
            {
                "agent_id": aid,
                "alias": r["alias"],
                "human_name": r.get("human_name") or "",
                "agent_type": r.get("agent_type") or "agent",
                "access_mode": r.get("access_mode", "open"),
                "online": p is not None,
                "did": r.get("did") or "",
                "custody": r.get("custody") or "",
                "lifetime": r.get("lifetime") or "persistent",
                "status": r.get("status") or "active",
            }
        )

    return json.dumps({"project_id": auth.project_id, "agents": agents})


async def heartbeat(db_infra, redis) -> str:
    """Send a heartbeat to maintain agent presence."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")

    row = await aweb_db.fetch_one(
        """
        SELECT alias
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        UUID(auth.agent_id),
        UUID(auth.project_id),
    )
    if not row:
        return json.dumps({"error": "Agent not found"})

    ttl = DEFAULT_PRESENCE_TTL_SECONDS
    last_seen = await update_agent_presence(
        redis,
        agent_id=auth.agent_id,
        alias=row["alias"],
        project_id=auth.project_id,
        ttl_seconds=ttl,
    )

    return json.dumps(
        {
            "agent_id": auth.agent_id,
            "last_seen": last_seen,
            "ttl_seconds": ttl,
        }
    )
