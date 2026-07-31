"""MCP tools for agent listing and heartbeat."""

from __future__ import annotations

import json

from aweb.mcp.tools._common import require_team_context
from aweb.presence import (
    DEFAULT_PRESENCE_TTL_SECONDS,
    list_agent_presences_by_workspace_ids,
    update_agent_presence,
)


async def list_agents(db_infra, redis) -> str:
    """List all agents in the authenticated team."""
    auth, error = require_team_context()
    if auth is None:
        return error or json.dumps({"error": "This tool requires team context. Use a team certificate."})
    aweb_db = db_infra.get_manager("aweb")

    rows = await aweb_db.fetch_all(
        """
        SELECT a.agent_id, w.workspace_id, a.alias, a.human_name, a.agent_type,
               a.identity_scope, a.status
        FROM {{tables.agents}} a
        LEFT JOIN {{tables.workspaces}} w
          ON w.team_id = a.team_id
         AND w.agent_id = a.agent_id
         AND w.alias = a.alias
         AND w.deleted_at IS NULL
        WHERE a.team_id = $1 AND a.deleted_at IS NULL AND a.agent_type != 'human'
        ORDER BY a.alias
        """,
        auth.team_id,
    )

    workspace_ids = [str(r["workspace_id"]) for r in rows if r.get("workspace_id")]
    presences = await list_agent_presences_by_workspace_ids(redis, workspace_ids)
    presence_map = {}
    for presence in presences:
        presence_id = (presence.get("workspace_id") or presence.get("agent_id") or "").strip()
        if presence_id:
            presence_map[presence_id] = presence

    agents = []
    for r in rows:
        aid = str(r["agent_id"])
        workspace_id = str(r["workspace_id"]) if r.get("workspace_id") else ""
        p = presence_map.get(workspace_id)
        agents.append(
            {
                "agent_id": aid,
                "alias": r["alias"],
                "human_name": r.get("human_name") or "",
                "agent_type": r.get("agent_type") or "agent",
                "online": p is not None,
                "identity_scope": r.get("identity_scope") or "local",
                "status": r.get("status") or "active",
            }
        )

    return json.dumps({"team_id": auth.team_id, "agents": agents})


async def heartbeat(db_infra, redis) -> str:
    """Send a heartbeat to maintain agent presence."""
    auth, error = require_team_context()
    if auth is None:
        return error or json.dumps({"error": "This tool requires team context. Use a team certificate."})
    aweb_db = db_infra.get_manager("aweb")

    row = await aweb_db.fetch_one(
        """
        SELECT a.alias, w.workspace_id
        FROM {{tables.agents}} a
        JOIN {{tables.workspaces}} w
          ON w.team_id = a.team_id
         AND w.agent_id = a.agent_id
         AND w.alias = a.alias
         AND w.deleted_at IS NULL
        WHERE a.agent_id = $1 AND a.team_id = $2 AND a.deleted_at IS NULL
        """,
        auth.agent_id,
        auth.team_id,
    )
    if not row:
        return json.dumps({"error": "Agent not found"})

    ttl = DEFAULT_PRESENCE_TTL_SECONDS
    last_seen = await update_agent_presence(
        redis,
        workspace_id=str(row["workspace_id"]),
        alias=row["alias"],
        team_id=auth.team_id,
        ttl_seconds=ttl,
    )

    return json.dumps(
        {
            "agent_id": auth.agent_id,
            "last_seen": last_seen,
            "ttl_seconds": ttl,
        }
    )
