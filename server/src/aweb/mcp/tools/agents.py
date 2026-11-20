"""MCP tools for agent listing and heartbeat."""

from __future__ import annotations

from aweb.config import get_presence_ttl_seconds
from aweb.member_team_key import current_member_sql

from aweb.human_kind import agent_listing_predicate_sql, effective_agent_type

import json
from datetime import UTC, datetime
from typing import Any
from aweb.application_state import RegistryClientUnavailable
from aweb.grant_liveness_policy import GrantLivenessFailurePolicy
from aweb.workspace_activity import workspace_activity_by_id

from aweb.mcp.tools._common import require_team_context
from aweb.presence import (
    update_agent_presence,
)


async def list_agents(db_infra, redis, *, registry_client=None) -> str:
    """List all agents in the authenticated team."""
    auth, error = require_team_context()
    if auth is None:
        return error or json.dumps(
            {"error": "This tool requires team context. Use a team certificate."}
        )
    if registry_client is None:
        raise RegistryClientUnavailable()
    aweb_db = db_infra.get_manager("aweb")

    rows = await aweb_db.fetch_all(
        f"""
        SELECT a.agent_id, w.workspace_id, a.alias, a.human_name, a.agent_type, a.human_verified_key, a.did_key,
               a.identity_scope, a.status
        FROM {{{{tables.agents}}}} a
        LEFT JOIN {{{{tables.workspaces}}}} w
          ON w.team_id = a.team_id
         AND w.agent_id = a.agent_id
         AND w.alias = a.alias
         AND w.deleted_at IS NULL
        WHERE a.team_id = $1 AND {current_member_sql("a")} AND {agent_listing_predicate_sql("a")}
        ORDER BY a.alias
        """,
        auth.team_id,
    )

    workspace_ids = [str(r["workspace_id"]) for r in rows if r.get("workspace_id")]
    activity_by_id = await workspace_activity_by_id(
        aweb_db,
        redis,
        workspace_ids=workspace_ids,
        registry_client=registry_client,
        request=auth.request,
        failure_policy=GrantLivenessFailurePolicy.OMIT_UNPROVEN,
    )
    now = datetime.now(UTC)

    agents = []
    for r in rows:
        aid = str(r["agent_id"])
        workspace_id = str(r["workspace_id"]) if r.get("workspace_id") else ""
        activity = activity_by_id.get(workspace_id)
        agents.append(
            {
                "agent_id": aid,
                "alias": r["alias"],
                "human_name": r.get("human_name") or "",
                "agent_type": effective_agent_type(r),
                "online": activity is not None and activity.is_online(now=now),
                "identity_scope": r.get("identity_scope") or "local",
                "status": r.get("status") or "active",
            }
        )

    by_agent: dict[str, dict[str, Any]] = {}
    for agent in agents:
        prior = by_agent.get(agent["agent_id"])
        if prior is None or agent["online"]:
            by_agent[agent["agent_id"]] = agent
    return json.dumps({"team_id": auth.team_id, "agents": list(by_agent.values())})


async def heartbeat(db_infra, redis) -> str:
    """Send a heartbeat to maintain agent presence."""
    auth, error = require_team_context()
    if auth is None:
        return error or json.dumps(
            {"error": "This tool requires team context. Use a team certificate."}
        )
    aweb_db = db_infra.get_manager("aweb")

    row = await aweb_db.fetch_one(
        """
        UPDATE {{tables.workspaces}} w
        SET last_seen_at = NOW(), updated_at = NOW()
        FROM {{tables.agents}} a
        WHERE w.team_id = a.team_id
          AND w.agent_id = a.agent_id
          AND w.alias = a.alias
          AND w.deleted_at IS NULL
          AND a.agent_id = $1 AND a.team_id = $2 AND a.deleted_at IS NULL
        RETURNING a.alias, w.workspace_id
        """,
        auth.agent_id,
        auth.team_id,
    )
    if not row:
        return json.dumps({"error": "Agent not found"})

    ttl = get_presence_ttl_seconds()
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
