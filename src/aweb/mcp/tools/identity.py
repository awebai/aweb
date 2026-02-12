"""MCP tools for agent identity."""

from __future__ import annotations

import json
from uuid import UUID

from aweb.mcp.auth import get_auth


async def whoami(db_infra) -> str:
    """Return the authenticated agent's identity."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")

    agent = await aweb_db.fetch_one(
        """
        SELECT alias, human_name, agent_type
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        UUID(auth.agent_id),
        UUID(auth.project_id),
    )

    result = {
        "project_id": auth.project_id,
        "agent_id": auth.agent_id,
    }
    if agent:
        result["alias"] = agent["alias"]
        result["human_name"] = agent.get("human_name") or ""
        result["agent_type"] = agent.get("agent_type") or "agent"

    return json.dumps(result)
