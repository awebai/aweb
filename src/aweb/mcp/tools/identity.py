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
        SELECT a.alias, a.human_name, a.agent_type, a.did, a.custody, a.lifetime,
               a.role, a.program, a.context,
               n.slug AS namespace_slug
        FROM {{tables.agents}} a
        LEFT JOIN {{tables.namespaces}} n ON a.namespace_id = n.namespace_id
            AND n.deleted_at IS NULL
        WHERE a.agent_id = $1 AND a.project_id = $2 AND a.deleted_at IS NULL
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
        result["did"] = agent.get("did") or ""
        result["custody"] = agent.get("custody") or ""
        result["lifetime"] = agent.get("lifetime") or "persistent"
        result["role"] = agent.get("role")
        result["program"] = agent.get("program")
        ctx = agent.get("context")
        if isinstance(ctx, str):
            try:
                ctx = json.loads(ctx)
            except (json.JSONDecodeError, TypeError):
                pass
        result["context"] = ctx
        ns_slug = agent.get("namespace_slug")
        if ns_slug:
            result["namespace_slug"] = ns_slug
            result["address"] = f"{ns_slug}/{agent['alias']}"

    return json.dumps(result)
