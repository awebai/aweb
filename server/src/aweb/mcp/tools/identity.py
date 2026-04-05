"""MCP tools for agent identity."""

from __future__ import annotations

import json
from uuid import UUID

from aweb.address_scope import get_project_scope
from aweb.awid.registry import RegistryError
from aweb.mcp.auth import get_auth


async def whoami(db_infra, *, registry_client) -> str:
    """Return the authenticated agent's identity."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")

    agent = await aweb_db.fetch_one(
        """
        SELECT a.alias, a.human_name, a.agent_type, a.did, a.stable_id,
               a.custody, a.lifetime, a.role, a.program, a.context
        FROM {{tables.agents}} a
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
        scope = await get_project_scope(db_infra, project_id=auth.project_id)
        assigned_addresses = []
        stable_id = (agent.get("stable_id") or "").strip()
        if stable_id:
            try:
                assigned_addresses = await registry_client.list_did_addresses(stable_id)
            except RegistryError:
                assigned_addresses = []
        result["alias"] = agent["alias"]
        result["human_name"] = agent.get("human_name") or ""
        result["agent_type"] = agent.get("agent_type") or "agent"
        result["did"] = agent.get("did") or ""
        result["stable_id"] = agent.get("stable_id") or ""
        result["custody"] = agent.get("custody") or ""
        result["lifetime"] = agent.get("lifetime") or "ephemeral"
        result["role"] = agent.get("role")
        result["role_name"] = agent.get("role")
        result["program"] = agent.get("program")
        result["scope"] = {
            "project_id": scope.project_id,
            "project_slug": scope.project_slug,
            "owner_type": scope.owner_type,
            "owner_ref": scope.owner_ref,
        }
        result["addresses"] = [f"{address.domain}/{address.name}" for address in assigned_addresses]
        ctx = agent.get("context")
        if isinstance(ctx, str):
            try:
                ctx = json.loads(ctx)
            except (json.JSONDecodeError, TypeError):
                pass
        result["context"] = ctx

    return json.dumps(result)
