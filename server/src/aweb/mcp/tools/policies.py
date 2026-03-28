"""MCP tools for project policy inspection."""

from __future__ import annotations

import json
from uuid import UUID

from aweb.coordination.routes.policies import get_active_policy
from aweb.mcp.auth import get_auth


async def policy_show(db_infra, *, only_selected: bool = False) -> str:
    """Show the active policy for the authenticated project and current agent role."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")
    server_db = db_infra.get_manager("server")

    agent = await aweb_db.fetch_one(
        """
        SELECT role
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        UUID(auth.agent_id),
        UUID(auth.project_id),
    )
    agent_role = (agent.get("role") or "").strip() if agent else ""

    policy = await get_active_policy(server_db, auth.project_id, bootstrap_if_missing=True)
    if policy is None:
        return json.dumps({"error": "Policy not found"})

    selected_role = None
    if agent_role and agent_role in policy.bundle.roles:
        role_info = policy.bundle.roles[agent_role]
        selected_role = {
            "role": agent_role,
            "role_name": agent_role,
            "title": role_info.get("title", agent_role),
            "playbook_md": role_info.get("playbook_md", ""),
        }

    invariants = [
        {
            "id": inv.get("id", ""),
            "title": inv.get("title", ""),
            "body_md": inv.get("body_md", ""),
        }
        for inv in policy.bundle.invariants
    ]
    roles = (
        {agent_role: policy.bundle.roles[agent_role]}
        if only_selected and selected_role is not None
        else ({} if only_selected else policy.bundle.roles)
    )

    return json.dumps(
        {
            "policy_id": policy.policy_id,
            "project_id": policy.project_id,
            "version": policy.version,
            "updated_at": policy.updated_at.isoformat(),
            "agent_id": auth.agent_id,
            "agent_role": agent_role or None,
            "agent_role_name": agent_role or None,
            "selected_role": selected_role,
            "invariants": invariants,
            "roles": roles,
            "available_roles": sorted(policy.bundle.roles.keys()),
            "adapters": policy.bundle.adapters,
        }
    )


async def roles_list(db_infra) -> str:
    """List available roles from the active project policy plus the agent's current role."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")
    server_db = db_infra.get_manager("server")

    agent = await aweb_db.fetch_one(
        """
        SELECT role
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        UUID(auth.agent_id),
        UUID(auth.project_id),
    )
    current_role = (agent.get("role") or "").strip() if agent else ""

    policy = await get_active_policy(server_db, auth.project_id, bootstrap_if_missing=True)
    available_roles = sorted(policy.bundle.roles.keys()) if policy else []

    return json.dumps(
        {
            "project_id": auth.project_id,
            "agent_id": auth.agent_id,
            "current_role": current_role or None,
            "current_role_name": current_role or None,
            "roles": available_roles,
        }
    )
