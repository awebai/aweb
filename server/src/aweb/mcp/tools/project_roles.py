"""MCP tools for project roles inspection."""

from __future__ import annotations

import json

from aweb.coordination.routes.project_roles import get_active_project_roles
from aweb.mcp.auth import get_auth


async def roles_show(db_infra, *, only_selected: bool = False) -> str:
    """Show the active project roles for the authenticated project and current agent role."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")
    agent = await aweb_db.fetch_one(
        """
        SELECT role
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND team_address = $2 AND deleted_at IS NULL
        """,
        auth.agent_id,
        auth.team_address,
    )
    agent_role = (agent.get("role") or "").strip() if agent else ""

    project_roles_version = await get_active_project_roles(
        aweb_db, auth.team_address, bootstrap_if_missing=True
    )
    if project_roles_version is None:
        return json.dumps({"error": "Project roles not found"})

    selected_role = None
    if agent_role and agent_role in project_roles_version.bundle.roles:
        role_info = project_roles_version.bundle.roles[agent_role]
        selected_role = {
            "role": agent_role,
            "role_name": agent_role,
            "title": role_info.get("title", agent_role),
            "playbook_md": role_info.get("playbook_md", ""),
        }

    roles = (
        {agent_role: project_roles_version.bundle.roles[agent_role]}
        if only_selected and selected_role is not None
        else ({} if only_selected else project_roles_version.bundle.roles)
    )

    return json.dumps(
        {
            "id": project_roles_version.id,
            "team_address": project_roles_version.team_address,
            "version": project_roles_version.version,
            "updated_at": project_roles_version.updated_at.isoformat(),
            "agent_id": auth.agent_id,
            "agent_role": agent_role or None,
            "agent_role_name": agent_role or None,
            "selected_role": selected_role,
            "roles": roles,
            "available_roles": sorted(project_roles_version.bundle.roles.keys()),
            "adapters": project_roles_version.bundle.adapters,
        }
    )


async def roles_list(db_infra) -> str:
    """List available roles from the active project roles bundle plus the agent's current role."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")

    agent = await aweb_db.fetch_one(
        """
        SELECT role
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND team_address = $2 AND deleted_at IS NULL
        """,
        auth.agent_id,
        auth.team_address,
    )
    current_role = (agent.get("role") or "").strip() if agent else ""

    project_roles_version = await get_active_project_roles(
        aweb_db, auth.team_address, bootstrap_if_missing=True
    )
    available_roles = (
        sorted(project_roles_version.bundle.roles.keys()) if project_roles_version else []
    )

    return json.dumps(
        {
            "team_address": auth.team_address,
            "agent_id": auth.agent_id,
            "current_role": current_role or None,
            "current_role_name": current_role or None,
            "roles": available_roles,
        }
    )
