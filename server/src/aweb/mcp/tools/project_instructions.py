"""MCP tools for project-wide shared instructions."""

from __future__ import annotations

import json

from aweb.coordination.routes.project_instructions import get_active_project_instructions
from aweb.mcp.auth import get_auth


async def instructions_show(db_infra, *, project_instructions_id: str = "") -> str:
    """Show the active or requested project instructions version."""
    auth = get_auth()
    server_db = db_infra.get_manager("server")

    if project_instructions_id:
        row = await server_db.fetch_one(
            """
            SELECT project_instructions_id, project_id, version, document_json, updated_at
            FROM {{tables.project_instructions}}
            WHERE project_instructions_id = $1 AND project_id = $2
            """,
            project_instructions_id,
            auth.project_id,
        )
        if row is None:
            return json.dumps({"error": "Project instructions not found"})
        active_version = await get_active_project_instructions(
            server_db, auth.project_id, bootstrap_if_missing=True
        )
        document_data = row["document_json"]
        if isinstance(document_data, str):
            document_data = json.loads(document_data)
        return json.dumps(
            {
                "project_instructions_id": str(row["project_instructions_id"]),
                "active_project_instructions_id": (
                    active_version.project_instructions_id if active_version else None
                ),
                "project_id": str(row["project_id"]),
                "version": row["version"],
                "updated_at": row["updated_at"].isoformat(),
                "document": document_data,
            }
        )

    version = await get_active_project_instructions(server_db, auth.project_id, bootstrap_if_missing=True)
    if version is None:
        return json.dumps({"error": "Project instructions not found"})

    return json.dumps(
        {
            "project_instructions_id": version.project_instructions_id,
            "active_project_instructions_id": version.project_instructions_id,
            "project_id": version.project_id,
            "version": version.version,
            "updated_at": version.updated_at.isoformat(),
            "document": version.document.model_dump(),
        }
    )


async def instructions_history(db_infra, *, limit: int = 20) -> str:
    """List recent project instructions versions for the authenticated project."""
    auth = get_auth()
    server_db = db_infra.get_manager("server")
    limit = max(1, min(int(limit), 100))

    active_version = await get_active_project_instructions(server_db, auth.project_id, bootstrap_if_missing=True)
    active_project_instructions_id = (
        active_version.project_instructions_id if active_version is not None else None
    )

    rows = await server_db.fetch_all(
        """
        SELECT project_instructions_id, version, created_at, created_by_workspace_id
        FROM {{tables.project_instructions}}
        WHERE project_id = $1
        ORDER BY version DESC
        LIMIT $2
        """,
        auth.project_id,
        limit,
    )

    return json.dumps(
        {
            "project_instructions_versions": [
                {
                    "project_instructions_id": str(row["project_instructions_id"]),
                    "version": row["version"],
                    "created_at": row["created_at"].isoformat(),
                    "created_by_workspace_id": (
                        str(row["created_by_workspace_id"])
                        if row["created_by_workspace_id"]
                        else None
                    ),
                    "is_active": (
                        str(row["project_instructions_id"]) == active_project_instructions_id
                    ),
                }
                for row in rows
            ]
        }
    )
