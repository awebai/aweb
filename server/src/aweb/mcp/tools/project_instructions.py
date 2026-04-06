"""MCP tools for project-wide shared instructions."""

from __future__ import annotations

import json

from aweb.coordination.routes.project_instructions import get_active_project_instructions
from aweb.mcp.auth import get_auth


async def instructions_show(db_infra, *, project_instructions_id: str = "") -> str:
    """Show the active or requested project instructions version."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")

    if project_instructions_id:
        row = await aweb_db.fetch_one(
            """
            SELECT id, team_address, version, document_json, updated_at
            FROM {{tables.project_instructions}}
            WHERE id = $1 AND team_address = $2
            """,
            project_instructions_id,
            auth.team_address,
        )
        if row is None:
            return json.dumps({"error": "Project instructions not found"})
        document_data = row["document_json"]
        if isinstance(document_data, str):
            document_data = json.loads(document_data)
        return json.dumps(
            {
                "project_instructions_id": str(row["id"]),
                "active_project_instructions_id": None,
                "team_address": str(row["team_address"]),
                "version": row["version"],
                "updated_at": row["updated_at"].isoformat(),
                "document": document_data,
            }
        )

    version = await get_active_project_instructions(aweb_db, auth.team_address, bootstrap_if_missing=True)
    if version is None:
        return json.dumps({"error": "Project instructions not found"})

    return json.dumps(
        {
            "project_instructions_id": version.id,
            "active_project_instructions_id": version.id,
            "team_address": version.team_address,
            "version": version.version,
            "updated_at": version.updated_at.isoformat(),
            "document": version.document.model_dump(),
        }
    )


async def instructions_history(db_infra, *, limit: int = 20) -> str:
    """List recent project instructions versions for the authenticated project."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")
    limit = max(1, min(int(limit), 100))

    await get_active_project_instructions(aweb_db, auth.team_address, bootstrap_if_missing=True)

    rows = await aweb_db.fetch_all(
        """
        SELECT id, version, created_at, created_by_alias, is_active
        FROM {{tables.project_instructions}}
        WHERE team_address = $1
        ORDER BY version DESC
        LIMIT $2
        """,
        auth.team_address,
        limit,
    )

    return json.dumps(
        {
            "project_instructions_versions": [
                {
                    "project_instructions_id": str(row["id"]),
                    "version": row["version"],
                    "created_at": row["created_at"].isoformat(),
                    "created_by_alias": (
                        str(row["created_by_alias"])
                        if row["created_by_alias"]
                        else None
                    ),
                    "is_active": bool(row["is_active"]),
                }
                for row in rows
            ]
        }
    )
