"""MCP tools for team-wide shared instructions."""

from __future__ import annotations

import json

from aweb.coordination.routes.team_instructions import get_active_team_instructions
from aweb.mcp.auth import get_auth


async def instructions_show(db_infra, *, team_instructions_id: str = "") -> str:
    """Show the active or requested team instructions version."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")

    if team_instructions_id:
        row = await aweb_db.fetch_one(
            """
            SELECT id, team_id, version, document_json, created_at, updated_at
            FROM {{tables.team_instructions}}
            WHERE id = $1 AND team_id = $2
            """,
            team_instructions_id,
            auth.team_id,
        )
        if row is None:
            return json.dumps({"error": "Team instructions not found"})
        document_data = row["document_json"]
        if isinstance(document_data, str):
            document_data = json.loads(document_data)
        updated_at = row["updated_at"] or row["created_at"]
        return json.dumps(
            {
                "team_instructions_id": str(row["id"]),
                "active_team_instructions_id": None,
                "team_id": str(row["team_id"]),
                "version": row["version"],
                "updated_at": updated_at.isoformat(),
                "document": document_data,
            }
        )

    version = await get_active_team_instructions(aweb_db, auth.team_id, bootstrap_if_missing=True)
    if version is None:
        return json.dumps({"error": "Team instructions not found"})
    updated_at = version.updated_at or version.created_at

    return json.dumps(
        {
            "team_instructions_id": version.id,
            "active_team_instructions_id": version.id,
            "team_id": version.team_id,
            "version": version.version,
            "updated_at": updated_at.isoformat(),
            "document": version.document.model_dump(),
        }
    )


async def instructions_history(db_infra, *, limit: int = 20) -> str:
    """List recent team instructions versions for the authenticated team."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")
    limit = max(1, min(int(limit), 100))

    await get_active_team_instructions(aweb_db, auth.team_id, bootstrap_if_missing=True)

    rows = await aweb_db.fetch_all(
        """
        SELECT id, version, created_at, created_by_alias, is_active
        FROM {{tables.team_instructions}}
        WHERE team_id = $1
        ORDER BY version DESC
        LIMIT $2
        """,
        auth.team_id,
        limit,
    )

    return json.dumps(
        {
            "team_instructions_versions": [
                {
                    "team_instructions_id": str(row["id"]),
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
