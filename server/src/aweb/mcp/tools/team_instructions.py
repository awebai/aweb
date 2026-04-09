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
            SELECT id, team_address, version, document_json, updated_at
            FROM {{tables.team_instructions}}
            WHERE id = $1 AND team_address = $2
            """,
            team_instructions_id,
            auth.team_address,
        )
        if row is None:
            return json.dumps({"error": "Team instructions not found"})
        document_data = row["document_json"]
        if isinstance(document_data, str):
            document_data = json.loads(document_data)
        return json.dumps(
            {
                "team_instructions_id": str(row["id"]),
                "active_team_instructions_id": None,
                "team_address": str(row["team_address"]),
                "version": row["version"],
                "updated_at": row["updated_at"].isoformat(),
                "document": document_data,
            }
        )

    version = await get_active_team_instructions(aweb_db, auth.team_address, bootstrap_if_missing=True)
    if version is None:
        return json.dumps({"error": "Team instructions not found"})

    return json.dumps(
        {
            "team_instructions_id": version.id,
            "active_team_instructions_id": version.id,
            "team_address": version.team_address,
            "version": version.version,
            "updated_at": version.updated_at.isoformat(),
            "document": version.document.model_dump(),
        }
    )


async def instructions_history(db_infra, *, limit: int = 20) -> str:
    """List recent team instructions versions for the authenticated team."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")
    limit = max(1, min(int(limit), 100))

    await get_active_team_instructions(aweb_db, auth.team_address, bootstrap_if_missing=True)

    rows = await aweb_db.fetch_all(
        """
        SELECT id, version, created_at, created_by_alias, is_active
        FROM {{tables.team_instructions}}
        WHERE team_address = $1
        ORDER BY version DESC
        LIMIT $2
        """,
        auth.team_address,
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
