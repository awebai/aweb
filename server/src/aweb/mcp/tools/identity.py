"""MCP tools for identity-style introspection."""

from __future__ import annotations

import json

from aweb.mcp.auth import get_auth


async def whoami(db_infra) -> str:
    """Show the authenticated agent identity for the current request."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")

    if auth.team_id:
        row = await aweb_db.fetch_one(
            """
            SELECT did_aw, address
            FROM {{tables.agents}}
            WHERE team_id = $1 AND did_key = $2 AND deleted_at IS NULL
            """,
            auth.team_id,
            auth.did_key,
        )
    else:
        row = await aweb_db.fetch_one(
            """
            SELECT did_aw, address
            FROM {{tables.agents}}
            WHERE did_key = $1 AND deleted_at IS NULL
            ORDER BY created_at DESC
            LIMIT 1
            """,
            auth.did_key,
        )

    return json.dumps(
        {
            "team_id": auth.team_id,
            "agent_id": auth.agent_id,
            "alias": auth.alias,
            "did_key": auth.did_key,
            "did_aw": (row["did_aw"] if row and row["did_aw"] else ""),
            "address": (row["address"] if row and row["address"] else ""),
        }
    )
