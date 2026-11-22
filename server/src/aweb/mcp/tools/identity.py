"""MCP tools for identity-style introspection."""

from __future__ import annotations

from aweb.identity_binding import IdentityProjectionField, verified_identity_field_sql

import json

from aweb.mcp.auth import get_auth


async def whoami(db_infra) -> str:
    """Show the authenticated agent identity for the current request."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")

    if auth.team_id:
        row = await aweb_db.fetch_one(
            f"""
            SELECT {verified_identity_field_sql(IdentityProjectionField.STABLE_DID)} AS did_aw, {verified_identity_field_sql(IdentityProjectionField.ADDRESS)} AS address
            FROM {{{{tables.agents}}}}
            WHERE team_id = $1 AND did_key = $2 AND deleted_at IS NULL
            """,
            auth.team_id,
            auth.did_key,
        )
    else:
        row = await aweb_db.fetch_one(
            f"""
            SELECT {verified_identity_field_sql(IdentityProjectionField.STABLE_DID)} AS did_aw, {verified_identity_field_sql(IdentityProjectionField.ADDRESS)} AS address
            FROM {{{{tables.agents}}}}
            WHERE did_key = $1 AND deleted_at IS NULL
            ORDER BY created_at DESC
            LIMIT 1
            """,
            auth.did_key,
        )

    outcome = auth.address_resolution
    result = {
        "team_id": auth.team_id,
        "agent_id": auth.agent_id,
        "alias": auth.alias,
        "did_key": auth.did_key,
        "did_aw": (auth.did_aw or (row["did_aw"] if row and row["did_aw"] else "")),
        "address": (auth.address or (row["address"] if row and row["address"] else "")),
    }
    if outcome.state == "unknown":
        result["address"] = None
        result["address_status"] = "unknown"
    return json.dumps(result)
