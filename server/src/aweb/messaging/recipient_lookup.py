"""Shared native messaging identity lookups; reads grant no membership."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from aweb.human_kind import effective_agent_type, human_predicate_sql
from aweb.service_errors import ValidationError


def _parse_uuid(v: str, *, field_name: str) -> UUID:
    v = str(v).strip()
    if not v:
        raise ValidationError(f"Missing {field_name}")
    try:
        return UUID(v)
    except Exception:
        raise ValidationError(f"Invalid {field_name} format")


async def get_agent_by_id(
    db, *, agent_id: str, team_id: str | None = None
) -> dict | None:
    """Look up an agent by agent_id, optionally scoped to a team."""
    aweb_db = db.get_manager("aweb")
    if team_id is None:
        row = await aweb_db.fetch_one(
            """
            SELECT agent_id, team_id, alias, did_key, agent_type, human_verified_key, CASE WHEN did_aw_verified_key = did_key THEN did_aw END AS did_aw, CASE WHEN did_aw_verified_key = did_key THEN address END AS address, identity_scope, (NULLIF(did_aw, '') IS NOT NULL) AS has_global_claim, did_aw AS policy_did_aw, inbound_mode, status, deleted_at
            FROM {{tables.agents}}
            WHERE agent_id = $1 AND deleted_at IS NULL
            """,
            _parse_uuid(agent_id, field_name="agent_id"),
        )
    else:
        row = await aweb_db.fetch_one(
            """
            SELECT agent_id, team_id, alias, did_key, agent_type, human_verified_key, CASE WHEN did_aw_verified_key = did_key THEN did_aw END AS did_aw, CASE WHEN did_aw_verified_key = did_key THEN address END AS address, identity_scope, (NULLIF(did_aw, '') IS NOT NULL) AS has_global_claim, did_aw AS policy_did_aw, inbound_mode, status, deleted_at
            FROM {{tables.agents}}
            WHERE agent_id = $1 AND team_id = $2 AND deleted_at IS NULL
            """,
            _parse_uuid(agent_id, field_name="agent_id"),
            team_id,
        )
    if not row:
        return None
    return {**dict(row), "agent_type": effective_agent_type(row)}


async def get_agent_by_alias(db, *, team_id: str, alias: str) -> dict | None:
    """Look up an agent by alias within a team."""
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        f"""
        SELECT agent_id, team_id, alias, did_key, agent_type, human_verified_key, CASE WHEN did_aw_verified_key = did_key THEN did_aw END AS did_aw, CASE WHEN did_aw_verified_key = did_key THEN address END AS address, identity_scope, (NULLIF(did_aw, '') IS NOT NULL) AS has_global_claim, did_aw AS policy_did_aw, inbound_mode, status, deleted_at
        FROM {{{{tables.agents}}}}
        WHERE team_id = $1 AND alias = $2 AND deleted_at IS NULL
          AND NOT {human_predicate_sql()}
        """,
        team_id,
        alias,
    )
    if not row:
        return None
    return {**dict(row), "agent_type": effective_agent_type(row)}


async def resolve_agent_by_did(db, did: str) -> dict | None:
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, team_id, alias, did_key, agent_type, human_verified_key, CASE WHEN did_aw_verified_key = did_key THEN did_aw END AS did_aw, CASE WHEN did_aw_verified_key = did_key THEN address END AS address, identity_scope, (NULLIF(did_aw, '') IS NOT NULL) AS has_global_claim, did_aw AS policy_did_aw, inbound_mode, status, deleted_at
        FROM {{tables.agents}}
        WHERE deleted_at IS NULL
          AND ((did_aw = $1 AND did_aw_verified_key = did_key) OR did_key = $1)
        ORDER BY CASE WHEN did_aw = $1 THEN 0 ELSE 1 END, created_at DESC
        LIMIT 1
        """,
        did,
    )
    return None if not row else {**dict(row), "agent_type": effective_agent_type(row)}


async def get_agents_by_aliases(
    db, *, team_id: str, aliases: list[str]
) -> list[dict[str, Any]]:
    if not aliases:
        return []
    aweb_db = db.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        f"""
        SELECT agent_id, team_id, alias, did_key, CASE WHEN did_aw_verified_key = did_key THEN did_aw END AS did_aw, CASE WHEN did_aw_verified_key = did_key THEN address END AS address, identity_scope, (NULLIF(did_aw, '') IS NOT NULL) AS has_global_claim, did_aw AS policy_did_aw, inbound_mode, deleted_at
        FROM {{{{tables.agents}}}}
        WHERE team_id = $1 AND alias = ANY($2::text[]) AND deleted_at IS NULL
          AND NOT {human_predicate_sql()}
        """,
        team_id,
        aliases,
    )
    return [dict(row) for row in rows]
