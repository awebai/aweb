"""MCP tools for distributed locks (reservations)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import UUID

from aweb.mcp.auth import get_auth

RESERVATION_MIN_TTL_SECONDS = 60
RESERVATION_MAX_TTL_SECONDS = 3600


def _clamp_ttl(ttl_seconds: int) -> int:
    if ttl_seconds < RESERVATION_MIN_TTL_SECONDS:
        return RESERVATION_MIN_TTL_SECONDS
    if ttl_seconds > RESERVATION_MAX_TTL_SECONDS:
        return RESERVATION_MAX_TTL_SECONDS
    return ttl_seconds


def _decode_metadata(value) -> dict:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


async def lock_acquire(
    db_infra, *, resource_key: str, ttl_seconds: int = 60, metadata: str = ""
) -> str:
    """Acquire a distributed lock on a resource."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")

    if not resource_key.strip():
        return json.dumps({"error": "resource_key must not be empty"})

    agent = await aweb_db.fetch_one(
        """
        SELECT agent_id, alias
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        UUID(auth.agent_id),
        UUID(auth.project_id),
    )
    if not agent:
        return json.dumps({"error": "Agent not found"})

    ttl = _clamp_ttl(int(ttl_seconds))
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=ttl)

    # Parse metadata JSON string from tool argument.
    meta_dict: dict = {}
    if metadata:
        try:
            parsed = json.loads(metadata)
            if isinstance(parsed, dict):
                meta_dict = parsed
        except Exception:
            return json.dumps({"error": "metadata must be a valid JSON object"})

    async with aweb_db.transaction() as tx:
        existing = await tx.fetch_one(
            """
            SELECT holder_agent_id, holder_alias, expires_at
            FROM {{tables.reservations}}
            WHERE project_id = $1 AND resource_key = $2
            FOR UPDATE
            """,
            UUID(auth.project_id),
            resource_key.strip(),
        )

        if existing and existing["expires_at"] > now:
            return json.dumps(
                {
                    "error": "Resource is already locked",
                    "holder_agent_id": str(existing["holder_agent_id"]),
                    "holder_alias": existing["holder_alias"],
                    "expires_at": existing["expires_at"].isoformat(),
                }
            )

        if existing:
            await tx.execute(
                """
                DELETE FROM {{tables.reservations}}
                WHERE project_id = $1 AND resource_key = $2
                """,
                UUID(auth.project_id),
                resource_key.strip(),
            )

        await tx.execute(
            """
            INSERT INTO {{tables.reservations}}
                (project_id, resource_key, holder_agent_id, holder_alias,
                 acquired_at, expires_at, metadata_json)
            VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
            """,
            UUID(auth.project_id),
            resource_key.strip(),
            UUID(auth.agent_id),
            agent["alias"],
            now,
            expires_at,
            json.dumps(meta_dict),
        )

    return json.dumps(
        {
            "status": "acquired",
            "resource_key": resource_key.strip(),
            "holder_alias": agent["alias"],
            "acquired_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
        }
    )


async def lock_release(db_infra, *, resource_key: str) -> str:
    """Release a distributed lock."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")

    if not resource_key.strip():
        return json.dumps({"error": "resource_key must not be empty"})

    now = datetime.now(timezone.utc)

    async with aweb_db.transaction() as tx:
        existing = await tx.fetch_one(
            """
            SELECT holder_agent_id, expires_at
            FROM {{tables.reservations}}
            WHERE project_id = $1 AND resource_key = $2
            FOR UPDATE
            """,
            UUID(auth.project_id),
            resource_key.strip(),
        )
        if not existing or existing["expires_at"] <= now:
            return json.dumps({"status": "released", "resource_key": resource_key.strip()})
        if str(existing["holder_agent_id"]) != auth.agent_id:
            return json.dumps({"error": "Lock held by another agent"})

        await tx.execute(
            """
            DELETE FROM {{tables.reservations}}
            WHERE project_id = $1 AND resource_key = $2
            """,
            UUID(auth.project_id),
            resource_key.strip(),
        )

    return json.dumps({"status": "released", "resource_key": resource_key.strip()})


async def lock_list(db_infra, *, prefix: str = "") -> str:
    """List active locks in the project."""
    auth = get_auth()
    aweb_db = db_infra.get_manager("aweb")
    now = datetime.now(timezone.utc)

    if prefix:
        rows = await aweb_db.fetch_all(
            """
            SELECT project_id, resource_key, holder_agent_id, holder_alias,
                   acquired_at, expires_at, metadata_json
            FROM {{tables.reservations}}
            WHERE project_id = $1 AND expires_at > $2 AND resource_key LIKE ($3 || '%')
            ORDER BY resource_key ASC
            """,
            UUID(auth.project_id),
            now,
            prefix,
        )
    else:
        rows = await aweb_db.fetch_all(
            """
            SELECT project_id, resource_key, holder_agent_id, holder_alias,
                   acquired_at, expires_at, metadata_json
            FROM {{tables.reservations}}
            WHERE project_id = $1 AND expires_at > $2
            ORDER BY resource_key ASC
            """,
            UUID(auth.project_id),
            now,
        )

    return json.dumps(
        {
            "reservations": [
                {
                    "resource_key": r["resource_key"],
                    "holder_agent_id": str(r["holder_agent_id"]),
                    "holder_alias": r["holder_alias"],
                    "acquired_at": r["acquired_at"].isoformat(),
                    "expires_at": r["expires_at"].isoformat(),
                    "metadata": _decode_metadata(r.get("metadata_json")),
                }
                for r in rows
            ]
        }
    )
