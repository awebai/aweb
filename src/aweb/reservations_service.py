from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from fastapi import HTTPException

RESERVATION_MIN_TTL_SECONDS = 60
RESERVATION_MAX_TTL_SECONDS = 3600


def clamp_ttl(ttl_seconds: int) -> int:
    if ttl_seconds < RESERVATION_MIN_TTL_SECONDS:
        return RESERVATION_MIN_TTL_SECONDS
    if ttl_seconds > RESERVATION_MAX_TTL_SECONDS:
        return RESERVATION_MAX_TTL_SECONDS
    return ttl_seconds


def _decode_metadata(value: Any) -> dict[str, Any]:
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


async def get_agent(db, *, project_id: str, agent_id: str) -> dict[str, Any] | None:
    """Look up an active agent by ID within a project."""
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, alias
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        UUID(agent_id),
        UUID(project_id),
    )
    if not row:
        return None
    return dict(row)


async def acquire_reservation(
    db,
    *,
    project_id: str,
    agent_id: str,
    resource_key: str,
    ttl_seconds: int,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    """Acquire a reservation. Returns dict with status="acquired" or status="conflict".

    Raises HTTPException(404) if the agent is not found.
    """
    agent = await get_agent(db, project_id=project_id, agent_id=agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    ttl = clamp_ttl(int(ttl_seconds))
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=ttl)

    aweb_db = db.get_manager("aweb")
    async with aweb_db.transaction() as tx:
        existing = await tx.fetch_one(
            """
            SELECT holder_agent_id, holder_alias, expires_at
            FROM {{tables.reservations}}
            WHERE project_id = $1 AND resource_key = $2
            FOR UPDATE
            """,
            UUID(project_id),
            resource_key,
        )

        if existing and existing["expires_at"] > now:
            return {
                "status": "conflict",
                "detail": "Reservation is already held",
                "holder_agent_id": str(existing["holder_agent_id"]),
                "holder_alias": existing["holder_alias"],
                "expires_at": existing["expires_at"].isoformat(),
            }

        if existing:
            await tx.execute(
                """
                DELETE FROM {{tables.reservations}}
                WHERE project_id = $1 AND resource_key = $2
                """,
                UUID(project_id),
                resource_key,
            )

        await tx.execute(
            """
            INSERT INTO {{tables.reservations}}
                (project_id, resource_key, holder_agent_id, holder_alias, acquired_at, expires_at, metadata_json)
            VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
            """,
            UUID(project_id),
            resource_key,
            UUID(agent_id),
            agent["alias"],
            now,
            expires_at,
            json.dumps(metadata or {}),
        )

    return {
        "status": "acquired",
        "project_id": project_id,
        "resource_key": resource_key,
        "holder_agent_id": agent_id,
        "holder_alias": agent["alias"],
        "acquired_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
        "ttl_seconds": ttl,
    }


async def release_reservation(
    db,
    *,
    project_id: str,
    agent_id: str,
    resource_key: str,
) -> dict[str, Any]:
    """Release a reservation. Returns dict with status="released".

    Raises HTTPException(409) if the reservation is held by another agent.
    Missing/expired reservations are treated as idempotent success.
    Does NOT validate that agent_id exists — caller is responsible.
    """
    now = datetime.now(timezone.utc)
    aweb_db = db.get_manager("aweb")
    async with aweb_db.transaction() as tx:
        existing = await tx.fetch_one(
            """
            SELECT holder_agent_id, expires_at
            FROM {{tables.reservations}}
            WHERE project_id = $1 AND resource_key = $2
            FOR UPDATE
            """,
            UUID(project_id),
            resource_key,
        )
        if not existing or existing["expires_at"] <= now:
            # Treat missing/expired as idempotent success.
            return {"status": "released", "resource_key": resource_key, "deleted": False}
        if str(existing["holder_agent_id"]) != agent_id:
            raise HTTPException(status_code=409, detail="Reservation held by another agent")

        await tx.execute(
            """
            DELETE FROM {{tables.reservations}}
            WHERE project_id = $1 AND resource_key = $2
            """,
            UUID(project_id),
            resource_key,
        )

    return {"status": "released", "resource_key": resource_key, "deleted": True}


async def list_reservations(
    db,
    *,
    project_id: str,
    prefix: str | None = None,
) -> list[dict[str, Any]]:
    """List active (non-expired) reservations, optionally filtered by prefix."""
    now = datetime.now(timezone.utc)
    aweb_db = db.get_manager("aweb")

    if prefix is None:
        rows = await aweb_db.fetch_all(
            """
            SELECT project_id, resource_key, holder_agent_id, holder_alias,
                   acquired_at, expires_at, metadata_json
            FROM {{tables.reservations}}
            WHERE project_id = $1 AND expires_at > $2
            ORDER BY resource_key ASC
            """,
            UUID(project_id),
            now,
        )
    else:
        rows = await aweb_db.fetch_all(
            """
            SELECT project_id, resource_key, holder_agent_id, holder_alias,
                   acquired_at, expires_at, metadata_json
            FROM {{tables.reservations}}
            WHERE project_id = $1 AND expires_at > $2 AND resource_key LIKE ($3 || '%')
            ORDER BY resource_key ASC
            """,
            UUID(project_id),
            now,
            prefix,
        )

    return [
        {
            "project_id": str(r["project_id"]),
            "resource_key": r["resource_key"],
            "holder_agent_id": str(r["holder_agent_id"]),
            "holder_alias": r["holder_alias"],
            "acquired_at": r["acquired_at"].isoformat(),
            "expires_at": r["expires_at"].isoformat(),
            "metadata": _decode_metadata(r.get("metadata_json")),
        }
        for r in rows
    ]
