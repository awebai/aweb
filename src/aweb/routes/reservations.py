from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from aweb.auth import get_actor_agent_id_from_auth, get_project_from_auth
from aweb.deps import get_db

router = APIRouter(prefix="/v1/reservations", tags=["aweb-reservations"])

RESERVATION_MIN_TTL_SECONDS = 60
RESERVATION_MAX_TTL_SECONDS = 3600


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _clamp_ttl(ttl_seconds: int) -> int:
    if ttl_seconds < RESERVATION_MIN_TTL_SECONDS:
        return RESERVATION_MIN_TTL_SECONDS
    if ttl_seconds > RESERVATION_MAX_TTL_SECONDS:
        return RESERVATION_MAX_TTL_SECONDS
    return ttl_seconds


async def _get_agent(db, *, project_id: str, agent_id: str) -> dict[str, Any] | None:
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


class AcquireRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resource_key: str = Field(..., min_length=1, max_length=4096)
    ttl_seconds: int = Field(RESERVATION_MIN_TTL_SECONDS, ge=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReservationView(BaseModel):
    project_id: str
    resource_key: str
    holder_agent_id: str
    holder_alias: str
    acquired_at: str
    expires_at: str
    metadata: dict[str, Any]


class ListResponse(BaseModel):
    reservations: list[ReservationView]


class ReleaseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resource_key: str = Field(..., min_length=1, max_length=4096)


class RevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prefix: Optional[str] = Field(None, max_length=4096)


class RenewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resource_key: str = Field(..., min_length=1, max_length=4096)
    ttl_seconds: int = Field(RESERVATION_MIN_TTL_SECONDS, ge=1)


@router.post("")
async def acquire(request: Request, payload: AcquireRequest, db=Depends(get_db)) -> dict[str, Any]:
    project_id = await get_project_from_auth(request, db, manager_name="aweb")
    actor_id = await get_actor_agent_id_from_auth(request, db, manager_name="aweb")

    agent = await _get_agent(db, project_id=project_id, agent_id=actor_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    ttl = _clamp_ttl(int(payload.ttl_seconds))
    now = _now()
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
            payload.resource_key,
        )

        if existing and existing["expires_at"] > now:
            return JSONResponse(
                status_code=409,
                content={
                    "detail": "Reservation is already held",
                    "holder_agent_id": str(existing["holder_agent_id"]),
                    "holder_alias": existing["holder_alias"],
                    "expires_at": existing["expires_at"].isoformat(),
                },
            )

        if existing:
            await tx.execute(
                """
                DELETE FROM {{tables.reservations}}
                WHERE project_id = $1 AND resource_key = $2
                """,
                UUID(project_id),
                payload.resource_key,
            )

        await tx.execute(
            """
            INSERT INTO {{tables.reservations}}
                (project_id, resource_key, holder_agent_id, holder_alias, acquired_at, expires_at, metadata_json)
            VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
            """,
            UUID(project_id),
            payload.resource_key,
            UUID(actor_id),
            agent["alias"],
            now,
            expires_at,
            json.dumps(payload.metadata or {}),
        )

    return {
        "status": "acquired",
        "project_id": project_id,
        "resource_key": payload.resource_key,
        "holder_agent_id": actor_id,
        "holder_alias": agent["alias"],
        "acquired_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
    }


@router.post("/renew")
async def renew(request: Request, payload: RenewRequest, db=Depends(get_db)) -> dict[str, Any]:
    project_id = await get_project_from_auth(request, db, manager_name="aweb")
    actor_id = await get_actor_agent_id_from_auth(request, db, manager_name="aweb")
    agent = await _get_agent(db, project_id=project_id, agent_id=actor_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    ttl = _clamp_ttl(int(payload.ttl_seconds))
    now = _now()
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
            payload.resource_key,
        )
        if not existing or existing["expires_at"] <= now:
            raise HTTPException(status_code=404, detail="Reservation not found")
        if str(existing["holder_agent_id"]) != actor_id:
            raise HTTPException(status_code=409, detail="Reservation held by another agent")

        await tx.execute(
            """
            UPDATE {{tables.reservations}}
            SET expires_at = $3
            WHERE project_id = $1 AND resource_key = $2
            """,
            UUID(project_id),
            payload.resource_key,
            expires_at,
        )

    return {
        "status": "renewed",
        "resource_key": payload.resource_key,
        "expires_at": expires_at.isoformat(),
    }


@router.post("/release")
async def release(request: Request, payload: ReleaseRequest, db=Depends(get_db)) -> dict[str, Any]:
    project_id = await get_project_from_auth(request, db, manager_name="aweb")
    actor_id = await get_actor_agent_id_from_auth(request, db, manager_name="aweb")
    agent = await _get_agent(db, project_id=project_id, agent_id=actor_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    now = _now()
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
            payload.resource_key,
        )
        if not existing or existing["expires_at"] <= now:
            # Treat missing/expired as idempotent success.
            return {"status": "released", "resource_key": payload.resource_key}
        if str(existing["holder_agent_id"]) != actor_id:
            raise HTTPException(status_code=409, detail="Reservation held by another agent")

        await tx.execute(
            """
            DELETE FROM {{tables.reservations}}
            WHERE project_id = $1 AND resource_key = $2
            """,
            UUID(project_id),
            payload.resource_key,
        )

    return {"status": "released", "resource_key": payload.resource_key}


@router.post("/revoke")
async def revoke(
    request: Request,
    payload: RevokeRequest,
    db=Depends(get_db),
) -> dict[str, Any]:
    """Force-release reservations in this project.

    Intended for admin/support tooling and recovery from stale locks.
    The operation is project-scoped via auth.

    Optional prefix narrows the revoked set to resource_key LIKE '<prefix>%'.
    """
    project_id = await get_project_from_auth(request, db, manager_name="aweb")
    _actor_id = await get_actor_agent_id_from_auth(request, db, manager_name="aweb")

    aweb_db = db.get_manager("aweb")
    if payload.prefix:
        rows = await aweb_db.fetch_all(
            """
            DELETE FROM {{tables.reservations}}
            WHERE project_id = $1 AND resource_key LIKE ($2 || '%')
            RETURNING 1
            """,
            UUID(project_id),
            payload.prefix,
        )
    else:
        rows = await aweb_db.fetch_all(
            """
            DELETE FROM {{tables.reservations}}
            WHERE project_id = $1
            RETURNING 1
            """,
            UUID(project_id),
        )

    return {"status": "revoked", "deleted": len(rows)}


@router.get("", response_model=ListResponse)
async def list_reservations(
    request: Request,
    prefix: Optional[str] = Query(None),
    db=Depends(get_db),
) -> ListResponse:
    project_id = await get_project_from_auth(request, db, manager_name="aweb")
    now = _now()

    aweb_db = db.get_manager("aweb")
    if prefix is None:
        rows = await aweb_db.fetch_all(
            """
            SELECT project_id, resource_key, holder_agent_id, holder_alias, acquired_at, expires_at, metadata_json
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
            SELECT project_id, resource_key, holder_agent_id, holder_alias, acquired_at, expires_at, metadata_json
            FROM {{tables.reservations}}
            WHERE project_id = $1 AND expires_at > $2 AND resource_key LIKE ($3 || '%')
            ORDER BY resource_key ASC
            """,
            UUID(project_id),
            now,
            prefix,
        )

    return ListResponse(
        reservations=[
            ReservationView(
                project_id=str(r["project_id"]),
                resource_key=r["resource_key"],
                holder_agent_id=str(r["holder_agent_id"]),
                holder_alias=r["holder_alias"],
                acquired_at=r["acquired_at"].isoformat(),
                expires_at=r["expires_at"].isoformat(),
                metadata=_decode_metadata(r.get("metadata_json")),
            )
            for r in rows
        ]
    )


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
