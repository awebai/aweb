from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from aweb.auth import get_actor_agent_id_from_auth, get_project_from_auth
from aweb.deps import get_db
from aweb.hooks import fire_mutation_hook
from aweb.reservations_service import (
    RESERVATION_MIN_TTL_SECONDS,
    acquire_reservation,
    clamp_ttl,
    get_agent,
    list_reservations,
    release_reservation,
)

router = APIRouter(prefix="/v1/reservations", tags=["aweb-reservations"])


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

    result = await acquire_reservation(
        db,
        project_id=project_id,
        agent_id=actor_id,
        resource_key=payload.resource_key,
        ttl_seconds=payload.ttl_seconds,
        metadata=payload.metadata,
    )

    if result["status"] == "conflict":
        return JSONResponse(
            status_code=409,
            content={
                "detail": result["detail"],
                "holder_agent_id": result["holder_agent_id"],
                "holder_alias": result["holder_alias"],
                "expires_at": result["expires_at"],
            },
        )

    await fire_mutation_hook(
        request,
        "reservation.acquired",
        {
            "resource_key": payload.resource_key,
            "holder_agent_id": actor_id,
            "ttl_seconds": result["ttl_seconds"],
        },
    )

    return {
        "status": "acquired",
        "project_id": result["project_id"],
        "resource_key": result["resource_key"],
        "holder_agent_id": result["holder_agent_id"],
        "holder_alias": result["holder_alias"],
        "acquired_at": result["acquired_at"],
        "expires_at": result["expires_at"],
    }


@router.post("/renew")
async def renew(request: Request, payload: RenewRequest, db=Depends(get_db)) -> dict[str, Any]:
    project_id = await get_project_from_auth(request, db, manager_name="aweb")
    actor_id = await get_actor_agent_id_from_auth(request, db, manager_name="aweb")
    agent = await get_agent(db, project_id=project_id, agent_id=actor_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    ttl = clamp_ttl(int(payload.ttl_seconds))
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
    agent = await get_agent(db, project_id=project_id, agent_id=actor_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    result = await release_reservation(
        db,
        project_id=project_id,
        agent_id=actor_id,
        resource_key=payload.resource_key,
    )

    if result["deleted"]:
        await fire_mutation_hook(
            request,
            "reservation.released",
            {
                "resource_key": payload.resource_key,
                "holder_agent_id": actor_id,
            },
        )

    return {"status": result["status"], "resource_key": result["resource_key"]}


@router.post("/revoke")
async def revoke(
    request: Request,
    payload: RevokeRequest,
    db=Depends(get_db),
) -> dict[str, Any]:
    """Release the caller's own reservations in this project.

    Optional prefix narrows the released set to resource_key LIKE '<prefix>%'.
    Returns 403 if the prefix matches reservations held by other agents.
    """
    project_id = await get_project_from_auth(request, db, manager_name="aweb")
    actor_id = await get_actor_agent_id_from_auth(request, db, manager_name="aweb")
    actor_uuid = UUID(actor_id)
    project_uuid = UUID(project_id)

    aweb_db = db.get_manager("aweb")
    if payload.prefix:
        async with aweb_db.transaction() as tx:
            rows = await tx.fetch_all(
                """
                DELETE FROM {{tables.reservations}}
                WHERE project_id = $1 AND resource_key LIKE ($2 || '%')
                  AND holder_agent_id = $3
                RETURNING 1
                """,
                project_uuid,
                payload.prefix,
                actor_uuid,
            )
            if not rows:
                held_by_others = await tx.fetch_one(
                    """
                    SELECT 1 FROM {{tables.reservations}}
                    WHERE project_id = $1 AND resource_key LIKE ($2 || '%')
                    LIMIT 1
                    """,
                    project_uuid,
                    payload.prefix,
                )
                if held_by_others:
                    raise HTTPException(
                        status_code=403,
                        detail="Cannot revoke reservations held by other agents",
                    )
    else:
        rows = await aweb_db.fetch_all(
            """
            DELETE FROM {{tables.reservations}}
            WHERE project_id = $1 AND holder_agent_id = $2
            RETURNING 1
            """,
            project_uuid,
            actor_uuid,
        )

    return {"status": "revoked", "deleted": len(rows)}


@router.get("", response_model=ListResponse)
async def list_reservations_route(
    request: Request,
    prefix: Optional[str] = Query(None),
    db=Depends(get_db),
) -> ListResponse:
    project_id = await get_project_from_auth(request, db, manager_name="aweb")
    reservations = await list_reservations(db, project_id=project_id, prefix=prefix)
    return ListResponse(
        reservations=[ReservationView(**r) for r in reservations]
    )
