"""Reservations API - view active resource locks."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from fastapi.responses import JSONResponse

from aweb.deps import get_db
from aweb.team_auth_deps import TeamIdentity, get_team_identity

from ._reservation_utils import reservation_metadata, reservation_prefix_like

router = APIRouter(prefix="/v1", tags=["reservations"])

DEFAULT_RESERVATION_TTL_SECONDS = 3600


class ReservationView(BaseModel):
    team_id: str
    resource_key: str
    holder_agent_id: str
    holder_alias: str
    acquired_at: str
    expires_at: str
    ttl_remaining_seconds: int
    reason: Optional[str] = None
    metadata: dict[str, object]


class ReservationListResponse(BaseModel):
    reservations: list[ReservationView]


class ReservationAcquireRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resource_key: str = Field(..., min_length=1, max_length=4096)
    ttl_seconds: int = Field(DEFAULT_RESERVATION_TTL_SECONDS, ge=1, le=86400)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReservationAcquireResponse(BaseModel):
    status: str
    team_id: str
    resource_key: str
    holder_agent_id: str
    holder_alias: str
    acquired_at: str
    expires_at: str


class ReservationConflictResponse(BaseModel):
    detail: str
    holder_agent_id: str
    holder_alias: str
    expires_at: str


class ReservationRenewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resource_key: str = Field(..., min_length=1, max_length=4096)
    ttl_seconds: int = Field(DEFAULT_RESERVATION_TTL_SECONDS, ge=1, le=86400)


class ReservationRenewResponse(BaseModel):
    status: str
    resource_key: str
    expires_at: str


class ReservationReleaseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resource_key: str = Field(..., min_length=1, max_length=4096)


class ReservationReleaseResponse(BaseModel):
    status: str
    resource_key: str


class ReservationRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prefix: str = Field("", max_length=4096)


class ReservationRevokeResponse(BaseModel):
    revoked_count: int
    revoked_keys: list[str]


def _reservation_reason(metadata: dict[str, Any]) -> Optional[str]:
    reason = metadata.get("reason")
    if not isinstance(reason, str):
        return None
    reason = reason.strip()
    return reason or None


def _reservation_conflict_response(*, holder_agent_id: str, holder_alias: str, expires_at: str) -> JSONResponse:
    return JSONResponse(
        status_code=409,
        content={
            "detail": "reservation is already held",
            "holder_agent_id": holder_agent_id,
            "holder_alias": holder_alias,
            "expires_at": expires_at,
        },
    )


def _reservation_view(row, *, now: datetime) -> ReservationView:
    metadata = reservation_metadata(row["metadata_json"])
    return ReservationView(
        team_id=row["team_id"],
        resource_key=row["resource_key"],
        holder_agent_id=str(row["holder_agent_id"]),
        holder_alias=row["holder_alias"],
        acquired_at=row["acquired_at"].isoformat(),
        expires_at=row["expires_at"].isoformat(),
        ttl_remaining_seconds=max(int((row["expires_at"] - now).total_seconds()), 0),
        reason=_reservation_reason(metadata),
        metadata=metadata,
    )


@router.get("/reservations")
async def list_reservations(
    request: Request,
    prefix: Optional[str] = Query(None, description="Optional resource key prefix filter"),
    db=Depends(get_db),
    identity: TeamIdentity = Depends(get_team_identity),
) -> ReservationListResponse:
    aweb_db = db.get_manager("aweb")
    now = datetime.now(timezone.utc)

    conditions = ["team_id = $1", "expires_at > NOW()"]
    params: list[object] = [identity.team_id]

    if prefix:
        conditions.append(f"resource_key LIKE ${len(params) + 1} ESCAPE '\\'")
        params.append(reservation_prefix_like(prefix))

    where_clause = " AND ".join(conditions)
    rows = await aweb_db.fetch_all(
        f"""
        SELECT team_id, resource_key, holder_agent_id, holder_alias,
               acquired_at, expires_at, metadata_json
        FROM {{{{tables.reservations}}}}
        WHERE {where_clause}
        ORDER BY resource_key ASC
        """,
        *params,
    )

    return ReservationListResponse(
        reservations=[_reservation_view(row, now=now) for row in rows]
    )


@router.post(
    "/reservations",
    response_model=ReservationAcquireResponse,
    responses={409: {"model": ReservationConflictResponse}},
    status_code=status.HTTP_200_OK,
)
async def acquire_reservation(
    request: Request,
    payload: ReservationAcquireRequest,
    db=Depends(get_db),
    identity: TeamIdentity = Depends(get_team_identity),
) -> ReservationAcquireResponse | JSONResponse:
    aweb_db = db.get_manager("aweb")
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=payload.ttl_seconds)

    async with aweb_db.transaction() as tx:
        row = await tx.fetch_one(
            """
            SELECT team_id, resource_key, holder_agent_id, holder_alias,
                   acquired_at, expires_at, metadata_json
            FROM {{tables.reservations}}
            WHERE team_id = $1 AND resource_key = $2
            FOR UPDATE
            """,
            identity.team_id,
            payload.resource_key,
        )

        if row and row["expires_at"] > now and str(row["holder_agent_id"]) != identity.agent_id:
            return _reservation_conflict_response(
                holder_agent_id=str(row["holder_agent_id"]),
                holder_alias=row["holder_alias"],
                expires_at=row["expires_at"].isoformat(),
            )

        # An empty metadata object means "preserve existing metadata" so the
        # current CLI acquire path does not silently clear reason/context fields.
        metadata = payload.metadata or (reservation_metadata(row["metadata_json"]) if row else {})
        if row:
            await tx.execute(
                """
                UPDATE {{tables.reservations}}
                SET holder_agent_id = $3,
                    holder_alias = $4,
                    acquired_at = $5,
                    expires_at = $6,
                    metadata_json = $7::jsonb
                WHERE team_id = $1 AND resource_key = $2
                """,
                identity.team_id,
                payload.resource_key,
                UUID(identity.agent_id),
                identity.alias,
                now,
                expires_at,
                json.dumps(metadata),
            )
        else:
            await tx.execute(
                """
                INSERT INTO {{tables.reservations}}
                    (team_id, resource_key, holder_agent_id, holder_alias, acquired_at, expires_at, metadata_json)
                VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
                """,
                identity.team_id,
                payload.resource_key,
                UUID(identity.agent_id),
                identity.alias,
                now,
                expires_at,
                json.dumps(metadata),
            )

    return ReservationAcquireResponse(
        status="acquired",
        team_id=identity.team_id,
        resource_key=payload.resource_key,
        holder_agent_id=identity.agent_id,
        holder_alias=identity.alias,
        acquired_at=now.isoformat(),
        expires_at=expires_at.isoformat(),
    )


@router.post(
    "/reservations/renew",
    response_model=ReservationRenewResponse,
    responses={409: {"model": ReservationConflictResponse}},
)
async def renew_reservation(
    request: Request,
    payload: ReservationRenewRequest,
    db=Depends(get_db),
    identity: TeamIdentity = Depends(get_team_identity),
) -> ReservationRenewResponse | JSONResponse:
    aweb_db = db.get_manager("aweb")
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=payload.ttl_seconds)

    async with aweb_db.transaction() as tx:
        row = await tx.fetch_one(
            """
            SELECT holder_agent_id, holder_alias, expires_at
            FROM {{tables.reservations}}
            WHERE team_id = $1 AND resource_key = $2
            FOR UPDATE
            """,
            identity.team_id,
            payload.resource_key,
        )
        if row is None or row["expires_at"] <= now:
            raise HTTPException(status_code=404, detail="reservation not found")
        if str(row["holder_agent_id"]) != identity.agent_id:
            return _reservation_conflict_response(
                holder_agent_id=str(row["holder_agent_id"]),
                holder_alias=row["holder_alias"],
                expires_at=row["expires_at"].isoformat(),
            )

        await tx.execute(
            """
            UPDATE {{tables.reservations}}
            SET expires_at = $3
            WHERE team_id = $1 AND resource_key = $2
            """,
            identity.team_id,
            payload.resource_key,
            expires_at,
        )

    return ReservationRenewResponse(
        status="renewed",
        resource_key=payload.resource_key,
        expires_at=expires_at.isoformat(),
    )


@router.post(
    "/reservations/release",
    response_model=ReservationReleaseResponse,
    responses={409: {"model": ReservationConflictResponse}},
)
async def release_reservation(
    request: Request,
    payload: ReservationReleaseRequest,
    db=Depends(get_db),
    identity: TeamIdentity = Depends(get_team_identity),
) -> ReservationReleaseResponse | JSONResponse:
    aweb_db = db.get_manager("aweb")
    now = datetime.now(timezone.utc)

    async with aweb_db.transaction() as tx:
        row = await tx.fetch_one(
            """
            SELECT holder_agent_id, holder_alias, expires_at
            FROM {{tables.reservations}}
            WHERE team_id = $1 AND resource_key = $2
            FOR UPDATE
            """,
            identity.team_id,
            payload.resource_key,
        )

        if row is not None and row["expires_at"] > now and str(row["holder_agent_id"]) != identity.agent_id:
            return _reservation_conflict_response(
                holder_agent_id=str(row["holder_agent_id"]),
                holder_alias=row["holder_alias"],
                expires_at=row["expires_at"].isoformat(),
            )

        if row is not None:
            await tx.execute(
                """
                DELETE FROM {{tables.reservations}}
                WHERE team_id = $1 AND resource_key = $2
                """,
                identity.team_id,
                payload.resource_key,
            )

    return ReservationReleaseResponse(status="released", resource_key=payload.resource_key)


@router.post("/reservations/revoke", response_model=ReservationRevokeResponse)
async def revoke_reservations(
    request: Request,
    payload: ReservationRevokeRequest,
    db=Depends(get_db),
    identity: TeamIdentity = Depends(get_team_identity),
) -> ReservationRevokeResponse:
    aweb_db = db.get_manager("aweb")

    params: list[object] = [identity.team_id]
    where = ["team_id = $1", "expires_at > NOW()"]
    if payload.prefix:
        where.append(f"resource_key LIKE ${len(params) + 1} ESCAPE '\\'")
        params.append(reservation_prefix_like(payload.prefix))

    rows = await aweb_db.fetch_all(
        f"""
        DELETE FROM {{{{tables.reservations}}}}
        WHERE {' AND '.join(where)}
        RETURNING resource_key
        """,
        *params,
    )

    revoked_keys = [row["resource_key"] for row in rows]
    return ReservationRevokeResponse(
        revoked_count=len(revoked_keys),
        revoked_keys=revoked_keys,
    )
