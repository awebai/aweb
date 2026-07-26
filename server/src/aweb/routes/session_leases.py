"""Session-scoped admission leases.

These leases prevent accidental concurrent admission when callers use them.
They are not fencing credentials and are not automatically acquired by OAS.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from aweb.deps import get_db
from aweb.team_auth_deps import TeamIdentity, get_team_identity

router = APIRouter(prefix="/v1/session-leases", tags=["session-leases"])


class LeaseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str = Field(..., min_length=1, max_length=256)
    session_key: str = Field(..., min_length=32, max_length=1024)
    ttl_seconds: int = Field(300, ge=1, le=86400)


class LeaseReleaseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str = Field(..., min_length=1, max_length=256)
    session_key: str = Field(..., min_length=32, max_length=1024)


class LeaseTakeoverRequest(LeaseRequest):
    reason: str = Field(..., min_length=1, max_length=4096)


class LeaseView(BaseModel):
    status: str
    team_id: str
    principal_agent_id: str
    session_id: str
    generation: int
    acquired_at: str
    expires_at: str


def _key_hash(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def _matches(row, session_id: str, session_key: str) -> bool:
    return row["session_id"] == session_id and secrets.compare_digest(
        bytes(row["session_key_hash"]), _key_hash(session_key)
    )


def _view(row, *, status: str) -> LeaseView:
    return LeaseView(
        status=status,
        team_id=row["team_id"],
        principal_agent_id=str(row["principal_agent_id"]),
        session_id=row["session_id"],
        generation=row["generation"],
        acquired_at=row["acquired_at"].isoformat(),
        expires_at=row["expires_at"].isoformat(),
    )


def _conflict(row) -> JSONResponse:
    return JSONResponse(
        status_code=409,
        content={
            "detail": "principal already has a live session admission lease",
            "session_id": row["session_id"],
            "generation": row["generation"],
            "expires_at": row["expires_at"].isoformat(),
        },
    )


async def _locked_row(tx, identity: TeamIdentity):
    await tx.fetch_value(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
        f"session-admission:{identity.team_id}:{identity.agent_id}",
    )
    return await tx.fetch_one(
        """
        SELECT team_id, principal_agent_id, session_id, session_key_hash,
               generation, acquired_at, expires_at
        FROM {{tables.session_admission_leases}}
        WHERE team_id = $1 AND principal_agent_id = $2
        FOR UPDATE
        """,
        identity.team_id,
        identity.agent_id,
    )


@router.get("")
async def get_session_lease(
    db=Depends(get_db), identity: TeamIdentity = Depends(get_team_identity)
) -> Optional[LeaseView]:
    row = await db.get_manager("aweb").fetch_one(
        """
        SELECT team_id, principal_agent_id, session_id, session_key_hash,
               generation, acquired_at, expires_at
        FROM {{tables.session_admission_leases}}
        WHERE team_id = $1 AND principal_agent_id = $2 AND expires_at > NOW()
        """,
        identity.team_id,
        identity.agent_id,
    )
    return _view(row, status="active") if row else None


@router.post("", response_model=None)
async def acquire_session_lease(
    payload: LeaseRequest,
    db=Depends(get_db),
    identity: TeamIdentity = Depends(get_team_identity),
) -> LeaseView | JSONResponse:
    manager = db.get_manager("aweb")
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=payload.ttl_seconds)
    async with manager.transaction() as tx:
        row = await _locked_row(tx, identity)
        live = bool(row and row["expires_at"] > now)
        same_session = bool(row and _matches(row, payload.session_id, payload.session_key))
        if live and not same_session:
            return _conflict(row)
        generation = (row["generation"] if live and same_session else row["generation"] + 1) if row else 1
        if row:
            await tx.execute(
                """
                UPDATE {{tables.session_admission_leases}}
                SET session_id = $3, session_key_hash = $4, generation = $5,
                    acquired_at = $6, expires_at = $7
                WHERE team_id = $1 AND principal_agent_id = $2
                """,
                identity.team_id, identity.agent_id, payload.session_id,
                _key_hash(payload.session_key), generation, now, expires_at,
            )
        else:
            await tx.execute(
                """
                INSERT INTO {{tables.session_admission_leases}}
                    (team_id, principal_agent_id, session_id, session_key_hash,
                     generation, acquired_at, expires_at)
                VALUES ($1, $2, $3, $4, 1, $5, $6)
                """,
                identity.team_id, identity.agent_id, payload.session_id,
                _key_hash(payload.session_key), now, expires_at,
            )
    return LeaseView(status="acquired", team_id=identity.team_id,
                     principal_agent_id=identity.agent_id, session_id=payload.session_id,
                     generation=generation, acquired_at=now.isoformat(), expires_at=expires_at.isoformat())


@router.post("/renew")
async def renew_session_lease(
    payload: LeaseRequest,
    db=Depends(get_db),
    identity: TeamIdentity = Depends(get_team_identity),
) -> LeaseView:
    manager = db.get_manager("aweb")
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=payload.ttl_seconds)
    async with manager.transaction() as tx:
        row = await _locked_row(tx, identity)
        if not row or row["expires_at"] <= now:
            raise HTTPException(status_code=404, detail="session admission lease not found or expired")
        if not _matches(row, payload.session_id, payload.session_key):
            raise HTTPException(status_code=409, detail="session admission lease is held by another session")
        await tx.execute(
            "UPDATE {{tables.session_admission_leases}} SET expires_at = $3 WHERE team_id = $1 AND principal_agent_id = $2",
            identity.team_id, identity.agent_id, expires_at,
        )
    row = dict(row)
    row["expires_at"] = expires_at
    return _view(row, status="renewed")


@router.post("/release")
async def release_session_lease(
    payload: LeaseReleaseRequest,
    db=Depends(get_db),
    identity: TeamIdentity = Depends(get_team_identity),
) -> dict[str, str]:
    manager = db.get_manager("aweb")
    async with manager.transaction() as tx:
        row = await _locked_row(tx, identity)
        if not row:
            raise HTTPException(status_code=404, detail="session admission lease not found")
        if not _matches(row, payload.session_id, payload.session_key):
            raise HTTPException(status_code=409, detail="session admission lease is held by another session")
        await tx.execute(
            "DELETE FROM {{tables.session_admission_leases}} WHERE team_id = $1 AND principal_agent_id = $2",
            identity.team_id, identity.agent_id,
        )
    return {"status": "released", "session_id": payload.session_id}


@router.post("/takeover")
async def take_over_session_lease(
    request: Request,
    payload: LeaseTakeoverRequest,
    db=Depends(get_db),
    identity: TeamIdentity = Depends(get_team_identity),
) -> LeaseView:
    manager = db.get_manager("aweb")
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=payload.ttl_seconds)
    async with manager.transaction() as tx:
        row = await _locked_row(tx, identity)
        old_session_id = row["session_id"] if row else None
        generation = (row["generation"] + 1) if row else 1
        if row:
            await tx.execute(
                """
                UPDATE {{tables.session_admission_leases}}
                SET session_id = $3, session_key_hash = $4, generation = $5,
                    acquired_at = $6, expires_at = $7
                WHERE team_id = $1 AND principal_agent_id = $2
                """,
                identity.team_id, identity.agent_id, payload.session_id,
                _key_hash(payload.session_key), generation, now, expires_at,
            )
        else:
            await tx.execute(
                """
                INSERT INTO {{tables.session_admission_leases}}
                    (team_id, principal_agent_id, session_id, session_key_hash,
                     generation, acquired_at, expires_at)
                VALUES ($1, $2, $3, $4, 1, $5, $6)
                """,
                identity.team_id, identity.agent_id, payload.session_id,
                _key_hash(payload.session_key), now, expires_at,
            )
        await tx.execute(
            """
            INSERT INTO {{tables.audit_log}} (team_id, alias, event_type, resource, details)
            VALUES ($1, $2, 'session_lease.takeover', $3, $4::jsonb)
            """,
            identity.team_id, identity.alias, identity.agent_id,
            json.dumps({"old_session_id": old_session_id, "new_session_id": payload.session_id,
                        "generation": generation, "reason": payload.reason}),
        )
    return LeaseView(status="taken_over", team_id=identity.team_id,
                     principal_agent_id=identity.agent_id, session_id=payload.session_id,
                     generation=generation, acquired_at=now.isoformat(), expires_at=expires_at.isoformat())
