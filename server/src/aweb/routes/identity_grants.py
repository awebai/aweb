"""Identity session grants: mint, list, and revoke.

Grants are scoped, expiring, revocable credentials derived from a durable
identity. Minting and revocation require the subject's ordinary
team-certificate auth; grant-authenticated requests can never reach these
routes (the grant verifier rejects the path, and the scheme guard below
rejects the header even before certificate auth runs).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from aweb.deps import get_db
from aweb.identity_grant_auth import GRANT_AUTH_SCHEME, GRANT_SCOPES
from aweb.team_auth_deps import TeamIdentity, get_team_identity

router = APIRouter(prefix="/v1/identity-grants", tags=["identity-grants"])

GRANT_TTL_MIN_SECONDS = 60
GRANT_TTL_MAX_SECONDS = 2592000  # 30 days


class GrantMintRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    grant_did_key: str = Field(..., min_length=1, max_length=512)
    scopes: list[str] = Field(..., min_length=1)
    ttl_seconds: int = Field(..., ge=GRANT_TTL_MIN_SECONDS, le=GRANT_TTL_MAX_SECONDS)
    label: Optional[str] = Field(None, max_length=200)

    @field_validator("grant_did_key")
    @classmethod
    def grant_did_key_must_be_did_key(cls, value: str) -> str:
        value = value.strip()
        if not value.startswith("did:key:z"):
            raise ValueError("grant_did_key must be a did:key:z... identifier")
        return value

    @field_validator("scopes")
    @classmethod
    def scopes_must_be_known(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for raw in values:
            scope = (raw or "").strip()
            if scope not in GRANT_SCOPES:
                raise ValueError(f"invalid scope {raw!r}")
            if scope not in normalized:
                normalized.append(scope)
        return normalized


class GrantView(BaseModel):
    grant_id: str
    team_id: str
    subject_alias: str
    subject_did_aw: Optional[str]
    grant_did_key: str
    scopes: list[str]
    issued_at: str
    expires_at: str


class GrantListItem(GrantView):
    label: Optional[str]
    status: str
    revoked_at: Optional[str]


def reject_grant_scheme(request: Request) -> None:
    if (request.headers.get("Authorization") or "").lstrip().startswith(GRANT_AUTH_SCHEME):
        raise HTTPException(status_code=403, detail="grants cannot mint or revoke grants")


def _status(row, now: datetime) -> str:
    if row["revoked_at"] is not None:
        return "revoked"
    if row["expires_at"] <= now:
        return "expired"
    return "active"


@router.post("")
async def mint_identity_grant(
    request: Request,
    payload: GrantMintRequest,
    db=Depends(get_db),
    _scheme_guard: None = Depends(reject_grant_scheme),
    identity: TeamIdentity = Depends(get_team_identity),
) -> GrantView:
    manager = db.get_manager("aweb")
    subject = await manager.fetch_one(
        """
        SELECT agent_id, alias, did_aw, status
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND team_id = $2 AND deleted_at IS NULL
        """,
        identity.agent_id,
        identity.team_id,
    )
    if not subject or subject["status"] != "active":
        raise HTTPException(status_code=403, detail="subject identity is not active")
    subject_did_aw = (identity.did_aw or subject.get("did_aw") or "").strip() or None

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=payload.ttl_seconds)
    async with manager.transaction() as tx:
        await tx.fetch_value(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            f"identity-grant:{payload.grant_did_key}",
        )
        existing = await tx.fetch_one(
            """
            SELECT grant_id, expires_at
            FROM {{tables.identity_session_grants}}
            WHERE grant_did_key = $1 AND revoked_at IS NULL
            """,
            payload.grant_did_key,
        )
        if existing and existing["expires_at"] > now:
            raise HTTPException(
                status_code=409,
                detail="an active grant already exists for this grant_did_key",
            )
        if existing:
            # The active-key unique index covers all unrevoked rows, so an
            # expired-but-unrevoked grant must be retired before reissue.
            await tx.execute(
                "UPDATE {{tables.identity_session_grants}} SET revoked_at = $2 WHERE grant_id = $1",
                existing["grant_id"],
                now,
            )
        row = await tx.fetch_one(
            """
            INSERT INTO {{tables.identity_session_grants}} (
                team_id, subject_agent_id, subject_did_aw, grant_did_key,
                scopes, label, issued_by_certificate_id, issued_at, expires_at
            )
            VALUES ($1, $2::UUID, $3, $4, $5, $6, $7, $8, $9)
            RETURNING grant_id, issued_at, expires_at
            """,
            identity.team_id,
            identity.agent_id,
            subject_did_aw,
            payload.grant_did_key,
            payload.scopes,
            (payload.label or "").strip() or None,
            (identity.certificate_id or "").strip() or None,
            now,
            expires_at,
        )
    return GrantView(
        grant_id=str(row["grant_id"]),
        team_id=identity.team_id,
        subject_alias=identity.alias,
        subject_did_aw=subject_did_aw,
        grant_did_key=payload.grant_did_key,
        scopes=payload.scopes,
        issued_at=row["issued_at"].isoformat(),
        expires_at=row["expires_at"].isoformat(),
    )


@router.get("")
async def list_identity_grants(
    db=Depends(get_db),
    _scheme_guard: None = Depends(reject_grant_scheme),
    identity: TeamIdentity = Depends(get_team_identity),
) -> dict[str, list[GrantListItem]]:
    rows = await db.get_manager("aweb").fetch_all(
        """
        SELECT grant_id, team_id, subject_did_aw, grant_did_key, scopes, label,
               issued_at, expires_at, revoked_at
        FROM {{tables.identity_session_grants}}
        WHERE team_id = $1 AND subject_agent_id = $2::UUID
        ORDER BY issued_at DESC, grant_id ASC
        """,
        identity.team_id,
        identity.agent_id,
    )
    now = datetime.now(timezone.utc)
    return {
        "grants": [
            GrantListItem(
                grant_id=str(row["grant_id"]),
                team_id=row["team_id"],
                subject_alias=identity.alias,
                subject_did_aw=row.get("subject_did_aw") or None,
                grant_did_key=row["grant_did_key"],
                scopes=list(row["scopes"] or []),
                label=row.get("label") or None,
                status=_status(row, now),
                issued_at=row["issued_at"].isoformat(),
                expires_at=row["expires_at"].isoformat(),
                revoked_at=row["revoked_at"].isoformat() if row["revoked_at"] else None,
            )
            for row in rows
        ]
    }


@router.post("/{grant_id}/revoke")
async def revoke_identity_grant(
    grant_id: str,
    db=Depends(get_db),
    _scheme_guard: None = Depends(reject_grant_scheme),
    identity: TeamIdentity = Depends(get_team_identity),
) -> dict[str, str]:
    try:
        grant_id = str(UUID(grant_id))
    except ValueError:
        raise HTTPException(status_code=404, detail="grant not found")
    manager = db.get_manager("aweb")
    async with manager.transaction() as tx:
        row = await tx.fetch_one(
            """
            SELECT grant_id, revoked_at
            FROM {{tables.identity_session_grants}}
            WHERE grant_id = $1::UUID AND team_id = $2 AND subject_agent_id = $3::UUID
            FOR UPDATE
            """,
            grant_id,
            identity.team_id,
            identity.agent_id,
        )
        if not row:
            raise HTTPException(status_code=404, detail="grant not found")
        if row["revoked_at"] is not None:
            return {
                "grant_id": grant_id,
                "status": "revoked",
                "revoked_at": row["revoked_at"].isoformat(),
            }
        now = datetime.now(timezone.utc)
        await tx.execute(
            "UPDATE {{tables.identity_session_grants}} SET revoked_at = $2 WHERE grant_id = $1::UUID",
            grant_id,
            now,
        )
        await tx.execute(
            """
            INSERT INTO {{tables.audit_log}} (team_id, alias, event_type, resource, details)
            VALUES ($1, $2, 'identity_grant.revoke', $3, $4::jsonb)
            """,
            identity.team_id,
            identity.alias,
            grant_id,
            json.dumps({"grant_id": grant_id, "subject_agent_id": identity.agent_id}),
        )
    return {"grant_id": grant_id, "status": "revoked", "revoked_at": now.isoformat()}
