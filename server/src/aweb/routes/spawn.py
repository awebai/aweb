from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, field_validator

from aweb.access_modes import validate_access_mode
from aweb.address_reachability import normalize_address_reachability
from aweb.aweb_introspection import AuthIdentity, get_identity_from_auth
from aweb.bootstrap import bootstrap_identity
from aweb.db import DatabaseInfra, get_db_infra
from aweb.input_validation import is_valid_alias, is_valid_human_name
from aweb.namespace_registry import validate_agent_name
from aweb.routes.init import (
    InitResponse,
    _build_init_response,
    _lookup_attached_namespace,
    _resolve_aweb_project,
    _server_url,
    _translate_bootstrap_value_error,
)

router = APIRouter(prefix="/api/v1/spawn", tags=["spawn"])

INVITE_PREFIX = "aw_inv_"
DEFAULT_EXPIRES_IN_SECONDS = 24 * 60 * 60
MAX_EXPIRES_IN_SECONDS = 30 * 24 * 60 * 60


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _token_prefix(token: str) -> str:
    return token[len(INVITE_PREFIX) : len(INVITE_PREFIX) + 8]


def _utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


class CreateSpawnInviteRequest(BaseModel):
    alias_hint: str | None = Field(default=None, max_length=64)
    access_mode: str = Field(default="open", max_length=64)
    max_uses: int | None = Field(default=None, ge=1)
    expires_in_seconds: int | None = Field(default=None, ge=60)

    @field_validator("alias_hint")
    @classmethod
    def _validate_alias_hint(cls, v: str | None) -> str | None:
        if v is None:
            return None
        candidate = v.strip()
        if not candidate:
            return None
        if not is_valid_alias(candidate):
            raise ValueError("Invalid alias_hint")
        return candidate

    @field_validator("access_mode")
    @classmethod
    def _validate_access_mode(cls, v: str) -> str:
        return validate_access_mode(v) or "open"


class CreateSpawnInviteResponse(BaseModel):
    invite_id: str
    token: str
    token_prefix: str
    alias_hint: str | None = None
    access_mode: str
    max_uses: int
    expires_at: str
    namespace_slug: str
    namespace: str
    server_url: str


class SpawnInviteView(BaseModel):
    invite_id: str
    token_prefix: str
    alias_hint: str | None = None
    access_mode: str
    max_uses: int
    current_uses: int
    expires_at: str
    revoked_at: str | None = None
    created_at: str


class ListSpawnInvitesResponse(BaseModel):
    invites: list[SpawnInviteView]


class AcceptSpawnInviteRequest(BaseModel):
    token: str = Field(..., min_length=1, max_length=256)
    alias: str | None = Field(default=None, max_length=64)
    name: str | None = Field(default=None, max_length=64)
    human_name: str | None = Field(default=None, max_length=64)
    agent_type: str | None = Field(default=None, max_length=32)
    did: str | None = Field(default=None, max_length=255)
    public_key: str | None = Field(default=None, max_length=128)
    custody: str | None = Field(default=None, max_length=32)
    lifetime: str | None = Field(default=None, max_length=32)
    address_reachability: str | None = Field(default=None, max_length=32)

    @field_validator("alias")
    @classmethod
    def _validate_alias(cls, v: str | None) -> str | None:
        if v is None:
            return None
        candidate = v.strip()
        if not candidate:
            return None
        if not is_valid_alias(candidate):
            raise ValueError("Invalid alias")
        return candidate

    @field_validator("name")
    @classmethod
    def _validate_name(cls, v: str | None) -> str | None:
        if v is None:
            return None
        candidate = v.strip()
        if not candidate:
            return None
        return validate_agent_name(candidate)

    @field_validator("human_name")
    @classmethod
    def _validate_human_name(cls, v: str | None) -> str | None:
        if v is None:
            return None
        candidate = v.strip()
        if not candidate:
            return None
        if not is_valid_human_name(candidate):
            raise ValueError("Invalid human_name")
        return candidate

    @field_validator("address_reachability")
    @classmethod
    def _validate_address_reachability(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return normalize_address_reachability(v)


class AcceptSpawnInviteResponse(InitResponse):
    access_mode: str


def _normalize_accept_labels(
    *,
    alias: str | None,
    alias_hint: str | None,
    name: str | None,
    lifetime: str | None,
) -> tuple[str, str | None, str | None]:
    normalized_name = (name or "").strip() or None
    effective_lifetime = (lifetime or "ephemeral").strip() or "ephemeral"
    if effective_lifetime == "persistent":
        if alias is not None and alias.strip():
            raise HTTPException(status_code=422, detail="Permanent self-custodial identity creation uses name, not alias")
        if normalized_name is None:
            raise HTTPException(status_code=422, detail="Permanent self-custodial identity creation requires name")
        return normalized_name, None, normalized_name

    if normalized_name is not None:
        raise HTTPException(status_code=422, detail="name is only valid for explicit permanent identity creation")

    candidate = (alias or "").strip() or (alias_hint or "").strip()
    if not candidate:
        raise HTTPException(status_code=422, detail="alias is required")
    if not is_valid_alias(candidate):
        raise HTTPException(status_code=422, detail="Invalid alias")
    return candidate, candidate, None


async def _require_identity_authority(
    request: Request,
    db_infra: DatabaseInfra,
) -> AuthIdentity:
    identity = await get_identity_from_auth(request, db_infra)
    if not identity.project_id or not identity.agent_id:
        raise HTTPException(status_code=401, detail="Identity authority required")
    return identity


async def _project_namespace_or_409(
    db_infra: DatabaseInfra,
    *,
    project_id: str,
) -> tuple[str, str]:
    attached = await _lookup_attached_namespace(db_infra, project_id=project_id)
    if attached is None:
        raise HTTPException(
            status_code=409,
            detail="Current project does not have an attached namespace for spawn invites",
        )
    return attached


@router.post("/create-invite", response_model=CreateSpawnInviteResponse, status_code=201)
async def create_spawn_invite(
    request: Request,
    payload: CreateSpawnInviteRequest,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> CreateSpawnInviteResponse:
    identity = await _require_identity_authority(request, db_infra)
    namespace_slug, namespace_domain = await _project_namespace_or_409(
        db_infra,
        project_id=identity.project_id,
    )

    max_uses = payload.max_uses or 1
    expires_in_seconds = payload.expires_in_seconds or DEFAULT_EXPIRES_IN_SECONDS
    if expires_in_seconds > MAX_EXPIRES_IN_SECONDS:
        raise HTTPException(
            status_code=422,
            detail=f"expires_in_seconds must be at most {MAX_EXPIRES_IN_SECONDS}",
        )

    token = f"{INVITE_PREFIX}{secrets.token_urlsafe(32)}"
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in_seconds)
    aweb_db = db_infra.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.spawn_invite_tokens}}
            (project_id, created_by_agent_id, token_hash, token_prefix, alias_hint, access_mode, max_uses, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id, token_prefix, alias_hint, access_mode, max_uses, expires_at
        """,
        UUID(identity.project_id),
        UUID(identity.agent_id),
        _hash_token(token),
        _token_prefix(token),
        payload.alias_hint,
        payload.access_mode,
        max_uses,
        expires_at,
    )
    if row is None:
        raise HTTPException(status_code=500, detail="Failed to create spawn invite")

    return CreateSpawnInviteResponse(
        invite_id=str(row["id"]),
        token=token,
        token_prefix=str(row["token_prefix"]),
        alias_hint=row.get("alias_hint"),
        access_mode=str(row["access_mode"]),
        max_uses=int(row["max_uses"]),
        expires_at=_utc_iso(row["expires_at"]),
        namespace_slug=namespace_slug,
        namespace=namespace_domain,
        server_url=_server_url(request),
    )


@router.get("/invites", response_model=ListSpawnInvitesResponse)
async def list_spawn_invites(
    request: Request,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> ListSpawnInvitesResponse:
    identity = await _require_identity_authority(request, db_infra)
    aweb_db = db_infra.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        """
        SELECT id, token_prefix, alias_hint, access_mode, max_uses, current_uses, expires_at, revoked_at, created_at
        FROM {{tables.spawn_invite_tokens}}
        WHERE created_by_agent_id = $1
        ORDER BY created_at DESC
        """,
        UUID(identity.agent_id),
    )
    return ListSpawnInvitesResponse(
        invites=[
            SpawnInviteView(
                invite_id=str(row["id"]),
                token_prefix=str(row["token_prefix"]),
                alias_hint=row.get("alias_hint"),
                access_mode=str(row["access_mode"]),
                max_uses=int(row["max_uses"]),
                current_uses=int(row["current_uses"]),
                expires_at=_utc_iso(row["expires_at"]),
                revoked_at=_utc_iso(row["revoked_at"]) if row.get("revoked_at") else None,
                created_at=_utc_iso(row["created_at"]),
            )
            for row in rows
        ]
    )


@router.delete("/invites/{invite_id}", status_code=204)
async def revoke_spawn_invite(
    invite_id: str,
    request: Request,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> Response:
    identity = await _require_identity_authority(request, db_infra)
    aweb_db = db_infra.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT created_by_agent_id
        FROM {{tables.spawn_invite_tokens}}
        WHERE id = $1
        """,
        UUID(invite_id),
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Invite not found")
    if str(row["created_by_agent_id"]) != identity.agent_id:
        raise HTTPException(status_code=403, detail="Not allowed to revoke this invite")

    await aweb_db.execute(
        """
        UPDATE {{tables.spawn_invite_tokens}}
        SET revoked_at = NOW()
        WHERE id = $1 AND revoked_at IS NULL
        """,
        UUID(invite_id),
    )
    return Response(status_code=204)


@router.post("/accept-invite", response_model=AcceptSpawnInviteResponse)
async def accept_spawn_invite(
    request: Request,
    payload: AcceptSpawnInviteRequest,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> AcceptSpawnInviteResponse:
    aweb_db = db_infra.get_manager("aweb")
    now = datetime.now(timezone.utc)

    async with aweb_db.transaction() as tx:
        row = await tx.fetch_one(
            """
            SELECT id, project_id, created_by_agent_id, alias_hint, access_mode, max_uses, current_uses, expires_at, revoked_at
            FROM {{tables.spawn_invite_tokens}}
            WHERE token_hash = $1
            FOR UPDATE
            """,
            _hash_token(payload.token.strip()),
        )
        if row is None:
            raise HTTPException(status_code=401, detail="Invalid invite token")
        if row.get("revoked_at") is not None or row["expires_at"] < now:
            raise HTTPException(status_code=410, detail="Invite token expired or revoked")
        if int(row["current_uses"]) >= int(row["max_uses"]):
            raise HTTPException(status_code=409, detail="Invite token use limit reached")

        tenant_id, project_slug, project_name, owner_type, owner_ref = await _resolve_aweb_project(
            db_infra,
            project_id=str(row["project_id"]),
        )
        attached = await _lookup_attached_namespace(db_infra, project_id=str(row["project_id"]))
        if attached is None:
            raise HTTPException(status_code=409, detail="Invite namespace is no longer available")
        namespace_slug, namespace_domain = attached

        routing_alias, public_alias, public_name = _normalize_accept_labels(
            alias=payload.alias,
            alias_hint=row.get("alias_hint"),
            name=payload.name,
            lifetime=payload.lifetime,
        )
        alias_exists = await tx.fetch_value(
            """
            SELECT 1
            FROM {{tables.agents}}
            WHERE project_id = $1
              AND alias = $2
              AND deleted_at IS NULL
            """,
            UUID(str(row["project_id"])),
            routing_alias,
        )
        if alias_exists:
            conflict_field = "Name" if public_name is not None else "Alias"
            raise HTTPException(status_code=409, detail=f"{conflict_field} already taken in this project")

        try:
            identity = await bootstrap_identity(
                db_infra,
                project_slug=project_slug,
                project_name=project_name,
                project_id=str(row["project_id"]),
                tenant_id=tenant_id,
                owner_type=owner_type,
                owner_ref=owner_ref,
                alias=routing_alias,
                human_name=payload.human_name or "",
                agent_type=payload.agent_type or "agent",
                did=payload.did,
                public_key=payload.public_key,
                custody=payload.custody,
                lifetime=payload.lifetime or "ephemeral",
                namespace=namespace_slug if public_name is not None else None,
                address_reachability=payload.address_reachability,
                access_mode=str(row["access_mode"]),
            )
        except ValueError as exc:
            raise _translate_bootstrap_value_error(exc) from exc

        await tx.execute(
            """
            UPDATE {{tables.spawn_invite_tokens}}
            SET current_uses = current_uses + 1
            WHERE id = $1
            """,
            UUID(str(row["id"])),
        )

    response = _build_init_response(
        request=request,
        identity=identity,
        namespace_slug=namespace_slug,
        namespace_domain=namespace_domain,
        response_name=public_name,
    )
    return AcceptSpawnInviteResponse(**response.model_dump(), access_mode=str(row["access_mode"]))
