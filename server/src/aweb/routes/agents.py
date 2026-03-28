from __future__ import annotations

import json
import os
from datetime import timezone
from typing import Literal, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator, model_validator
from redis.asyncio import Redis

from aweb.access_modes import VALID_ACCESS_MODES, validate_access_mode
from aweb.address_scope import resolve_local_recipient
from aweb.alias_allocator import suggest_next_name_prefix
from aweb.auth import (
    get_actor_agent_id_from_auth,
    validate_project_slug,
    validate_workspace_id,
    verify_workspace_access,
)
from aweb.aweb_introspection import get_project_from_auth
from aweb.awid.did import (
    decode_public_key,
    did_from_public_key,
    encode_public_key,
    generate_keypair,
    stable_id_from_did_key,
)
from aweb.hooks import fire_mutation_hook
from aweb.internal_auth import INTERNAL_PROJECT_ROLE_HEADER, parse_internal_auth_context

from ..config import get_settings
from ..db import DatabaseInfra, get_db_infra
from ..input_validation import is_valid_alias
from ..presence import list_agent_presences_by_workspace_ids, update_agent_presence
from ..redis_client import get_redis
from ..coordination.routes.policies import get_active_policy
from ..coordination.roles import ROLE_MAX_LENGTH
from ..role_name_compat import normalize_optional_role_name, resolve_role_name_aliases
from aweb.namespace_registry import list_namespace_addresses
from aweb.projection import ensure_aweb_project_and_agent
from aweb.scope_agents import get_scope_agent, list_scope_agents

router = APIRouter(prefix="/v1/agents", tags=["agents"])


async def _require_human_owner_or_admin_for_lifecycle_action(
    request: Request,
    db_infra: DatabaseInfra,
    *,
    project_id: str,
    action: str,
) -> None:
    user_id = (request.headers.get("X-User-ID") or "").strip()
    if not user_id:
        raise HTTPException(status_code=403, detail=f"Only human project owner or admin can {action}")

    server_db = db_infra.get_manager("server")
    try:
        project_uuid = UUID(project_id)
        user_uuid = UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=403, detail=f"Only human project owner or admin can {action}")

    internal_ctx = parse_internal_auth_context(request)
    trusted_project_role = (request.headers.get(INTERNAL_PROJECT_ROLE_HEADER) or "").strip().lower()
    if (
        internal_ctx is not None
        and internal_ctx.get("principal_type") == "u"
        and internal_ctx.get("principal_id") == str(user_uuid)
        and internal_ctx.get("project_id") == str(project_uuid)
        and trusted_project_role in {"owner", "admin"}
    ):
        return

    row = await server_db.fetch_one(
        """
        SELECT p.id,
               p.owner_type,
               p.owner_ref
        FROM {{tables.projects}} p
        WHERE p.id = $1
          AND p.deleted_at IS NULL
        """,
        project_uuid,
    )
    if row is None:
        raise HTTPException(status_code=403, detail=f"Only human project owner or admin can {action}")
    owner_ref = (row.get("owner_ref") or "").strip()
    if row.get("owner_type") == "user" and owner_ref == str(user_uuid):
        return
    raise HTTPException(status_code=403, detail=f"Only human project owner or admin can {action}")


def _validate_workspace_id_field(v: str) -> str:
    """Pydantic validator wrapper for workspace_id."""
    try:
        return validate_workspace_id(v)
    except ValueError as e:
        raise ValueError(str(e))


def _validate_alias_field(v: str) -> str:
    """Pydantic validator wrapper for alias."""
    if not is_valid_alias(v):
        raise ValueError("Invalid alias: must be alphanumeric with hyphens/underscores, 1-64 chars")
    return v


class RegisterAgentRequest(BaseModel):
    workspace_id: str = Field(..., min_length=1)
    alias: str = Field(..., min_length=1, max_length=64)
    human_name: Optional[str] = Field(None, max_length=64)
    project_slug: Optional[str] = Field(None, max_length=63)
    program: Optional[str] = None
    model: Optional[str] = None
    task_description: Optional[str] = None
    repo: Optional[str] = Field(None, max_length=255)
    branch: Optional[str] = Field(None, max_length=255)
    role: Optional[str] = Field(
        None,
        max_length=ROLE_MAX_LENGTH,
        description="Brief description of workspace purpose",
    )
    role_name: Optional[str] = Field(
        None,
        max_length=ROLE_MAX_LENGTH,
        description="Canonical selector name for the workspace role",
    )
    ttl_seconds: Optional[int] = Field(
        None, gt=0, le=86400, description="Presence TTL in seconds (default 300, max 86400)"
    )

    @field_validator("workspace_id")
    @classmethod
    def validate_workspace_id(cls, v: str) -> str:
        return _validate_workspace_id_field(v)

    @field_validator("alias")
    @classmethod
    def validate_alias(cls, v: str) -> str:
        return _validate_alias_field(v)

    @field_validator("role", "role_name")
    @classmethod
    def validate_role(cls, v: Optional[str]) -> Optional[str]:
        return normalize_optional_role_name(v)

    @model_validator(mode="after")
    def sync_role_aliases(self):
        resolved = resolve_role_name_aliases(role=self.role, role_name=self.role_name)
        self.role = resolved
        self.role_name = resolved
        return self


class AgentInfo(BaseModel):
    alias: str
    human_name: Optional[str] = None
    project_slug: Optional[str] = None
    program: Optional[str] = None
    model: Optional[str] = None
    member: Optional[str] = None
    repo: Optional[str] = None
    branch: Optional[str] = None
    role: Optional[str] = None
    role_name: Optional[str] = None
    registered_at: str

    @model_validator(mode="after")
    def sync_role_aliases(self):
        resolved = resolve_role_name_aliases(role=self.role, role_name=self.role_name)
        self.role = resolved
        self.role_name = resolved
        return self


class WorkspaceInfo(BaseModel):
    workspace_id: str


class RegisterAgentResponse(BaseModel):
    agent: AgentInfo
    workspace: WorkspaceInfo


class AgentView(BaseModel):
    agent_id: str
    alias: str
    owner_type: Optional[str] = None
    human_name: Optional[str] = None
    agent_type: Optional[str] = None
    workspace_type: Optional[str] = None
    role: Optional[str] = None
    role_name: Optional[str] = None
    context_kind: Optional[str] = None
    hostname: Optional[str] = None
    workspace_path: Optional[str] = None
    repo: Optional[str] = None
    branch: Optional[str] = None
    status: str = "offline"
    last_seen: Optional[str] = None
    online: bool = False
    did: Optional[str] = None
    custody: Optional[str] = None
    lifetime: str = "ephemeral"
    identity_status: str = "active"
    access_mode: str = "open"
    address: Optional[str] = None
    address_reachability: Optional[str] = None

    @model_validator(mode="after")
    def sync_role_aliases(self):
        resolved = resolve_role_name_aliases(role=self.role, role_name=self.role_name)
        self.role = resolved
        self.role_name = resolved
        return self


class ListAgentsResponse(BaseModel):
    project_id: str
    agents: list[AgentView]


class HeartbeatResponse(BaseModel):
    agent_id: str
    last_seen: str
    ttl_seconds: int


class ClaimIdentityRequest(BaseModel):
    did: str = Field(..., max_length=256)
    public_key: str = Field(..., max_length=64)
    custody: Literal["self"]
    lifetime: Literal["persistent"]


class ClaimIdentityResponse(BaseModel):
    agent_id: str
    alias: str
    did: str
    public_key: str
    stable_id: str | None = None
    custody: str
    lifetime: str


class ResetIdentityRequest(BaseModel):
    confirm: bool


class ResetIdentityResponse(BaseModel):
    agent_id: str
    alias: str
    did: str | None = None
    public_key: str | None = None
    stable_id: str | None = None
    custody: str | None = None
    lifetime: str | None = None


class PatchAgentRequest(BaseModel):
    access_mode: str | None = None
    role: str | None = None
    role_name: str | None = None
    program: str | None = None
    context: dict | None = None

    @field_validator("access_mode")
    @classmethod
    def _validate_access_mode(cls, v: str | None) -> str | None:
        return validate_access_mode(v) if v is not None else None

    @field_validator("role", "role_name")
    @classmethod
    def _validate_role(cls, v: str | None) -> str | None:
        return normalize_optional_role_name(v)

    @model_validator(mode="after")
    def sync_role_aliases(self):
        resolved = resolve_role_name_aliases(role=self.role, role_name=self.role_name)
        self.role = resolved
        self.role_name = resolved
        return self


class PatchAgentResponse(BaseModel):
    agent_id: str
    access_mode: str
    role: str | None = None
    role_name: str | None = None
    program: str | None = None
    context: dict | None = None

    @model_validator(mode="after")
    def sync_role_aliases(self):
        resolved = resolve_role_name_aliases(role=self.role, role_name=self.role_name)
        self.role = resolved
        self.role_name = resolved
        return self


async def _patch_agent_row(
    *,
    aweb_db,
    project_id: str,
    agent_uuid: UUID,
    payload: PatchAgentRequest,
) -> PatchAgentResponse:
    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, access_mode, role, program, context
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        agent_uuid,
        UUID(project_id),
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    new_access_mode = payload.access_mode if payload.access_mode is not None else row["access_mode"]
    new_role = payload.role if payload.role is not None else row["role"]
    new_program = payload.program if payload.program is not None else row["program"]
    new_context = payload.context if payload.context is not None else parse_context(row["context"])

    await aweb_db.execute(
        """
        UPDATE {{tables.agents}}
        SET access_mode = $1, role = $2, program = $3, context = $4
        WHERE agent_id = $5 AND project_id = $6
        """,
        new_access_mode,
        new_role,
        new_program,
        json.dumps(new_context) if isinstance(new_context, dict) else new_context,
        agent_uuid,
        UUID(project_id),
    )

    return PatchAgentResponse(
        agent_id=str(agent_uuid),
        access_mode=new_access_mode,
        role=new_role,
        program=new_program,
        context=parse_context(new_context),
    )


class ResolveAgentResponse(BaseModel):
    did: str | None
    stable_id: str | None
    address: str
    agent_id: str
    human_name: str | None
    public_key: str | None
    server: str
    controller_did: str | None = None
    custody: str | None
    lifetime: str
    status: str


class AgentLogEntry(BaseModel):
    log_id: str
    operation: str
    old_did: str | None
    new_did: str | None
    signed_by: str | None
    entry_signature: str | None
    metadata: dict | None
    created_at: str


class AgentLogResponse(BaseModel):
    agent_id: str
    address: str
    log: list[AgentLogEntry]


class AgentActivityItem(BaseModel):
    entry_id: str
    source: str
    event_type: str
    summary: str
    details: dict | None = None
    created_at: str


class AgentActivityResponse(BaseModel):
    agent_id: str
    alias: str
    items: list[AgentActivityItem]


class SuggestAliasPrefixRequest(BaseModel):
    project_slug: str | None = Field(default=None, max_length=256)

    @field_validator("project_slug")
    @classmethod
    def validate_project_slug(cls, v: str | None) -> str | None:
        if v is None:
            return None
        candidate = v.strip()
        if candidate == "":
            return None
        return validate_project_slug(candidate)


class SuggestAliasPrefixResponse(BaseModel):
    project_slug: str
    project_id: str | None
    name_prefix: str
    roles: list[str] = Field(default_factory=list)


@router.post("/suggest-alias-prefix", response_model=SuggestAliasPrefixResponse)
async def suggest_alias_prefix(
    request: Request,
    payload: SuggestAliasPrefixRequest,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> SuggestAliasPrefixResponse:
    """Suggest the next available classic alias prefix for a project.

    This endpoint is intentionally unauthenticated so new
    agents can bootstrap cleanly in standalone coordination deployments.
    """
    aweb_db = db_infra.get_manager("aweb")

    row = None
    if payload.project_slug is not None:
        row = await aweb_db.fetch_one(
            """
            SELECT project_id, slug
            FROM {{tables.projects}}
            WHERE slug = $1 AND deleted_at IS NULL
            """,
            payload.project_slug,
        )
    else:
        try:
            project_id = await get_project_from_auth(request, db_infra)
        except HTTPException:
            project_id = None
        if project_id is not None:
            row = await aweb_db.fetch_one(
                """
                SELECT project_id, slug
                FROM {{tables.projects}}
                WHERE project_id = $1 AND deleted_at IS NULL
                """,
                UUID(project_id),
            )

    if row is None:
        return SuggestAliasPrefixResponse(
            project_slug=payload.project_slug or "",
            project_id=None,
            name_prefix="alice",
            roles=[],
        )

    project_id = str(row["project_id"])
    server_db = db_infra.get_manager("server")
    policy = await get_active_policy(server_db, project_id, bootstrap_if_missing=False)
    roles = list(policy.bundle.roles.keys()) if policy else []
    aliases = await aweb_db.fetch_all(
        """
        SELECT alias
        FROM {{tables.agents}}
        WHERE project_id = $1 AND deleted_at IS NULL
          AND agent_type != 'system'
        ORDER BY alias
        """,
        UUID(project_id),
    )
    name_prefix = suggest_next_name_prefix([r.get("alias") or "" for r in aliases])
    if name_prefix is None:
        raise HTTPException(status_code=409, detail="alias_exhausted")

    return SuggestAliasPrefixResponse(
        project_slug=payload.project_slug or row["slug"],
        project_id=project_id,
        name_prefix=name_prefix,
        roles=roles,
    )


@router.post("/heartbeat", response_model=HeartbeatResponse)
async def heartbeat(
    request: Request,
    db_infra: DatabaseInfra = Depends(get_db_infra),
    redis: Redis = Depends(get_redis),
) -> HeartbeatResponse:
    project_id = await get_project_from_auth(request, db_infra)
    agent_id = await get_actor_agent_id_from_auth(request, db_infra, manager_name="aweb")
    aweb_db = db_infra.get_manager("aweb")

    row = await aweb_db.fetch_one(
        """
        SELECT alias
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        UUID(agent_id),
        UUID(project_id),
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    ttl_seconds = 1800
    last_seen = await update_agent_presence(
        redis,
        agent_id=agent_id,
        alias=row["alias"],
        project_id=project_id,
        ttl_seconds=ttl_seconds,
    )
    return HeartbeatResponse(agent_id=agent_id, last_seen=last_seen, ttl_seconds=ttl_seconds)


@router.patch("/me", response_model=PatchAgentResponse)
async def patch_agent(
    request: Request,
    payload: PatchAgentRequest,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> PatchAgentResponse:
    project_id = await get_project_from_auth(request, db_infra)
    agent_id = await get_actor_agent_id_from_auth(request, db_infra, manager_name="aweb")
    aweb_db = db_infra.get_manager("aweb")
    return await _patch_agent_row(
        aweb_db=aweb_db,
        project_id=project_id,
        agent_uuid=UUID(agent_id),
        payload=payload,
    )


@router.patch("/{agent_id}", response_model=PatchAgentResponse)
async def patch_agent_by_id(
    agent_id: str,
    payload: PatchAgentRequest,
    request: Request,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> PatchAgentResponse:
    project_id = await get_project_from_auth(request, db_infra)
    aweb_db = db_infra.get_manager("aweb")
    return await _patch_agent_row(
        aweb_db=aweb_db,
        project_id=project_id,
        agent_uuid=UUID(agent_id),
        payload=payload,
    )


@router.get("/resolve/{namespace}/{alias}", response_model=ResolveAgentResponse)
async def resolve_agent(
    request: Request,
    namespace: str,
    alias: str,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> ResolveAgentResponse:
    project_id = await get_project_from_auth(request, db_infra)
    actor_id = await get_actor_agent_id_from_auth(request, db_infra, manager_name="aweb")
    aweb_db = db_infra.get_manager("aweb")
    resolved = await resolve_local_recipient(
        db_infra,
        sender_project_id=project_id,
        sender_agent_id=actor_id,
        ref=f"{namespace}/{alias}",
    )
    row = await aweb_db.fetch_one(
        """
        SELECT a.agent_id, a.alias, a.human_name, a.did, a.stable_id, a.public_key,
               a.custody, a.lifetime, a.status,
               pn.domain, pn.controller_did, pa.name AS address_name
        FROM {{tables.public_addresses}} pa
        JOIN {{tables.dns_namespaces}} pn ON pa.namespace_id = pn.namespace_id
            AND pn.deleted_at IS NULL
        JOIN {{tables.agents}} a ON a.stable_id = pa.did_aw
            AND a.deleted_at IS NULL
        JOIN {{tables.projects}} p ON a.project_id = p.project_id
            AND p.deleted_at IS NULL
        WHERE a.agent_id = $1
          AND p.project_id = $2
          AND pn.domain = $3
          AND pa.name = $4
          AND pa.deleted_at IS NULL
        """,
        UUID(resolved.agent_id),
        UUID(resolved.project_id),
        namespace,
        alias,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    return ResolveAgentResponse(
        did=row["did"],
        stable_id=row.get("stable_id"),
        address=f"{row['domain']}/{row['address_name']}",
        agent_id=str(row["agent_id"]),
        human_name=row.get("human_name"),
        public_key=row["public_key"],
        server=os.environ.get("AWEB_SERVER_URL", ""),
        controller_did=row.get("controller_did"),
        custody=row["custody"],
        lifetime=row["lifetime"],
        status=row["status"],
    )


def _parse_log_metadata(raw) -> dict | None:
    if not raw:
        return None
    if isinstance(raw, dict):
        return raw
    return json.loads(raw)


@router.get("/me/log", response_model=AgentLogResponse)
async def agent_log(
    request: Request,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> AgentLogResponse:
    project_id = await get_project_from_auth(request, db_infra)
    agent_id = await get_actor_agent_id_from_auth(request, db_infra, manager_name="aweb")
    aweb_db = db_infra.get_manager("aweb")
    agent_uuid = UUID(agent_id)

    agent = await aweb_db.fetch_one(
        """
        SELECT a.agent_id, a.alias
        FROM {{tables.agents}} a
        JOIN {{tables.projects}} p ON a.project_id = p.project_id
        WHERE a.agent_id = $1 AND a.project_id = $2
          AND p.deleted_at IS NULL
        """,
        agent_uuid,
        UUID(project_id),
    )
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    rows = await aweb_db.fetch_all(
        """
        SELECT log_id, operation, old_did, new_did, signed_by, entry_signature, metadata, created_at
        FROM {{tables.agent_log}}
        WHERE agent_id = $1 AND project_id = $2
        ORDER BY created_at ASC
        """,
        agent_uuid,
        UUID(project_id),
    )

    return AgentLogResponse(
        agent_id=agent_id,
        address=agent["alias"],
        log=[
            AgentLogEntry(
                log_id=str(r["log_id"]),
                operation=r["operation"],
                old_did=r["old_did"],
                new_did=r["new_did"],
                signed_by=r["signed_by"],
                entry_signature=r["entry_signature"],
                metadata=_parse_log_metadata(r["metadata"]),
                created_at=r["created_at"].isoformat(),
            )
            for r in rows
        ],
    )


def parse_context(raw):
    if raw is None:
        return None
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


@router.put("/me/identity", response_model=ClaimIdentityResponse)
async def claim_identity(
    request: Request,
    payload: ClaimIdentityRequest,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> ClaimIdentityResponse:
    project_id = await get_project_from_auth(request, db_infra)
    agent_id = await get_actor_agent_id_from_auth(request, db_infra, manager_name="aweb")
    aweb_db = db_infra.get_manager("aweb")
    agent_uuid = UUID(agent_id)

    try:
        public_key_bytes = decode_public_key(payload.public_key)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="public_key must be a base64-encoded 32-byte Ed25519 key",
        )
    expected_did = did_from_public_key(public_key_bytes)
    if expected_did != payload.did:
        raise HTTPException(status_code=400, detail="DID does not match public_key")

    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, alias, did, public_key, stable_id, custody, lifetime
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        agent_uuid,
        UUID(project_id),
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    if row["did"] is not None:
        if row["did"] == payload.did:
            existing_stable_id = row["stable_id"] or stable_id_from_did_key(row["did"])
            return ClaimIdentityResponse(
                agent_id=agent_id,
                alias=row["alias"],
                did=row["did"],
                public_key=row["public_key"],
                stable_id=existing_stable_id,
                custody=row["custody"] or "self",
                lifetime=row["lifetime"] or "persistent",
            )
        raise HTTPException(status_code=409, detail="Identity already claimed with a different DID")

    canonical_public_key = encode_public_key(public_key_bytes)
    stable_id = stable_id_from_did_key(payload.did)

    updated = await aweb_db.fetch_one(
        """
        UPDATE {{tables.agents}}
        SET did = $1, public_key = $2, stable_id = $3, custody = $4, lifetime = $5
        WHERE agent_id = $6 AND project_id = $7 AND did IS NULL
        RETURNING agent_id
        """,
        payload.did,
        canonical_public_key,
        stable_id,
        payload.custody,
        payload.lifetime,
        agent_uuid,
        UUID(project_id),
    )
    if updated is None:
        current = await aweb_db.fetch_one(
            """
            SELECT did
            FROM {{tables.agents}}
            WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
            """,
            agent_uuid,
            UUID(project_id),
        )
        if current and current["did"] == payload.did:
            return ClaimIdentityResponse(
                agent_id=agent_id,
                alias=row["alias"],
                did=payload.did,
                public_key=canonical_public_key,
                stable_id=stable_id,
                custody=payload.custody,
                lifetime=payload.lifetime,
            )
        raise HTTPException(status_code=409, detail="Identity already claimed with a different DID")

    await aweb_db.execute(
        """
        INSERT INTO {{tables.agent_log}} (agent_id, project_id, operation, new_did)
        VALUES ($1, $2, $3, $4)
        """,
        agent_uuid,
        UUID(project_id),
        "claim_identity",
        payload.did,
    )

    return ClaimIdentityResponse(
        agent_id=agent_id,
        alias=row["alias"],
        did=payload.did,
        public_key=canonical_public_key,
        stable_id=stable_id,
        custody=payload.custody,
        lifetime=payload.lifetime,
    )


@router.post("/me/identity/reset", response_model=ResetIdentityResponse)
async def reset_identity(
    request: Request,
    payload: ResetIdentityRequest,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> ResetIdentityResponse:
    if not payload.confirm:
        raise HTTPException(status_code=400, detail="confirm must be true to reset identity")

    project_id = await get_project_from_auth(request, db_infra)
    agent_id = await get_actor_agent_id_from_auth(request, db_infra, manager_name="aweb")
    aweb_db = db_infra.get_manager("aweb")
    agent_uuid = UUID(agent_id)

    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, alias, did, public_key, stable_id, custody, lifetime
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        agent_uuid,
        UUID(project_id),
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    if row["did"] is None:
        return ResetIdentityResponse(agent_id=agent_id, alias=row["alias"])

    metadata = json.dumps(
        {
            "old_public_key": row["public_key"],
            "old_stable_id": row["stable_id"],
        }
    )

    await aweb_db.execute(
        """
        UPDATE {{tables.agents}}
        SET did = NULL, public_key = NULL, stable_id = NULL,
            custody = NULL, signing_key_enc = NULL
        WHERE agent_id = $1 AND project_id = $2
        """,
        agent_uuid,
        UUID(project_id),
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agent_log}} (agent_id, project_id, operation, old_did, metadata)
        VALUES ($1, $2, $3, $4, $5::jsonb)
        """,
        agent_uuid,
        UUID(project_id),
        "reset_identity",
        row["did"],
        metadata,
    )
    return ResetIdentityResponse(agent_id=agent_id, alias=row["alias"])


class RotateKeyRequest(BaseModel):
    model_config = {"extra": "forbid"}

    new_did: str | None = None
    new_public_key: str | None = None
    custody: Literal["self", "custodial"]
    rotation_signature: str | None = None
    timestamp: str

    @model_validator(mode="after")
    def _validate_key_fields(self) -> "RotateKeyRequest":
        if self.custody == "self":
            if not self.new_did or not self.new_public_key:
                raise ValueError("new_did and new_public_key are required when custody='self'")
        else:
            if self.new_did is not None or self.new_public_key is not None:
                raise ValueError("new_did/new_public_key must be omitted when custody='custodial'")
        return self


class RotateKeyResponse(BaseModel):
    status: str
    old_did: str | None
    new_did: str
    new_public_key: str
    custody: str


@router.put("/me/rotate", response_model=RotateKeyResponse)
async def rotate_key(
    request: Request,
    payload: RotateKeyRequest,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> RotateKeyResponse:
    import base64 as _base64
    import json as _json

    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey

    from aweb.awid.custody import decrypt_signing_key, encrypt_signing_key, get_custody_key
    from aweb.awid.signing import sign_message

    project_id = await get_project_from_auth(request, db_infra)
    agent_id = await get_actor_agent_id_from_auth(request, db_infra, manager_name="aweb")
    aweb_db = db_infra.get_manager("aweb")
    agent_uuid = UUID(agent_id)

    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, did, public_key, custody, lifetime, signing_key_enc
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        agent_uuid,
        UUID(project_id),
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    if row["lifetime"] == "ephemeral":
        raise HTTPException(
            status_code=400,
            detail="Cannot rotate key for an ephemeral agent. Deregister and create a new agent instead.",
        )

    current_custody = row["custody"]
    if current_custody not in ("self", "custodial"):
        raise HTTPException(status_code=403, detail="Agent custody is not configured for rotation")
    if current_custody == "self" and payload.custody != "self":
        raise HTTPException(
            status_code=400,
            detail="Cannot change a self-custodial agent back to custodial via rotate",
        )
    if current_custody != "custodial" and payload.custody == "custodial":
        raise HTTPException(
            status_code=400,
            detail="Only custodial agents can request custody='custodial' rotations",
        )

    old_did = row["did"]
    old_public_key_encoded = row["public_key"]
    if not old_did:
        raise HTTPException(status_code=403, detail="Agent has no DID to rotate")
    if not old_public_key_encoded:
        raise HTTPException(status_code=403, detail="Agent has no public key to verify proof against")

    try:
        old_public_key = decode_public_key(old_public_key_encoded)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Corrupt public key in database") from exc

    if payload.custody == "custodial":
        master_key = get_custody_key()
        if master_key is None:
            raise HTTPException(status_code=500, detail="Custody key not configured")
        seed, pub = generate_keypair()
        new_did = did_from_public_key(pub)
        new_public_key_encoded = encode_public_key(pub)
        try:
            new_signing_key_enc = encrypt_signing_key(seed, master_key)
        except Exception as exc:
            raise HTTPException(status_code=500, detail="Failed to encrypt new signing key") from exc
    else:
        new_did = payload.new_did or ""
        new_public_key = payload.new_public_key or ""
        try:
            new_pub_bytes = decode_public_key(new_public_key)
        except Exception:
            raise HTTPException(
                status_code=400,
                detail="new_public_key must be a base64-encoded 32-byte Ed25519 key (url-safe or standard)",
            )
        expected_did = did_from_public_key(new_pub_bytes)
        if expected_did != new_did:
            raise HTTPException(status_code=400, detail="DID does not match new_public_key")
        new_public_key_encoded = encode_public_key(new_pub_bytes)
        new_signing_key_enc = None

    canonical = _json.dumps(
        {
            "new_did": new_did,
            "old_did": old_did,
            "timestamp": payload.timestamp,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    rotation_signature = payload.rotation_signature
    if rotation_signature is None and current_custody == "custodial":
        master_key = get_custody_key()
        if master_key is None:
            raise HTTPException(status_code=500, detail="Custody key not configured")
        if row["signing_key_enc"] is None:
            raise HTTPException(status_code=500, detail="Agent has no signing key")
        try:
            old_private_key = decrypt_signing_key(bytes(row["signing_key_enc"]), master_key)
        except Exception as exc:
            raise HTTPException(status_code=500, detail="Failed to decrypt signing key") from exc
        rotation_signature = sign_message(old_private_key, canonical)

    if rotation_signature is None:
        raise HTTPException(status_code=422, detail="rotation_signature is required")

    try:
        padded = rotation_signature + "=" * (-len(rotation_signature) % 4)
        sig_bytes = _base64.urlsafe_b64decode(padded)
    except Exception:
        raise HTTPException(status_code=403, detail="Malformed rotation proof encoding")
    try:
        VerifyKey(old_public_key).verify(canonical, sig_bytes)
    except BadSignatureError:
        raise HTTPException(status_code=403, detail="Invalid rotation proof")
    except Exception:
        raise HTTPException(status_code=403, detail="Rotation proof verification error")

    if payload.custody == "custodial":
        await aweb_db.execute(
            """
            UPDATE {{tables.agents}}
            SET did = $1, public_key = $2, custody = 'custodial', signing_key_enc = $3
            WHERE agent_id = $4 AND project_id = $5
            """,
            new_did,
            new_public_key_encoded,
            new_signing_key_enc,
            agent_uuid,
            UUID(project_id),
        )
    else:
        await aweb_db.execute(
            """
            UPDATE {{tables.agents}}
            SET did = $1, public_key = $2, custody = 'self', signing_key_enc = NULL
            WHERE agent_id = $3 AND project_id = $4
            """,
            new_did,
            new_public_key_encoded,
            agent_uuid,
            UUID(project_id),
        )

    metadata = _json.dumps({"timestamp": payload.timestamp, "new_custody": payload.custody})
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agent_log}}
            (agent_id, project_id, operation, old_did, new_did, signed_by, entry_signature, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
        """,
        agent_uuid,
        UUID(project_id),
        "rotate",
        old_did,
        new_did,
        old_did,
        rotation_signature,
        metadata,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.rotation_announcements}}
            (agent_id, project_id, old_did, new_did, rotation_timestamp, old_key_signature)
        VALUES ($1, $2, $3, $4, $5, $6)
        """,
        agent_uuid,
        UUID(project_id),
        old_did,
        new_did,
        payload.timestamp,
        rotation_signature,
    )
    await fire_mutation_hook(
        request,
        "agent.key_rotated",
        {
            "agent_id": str(agent_uuid),
            "project_id": project_id,
            "old_did": old_did,
            "new_did": new_did,
            "custody": payload.custody,
        },
    )
    return RotateKeyResponse(
        status="rotated",
        old_did=old_did,
        new_did=new_did,
        new_public_key=new_public_key_encoded,
        custody=payload.custody,
    )


class RetireAgentRequest(BaseModel):
    model_config = {"extra": "forbid"}

    successor_agent_id: str
    retirement_proof: str | None = None
    timestamp: str | None = None

    @field_validator("successor_agent_id")
    @classmethod
    def _validate_successor_id(cls, v: str) -> str:
        try:
            return str(UUID(v.strip()))
        except Exception:
            raise ValueError("Invalid successor_agent_id format")


class RetireAgentResponse(BaseModel):
    status: str
    agent_id: str
    successor_agent_id: str


async def _retire_agent(
    request: Request,
    aweb_db,
    *,
    agent_uuid: UUID,
    project_id: str,
    payload: RetireAgentRequest,
) -> RetireAgentResponse:
    import base64 as _base64
    import json as _json

    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey

    from aweb.awid.custody import decrypt_signing_key, get_custody_key
    from aweb.awid.signing import sign_message

    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, did, public_key, custody, lifetime, status, signing_key_enc
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        agent_uuid,
        UUID(project_id),
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if row["lifetime"] == "ephemeral":
        raise HTTPException(
            status_code=400,
            detail="Cannot retire an ephemeral identity. Use the delete endpoint instead.",
        )
    if row["status"] == "retired":
        raise HTTPException(status_code=400, detail="Agent is already retired")
    if row["status"] == "archived":
        raise HTTPException(status_code=400, detail="Agent is already archived")
    if row["status"] == "deleted":
        raise HTTPException(status_code=400, detail="Agent is already deleted")

    successor_uuid = UUID(payload.successor_agent_id)
    if successor_uuid == agent_uuid:
        raise HTTPException(status_code=400, detail="An agent cannot name itself as its own successor")
    successor = await aweb_db.fetch_one(
        """
        SELECT agent_id, did, alias FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        successor_uuid,
        UUID(project_id),
    )
    if successor is None:
        raise HTTPException(status_code=404, detail="Successor agent not found in this project")
    if not successor["did"]:
        raise HTTPException(
            status_code=422,
            detail="Successor agent has no DID — cannot build verifiable retirement proof",
        )
    successor_did = successor["did"]

    pub_row = await aweb_db.fetch_one(
        """
        SELECT pn.domain, pa.name
        FROM {{tables.public_addresses}} pa
        JOIN {{tables.dns_namespaces}} pn ON pa.namespace_id = pn.namespace_id
            AND pn.deleted_at IS NULL
        WHERE pa.did_aw = $1 AND pa.deleted_at IS NULL
        """,
        stable_id_from_did_key(successor_did),
    )
    successor_address = f"{pub_row['domain']}/{pub_row['name']}" if pub_row else successor["alias"]

    timestamp = payload.timestamp or ""
    canonical = _json.dumps(
        {
            "operation": "retire",
            "successor_address": successor_address,
            "successor_did": successor_did,
            "timestamp": timestamp,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    if row["custody"] == "custodial" and payload.retirement_proof is None:
        master_key = get_custody_key()
        if master_key is None:
            raise HTTPException(status_code=500, detail="Custody key not configured")
        if row["signing_key_enc"] is None:
            raise HTTPException(status_code=500, detail="Agent has no signing key")
        try:
            private_key = decrypt_signing_key(bytes(row["signing_key_enc"]), master_key)
        except Exception as exc:
            raise HTTPException(status_code=500, detail="Failed to decrypt signing key") from exc
        entry_signature = sign_message(private_key, canonical)
    else:
        if not payload.retirement_proof:
            raise HTTPException(status_code=422, detail="retirement_proof is required for self-custodial agents")
        old_public_key_encoded = row["public_key"]
        if not old_public_key_encoded:
            raise HTTPException(status_code=403, detail="Agent has no public key to verify proof against")
        try:
            old_public_key = decode_public_key(old_public_key_encoded)
        except Exception as exc:
            raise HTTPException(status_code=500, detail="Corrupt public key in database") from exc
        try:
            padded = payload.retirement_proof + "=" * (-len(payload.retirement_proof) % 4)
            sig_bytes = _base64.urlsafe_b64decode(padded)
        except Exception:
            raise HTTPException(status_code=403, detail="Malformed retirement proof encoding")
        try:
            VerifyKey(old_public_key).verify(canonical, sig_bytes)
        except BadSignatureError:
            raise HTTPException(status_code=403, detail="Invalid retirement proof")
        except Exception:
            raise HTTPException(status_code=403, detail="Retirement proof verification error")
        entry_signature = payload.retirement_proof

    await aweb_db.execute(
        """
        UPDATE {{tables.agents}}
        SET status = 'retired', successor_agent_id = $1
        WHERE agent_id = $2 AND project_id = $3
        """,
        successor_uuid,
        agent_uuid,
        UUID(project_id),
    )
    metadata = _json.dumps(
        {
            "successor_agent_id": payload.successor_agent_id,
            "successor_did": successor_did,
            "successor_address": successor_address,
        }
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agent_log}}
            (agent_id, project_id, operation, old_did, signed_by, entry_signature, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
        """,
        agent_uuid,
        UUID(project_id),
        "retire",
        row["did"],
        row["did"],
        entry_signature,
        metadata,
    )
    await fire_mutation_hook(
        request,
        "agent.retired",
        {
            "agent_id": str(agent_uuid),
            "project_id": project_id,
            "did": row["did"],
            "successor_agent_id": payload.successor_agent_id,
        },
    )
    return RetireAgentResponse(
        status="retired",
        agent_id=str(agent_uuid),
        successor_agent_id=payload.successor_agent_id,
    )


@router.put("/me/retire", response_model=RetireAgentResponse)
async def retire_agent(
    request: Request,
    payload: RetireAgentRequest,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> RetireAgentResponse:
    project_id = await get_project_from_auth(request, db_infra)
    agent_id = await get_actor_agent_id_from_auth(request, db_infra, manager_name="aweb")
    aweb_db = db_infra.get_manager("aweb")
    return await _retire_agent(
        request,
        aweb_db,
        agent_uuid=UUID(agent_id),
        project_id=project_id,
        payload=payload,
    )


@router.put("/{agent_id}/retire", response_model=RetireAgentResponse)
async def retire_agent_by_id(
    agent_id: str,
    payload: RetireAgentRequest,
    request: Request,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> RetireAgentResponse:
    project_id = await get_project_from_auth(request, db_infra)
    await _require_human_owner_or_admin_for_lifecycle_action(
        request,
        db_infra,
        project_id=project_id,
        action="retire agents",
    )
    aweb_db = db_infra.get_manager("aweb")
    return await _retire_agent(
        request,
        aweb_db,
        agent_uuid=UUID(agent_id),
        project_id=project_id,
        payload=payload,
    )


class DeleteAgentResponse(BaseModel):
    agent_id: str
    status: str


async def _delete_ephemeral_agent(
    request: Request,
    aweb_db,
    *,
    agent_uuid: UUID,
    project_id: str,
) -> DeleteAgentResponse:
    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, did, lifetime, signing_key_enc
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        agent_uuid,
        UUID(project_id),
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if row["lifetime"] == "persistent":
        raise HTTPException(
            status_code=400,
            detail="Cannot delete a persistent identity. Use archive, replace, or retire instead.",
        )

    await aweb_db.execute(
        """
        UPDATE {{tables.agents}}
        SET signing_key_enc = NULL, status = 'deleted', deleted_at = NOW()
        WHERE agent_id = $1 AND project_id = $2
        """,
        agent_uuid,
        UUID(project_id),
    )
    await aweb_db.execute(
        """
        UPDATE {{tables.api_keys}}
        SET is_active = FALSE
        WHERE agent_id = $1
          AND project_id = $2
        """,
        agent_uuid,
        UUID(project_id),
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agent_log}} (agent_id, project_id, operation, old_did)
        VALUES ($1, $2, $3, $4)
        """,
        agent_uuid,
        UUID(project_id),
        "delete",
        row["did"],
    )
    await fire_mutation_hook(
        request,
        "agent.deleted",
        {
            "agent_id": str(agent_uuid),
            "project_id": project_id,
            "did": row["did"],
        },
    )
    return DeleteAgentResponse(agent_id=str(agent_uuid), status="deleted")


@router.delete("/me", response_model=DeleteAgentResponse)
async def delete_agent(
    request: Request,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> DeleteAgentResponse:
    project_id = await get_project_from_auth(request, db_infra)
    agent_id = await get_actor_agent_id_from_auth(request, db_infra, manager_name="aweb")
    aweb_db = db_infra.get_manager("aweb")
    return await _delete_ephemeral_agent(request, aweb_db, agent_uuid=UUID(agent_id), project_id=project_id)


@router.delete("/{agent_id}", response_model=DeleteAgentResponse)
async def delete_agent_by_id(
    agent_id: str,
    request: Request,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> DeleteAgentResponse:
    project_id = await get_project_from_auth(request, db_infra)
    await _require_human_owner_or_admin_for_lifecycle_action(
        request,
        db_infra,
        project_id=project_id,
        action="remove agents",
    )
    aweb_db = db_infra.get_manager("aweb")
    return await _delete_ephemeral_agent(request, aweb_db, agent_uuid=UUID(agent_id), project_id=project_id)


class SendControlSignalRequest(BaseModel):
    model_config = {"extra": "forbid"}

    signal: Literal["pause", "resume", "interrupt"]


@router.post("/{alias}/control")
async def send_control_signal(
    request: Request,
    alias: str,
    payload: SendControlSignalRequest,
    db_infra: DatabaseInfra = Depends(get_db_infra),
):
    project_id = await get_project_from_auth(request, db_infra)
    from_agent_id = await get_actor_agent_id_from_auth(request, db_infra, manager_name="aweb")
    aweb_db = db_infra.get_manager("aweb")
    target = await aweb_db.fetch_one(
        """
        SELECT agent_id FROM {{tables.agents}}
        WHERE project_id = $1 AND alias = $2 AND deleted_at IS NULL
        """,
        UUID(project_id),
        alias,
    )
    if not target:
        raise HTTPException(status_code=404, detail="Agent not found")
    result = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.control_signals}} (project_id, target_agent_id, from_agent_id, signal_type)
        VALUES ($1, $2, $3, $4)
        RETURNING signal_id
        """,
        UUID(project_id),
        target["agent_id"],
        UUID(from_agent_id),
        payload.signal,
    )
    return {"signal_id": str(result["signal_id"]), "signal": payload.signal}


def _identity_summary(operation: str, metadata: dict | None) -> str:
    if operation == "create":
        return "Agent identity created"
    if operation == "rotate":
        return "Identity key rotated"
    if operation == "retire":
        successor = (metadata or {}).get("successor_agent_id")
        return (
            f"Agent retired in favor of {successor}"
            if successor
            else "Agent retired"
        )
    if operation == "delete":
        return "Ephemeral identity deleted"
    if operation == "archive":
        return "Permanent identity archived"
    if operation == "replace":
        return "Permanent identity replaced"
    if operation == "replace_accept":
        replaced = (metadata or {}).get("replaced_agent_id")
        return (
            f"Replacement identity created for {replaced}"
            if replaced
            else "Replacement identity created"
        )
    if operation == "custody_change":
        return "Custody mode changed"
    return operation.replace("_", " ")


def _coordination_summary(event_type: str, details: dict | None) -> str:
    details = details or {}
    if event_type == "context.attached":
        context_kind = details.get("context_kind") or "context"
        if context_kind == "repo_worktree":
            repo = details.get("canonical_origin") or details.get("repo") or "repo"
            return f"Attached to repo context: {repo}"
        return f"Attached to {context_kind} context"
    if event_type == "policy_created":
        version = details.get("version")
        return f"Policy version {version} created" if version is not None else "Policy created"
    if event_type == "policy_activated":
        return "Policy activated"
    if event_type == "policy_reset_to_default":
        version = details.get("version")
        return (
            f"Policy reset to default (v{version})"
            if version is not None
            else "Policy reset to default"
        )
    return event_type.replace("_", " ").replace(".", " ")


async def _address_state_by_stable_id(
    *,
    api_db,
    aweb_db,
    server_db,
    project_id: str,
    stable_ids: list[str],
) -> dict[str, dict[str, str]]:
    if not stable_ids:
        return {}

    if api_db is None:
        return {}

    rows = await api_db.fetch_all(
        """
        SELECT domain
        FROM {{tables.managed_namespaces}}
        WHERE deleted_at IS NULL
          AND registration_status = 'registered'
          AND project_id = $1
        ORDER BY is_default DESC, domain ASC
        """,
        UUID(project_id),
    )

    domains = [str(row.get("domain") or "").strip() for row in rows if str(row.get("domain") or "").strip()]
    remaining = {stable_id for stable_id in stable_ids if stable_id}
    address_state: dict[str, dict[str, str]] = {}
    if not remaining:
        return address_state
    for domain in domains:
        for address in await list_namespace_addresses(aweb_db=aweb_db, domain=domain):
            stable_id = str(address.get("did_aw") or "").strip()
            if stable_id not in remaining:
                continue
            address_state[stable_id] = {
                "address": str(address["address"]),
                "reachability": str(address.get("reachability") or "private"),
            }
            remaining.discard(stable_id)
        if not remaining:
            break
    return address_state


@router.get("", response_model=ListAgentsResponse)
async def list_agents(
    request: Request,
    redis: Redis = Depends(get_redis),
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> ListAgentsResponse:
    """List agents in the current project with best-effort presence enrichment."""
    project_id = await get_project_from_auth(request, db_infra)

    aweb_db = db_infra.get_manager("aweb")
    server_db = db_infra.get_manager("server")
    owner_row = await aweb_db.fetch_one(
        """
        SELECT owner_type
        FROM {{tables.projects}}
        WHERE project_id = $1
          AND deleted_at IS NULL
        """,
        UUID(project_id),
    )
    project_owner_type = (str(owner_row.get("owner_type") or "") or None) if owner_row else None
    databases = getattr(request.app.state, "databases", None) or {}
    api_db = getattr(request.app.state, "api_db", None) or databases.get("api")
    project_row = await server_db.fetch_one(
        """
        SELECT id
        FROM {{tables.projects}}
        WHERE id = $1 AND deleted_at IS NULL
        """,
        UUID(project_id),
    )
    if not project_row:
        raise HTTPException(status_code=404, detail="Project not found")
    rows = await list_scope_agents(aweb_db=aweb_db, scope_id=project_id)
    for row in rows:
        await ensure_aweb_project_and_agent(
            oss_db=server_db,
            aweb_db=aweb_db,
            project_id=project_id,
            workspace_id=str(row["agent_id"]),
            alias=str(row.get("alias") or ""),
            human_name=str(row.get("human_name") or row.get("alias") or ""),
            agent_type=str(row.get("agent_type") or "agent"),
            role=str(row.get("role") or "") or None,
            program=str(row.get("program") or "") or None,
            context=parse_context(row.get("context")),
        )
    address_state_by_stable_id = await _address_state_by_stable_id(
        api_db=api_db,
        aweb_db=aweb_db,
        server_db=server_db,
        project_id=project_id,
        stable_ids=[str(r.get("stable_id") or "") for r in rows],
    )

    context_rows = await server_db.fetch_all(
        """
        SELECT
            w.workspace_id,
            w.workspace_type,
            CASE
                WHEN w.workspace_type = 'agent' THEN 'repo_worktree'::TEXT
                ELSE w.workspace_type
            END AS context_kind,
            w.hostname,
            w.workspace_path,
            w.role,
            r.canonical_origin AS repo,
            w.current_branch AS branch
        FROM {{tables.workspaces}} w
        LEFT JOIN {{tables.repos}} r ON w.repo_id = r.id AND r.deleted_at IS NULL
        WHERE w.project_id = $1 AND w.deleted_at IS NULL
        """,
        UUID(project_id),
    )
    context_by_id = {str(r["workspace_id"]): r for r in context_rows}

    agent_ids = [str(r["agent_id"]) for r in rows]
    presences = await list_agent_presences_by_workspace_ids(redis, agent_ids) if agent_ids else []
    presence_by_id = {str(p.get("workspace_id")): p for p in presences if p.get("workspace_id")}

    agents: list[AgentView] = []
    for r in rows:
        agent_id = str(r["agent_id"])
        if str(r.get("agent_type") or "") == "human":
            continue
        context_row = context_by_id.get(agent_id)
        workspace_type = str(context_row.get("workspace_type") or "") if context_row else ""
        if workspace_type == "dashboard_browser":
            continue
        presence = presence_by_id.get(agent_id)
        status = "offline"
        last_seen = None
        online = False
        branch = context_row.get("branch") if context_row else None
        role = (context_row.get("role") if context_row else None) or (r.get("role") or None)
        if presence and presence.get("project_id") == project_id:
            online = True
            status = presence.get("status") or "active"
            last_seen = presence.get("last_seen") or None
            branch = presence.get("current_branch") or branch
            role = presence.get("role") or role

        agents.append(
            AgentView(
                agent_id=agent_id,
                alias=r["alias"],
                owner_type=project_owner_type,
                human_name=(r.get("human_name") or None),
                agent_type=(r.get("agent_type") or None),
                workspace_type=(context_row.get("workspace_type") if context_row else None),
                role=role,
                context_kind=(context_row.get("context_kind") if context_row else None),
                hostname=(context_row.get("hostname") if context_row else None),
                workspace_path=(context_row.get("workspace_path") if context_row else None),
                repo=(context_row.get("repo") if context_row else None),
                branch=branch,
                status=status,
                last_seen=last_seen,
                online=online,
                did=(r.get("did") or None),
                custody=(r.get("custody") or None),
                lifetime=str(r.get("lifetime") or "ephemeral"),
                identity_status=str(r.get("status") or "active"),
                access_mode=str(r.get("access_mode") or "open"),
                address=address_state_by_stable_id.get(str(r.get("stable_id") or ""), {}).get("address"),
                address_reachability=address_state_by_stable_id.get(str(r.get("stable_id") or ""), {}).get("reachability"),
            )
        )

    return ListAgentsResponse(project_id=project_id, agents=agents)


@router.get("/{agent_id}/activity", response_model=AgentActivityResponse)
async def get_agent_activity(
    agent_id: str,
    request: Request,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> AgentActivityResponse:
    """Return persistent lifecycle and coordination activity for an agent."""
    project_id = await get_project_from_auth(request, db_infra)
    project_uuid = UUID(project_id)
    try:
        agent_uuid = UUID(validate_workspace_id(agent_id))
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e

    aweb_db = db_infra.get_manager("aweb")
    server_db = db_infra.get_manager("server")
    project_row = await server_db.fetch_one(
        """
        SELECT id
        FROM {{tables.projects}}
        WHERE id = $1 AND deleted_at IS NULL
        """,
        project_uuid,
    )
    if not project_row:
        raise HTTPException(status_code=404, detail="Project not found")
    scope_agent = await get_scope_agent(
        aweb_db=aweb_db,
        scope_id=project_id,
        agent_ref=str(agent_uuid),
    )
    await ensure_aweb_project_and_agent(
        oss_db=server_db,
        aweb_db=aweb_db,
        project_id=project_id,
        workspace_id=str(agent_uuid),
        alias=str(scope_agent.get("alias") or ""),
        human_name=str(scope_agent.get("human_name") or scope_agent.get("alias") or ""),
        agent_type=str(scope_agent.get("agent_type") or "agent"),
        role=str(scope_agent.get("role") or "") or None,
        program=str(scope_agent.get("program") or "") or None,
        context=parse_context(scope_agent.get("context")),
    )

    agent = await aweb_db.fetch_one(
        """
        SELECT agent_id, alias
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        agent_uuid,
        project_uuid,
    )
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    lifecycle_rows = await aweb_db.fetch_all(
        """
        SELECT log_id, operation, metadata, created_at
        FROM {{tables.agent_log}}
        WHERE agent_id = $1 AND project_id = $2
        ORDER BY created_at DESC
        LIMIT 50
        """,
        agent_uuid,
        project_uuid,
    )
    audit_rows = await server_db.fetch_all(
        """
        SELECT id, event_type, details, created_at
        FROM {{tables.audit_log}}
        WHERE project_id = $1 AND (agent_id = $2 OR workspace_id = $2)
        ORDER BY created_at DESC
        LIMIT 50
        """,
        project_uuid,
        agent_uuid,
    )

    items: list[AgentActivityItem] = []
    for row in lifecycle_rows:
        metadata = parse_context(row.get("metadata"))
        created_at = row["created_at"].astimezone(timezone.utc).isoformat()
        operation = row["operation"]
        items.append(
            AgentActivityItem(
                entry_id=str(row["log_id"]),
                source="identity",
                event_type=f"identity.{operation}",
                summary=_identity_summary(operation, metadata),
                details=metadata,
                created_at=created_at,
            )
        )
    for row in audit_rows:
        details = parse_context(row.get("details"))
        created_at = row["created_at"].astimezone(timezone.utc).isoformat()
        event_type = row["event_type"]
        items.append(
            AgentActivityItem(
                entry_id=str(row["id"]),
                source="coordination",
                event_type=event_type,
                summary=_coordination_summary(event_type, details),
                details=details,
                created_at=created_at,
            )
        )

    items.sort(key=lambda item: item.created_at, reverse=True)
    return AgentActivityResponse(
        agent_id=str(agent["agent_id"]),
        alias=agent["alias"],
        items=items[:50],
    )


@router.post("/register", response_model=RegisterAgentResponse)
async def register_agent(
    request: Request,
    payload: RegisterAgentRequest,
    redis: Redis = Depends(get_redis),
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> RegisterAgentResponse:
    """
    Register an agent and record presence for its workspace.

    Presence is a cache of SQL; the workspace must exist and be accessible under
    the authenticated project.
    """
    settings = get_settings()

    project_id = await verify_workspace_access(request, payload.workspace_id, db_infra)

    # Fetch workspace metadata for presence indexing (project_slug, repo_id) and to avoid
    # trusting client-supplied identifiers.
    server_db = db_infra.get_manager("server")
    workspace_row = await server_db.fetch_one(
        """
        SELECT
            w.alias,
            w.human_name,
            w.role,
            w.repo_id,
            p.slug AS project_slug
        FROM {{tables.workspaces}} w
        JOIN {{tables.projects}} p ON p.id = w.project_id AND p.deleted_at IS NULL
        WHERE w.workspace_id = $1 AND w.deleted_at IS NULL
        """,
        UUID(payload.workspace_id),
    )
    if not workspace_row:
        # Should be prevented by verify_workspace_access, but keep a defensive error here.
        raise HTTPException(status_code=422, detail="Workspace not found")

    alias = workspace_row["alias"]
    project_slug = workspace_row["project_slug"]
    repo_id = str(workspace_row["repo_id"]) if workspace_row.get("repo_id") else None
    human_name = payload.human_name or (workspace_row.get("human_name") or None)
    role = payload.role or (workspace_row.get("role") or None)

    registered_at = await update_agent_presence(
        redis,
        workspace_id=payload.workspace_id,
        alias=alias,
        human_name=human_name,
        project_id=project_id,
        project_slug=project_slug,
        repo_id=repo_id,
        program=payload.program,
        model=payload.model,
        current_branch=payload.branch,
        role=role,
        ttl_seconds=payload.ttl_seconds or settings.presence_ttl_seconds,
    )

    agent = AgentInfo(
        alias=alias,
        human_name=human_name,
        project_slug=project_slug,
        program=payload.program,
        model=payload.model,
        member=None,
        repo=payload.repo,
        branch=payload.branch,
        role=role,
        role_name=role,
        registered_at=registered_at,
    )
    workspace = WorkspaceInfo(workspace_id=payload.workspace_id)

    return RegisterAgentResponse(agent=agent, workspace=workspace)
