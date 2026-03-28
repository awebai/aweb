"""Privileged scope provisioning for service-level callers (e.g. aweb)."""

from __future__ import annotations

import hmac
import os
from datetime import datetime, timezone
from typing import Literal, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aweb.bootstrap import AliasExhaustedError, bootstrap_identity
from aweb.access_modes import validate_access_mode
from aweb.deps import get_db
from aweb.hooks import fire_mutation_hook
from aweb.role_name_compat import normalize_optional_role_name, resolve_role_name_aliases
from aweb.routes.agents import parse_context

router = APIRouter(prefix="/v1/scopes", tags=["scopes"])


async def require_service_token(request: Request) -> None:
    """Dependency that enforces service token auth."""
    expected = os.getenv("AWEB_SERVICE_TOKEN")
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="Service provisioning is not enabled (AWEB_SERVICE_TOKEN not set)",
        )

    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Service token required")

    token = auth[7:]
    if not hmac.compare_digest(str(token), str(expected)):
        raise HTTPException(status_code=401, detail="Invalid service token")


class ScopeProvisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_slug: str = Field(..., min_length=1, max_length=256)
    project_name: str = Field(default="", max_length=256)
    project_id: Optional[str] = Field(default=None, max_length=64)
    tenant_id: Optional[str] = Field(default=None, max_length=64)
    owner_type: Optional[str] = Field(default=None, max_length=64)
    owner_ref: Optional[str] = Field(default=None, max_length=256)
    alias: Optional[str] = Field(default=None, max_length=64)
    human_name: str = Field(default="", max_length=64)
    agent_type: str = Field(default="agent", max_length=32)
    did: Optional[str] = Field(default=None, max_length=256)
    public_key: Optional[str] = Field(default=None, max_length=64)
    custody: Optional[Literal["self", "custodial"]] = None
    lifetime: Literal["persistent", "ephemeral"] = "ephemeral"
    role: Optional[str] = Field(default=None, max_length=64)
    role_name: Optional[str] = Field(default=None, max_length=64)
    program: Optional[str] = Field(default=None, max_length=64)
    context: Optional[dict] = None
    access_mode: str = Field(default="open", max_length=64)

    @field_validator("access_mode")
    @classmethod
    def validate_access_mode_field(cls, v: str) -> str:
        return validate_access_mode(v)

    @field_validator("role", "role_name")
    @classmethod
    def validate_role_field(cls, v: str | None) -> str | None:
        return normalize_optional_role_name(v)

    @model_validator(mode="after")
    def sync_role_aliases(self):
        resolved = resolve_role_name_aliases(role=self.role, role_name=self.role_name)
        self.role = resolved
        self.role_name = resolved
        return self


class ScopeProvisionResponse(BaseModel):
    status: str = "ok"
    created_at: str
    project_id: str
    project_slug: str
    agent_id: str
    alias: str
    api_key: str
    created: bool
    role: Optional[str] = None
    role_name: Optional[str] = None
    did: Optional[str] = None
    stable_id: Optional[str] = None
    custody: Optional[str] = None
    lifetime: str = "ephemeral"


@router.post(
    "",
    response_model=ScopeProvisionResponse,
    dependencies=[Depends(require_service_token)],
)
async def provision_scope(
    request: Request,
    payload: ScopeProvisionRequest,
    db=Depends(get_db),
) -> ScopeProvisionResponse:
    """Provision a scope (project + agent + API key) on behalf of an external system."""
    try:
        result = await bootstrap_identity(
            db,
            project_slug=payload.project_slug,
            project_name=payload.project_name,
            project_id=payload.project_id,
            tenant_id=payload.tenant_id,
            owner_type=payload.owner_type,
            owner_ref=payload.owner_ref,
            alias=payload.alias,
            human_name=payload.human_name,
            agent_type=payload.agent_type,
            did=payload.did,
            public_key=payload.public_key,
            custody=payload.custody,
            lifetime=payload.lifetime,
            role=payload.role,
            program=payload.program,
            context=payload.context,
            access_mode=payload.access_mode,
        )
    except AliasExhaustedError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    if result.created:
        await fire_mutation_hook(
            request,
            "agent.created",
            {
                "agent_id": result.agent_id,
                "project_id": result.project_id,
                "alias": result.alias,
                "did": result.did or "",
                "custody": result.custody or "",
                "lifetime": result.lifetime,
            },
        )

    return ScopeProvisionResponse(
        created_at=datetime.now(timezone.utc).isoformat(),
        project_id=result.project_id,
        project_slug=result.project_slug,
        agent_id=result.agent_id,
        alias=result.alias,
        api_key=result.api_key,
        created=result.created,
        role=payload.role,
        role_name=payload.role,
        did=result.did,
        stable_id=result.stable_id,
        custody=result.custody,
        lifetime=result.lifetime,
    )


# ---------------------------------------------------------------------------
# Scope-scoped agent lifecycle (service-token auth)
# ---------------------------------------------------------------------------


async def _require_scope(db, scope_id: str) -> dict:
    """Look up a scope by ID, raising 404 if not found."""
    try:
        scope_uuid = UUID(scope_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Scope not found")

    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT project_id, slug, name
        FROM {{tables.projects}}
        WHERE project_id = $1 AND deleted_at IS NULL
        """,
        scope_uuid,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Scope not found")
    return dict(row)


class ScopeAgentBootstrapRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alias: Optional[str] = Field(default=None, max_length=64)
    human_name: str = Field(default="", max_length=64)
    agent_type: str = Field(default="agent", max_length=32)
    did: Optional[str] = Field(default=None, max_length=256)
    public_key: Optional[str] = Field(default=None, max_length=64)
    custody: Optional[Literal["self", "custodial"]] = None
    lifetime: Literal["persistent", "ephemeral"] = "ephemeral"
    role: Optional[str] = Field(default=None, max_length=64)
    role_name: Optional[str] = Field(default=None, max_length=64)
    program: Optional[str] = Field(default=None, max_length=64)
    context: Optional[dict] = None
    access_mode: str = Field(default="open", max_length=64)

    @field_validator("access_mode")
    @classmethod
    def validate_access_mode_field(cls, v: str) -> str:
        return validate_access_mode(v)

    @field_validator("role", "role_name")
    @classmethod
    def validate_role_field(cls, v: str | None) -> str | None:
        return normalize_optional_role_name(v)

    @model_validator(mode="after")
    def sync_role_aliases(self):
        resolved = resolve_role_name_aliases(role=self.role, role_name=self.role_name)
        self.role = resolved
        self.role_name = resolved
        return self


class ScopeAgentBootstrapResponse(BaseModel):
    scope_id: str
    agent_id: str
    alias: str
    agent_type: str = "agent"
    api_key: str
    created: bool
    did: Optional[str] = None
    stable_id: Optional[str] = None
    custody: Optional[str] = None
    lifetime: str = "ephemeral"


@router.post(
    "/{scope_id}/agents",
    response_model=ScopeAgentBootstrapResponse,
    dependencies=[Depends(require_service_token)],
)
async def bootstrap_agent_in_scope(
    request: Request,
    scope_id: str,
    payload: ScopeAgentBootstrapRequest,
    db=Depends(get_db),
) -> ScopeAgentBootstrapResponse:
    """Bootstrap an agent in an existing scope."""
    scope = await _require_scope(db, scope_id)

    try:
        result = await bootstrap_identity(
            db,
            project_slug=scope["slug"],
            project_id=str(scope["project_id"]),
            alias=payload.alias,
            human_name=payload.human_name,
            agent_type=payload.agent_type,
            did=payload.did,
            public_key=payload.public_key,
            custody=payload.custody,
            lifetime=payload.lifetime,
            role=payload.role,
            program=payload.program,
            context=payload.context,
            access_mode=payload.access_mode,
        )
    except AliasExhaustedError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    if result.created:
        await fire_mutation_hook(
            request,
            "agent.created",
            {
                "agent_id": result.agent_id,
                "project_id": result.project_id,
                "alias": result.alias,
                "did": result.did or "",
                "custody": result.custody or "",
                "lifetime": result.lifetime,
            },
        )

    return ScopeAgentBootstrapResponse(
        scope_id=str(scope["project_id"]),
        agent_id=result.agent_id,
        alias=result.alias,
        agent_type=result.agent_type,
        api_key=result.api_key,
        created=result.created,
        did=result.did,
        stable_id=result.stable_id,
        custody=result.custody,
        lifetime=result.lifetime,
    )


class ScopeAgentView(BaseModel):
    agent_id: str
    alias: str
    human_name: Optional[str] = None
    agent_type: Optional[str] = None
    access_mode: str = "open"
    did: Optional[str] = None
    stable_id: Optional[str] = None
    custody: Optional[str] = None
    lifetime: str = "ephemeral"
    status: str = "active"
    role: Optional[str] = None
    role_name: Optional[str] = None
    program: Optional[str] = None
    context: Optional[dict] = None

    @model_validator(mode="after")
    def sync_role_aliases(self):
        resolved = resolve_role_name_aliases(role=self.role, role_name=self.role_name)
        self.role = resolved
        self.role_name = resolved
        return self


class ScopeAgentListResponse(BaseModel):
    scope_id: str
    agents: list[ScopeAgentView]


@router.get(
    "/{scope_id}/agents",
    response_model=ScopeAgentListResponse,
    dependencies=[Depends(require_service_token)],
)
async def list_agents_in_scope(
    scope_id: str,
    db=Depends(get_db),
) -> ScopeAgentListResponse:
    """List all agents in a scope."""
    scope = await _require_scope(db, scope_id)
    aweb_db = db.get_manager("aweb")

    rows = await aweb_db.fetch_all(
        """
        SELECT agent_id, alias, human_name, agent_type, access_mode,
               did, stable_id, custody, lifetime, status,
               role, program, context
        FROM {{tables.agents}}
        WHERE project_id = $1 AND deleted_at IS NULL
        ORDER BY alias
        """,
        UUID(str(scope["project_id"])),
    )

    agents = [
        ScopeAgentView(
            agent_id=str(r["agent_id"]),
            alias=r["alias"],
            human_name=r.get("human_name"),
            agent_type=r.get("agent_type"),
            access_mode=r.get("access_mode", "open"),
            did=r.get("did"),
            stable_id=r.get("stable_id"),
            custody=r.get("custody"),
            lifetime=r.get("lifetime", "ephemeral"),
            status=r.get("status", "active"),
            role=r.get("role"),
            program=r.get("program"),
            context=parse_context(r.get("context")),
        )
        for r in rows
    ]

    return ScopeAgentListResponse(
        scope_id=str(scope["project_id"]),
        agents=agents,
    )


@router.get(
    "/{scope_id}/agents/{agent_id}",
    response_model=ScopeAgentView,
    dependencies=[Depends(require_service_token)],
)
async def get_agent_in_scope(
    scope_id: str,
    agent_id: str,
    db=Depends(get_db),
) -> ScopeAgentView:
    """Get a specific agent by UUID or stable_id within a scope."""
    scope = await _require_scope(db, scope_id)
    aweb_db = db.get_manager("aweb")
    scope_uuid = UUID(str(scope["project_id"]))

    # Try UUID lookup first, then stable_id.
    row = None
    try:
        agent_uuid = UUID(agent_id)
        row = await aweb_db.fetch_one(
            """
            SELECT agent_id, alias, human_name, agent_type, access_mode,
                   did, stable_id, custody, lifetime, status,
                   role, program, context
            FROM {{tables.agents}}
            WHERE project_id = $1 AND agent_id = $2 AND deleted_at IS NULL
            """,
            scope_uuid,
            agent_uuid,
        )
    except ValueError:
        pass

    if row is None:
        row = await aweb_db.fetch_one(
            """
            SELECT agent_id, alias, human_name, agent_type, access_mode,
                   did, stable_id, custody, lifetime, status,
                   role, program, context
            FROM {{tables.agents}}
            WHERE project_id = $1 AND stable_id = $2 AND deleted_at IS NULL
            """,
            scope_uuid,
            agent_id,
        )

    if row is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    return ScopeAgentView(
        agent_id=str(row["agent_id"]),
        alias=row["alias"],
        human_name=row.get("human_name"),
        agent_type=row.get("agent_type"),
        access_mode=row.get("access_mode", "open"),
        did=row.get("did"),
        stable_id=row.get("stable_id"),
        custody=row.get("custody"),
        lifetime=row.get("lifetime", "ephemeral"),
        status=row.get("status", "active"),
        role=row.get("role"),
        program=row.get("program"),
        context=parse_context(row.get("context")),
    )
