"""Workspace discovery and registration endpoints."""

from __future__ import annotations

import json
import logging
import uuid as uuid_module
from datetime import datetime, timezone
from typing import Dict, List, Literal, Optional
from uuid import UUID

import asyncpg.exceptions
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from pgdbm.errors import QueryError
from pydantic import BaseModel, Field, field_validator
from redis.asyncio import Redis

from aweb.auth import validate_workspace_id
from aweb.aweb_context import resolve_aweb_identity
from aweb.aweb_introspection import get_identity_from_auth, get_project_from_auth
from aweb.bootstrap import delete_agent_identity

from ...config import get_settings
from ...db import DatabaseInfra, get_db_infra
from ...input_validation import is_valid_alias, is_valid_canonical_origin, is_valid_human_name
from ...internal_auth import is_public_reader
from ...names import CLASSIC_NAMES
from ...pagination import encode_cursor, validate_pagination_params
from ...presence import (
    clear_workspace_presence,
    list_agent_presences,
    list_agent_presences_by_workspace_ids,
    update_agent_presence,
)
from ..project_registry import ensure_server_project_row
from ...redis_client import get_redis
from ..roles import (
    ROLE_ERROR_MESSAGE,
    ROLE_MAX_LENGTH,
    is_valid_role,
    normalize_role,
)
from .repos import canonicalize_git_url, extract_repo_name
from ..workspace_registry import (
    check_alias_collision,
    ensure_repo,
    upsert_workspace,
)

logger = logging.getLogger(__name__)

TEAM_STATUS_DEFAULT_LIMIT = 15
TEAM_STATUS_MAX_LIMIT = 200
TEAM_STATUS_CANDIDATE_MULTIPLIER = 5
TEAM_STATUS_CANDIDATE_MAX = 500
REGISTRY_MAX_LIMIT = 1000

router = APIRouter(prefix="/v1/workspaces", tags=["workspaces"])

# Request/Response models for suggest-name-prefix


class SuggestNamePrefixRequest(BaseModel):
    """Request body for /v1/workspaces/suggest-name-prefix endpoint."""

    origin_url: str = Field(..., min_length=1, max_length=2048, description="Git origin URL")

    @field_validator("origin_url")
    @classmethod
    def validate_origin_url(cls, v: str) -> str:
        try:
            canonicalize_git_url(v)
        except ValueError as e:
            raise ValueError(f"Invalid origin_url: {e}")
        return v


class SuggestNamePrefixResponse(BaseModel):
    """Response for /v1/workspaces/suggest-name-prefix endpoint."""

    name_prefix: str  # The next available name (e.g., "alice", "bob", "alice-01")
    project_id: str
    project_slug: str
    repo_id: str
    canonical_origin: str


async def _resolve_project_for_name_suggestion(
    server_db, canonical_origin: str, auth_project_id: UUID | None
) -> tuple[UUID, str, str]:
    """Resolve (project_id, project_slug, repo_id) for a name prefix suggestion.

    When authenticated, scopes to the authenticated project to prevent
    classic-name allocation from leaking across projects.
    """
    results = await server_db.fetch_all(
        """
        SELECT r.id as repo_id, r.canonical_origin,
               p.id as project_id, p.slug as project_slug
        FROM {{tables.repos}} r
        JOIN {{tables.projects}} p ON r.project_id = p.id AND p.deleted_at IS NULL
        WHERE r.canonical_origin = $1 AND r.deleted_at IS NULL
        ORDER BY p.slug
        """,
        canonical_origin,
    )

    if auth_project_id is not None:
        project_row = await server_db.fetch_one(
            """
            SELECT id, slug
            FROM {{tables.projects}}
            WHERE id = $1 AND deleted_at IS NULL
            """,
            auth_project_id,
        )
        if not project_row:
            raise HTTPException(status_code=404, detail="Project not found")

        matched_repo = next((r for r in results if r["project_id"] == auth_project_id), None)
        return (
            project_row["id"],
            project_row["slug"],
            str(matched_repo["repo_id"]) if matched_repo is not None else "",
        )

    if not results:
        raise HTTPException(
            status_code=404,
            detail=f"Repo not registered: {canonical_origin}. Run 'aw init' or 'aw use' from this repo to register it.",
        )
    if len(results) > 1:
        project_slugs = [r["project_slug"] for r in results]
        raise HTTPException(
            status_code=409,
            detail=f"Repo exists in multiple projects: {', '.join(project_slugs)}. "
            "Authenticate with the correct project account, then run 'aw init' or 'aw use' from this repo.",
        )

    result = results[0]
    return result["project_id"], result["project_slug"], str(result["repo_id"])


def _extract_used_prefixes(aliases: list[str]) -> set[str]:
    """Extract name prefixes from existing aliases.

    An alias like "alice-programmer" has prefix "alice".
    An alias like "alice-01-programmer" has prefix "alice-01".
    An alias like "alice" (no role) also has prefix "alice".
    """
    used: set[str] = set()
    for alias in aliases:
        parts = alias.split("-")
        if len(parts) >= 2 and parts[1].isdigit():
            prefix = f"{parts[0]}-{parts[1]}".lower()
        else:
            prefix = parts[0].lower()
        if prefix:
            used.add(prefix)
    return used


def _find_available_prefix(used_prefixes: set[str]) -> str | None:
    """Find the first available classic name prefix.

    Tries base names first (alice, bob, ...), then numbered (alice-01, bob-01, ...).
    """
    for name in CLASSIC_NAMES:
        if name not in used_prefixes:
            return name

    for num in range(1, 100):
        for name in CLASSIC_NAMES:
            numbered = f"{name}-{num:02d}"
            if numbered not in used_prefixes:
                return numbered

    return None


@router.post("/suggest-name-prefix", response_model=SuggestNamePrefixResponse)
async def suggest_name_prefix(
    request: Request,
    payload: SuggestNamePrefixRequest,
    db: DatabaseInfra = Depends(get_db_infra),
) -> SuggestNamePrefixResponse:
    """
    Get the next available name prefix for a new workspace.

    Given an origin_url, this endpoint:
    1. Looks up the repo to find the project
    2. Queries existing aliases to find used name prefixes
    3. Returns the first available classic name (e.g., alice, bob, alice-01)

    Classic names are used: alice, bob, charlie, etc. The client combines
    the name_prefix with their role to form the full alias.

    Returns 404 if the repo is not registered and the caller is not authenticated.
    Returns 409 if the repo exists in multiple projects and the caller is not authenticated
    (or the authenticated project is not among them), or all names are taken.
    """
    server_db = db.get_manager("server")
    canonical_origin = canonicalize_git_url(payload.origin_url)

    auth_project_id: UUID | None = None
    if "Authorization" in request.headers or "X-AWEB-Auth" in request.headers:
        auth_project_id = UUID(await get_project_from_auth(request, db))

    project_id, project_slug, repo_id = await _resolve_project_for_name_suggestion(
        server_db, canonical_origin, auth_project_id
    )

    # Query aweb.agents (not server.workspaces) for used aliases.
    # bootstrap_identity creates agents in aweb.agents, and an agent can exist
    # there without a corresponding workspace in server.workspaces.
    aweb_db = db.get_manager("aweb")
    existing = await aweb_db.fetch_all(
        """
        SELECT alias FROM {{tables.agents}}
        WHERE project_id = $1
          AND deleted_at IS NULL
        ORDER BY alias
        """,
        project_id,
    )

    used_prefixes = _extract_used_prefixes([row["alias"] for row in existing])
    available_prefix = _find_available_prefix(used_prefixes)

    if available_prefix is None:
        raise HTTPException(
            status_code=409,
            detail=f"All name prefixes are taken (tried {len(CLASSIC_NAMES)} names × 100 variants). "
            "Use --alias to specify a custom alias.",
        )

    return SuggestNamePrefixResponse(
        name_prefix=available_prefix,
        project_id=str(project_id),
        project_slug=project_slug,
        repo_id=repo_id,
        canonical_origin=canonical_origin,
    )


# Request/Response models for registration


class RegisterWorkspaceRequest(BaseModel):
    """Request body for /v1/workspaces/register endpoint (clean-slate split)."""

    repo_origin: str = Field(..., min_length=1, max_length=2048)
    role: Optional[str] = Field(
        None,
        max_length=ROLE_MAX_LENGTH,
        description="Brief description of workspace purpose",
    )
    hostname: Optional[str] = Field(
        None,
        max_length=255,
        description="Machine hostname for gone workspace detection",
    )
    workspace_path: Optional[str] = Field(
        None,
        max_length=4096,
        description="Directory path for gone workspace detection",
    )

    @field_validator("repo_origin")
    @classmethod
    def validate_repo_origin(cls, v: str) -> str:
        try:
            canonicalize_git_url(v)
        except ValueError as e:
            raise ValueError(f"Invalid repo_origin: {e}")
        return v

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        if not is_valid_role(v):
            raise ValueError(ROLE_ERROR_MESSAGE)
        return normalize_role(v)

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        if "\x00" in v or any(ord(c) < 32 for c in v):
            raise ValueError(
                "hostname contains invalid characters (null bytes or control characters)"
            )
        return v

    @field_validator("workspace_path")
    @classmethod
    def validate_workspace_path(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        if "\x00" in v or any(ord(c) < 32 and c not in "\t\n" for c in v):
            raise ValueError(
                "workspace_path contains invalid characters (null bytes or control characters)"
            )
        return v


class RegisterWorkspaceResponse(BaseModel):
    """Response for /v1/workspaces/register endpoint."""

    workspace_id: str
    project_id: str
    project_slug: str
    repo_id: str
    canonical_origin: str
    alias: str
    human_name: str
    created: bool  # True if new workspace, False if already existed


class RegisterAttachmentRequest(BaseModel):
    """Request body for /v1/workspaces/attach endpoint."""

    attachment_type: Literal["local_dir", "service_process", "manual"] = Field(
        ...,
        description="Non-repo runtime attachment type",
    )
    role: Optional[str] = Field(
        None,
        max_length=ROLE_MAX_LENGTH,
        description="Role used for policy and coordination",
    )
    hostname: Optional[str] = Field(
        None,
        max_length=255,
        description="Optional coarse host label for runtime coordination",
    )
    workspace_path: Optional[str] = Field(
        None,
        max_length=4096,
        description="Directory path for runtime coordination",
    )

    @field_validator("role")
    @classmethod
    def validate_attachment_role(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        if not is_valid_role(v):
            raise ValueError(ROLE_ERROR_MESSAGE)
        return normalize_role(v)

    @field_validator("hostname")
    @classmethod
    def validate_attachment_hostname(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        if "\x00" in v or any(ord(c) < 32 for c in v):
            raise ValueError(
                "hostname contains invalid characters (null bytes or control characters)"
            )
        return v

    @field_validator("workspace_path")
    @classmethod
    def validate_attachment_workspace_path(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        if "\x00" in v or any(ord(c) < 32 and c not in "\t\n" for c in v):
            raise ValueError(
                "workspace_path contains invalid characters (null bytes or control characters)"
            )
        return v


class RegisterAttachmentResponse(BaseModel):
    """Response for /v1/workspaces/attach endpoint."""

    workspace_id: str
    project_id: str
    project_slug: str
    alias: str
    human_name: str
    attachment_type: str
    created: bool


@router.post("/register", response_model=RegisterWorkspaceResponse)
async def register_workspace(
    request: Request,
    payload: RegisterWorkspaceRequest,
    db: DatabaseInfra = Depends(get_db_infra),
) -> RegisterWorkspaceResponse:
    """
    Register a workspace for the authenticated aweb agent.

    Identity and project scoping are derived from the unified aweb core:
    - project_id comes from aweb auth/introspection
    - workspace_id is the aweb agent_id (v1 mapping)
    - alias/human_name come from the canonical agent profile
    """
    server_db = db.get_manager("server")

    identity = await resolve_aweb_identity(request, db)
    project_id = identity.project_id
    workspace_id = identity.agent_id
    alias = identity.alias
    human_name = identity.human_name
    if not is_valid_alias(alias):
        raise HTTPException(status_code=502, detail="aweb returned invalid alias format")
    if human_name and not is_valid_human_name(human_name):
        raise HTTPException(status_code=502, detail="aweb returned invalid human_name format")

    project_slug = identity.project_slug
    project_name = identity.project_name or ""

    canonical_origin = canonicalize_git_url(payload.repo_origin)
    repo_name = extract_repo_name(canonical_origin)

    created = False
    async with server_db.transaction() as tx:
        await ensure_server_project_row(
            server_db=tx,
            aweb_db=db.get_manager("aweb"),
            project_id=project_id,
            project_slug=project_slug,
            project_name=project_name,
        )

        repo = await tx.fetch_one(
            """
            INSERT INTO {{tables.repos}} (project_id, origin_url, canonical_origin, name)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (project_id, canonical_origin)
            DO UPDATE SET origin_url = EXCLUDED.origin_url, deleted_at = NULL
            RETURNING id
            """,
            UUID(project_id),
            payload.repo_origin,
            canonical_origin,
            repo_name,
        )
        assert repo is not None
        repo_id = str(repo["id"])

        existing = await tx.fetch_one(
            """
            SELECT workspace_id, project_id, repo_id, alias, deleted_at
            FROM {{tables.workspaces}}
            WHERE workspace_id = $1
            """,
            UUID(workspace_id),
        )
        if existing:
            if str(existing["project_id"]) != project_id:
                raise HTTPException(
                    status_code=409, detail="Workspace already registered in another project"
                )
            if existing["repo_id"] is not None and str(existing["repo_id"]) != repo_id:
                raise HTTPException(
                    status_code=409, detail="Workspace already registered for another repo"
                )
            if existing["alias"] != alias:
                raise HTTPException(
                    status_code=409, detail="Workspace already registered with a different alias"
                )

            await tx.execute(
                """
                UPDATE {{tables.workspaces}}
                SET deleted_at = NULL,
                    repo_id = COALESCE(repo_id, $2),
                    hostname = $3,
                    workspace_path = $4,
                    role = COALESCE($5, role),
                    human_name = $6,
                    workspace_type = 'agent',
                    updated_at = NOW()
                WHERE workspace_id = $1
                """,
                UUID(workspace_id),
                UUID(repo_id),
                payload.hostname,
                payload.workspace_path,
                payload.role,
                human_name,
            )
            created = False
        else:
            try:
                await tx.execute(
                    """
                    INSERT INTO {{tables.workspaces}}
                        (workspace_id, project_id, repo_id, alias, human_name, role, hostname, workspace_path, workspace_type)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'agent')
                    """,
                    UUID(workspace_id),
                    UUID(project_id),
                    UUID(repo_id),
                    alias,
                    human_name,
                    payload.role,
                    payload.hostname,
                    payload.workspace_path,
                )
            except (QueryError, asyncpg.exceptions.UniqueViolationError) as e:
                # Alias uniqueness violation within the project.
                if isinstance(e, QueryError) and not isinstance(
                    e.__cause__, asyncpg.exceptions.UniqueViolationError
                ):
                    raise
                raise HTTPException(
                    status_code=409, detail=f"Alias '{alias}' is already used in this project"
                )
            created = True

    await server_db.execute(
        """
        INSERT INTO {{tables.audit_log}} (project_id, workspace_id, agent_id, event_type, alias, resource, details)
        VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
        """,
        UUID(project_id),
        UUID(workspace_id),
        UUID(workspace_id),
        "context.attached",
        alias,
        "agent_context",
        json.dumps(
            {
                "context_kind": "repo_worktree",
                "canonical_origin": canonical_origin,
                "repo_id": repo_id,
                "created": created,
            }
        ),
    )

    return RegisterWorkspaceResponse(
        workspace_id=workspace_id,
        project_id=project_id,
        project_slug=project_slug,
        repo_id=repo_id,
        canonical_origin=canonical_origin,
        alias=alias,
        human_name=human_name,
        created=created,
    )


@router.post("/attach", response_model=RegisterAttachmentResponse)
async def register_attachment(
    request: Request,
    payload: RegisterAttachmentRequest,
    redis: Redis = Depends(get_redis),
    db: DatabaseInfra = Depends(get_db_infra),
) -> RegisterAttachmentResponse:
    """
    Register a non-repo runtime attachment for the authenticated aweb agent.

    This creates a first-class coordination participant without requiring a
    shared repo identity or disclosing a local path.
    """
    server_db = db.get_manager("server")

    identity = await resolve_aweb_identity(request, db)
    project_id = identity.project_id
    workspace_id = identity.agent_id
    alias = identity.alias
    human_name = identity.human_name
    if not is_valid_alias(alias):
        raise HTTPException(status_code=502, detail="aweb returned invalid alias format")
    if human_name and not is_valid_human_name(human_name):
        raise HTTPException(status_code=502, detail="aweb returned invalid human_name format")

    project_slug = identity.project_slug
    project_name = identity.project_name or ""
    created = False

    async with server_db.transaction() as tx:
        await ensure_server_project_row(
            server_db=tx,
            aweb_db=db.get_manager("aweb"),
            project_id=project_id,
            project_slug=project_slug,
            project_name=project_name,
        )

        existing_workspace = await tx.fetch_one(
            """
            SELECT workspace_id, project_id, alias
            FROM {{tables.workspaces}}
            WHERE workspace_id = $1
            """,
            UUID(workspace_id),
        )
        if existing_workspace:
            if str(existing_workspace["project_id"]) != project_id:
                raise HTTPException(
                    status_code=409, detail="Agent is already attached in another project"
                )
            if existing_workspace["alias"] != alias:
                raise HTTPException(
                    status_code=409, detail="Agent is already attached with a different alias"
                )

        colliding_workspace = await check_alias_collision(
            db, redis, UUID(project_id), workspace_id, alias
        )
        if colliding_workspace:
            raise HTTPException(
                status_code=409,
                detail=f"Alias '{alias}' is already used by another participant in this project",
            )

        if existing_workspace is None:
            try:
                await tx.execute(
                    """
                    INSERT INTO {{tables.workspaces}}
                        (
                            workspace_id,
                            project_id,
                            repo_id,
                            alias,
                            human_name,
                            role,
                            hostname,
                            workspace_path,
                            workspace_type,
                            last_seen_at
                        )
                    VALUES ($1, $2, NULL, $3, $4, $5, $6, $7, $8, NOW())
                    """,
                    UUID(workspace_id),
                    UUID(project_id),
                    alias,
                    human_name,
                    payload.role,
                    payload.hostname,
                    payload.workspace_path,
                    payload.attachment_type,
                )
            except (QueryError, asyncpg.exceptions.UniqueViolationError) as e:
                if isinstance(e, QueryError) and not isinstance(
                    e.__cause__, asyncpg.exceptions.UniqueViolationError
                ):
                    raise
                raise HTTPException(
                    status_code=409,
                    detail=f"Alias '{alias}' is already used in this project",
                ) from e
            created = True
        else:
            await tx.execute(
                """
                UPDATE {{tables.workspaces}}
                SET deleted_at = NULL,
                    repo_id = NULL,
                    human_name = $2,
                    role = COALESCE($3, role),
                    hostname = $4,
                    workspace_path = $5,
                    workspace_type = $6,
                    last_seen_at = NOW(),
                    updated_at = NOW()
                WHERE workspace_id = $1
                """,
                UUID(workspace_id),
                human_name,
                payload.role,
                payload.hostname,
                payload.workspace_path,
                payload.attachment_type,
            )
            created = False

    settings = get_settings()
    try:
        await update_agent_presence(
            redis,
            workspace_id=workspace_id,
            alias=alias,
            human_name=human_name,
            project_id=project_id,
            project_slug=project_slug,
            repo_id=None,
            program="aw",
            model=None,
            role=payload.role,
            ttl_seconds=settings.presence_ttl_seconds,
        )
    except Exception as e:
        logger.warning(
            "Attachment SQL upsert succeeded but presence update failed",
            extra={
                "workspace_id": workspace_id,
                "project_id": project_id,
                "error": str(e),
            },
        )

    try:
        await update_agent_presence(
            redis,
            agent_id=workspace_id,
            alias=alias,
            project_id=project_id,
            ttl_seconds=settings.presence_ttl_seconds,
        )
    except Exception as e:
        logger.warning(
            "Aweb agent presence update failed for non-repo attachment",
            extra={
                "workspace_id": workspace_id,
                "project_id": project_id,
                "error": str(e),
            },
        )

    await server_db.execute(
        """
        INSERT INTO {{tables.audit_log}} (project_id, workspace_id, agent_id, event_type, alias, resource, details)
        VALUES ($1, $2, $2, $3, $4, $5, $6::jsonb)
        """,
        UUID(project_id),
        UUID(workspace_id),
        "context.attached",
        alias,
        "agent_context",
        json.dumps(
            {
                "context_kind": payload.attachment_type,
                "created": created,
            }
        ),
    )

    return RegisterAttachmentResponse(
        workspace_id=workspace_id,
        project_id=project_id,
        project_slug=project_slug,
        alias=alias,
        human_name=human_name,
        attachment_type=payload.attachment_type,
        created=created,
    )


# Heartbeat models and endpoint
# IMPORTANT: This endpoint MUST be defined BEFORE /{workspace_id} to prevent
# "heartbeat" from matching as a workspace_id parameter.


class WorkspaceHeartbeatRequest(BaseModel):
    workspace_id: str = Field(..., min_length=1)
    alias: str = Field(..., min_length=1, max_length=64)
    repo_origin: str = Field(..., min_length=1, max_length=512, description="Git remote origin URL")

    role: Optional[str] = Field(
        None,
        max_length=ROLE_MAX_LENGTH,
        description="Brief description of workspace purpose",
    )
    current_branch: Optional[str] = Field(None, max_length=255)
    timezone: Optional[str] = Field(None, max_length=64)
    hostname: Optional[str] = Field(None, max_length=255)
    workspace_path: Optional[str] = Field(None, max_length=1024)
    human_name: Optional[str] = Field(None, max_length=64)

    @field_validator("workspace_id")
    @classmethod
    def validate_workspace_id_field(cls, v: str) -> str:
        try:
            return validate_workspace_id(v)
        except ValueError as e:
            raise ValueError(str(e))

    @field_validator("alias")
    @classmethod
    def validate_alias_field(cls, v: str) -> str:
        if not is_valid_alias(v):
            raise ValueError(
                "Invalid alias: must be alphanumeric with hyphens/underscores, 1-64 chars"
            )
        return v

    @field_validator("repo_origin")
    @classmethod
    def validate_repo_origin_field(cls, v: str) -> str:
        try:
            canonicalize_git_url(v)
        except ValueError as e:
            raise ValueError(f"Invalid repo_origin: {e}")
        return v

    @field_validator("role")
    @classmethod
    def validate_role_field(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        if not is_valid_role(v):
            raise ValueError(ROLE_ERROR_MESSAGE)
        return normalize_role(v)

    @field_validator("timezone")
    @classmethod
    def validate_timezone_field(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        import re

        if not re.match(r"^[A-Za-z][A-Za-z0-9_+\-/]{0,63}$", v):
            raise ValueError(
                "timezone must be a valid IANA identifier (e.g. 'Europe/Madrid', 'America/New_York')"
            )
        return v


class WorkspaceHeartbeatResponse(BaseModel):
    ok: bool = True
    workspace_id: str


@router.post("/heartbeat", response_model=WorkspaceHeartbeatResponse)
async def heartbeat(
    payload: WorkspaceHeartbeatRequest,
    request: Request,
    redis: Redis = Depends(get_redis),
    db: DatabaseInfra = Depends(get_db_infra),
) -> WorkspaceHeartbeatResponse:
    """
    Refresh workspace presence, enforcing "presence is a cache of SQL".

    Order of operations:
    1) Ensure repo/workspace exists (SQL)
    2) Update presence (Redis)

    Note: If Redis is unavailable, SQL is still authoritative; presence updates
    are best-effort and will converge once the client retries.
    """
    identity = await get_identity_from_auth(request, db)
    enforce_actor_binding(identity, payload.workspace_id)
    project_id = UUID(identity.project_id)
    settings = get_settings()

    server_db = db.get_manager("server")

    # Pre-check immutability to avoid leaking DB trigger errors as 500s.
    existing = await server_db.fetch_one(
        """
        SELECT workspace_id, project_id, alias, repo_id, deleted_at
        FROM {{tables.workspaces}}
        WHERE workspace_id = $1
        """,
        UUID(payload.workspace_id),
    )
    if existing:
        if existing.get("deleted_at") is not None:
            raise HTTPException(
                status_code=410,
                detail="Workspace was deleted. Run 'aw init' or 'aw use' from this repo to re-register.",
            )
        if existing.get("project_id") and existing["project_id"] != project_id:
            raise HTTPException(
                status_code=400,
                detail=f"Workspace {payload.workspace_id} does not belong to this project. "
                "This may indicate a corrupted .aw/workspace.yaml file. Try running 'aw use' from this repo again.",
            )
        if existing.get("alias") and existing["alias"] != payload.alias:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Alias mismatch for workspace {payload.workspace_id} "
                    f"(expected '{existing['alias']}', got '{payload.alias}'). "
                    "Run 'aw init' or 'aw use' from this repo to re-register."
                ),
            )

    # Resolve repo_id without creating partial state in mismatch scenarios.
    canonical_origin = canonicalize_git_url(payload.repo_origin)
    repo_id: UUID
    if existing and existing.get("repo_id"):
        repo_id = existing["repo_id"]

        repo_row = await server_db.fetch_one(
            """
            SELECT canonical_origin
            FROM {{tables.repos}}
            WHERE id = $1 AND project_id = $2 AND deleted_at IS NULL
            """,
            repo_id,
            project_id,
        )
        if not repo_row:
            raise HTTPException(
                status_code=410,
                detail="Workspace repository was deleted. Run 'aw init' or 'aw use' from this repo to re-register.",
            )
        if repo_row.get("canonical_origin") != canonical_origin:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Repo mismatch: workspace is registered with a different repository. "
                    "This may indicate a corrupted .aw/workspace.yaml file. Run 'aw use' from this repo again."
                ),
            )
    else:
        colliding_workspace = await check_alias_collision(
            db, redis, project_id, payload.workspace_id, payload.alias
        )
        if colliding_workspace:
            raise HTTPException(
                status_code=409,
                detail=f"Alias '{payload.alias}' is already used by another workspace in this project. "
                "Please choose a different alias and run 'aw init' or 'aw use' again from this repo.",
            )

        # Ensure repo exists for this project (normalizes to canonical_origin).
        repo_id = await ensure_repo(db, project_id, payload.repo_origin)

    # Upsert workspace record first (SQL), then update presence (Redis; best-effort).
    try:
        await upsert_workspace(
            db,
            workspace_id=payload.workspace_id,
            project_id=project_id,
            repo_id=repo_id,
            alias=payload.alias,
            human_name=payload.human_name or "",
            role=payload.role,
            hostname=payload.hostname,
            workspace_path=payload.workspace_path,
        )
    except QueryError as e:
        if isinstance(e.__cause__, asyncpg.exceptions.UniqueViolationError):
            raise HTTPException(
                status_code=409,
                detail=f"Alias '{payload.alias}' is already used by another workspace in this project. "
                "Please choose a different alias and run 'aw init' or 'aw use' again from this repo.",
            ) from e
        raise

    if payload.current_branch is not None or payload.timezone is not None:
        await server_db.execute(
            """
            UPDATE {{tables.workspaces}}
            SET current_branch = COALESCE($1, current_branch),
                timezone = COALESCE($2, timezone),
                last_seen_at = NOW()
            WHERE workspace_id = $3
            """,
            payload.current_branch,
            payload.timezone,
            UUID(payload.workspace_id),
        )

    project_row = await server_db.fetch_one(
        "SELECT slug FROM {{tables.projects}} WHERE id = $1",
        project_id,
    )
    project_slug = project_row["slug"] if project_row else None

    try:
        await update_agent_presence(
            redis,
            workspace_id=payload.workspace_id,
            alias=payload.alias,
            human_name=payload.human_name or "",
            project_id=str(project_id),
            project_slug=project_slug,
            repo_id=str(repo_id),
            program="aw",
            model=None,
            current_branch=payload.current_branch,
            role=payload.role,
            canonical_origin=canonical_origin,
            timezone=payload.timezone,
            ttl_seconds=settings.presence_ttl_seconds,
        )
    except Exception as e:
        logger.warning(
            "Heartbeat SQL upsert succeeded but presence update failed",
            extra={
                "workspace_id": payload.workspace_id,
                "project_id": str(project_id),
                "error": str(e),
            },
        )

    # Update aweb agent-level presence (best-effort, non-blocking).
    try:
        await update_agent_presence(
            redis,
            agent_id=payload.workspace_id,
            alias=payload.alias,
            project_id=str(project_id),
            ttl_seconds=settings.presence_ttl_seconds,
        )
    except Exception as e:
        logger.warning(
            "Aweb agent presence update failed",
            extra={
                "workspace_id": payload.workspace_id,
                "project_id": str(project_id),
                "error": str(e),
            },
        )

    return WorkspaceHeartbeatResponse(ok=True, workspace_id=payload.workspace_id)


class DeleteWorkspaceResponse(BaseModel):
    """Response for DELETE /v1/workspaces/{workspace_id} endpoint."""

    workspace_id: str
    alias: str
    deleted_at: str


@router.delete("/{workspace_id}", response_model=DeleteWorkspaceResponse)
async def delete_workspace(
    workspace_id: str = Path(..., description="Workspace ID to delete"),
    request: Request = None,
    db: DatabaseInfra = Depends(get_db_infra),
    redis: Redis = Depends(get_redis),
) -> DeleteWorkspaceResponse:
    """Delete an ephemeral workspace and its bound identity."""
    # Validate workspace_id format
    try:
        validated_id = validate_workspace_id(workspace_id)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    identity = await get_identity_from_auth(request, db)
    # Note: No workspace identity check here - any workspace in the project can
    # delete any other workspace. This enables peer cleanup of stale workspaces
    # (whose directories no longer exist and thus can't delete themselves).
    project_id = identity.project_id

    server_db = db.get_manager("server")
    aweb_db = db.get_manager("aweb")

    existing = await server_db.fetch_one(
        """
        SELECT workspace_id, alias, project_id, deleted_at
        FROM {{tables.workspaces}}
        WHERE workspace_id = $1 AND project_id = $2
        """,
        UUID(validated_id),
        UUID(project_id),
    )

    if not existing:
        raise HTTPException(
            status_code=404,
            detail=f"Workspace {workspace_id} not found",
        )

    if existing["deleted_at"] is not None:
        raise HTTPException(
            status_code=404,
            detail=f"Workspace {workspace_id} is already deleted",
        )

    agent_row = await aweb_db.fetch_one(
        """
        SELECT lifetime
        FROM {{tables.agents}}
        WHERE agent_id = $1
          AND project_id = $2
          AND deleted_at IS NULL
        """,
        UUID(validated_id),
        UUID(project_id),
    )
    if agent_row is None:
        raise HTTPException(status_code=409, detail="Workspace is missing its bound identity")
    if str(agent_row.get("lifetime") or "ephemeral") != "ephemeral":
        raise HTTPException(
            status_code=409,
            detail="Workspace deletion is only available for ephemeral identities",
        )

    deleted_at = datetime.now(timezone.utc)
    await server_db.execute(
        """
        UPDATE {{tables.workspaces}}
        SET deleted_at = $2
        WHERE workspace_id = $1
        """,
        validated_id,
        deleted_at,
    )

    # Release all task claims for this workspace.
    # The CASCADE constraint only fires on hard delete, not soft-delete.
    await server_db.execute(
        """
        DELETE FROM {{tables.task_claims}}
        WHERE workspace_id = $1
        """,
        validated_id,
    )

    await clear_workspace_presence(redis, [validated_id])

    # Delete the matching ephemeral identity after the workspace is gone.
    await delete_agent_identity(db, agent_id=validated_id, project_id=project_id)

    return DeleteWorkspaceResponse(
        workspace_id=validated_id,
        alias=existing["alias"],
        deleted_at=deleted_at.isoformat(),
    )


class Claim(BaseModel):
    """A task claim - represents a workspace working on a task.

    The apex (apex_task_ref/apex_title/apex_type) is stored on the claim to avoid
    recursive read-time computation. Titles/types are joined from native tasks.
    """

    task_ref: str
    title: Optional[str] = None
    claimed_at: str
    apex_task_ref: Optional[str] = None
    apex_title: Optional[str] = None
    apex_type: Optional[str] = None


class WorkspaceInfo(BaseModel):
    """Workspace information from database with optional presence data."""

    workspace_id: str
    alias: str
    human_name: Optional[str] = None
    context_kind: Optional[str] = None
    project_id: Optional[str] = None
    project_slug: Optional[str] = None
    program: Optional[str] = None
    model: Optional[str] = None
    repo: Optional[str] = None
    branch: Optional[str] = None
    member_email: Optional[str] = None
    role: Optional[str] = None
    hostname: Optional[str] = None  # For gone workspace detection
    workspace_path: Optional[str] = None  # For gone workspace detection
    apex_task_ref: Optional[str] = None  # Apex from first claim (root of parent chain)
    apex_title: Optional[str] = None
    apex_type: Optional[str] = None
    focus_task_ref: Optional[str] = None
    focus_task_title: Optional[str] = None
    focus_task_type: Optional[str] = None
    focus_updated_at: Optional[str] = None
    status: str  # "active", "idle", "offline"
    last_seen: Optional[str] = None
    deleted_at: Optional[str] = None  # ISO timestamp if soft-deleted
    claims: List[Claim] = []  # All active task claims for this workspace (with apex computed)


class ListWorkspacesResponse(BaseModel):
    """Response for listing workspaces."""

    workspaces: List[WorkspaceInfo]
    has_more: bool = False
    next_cursor: Optional[str] = None


def _title_join(
    alias: str,
    project_col: str,
    task_ref_col: str,
    *,
    include_type: bool = False,
    guard_col: str | None = None,
) -> str:
    """Lateral join resolving title (+ optional type) from native aweb tasks only."""
    select_expr = "t.title, t.task_type AS issue_type" if include_type else "t.title AS title"

    guard_aweb = f"\n                  AND {guard_col} IS NOT NULL" if guard_col else ""

    return f"""
        LEFT JOIN LATERAL (
            SELECT {select_expr}
            FROM server.tasks t
            JOIN server.projects p ON t.project_id = p.id AND p.deleted_at IS NULL
            WHERE t.project_id = {project_col}
              AND p.slug || '-' || t.task_ref_suffix = {task_ref_col}
              AND t.deleted_at IS NULL{guard_aweb}
            LIMIT 1
        ) {alias} ON true"""


def _build_workspace_claims_query(placeholders: str) -> str:
    claim_join = _title_join("claim_info", "c.project_id", "c.task_ref")
    apex_join = _title_join(
        "apex_info",
        "c.project_id",
        "c.apex_task_ref",
        include_type=True,
        guard_col="c.apex_task_ref",
    )
    return f"""
        SELECT
            c.workspace_id,
            c.task_ref AS task_ref,
            c.claimed_at,
            c.apex_task_ref,
            claim_info.title AS claim_title,
            apex_info.title AS apex_title,
            apex_info.issue_type AS apex_type
        FROM {{{{tables.task_claims}}}} c
        {claim_join}
        {apex_join}
        WHERE c.workspace_id IN ({placeholders})
        ORDER BY c.workspace_id, c.claimed_at DESC
    """


def _to_iso(value: Optional[datetime]) -> Optional[str]:
    if not value:
        return None
    return value.isoformat()


def _timestamp(value: Optional[datetime] | Optional[str]) -> float:
    if not value:
        return 0.0
    if isinstance(value, datetime):
        return value.timestamp()
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return 0.0


_TEAM_FOCUS_JOIN = _title_join(
    "focus_issue",
    "w.project_id",
    "w.focus_task_ref",
    include_type=True,
    guard_col="w.focus_task_ref",
)

_TEAM_PARTICIPANT_WORKSPACE_SELECT = f"""
        SELECT
            w.workspace_id,
            w.alias,
            w.human_name,
            CASE
                WHEN w.workspace_type = 'agent' THEN 'repo_worktree'::TEXT
                ELSE w.workspace_type
            END AS context_kind,
            w.current_branch,
            w.project_id,
            w.role,
            w.hostname,
            w.workspace_path,
            w.last_seen_at,
            w.focus_task_ref,
            w.focus_updated_at,
            focus_issue.title AS focus_task_title,
            focus_issue.issue_type AS focus_task_type,
            p.slug AS project_slug,
            r.canonical_origin AS repo,
            COALESCE(cs.claim_count, 0) AS claim_count,
            cs.last_claimed_at,
            w.updated_at
        FROM {{{{tables.workspaces}}}} w
        JOIN {{{{tables.projects}}}} p ON w.project_id = p.id AND p.deleted_at IS NULL
        LEFT JOIN {{{{tables.repos}}}} r ON w.repo_id = r.id AND r.deleted_at IS NULL
        LEFT JOIN claim_stats cs ON cs.workspace_id = w.workspace_id
        {_TEAM_FOCUS_JOIN}
"""


async def _fetch_extra_team_workspace(
    server_db,
    workspace_id: str,
    project_id: str,
    *,
    human_name: str | None,
    repo: str | None,
):
    """Fetch a single workspace by ID for the always_include_workspace_id guarantee."""
    params: list = [uuid_module.UUID(workspace_id), uuid_module.UUID(project_id)]

    query = f"""
        WITH claim_stats AS (
            SELECT workspace_id,
                   COUNT(*) AS claim_count,
                   MAX(claimed_at) AS last_claimed_at
            FROM {{{{tables.task_claims}}}}
            WHERE project_id = $2
            GROUP BY workspace_id
        )
        SELECT *
        FROM (
            {_TEAM_PARTICIPANT_WORKSPACE_SELECT}
            WHERE w.deleted_at IS NULL
        ) participants
        WHERE workspace_id = $1 AND project_id = $2
    """

    if human_name:
        query += f" AND human_name = ${len(params) + 1}"
        params.append(human_name)

    if repo:
        query += f" AND repo = ${len(params) + 1}"
        params.append(repo)

    return await server_db.fetch_one(query, *params)


def _row_to_workspace_info(
    row,
    presence: dict | None,
    workspace_claims: list[Claim],
    *,
    public_reader: bool,
    include_presence: bool,
) -> WorkspaceInfo:
    workspace_id = str(row["workspace_id"])

    # Extract apex from first claim (most recent by claimed_at)
    first_apex_id = workspace_claims[0].apex_task_ref if workspace_claims else None
    first_apex_title = workspace_claims[0].apex_title if workspace_claims else None
    first_apex_type = workspace_claims[0].apex_type if workspace_claims else None

    role = row["role"]
    status = "offline"
    last_seen = _to_iso(row["last_seen_at"])
    program = None
    model = None
    member_email = None
    branch = row["current_branch"]

    if include_presence and presence:
        program = presence.get("program")
        model = presence.get("model")
        member_email = presence.get("member_email")
        branch = presence.get("current_branch") or branch
        role = presence.get("role") or role
        status = presence.get("status") or "active"
        last_seen = presence.get("last_seen") or last_seen

    human_name_value = row["human_name"]
    member_email_value = member_email
    role_value = role
    hostname_value = row["hostname"]
    workspace_path_value = row["workspace_path"]
    if public_reader:
        human_name_value = None
        member_email_value = None
        role_value = None
        hostname_value = None
        workspace_path_value = None

    return WorkspaceInfo(
        workspace_id=workspace_id,
        alias=row["alias"],
        human_name=human_name_value,
        context_kind=row.get("context_kind"),
        project_id=str(row["project_id"]),
        project_slug=row["project_slug"],
        program=program,
        model=model,
        repo=row["repo"],
        branch=branch,
        member_email=member_email_value,
        role=role_value,
        hostname=hostname_value,
        workspace_path=workspace_path_value,
        apex_task_ref=first_apex_id,
        apex_title=first_apex_title,
        apex_type=first_apex_type,
        focus_task_ref=row["focus_task_ref"],
        focus_task_title=row["focus_task_title"],
        focus_task_type=row["focus_task_type"],
        focus_updated_at=_to_iso(row["focus_updated_at"]),
        status=status,
        last_seen=last_seen,
        deleted_at=_to_iso(row.get("deleted_at")),
        claims=workspace_claims,
    )


async def _fetch_presence_map(redis: Redis, workspace_id_strings: list[str]) -> Dict[str, dict]:
    presences = await list_agent_presences_by_workspace_ids(redis, workspace_id_strings)
    return {str(p["workspace_id"]): p for p in presences if p.get("workspace_id")}


async def _fetch_claims_map(server_db, workspace_ids: list) -> Dict[str, List[Claim]]:
    if not workspace_ids:
        return {}
    placeholders = ", ".join(f"${i}" for i in range(1, len(workspace_ids) + 1))
    claim_rows = await server_db.fetch_all(
        _build_workspace_claims_query(placeholders),
        *workspace_ids,
    )
    claims_map: Dict[str, List[Claim]] = {}
    for cr in claim_rows:
        ws_id = str(cr["workspace_id"])
        claim = Claim(
            task_ref=cr["task_ref"],
            title=cr["claim_title"],
            claimed_at=cr["claimed_at"].isoformat() if cr["claimed_at"] else "",
            apex_task_ref=cr["apex_task_ref"],
            apex_title=cr["apex_title"],
            apex_type=cr["apex_type"],
        )
        if ws_id not in claims_map:
            claims_map[ws_id] = []
        claims_map[ws_id].append(claim)
    return claims_map


@router.get("", response_model=ListWorkspacesResponse)
async def list_workspaces(
    request: Request,
    human_name: Optional[str] = Query(None, description="Filter by workspace owner", max_length=64),
    repo: Optional[str] = Query(
        None, description="Filter by repo canonical origin", max_length=255
    ),
    alias: Optional[str] = Query(None, description="Filter by workspace alias", max_length=64),
    hostname: Optional[str] = Query(None, description="Filter by machine hostname", max_length=255),
    include_deleted: bool = Query(False, description="Include soft-deleted workspaces"),
    include_claims: bool = Query(False, description="Include active task claims"),
    include_presence: bool = Query(True, description="Include Redis presence data"),
    limit: Optional[int] = Query(None, description="Maximum items per page", ge=1, le=200),
    cursor: Optional[str] = Query(None, description="Pagination cursor from previous response"),
    db_infra: DatabaseInfra = Depends(get_db_infra),
    redis: Redis = Depends(get_redis),
) -> ListWorkspacesResponse:
    """
    List all registered workspaces from database with cursor-based pagination.

    Returns workspace information with optional presence/claim enrichment.
    Workspaces without active presence show status='offline'.
    Deleted workspaces are excluded by default (use include_deleted=true to show).

    Tenant isolation:
    - Always derived from authentication (project API key or proxy-injected internal context).

    Args:
        limit: Maximum number of workspaces to return (default 50, max 200).
        cursor: Pagination cursor from previous response for fetching next page.

    Returns:
        List of workspaces ordered by most recently updated first.
        Includes has_more and next_cursor for pagination.

    Use /v1/workspaces/online for only currently active workspaces.
    """
    project_id = await get_project_from_auth(request, db_infra)
    public_reader = is_public_reader(request)

    # Validate pagination params
    try:
        validated_limit, cursor_data = validate_pagination_params(limit, cursor)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    server_db = db_infra.get_manager("server")

    # Build query with optional filters
    query = (
        """
        SELECT
            w.workspace_id,
            w.alias,
            w.human_name,
            w.current_branch,
            w.project_id,
            w.role,
            w.hostname,
            w.workspace_path,
            w.last_seen_at,
            w.updated_at,
            w.deleted_at,
            w.focus_task_ref,
            w.focus_updated_at,
            focus_issue.title AS focus_task_title,
            focus_issue.issue_type AS focus_task_type,
            p.slug as project_slug,
            r.canonical_origin as repo
        FROM {{tables.workspaces}} w
        JOIN {{tables.projects}} p ON w.project_id = p.id AND p.deleted_at IS NULL
        LEFT JOIN {{tables.repos}} r ON w.repo_id = r.id AND r.deleted_at IS NULL
        """
        + _title_join(
            "focus_issue",
            "w.project_id",
            "w.focus_task_ref",
            include_type=True,
            guard_col="w.focus_task_ref",
        )
        + """
        WHERE 1=1
    """
    )
    params: list = []
    param_idx = 1

    query += f" AND w.project_id = ${param_idx}"
    params.append(uuid_module.UUID(project_id))
    param_idx += 1

    if human_name:
        query += f" AND w.human_name = ${param_idx}"
        params.append(human_name)
        param_idx += 1

    if repo:
        if not is_valid_canonical_origin(repo):
            raise HTTPException(
                status_code=422,
                detail=f"Invalid repo format: {repo[:50]}",
            )
        query += f" AND r.canonical_origin = ${param_idx}"
        params.append(repo)
        param_idx += 1

    if alias:
        if not is_valid_alias(alias):
            raise HTTPException(
                status_code=422,
                detail="Invalid alias: must be alphanumeric with hyphens/underscores, 1-64 chars",
            )
        query += f" AND w.alias = ${param_idx}"
        params.append(alias)
        param_idx += 1

    if hostname:
        # Validate hostname (same as RegisterWorkspaceRequest)
        if "\x00" in hostname or any(ord(c) < 32 for c in hostname):
            raise HTTPException(
                status_code=422,
                detail="Invalid hostname: contains null bytes or control characters",
            )
        query += f" AND w.hostname = ${param_idx}"
        params.append(hostname)
        param_idx += 1

    # Filter deleted workspaces by default
    if not include_deleted:
        query += " AND w.deleted_at IS NULL"

    # Apply cursor (updated_at < cursor_timestamp for DESC order)
    if cursor_data and "updated_at" in cursor_data:
        try:
            cursor_timestamp = datetime.fromisoformat(cursor_data["updated_at"])
        except (ValueError, TypeError) as e:
            raise HTTPException(status_code=422, detail=f"Invalid cursor timestamp: {e}")
        query += f" AND w.updated_at < ${param_idx}"
        params.append(cursor_timestamp)
        param_idx += 1

    query += " ORDER BY w.updated_at DESC"

    # Fetch limit + 1 to detect has_more
    query += f" LIMIT ${param_idx}"
    params.append(validated_limit + 1)
    param_idx += 1

    rows = await server_db.fetch_all(query, *params)

    # Check if there are more results
    has_more = len(rows) > validated_limit
    rows = rows[:validated_limit]  # Trim to requested limit

    workspace_ids = [row["workspace_id"] for row in rows]  # UUIDs from database
    workspace_id_strings = [str(ws_id) for ws_id in workspace_ids]

    presence_map: Dict[str, dict] = {}
    if include_presence and workspace_id_strings:
        presence_map = await _fetch_presence_map(redis, workspace_id_strings)

    claims_map: Dict[str, List[Claim]] = {}
    if include_claims and workspace_ids:
        claims_map = await _fetch_claims_map(server_db, workspace_ids)

    workspaces: List[WorkspaceInfo] = []
    for row in rows:
        workspace_claims = claims_map.get(str(row["workspace_id"]), []) if include_claims else []
        workspaces.append(
            _row_to_workspace_info(
                row,
                presence_map.get(str(row["workspace_id"])),
                workspace_claims,
                public_reader=public_reader,
                include_presence=include_presence,
            )
        )

    # Generate next_cursor if there are more results
    next_cursor = None
    if has_more and rows:
        last_row = rows[-1]
        next_cursor = encode_cursor({"updated_at": last_row["updated_at"].isoformat()})

    return ListWorkspacesResponse(workspaces=workspaces, has_more=has_more, next_cursor=next_cursor)


@router.get("/team", response_model=ListWorkspacesResponse)
async def list_team_workspaces(
    request: Request,
    human_name: Optional[str] = Query(None, description="Filter by workspace owner", max_length=64),
    repo: Optional[str] = Query(
        None, description="Filter by repo canonical origin", max_length=255
    ),
    include_claims: bool = Query(True, description="Include active task claims"),
    include_presence: bool = Query(True, description="Include Redis presence data"),
    only_with_claims: bool = Query(True, description="Only return workspaces with active claims"),
    always_include_workspace_id: Optional[str] = Query(
        None,
        description="Ensure a workspace is included even if filtered out",
    ),
    limit: int = Query(
        TEAM_STATUS_DEFAULT_LIMIT,
        ge=1,
        le=TEAM_STATUS_MAX_LIMIT,
        description="Maximum workspaces to return",
    ),
    db_infra: DatabaseInfra = Depends(get_db_infra),
    redis: Redis = Depends(get_redis),
) -> ListWorkspacesResponse:
    """
    List a bounded team-status view of workspaces for coordination.

    This endpoint is optimized for CLI usage and always returns a limited,
    prioritized set of workspaces.
    """
    project_id = await get_project_from_auth(request, db_infra)
    public_reader = is_public_reader(request)

    server_db = db_infra.get_manager("server")

    params: list = [uuid_module.UUID(project_id)]
    param_idx = 2
    claim_stats_where = ""
    claim_stats_where = "WHERE project_id = $1"

    query = f"""
        WITH claim_stats AS (
            SELECT workspace_id,
                   COUNT(*) AS claim_count,
                   MAX(claimed_at) AS last_claimed_at
            FROM {{{{tables.task_claims}}}}
            {claim_stats_where}
            GROUP BY workspace_id
        ),
        participants AS (
            {_TEAM_PARTICIPANT_WORKSPACE_SELECT}
            WHERE w.deleted_at IS NULL
        )
        SELECT *
        FROM participants
        WHERE 1=1
    """

    query += " AND project_id = $1"

    if human_name:
        query += f" AND human_name = ${param_idx}"
        params.append(human_name)
        param_idx += 1

    if repo:
        if not is_valid_canonical_origin(repo):
            raise HTTPException(
                status_code=422,
                detail=f"Invalid repo format: {repo[:50]}",
            )
        query += f" AND repo = ${param_idx}"
        params.append(repo)
        param_idx += 1

    if only_with_claims:
        query += " AND claim_count > 0"

    candidate_limit = limit
    if include_presence:
        candidate_limit = min(
            limit * TEAM_STATUS_CANDIDATE_MULTIPLIER,
            TEAM_STATUS_CANDIDATE_MAX,
        )

    query += """
        ORDER BY
            (claim_count > 0) DESC,
            last_seen_at DESC NULLS LAST,
            last_claimed_at DESC NULLS LAST,
            alias ASC
    """
    query += f" LIMIT ${param_idx}"
    params.append(candidate_limit)

    rows = await server_db.fetch_all(query, *params)

    if always_include_workspace_id:
        try:
            validated_id = validate_workspace_id(always_include_workspace_id)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))

        if validated_id not in {str(row["workspace_id"]) for row in rows}:
            extra_row = await _fetch_extra_team_workspace(
                server_db,
                validated_id,
                project_id,
                human_name=human_name,
                repo=repo,
            )
            if extra_row:
                rows.append(extra_row)

    workspace_ids = [row["workspace_id"] for row in rows]
    workspace_id_strings = [str(ws_id) for ws_id in workspace_ids]

    presence_map: Dict[str, dict] = {}
    if include_presence and workspace_id_strings:
        presence_map = await _fetch_presence_map(redis, workspace_id_strings)

    claims_map: Dict[str, List[Claim]] = {}
    if include_claims and workspace_ids:
        claims_map = await _fetch_claims_map(server_db, workspace_ids)

    entries: List[tuple[WorkspaceInfo, int, float, float, int, int]] = []
    for row in rows:
        workspace_id = str(row["workspace_id"])
        presence = presence_map.get(workspace_id) if include_presence else None
        workspace_claims = claims_map.get(workspace_id, []) if include_claims else []

        workspace_info = _row_to_workspace_info(
            row,
            presence,
            workspace_claims,
            public_reader=public_reader,
            include_presence=include_presence,
        )

        claim_count = int(row["claim_count"] or 0)
        entries.append(
            (
                workspace_info,
                1 if claim_count > 0 else 0,
                _timestamp(workspace_info.last_seen),
                _timestamp(row["last_claimed_at"]),
                1 if presence is not None else 0,
                claim_count,
            )
        )

    entries.sort(
        key=lambda item: (
            -item[1],
            -item[4],
            -item[2],
            -item[3],
            item[0].alias,
        )
    )

    workspaces = [entry[0] for entry in entries][:limit]

    # /team endpoint doesn't support cursor-based pagination (uses complex sorting)
    return ListWorkspacesResponse(workspaces=workspaces, has_more=False)


@router.get("/online", response_model=ListWorkspacesResponse)
async def list_online_workspaces(
    request: Request,
    human_name: Optional[str] = Query(None, description="Filter by workspace owner", max_length=64),
    redis: Redis = Depends(get_redis),
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> ListWorkspacesResponse:
    """
    List only currently online workspaces (active presence in Redis).

    This is a filtered view showing workspaces with recent activity.
    Presence expires after ~5 minutes of inactivity.

    For all registered workspaces (including offline), use GET /v1/workspaces.
    """
    project_id = await get_project_from_auth(request, db_infra)
    public_reader = is_public_reader(request)

    presences = await list_agent_presences(redis)

    workspaces: List[WorkspaceInfo] = []
    for presence in presences:
        workspace_id = presence.get("workspace_id")
        alias = presence.get("alias")
        if not workspace_id or not alias:
            continue

        if presence.get("project_id") != project_id:
            continue

        # Filter by human_name if specified
        if human_name and presence.get("human_name") != human_name:
            continue

        workspaces.append(
            WorkspaceInfo(
                workspace_id=workspace_id,
                alias=alias,
                human_name=presence.get("human_name"),
                project_slug=presence.get("project_slug"),
                program=presence.get("program"),
                model=presence.get("model"),
                repo=None,  # Not stored in presence
                branch=presence.get("current_branch"),
                member_email=None if public_reader else presence.get("member_email"),
                role=None if public_reader else (presence.get("role") or None),
                status=presence.get("status") or "unknown",
                last_seen=presence.get("last_seen") or "",
            )
        )

    # Sort by last_seen descending (most recent first)
    workspaces.sort(key=lambda w: w.last_seen or "", reverse=True)

    # /online endpoint returns all currently online workspaces (no pagination needed)
    return ListWorkspacesResponse(workspaces=workspaces, has_more=False)
