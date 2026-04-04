from __future__ import annotations

import os
from datetime import datetime, timezone
from uuid import UUID

import asyncpg.exceptions
from httpx import ASGITransport
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aweb.address_reachability import normalize_address_reachability
from aweb.aweb_introspection import get_identity_from_auth
from aweb.awid import CachedRegistryClient, RegistryClient
from aweb.auth import validate_project_slug
from aweb.bootstrap import AliasExhaustedError, BootstrapIdentityResult, bootstrap_identity
from aweb.coordination.project_registry import ensure_server_project_row
from aweb.coordination.routes.project_instructions import get_active_project_instructions
from aweb.coordination.routes.project_roles import get_active_project_roles
from aweb.coordination.roles import (
    ROLE_MAX_LENGTH,
    role_to_alias_prefix,
)
from aweb.coordination.routes.repos import canonicalize_git_url, extract_repo_name
from aweb.db import DatabaseInfra, get_db_infra
from aweb.input_validation import is_valid_alias, is_valid_human_name
from aweb.names import CLASSIC_NAMES
from aweb.namespace_registry import ensure_dns_namespace_registered, validate_subdomain_label
from aweb.config import get_awid_registry_url, is_local_awid_registry_url
from aweb.rate_limit import enforce_init_rate_limit
from aweb.redis_client import get_redis
from aweb.role_name_compat import normalize_optional_role_name, resolve_role_name_aliases

router = APIRouter(prefix="/v1/workspaces/init", tags=["workspaces"])
bootstrap_router = APIRouter(prefix="/api/v1", tags=["bootstrap"])


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _server_url(request: Request) -> str:
    return str(request.base_url).rstrip("/")


def _registry_client_for_request(request: Request) -> RegistryClient:
    registry_url = get_awid_registry_url()
    redis = getattr(request.app.state, "redis", None)
    if is_local_awid_registry_url(registry_url):
        client_class = CachedRegistryClient if redis is not None else RegistryClient
        client_kwargs = {
            "registry_url": registry_url,
            "base_url": _server_url(request),
            "transport": ASGITransport(app=request.app),
        }
        if redis is not None:
            return client_class(redis_client=redis, **client_kwargs)
        return client_class(**client_kwargs)
    if redis is not None:
        return CachedRegistryClient(registry_url=registry_url, redis_client=redis)
    return RegistryClient(registry_url=registry_url)


def _managed_namespace_domain(namespace_slug: str) -> str:
    managed_domain = (os.environ.get("AWEB_MANAGED_DOMAIN") or "").strip().lower()
    if managed_domain:
        return f"{namespace_slug}.{managed_domain}"
    return namespace_slug


def _namespace_slug_from_domain(domain: str) -> str:
    normalized = (domain or "").strip().lower().rstrip(".")
    managed_domain = (os.environ.get("AWEB_MANAGED_DOMAIN") or "").strip().lower()
    suffix = f".{managed_domain}" if managed_domain else ""
    if suffix and normalized.endswith(suffix):
        return normalized[: -len(suffix)]
    return normalized


def _namespace_unavailable() -> HTTPException:
    return HTTPException(
        status_code=503,
        detail="Permanent identity bootstrap is unavailable on this server",
    )


def _normalize_requested_namespace_slug(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return validate_subdomain_label(value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _translate_bootstrap_value_error(exc: ValueError) -> HTTPException:
    detail = str(exc)
    if detail == "Managed namespaces require AWEB_MANAGED_DOMAIN to be configured":
        return _namespace_unavailable()
    return HTTPException(status_code=422, detail=detail)


class _BootstrapBaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alias: str | None = Field(default=None, min_length=1, max_length=64)
    name: str | None = Field(default=None, min_length=1, max_length=64)
    human_name: str = Field(default="", max_length=64)
    agent_type: str = Field(default="agent", max_length=32)
    lifetime: str = Field(default="ephemeral", pattern="^(persistent|ephemeral)$")
    custody: str | None = Field(default=None, pattern="^(self|custodial)$")
    address_reachability: str | None = Field(default=None, max_length=32)
    did: str | None = Field(default=None, max_length=512)
    public_key: str | None = Field(default=None, max_length=512)

    @field_validator("alias")
    @classmethod
    def _validate_alias(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        if not is_valid_alias(v):
            raise ValueError("Invalid alias format")
        return v

    @field_validator("name")
    @classmethod
    def _validate_name(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        if not is_valid_alias(v):
            raise ValueError("Invalid name format")
        return v

    @field_validator("human_name")
    @classmethod
    def _validate_human_name(cls, v: str) -> str:
        v = (v or "").strip()
        if v and not is_valid_human_name(v):
            raise ValueError("Invalid human_name format")
        return v

    @field_validator("address_reachability")
    @classmethod
    def _validate_address_reachability(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return normalize_address_reachability(v)

    @model_validator(mode="after")
    def _validate_handle_shape(self):
        if self.alias is not None and self.name is not None:
            raise ValueError("provide either alias or name, not both")
        if self.lifetime == "persistent":
            if self.name is None:
                raise ValueError("name is required for persistent identities")
        elif self.name is not None:
            raise ValueError("name is only valid for persistent identities")
        return self


class CreateProjectRequest(_BootstrapBaseModel):
    """Create a project, attach its namespace, and bootstrap the first identity."""

    project_slug: str = Field(..., max_length=256)
    namespace_slug: str | None = Field(default=None, min_length=1, max_length=63)

    @field_validator("project_slug")
    @classmethod
    def _validate_project_slug(cls, v: str) -> str:
        return validate_project_slug((v or "").strip())

    @field_validator("namespace_slug")
    @classmethod
    def _validate_namespace_slug(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return validate_subdomain_label(v)

    @model_validator(mode="after")
    def _validate_identity_presence(self):
        if self.lifetime == "persistent" and self.name is None:
            raise ValueError("name is required for persistent identities")
        return self


class InitRequest(_BootstrapBaseModel):
    """Bootstrap an aweb identity and, optionally, an aweb workspace."""

    project_slug: str = Field(default="", max_length=256)
    # Compatibility-only input from older callers. The authenticated project
    # authority is canonical; mismatched names are rejected in the handler.
    project_name: str = Field(default="", max_length=256)
    namespace: str | None = Field(default=None, min_length=1, max_length=63)
    namespace_slug: str | None = Field(default=None, min_length=1, max_length=63)

    project_id: str | None = Field(default=None, max_length=36)
    repo_origin: str | None = Field(default=None, max_length=2048)
    role: str | None = Field(default=None, max_length=ROLE_MAX_LENGTH)
    role_name: str | None = Field(default=None, max_length=ROLE_MAX_LENGTH)
    hostname: str = Field(default="", max_length=255)
    workspace_path: str = Field(default="", max_length=4096)

    @model_validator(mode="before")
    @classmethod
    def _normalize_namespace_slug(cls, values):
        if isinstance(values, dict):
            ns_slug = values.get("namespace_slug")
            if ns_slug and not values.get("namespace"):
                values["namespace"] = ns_slug
        return values

    @field_validator("project_slug")
    @classmethod
    def _validate_project_slug(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            return ""
        return validate_project_slug(v)

    @field_validator("namespace")
    @classmethod
    def _validate_namespace(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return validate_subdomain_label(v)

    @field_validator("namespace_slug")
    @classmethod
    def _validate_namespace_slug(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return validate_subdomain_label(v)

    @field_validator("role", "role_name")
    @classmethod
    def _validate_role(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return normalize_optional_role_name(v)

    @model_validator(mode="after")
    def _sync_role_aliases(self):
        resolved = resolve_role_name_aliases(role=self.role, role_name=self.role_name) or "agent"
        self.role = resolved
        self.role_name = resolved
        return self

    @field_validator("project_id")
    @classmethod
    def _validate_project_id(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        try:
            return str(UUID(v))
        except ValueError as exc:
            raise ValueError("project_id must be a valid UUID") from exc

    @field_validator("hostname")
    @classmethod
    def _validate_hostname(cls, v: str) -> str:
        v = (v or "").strip()
        if v and ("\x00" in v or any(ord(c) < 32 for c in v)):
            raise ValueError(
                "hostname contains invalid characters (null bytes or control characters)"
            )
        return v

    @field_validator("workspace_path")
    @classmethod
    def _validate_workspace_path(cls, v: str) -> str:
        v = (v or "").strip()
        if v and ("\x00" in v or any(ord(c) < 32 and c not in "\t\n" for c in v)):
            raise ValueError(
                "workspace_path contains invalid characters (null bytes or control characters)"
            )
        return v


class InitResponse(BaseModel):
    status: str = "ok"
    created_at: str
    api_key: str
    project_id: str
    project_slug: str
    identity_id: str
    agent_id: str
    repo_id: str | None = None
    canonical_origin: str | None = None
    workspace_id: str | None = None
    alias: str | None = None
    name: str | None = None
    created: bool = False
    workspace_created: bool = False
    did: str | None = None
    stable_id: str | None = None
    custody: str | None = None
    lifetime: str = "ephemeral"
    namespace: str | None = None
    namespace_slug: str | None = None
    address: str | None = None
    address_reachability: str | None = None
    server_url: str | None = None


async def _resolve_aweb_project(
    db_infra: DatabaseInfra, *, project_id: str
) -> tuple[str | None, str, str, str | None, str | None]:
    """Look up a project in aweb.projects by ID."""
    aweb_db = db_infra.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT tenant_id, slug, name, owner_type, owner_ref
        FROM {{tables.projects}}
        WHERE project_id = $1 AND deleted_at IS NULL
        """,
        UUID(project_id),
    )
    if not row:
        raise HTTPException(status_code=404, detail="project_not_found: unknown project_id")
    tid = row.get("tenant_id")
    owner_type = (row.get("owner_type") or "").strip() or None
    owner_ref = (row.get("owner_ref") or "").strip() or None
    return (
        str(tid) if tid else None,
        row["slug"],
        (row.get("name") or "").strip() or row["slug"],
        owner_type,
        owner_ref,
    )


async def _lookup_attached_namespace(
    db_infra: DatabaseInfra, *, project_id: str
) -> tuple[str, str] | None:
    aweb_db = db_infra.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT domain
        FROM {{tables.dns_namespaces}}
        WHERE scope_id = $1
          AND namespace_type = 'managed'
          AND deleted_at IS NULL
        ORDER BY created_at
        LIMIT 1
        """,
        UUID(project_id),
    )
    if row is None:
        return None
    domain = (row.get("domain") or "").strip().lower()
    if not domain:
        return None
    return _namespace_slug_from_domain(domain), domain


async def _ensure_project_namespace(
    db_infra: DatabaseInfra,
    *,
    project_id: str,
    project_slug: str,
    requested_namespace_slug: str | None,
) -> tuple[str, str]:
    aweb_db = db_infra.get_manager("aweb")
    existing = await _lookup_attached_namespace(db_infra, project_id=project_id)
    if existing is not None:
        existing_slug, existing_domain = existing
        if requested_namespace_slug is not None:
            namespace_slug = _normalize_requested_namespace_slug(requested_namespace_slug)
        else:
            namespace_slug = existing_slug
        if existing_slug != namespace_slug:
            raise HTTPException(
                status_code=409,
                detail="namespace_slug_conflict: project already has a different attached namespace",
        )
        return existing_slug, existing_domain

    namespace_slug = _normalize_requested_namespace_slug(requested_namespace_slug or project_slug)

    namespace_domain = _managed_namespace_domain(namespace_slug)
    claimed = await aweb_db.fetch_one(
        """
        SELECT scope_id
        FROM {{tables.dns_namespaces}}
        WHERE domain = $1 AND deleted_at IS NULL
        """,
        namespace_domain,
    )
    if claimed is not None:
        scope_id = claimed.get("scope_id")
        if scope_id is None or str(scope_id) != project_id:
            raise HTTPException(status_code=409, detail="namespace_slug_conflict: namespace already claimed")

    try:
        namespace = await ensure_dns_namespace_registered(
            aweb_db=aweb_db,
            domain=namespace_domain,
            controller_did=None,
            namespace_type="managed",
            scope_id=project_id,
        )
    except asyncpg.UniqueViolationError:
        claimed = await aweb_db.fetch_one(
            """
            SELECT scope_id
            FROM {{tables.dns_namespaces}}
            WHERE domain = $1 AND deleted_at IS NULL
            """,
            namespace_domain,
        )
        if claimed is None:
            raise
        scope_id = claimed.get("scope_id")
        if scope_id is None or str(scope_id) != project_id:
            raise HTTPException(status_code=409, detail="namespace_slug_conflict: namespace already claimed")
        return namespace_slug, namespace_domain
    return namespace_slug, namespace["domain"]


def _response_identity_handle(payload: _BootstrapBaseModel) -> tuple[str | None, str | None]:
    alias = (payload.alias or "").strip() or None
    name = (payload.name or "").strip() or None
    if payload.lifetime == "persistent":
        if not name:
            raise HTTPException(status_code=422, detail="name is required for persistent identities")
        return name, name
    if name:
        raise HTTPException(status_code=422, detail="name is only valid for persistent identities")
    return alias, None


def _identity_address(
    *,
    namespace_domain: str,
    namespace_slug: str,
    handle: str,
    explicit_address: str | None,
) -> str:
    if explicit_address:
        return explicit_address
    if namespace_domain and namespace_domain != namespace_slug:
        return f"{namespace_domain}/{handle}"
    return f"{namespace_slug}/{handle}"


def _build_init_response(
    *,
    request: Request,
    identity: BootstrapIdentityResult,
    namespace_slug: str,
    namespace_domain: str,
    response_name: str | None,
    repo_id: str | None = None,
    canonical_origin: str | None = None,
    workspace_id: str | None = None,
    workspace_created: bool = False,
) -> InitResponse:
    handle = response_name or identity.alias
    return InitResponse(
        created_at=_now_iso(),
        api_key=identity.api_key,
        project_id=identity.project_id,
        project_slug=identity.project_slug,
        identity_id=identity.agent_id,
        agent_id=identity.agent_id,
        repo_id=repo_id,
        canonical_origin=canonical_origin,
        workspace_id=workspace_id,
        alias=identity.alias if identity.lifetime == "ephemeral" else None,
        name=response_name,
        created=identity.created,
        workspace_created=workspace_created,
        did=identity.did,
        stable_id=identity.stable_id,
        custody=identity.custody,
        lifetime=identity.lifetime,
        namespace=namespace_domain,
        namespace_slug=namespace_slug,
        address=(
            _identity_address(
                namespace_domain=namespace_domain,
                namespace_slug=namespace_slug,
                handle=handle,
                explicit_address=identity.address,
            )
            if handle
            else None
        ),
        address_reachability=identity.address_reachability,
        server_url=_server_url(request),
    )


async def _suggest_name_prefix_for_project(db_infra: DatabaseInfra, *, project_id: str) -> str:
    aweb_db = db_infra.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        """
        SELECT alias
        FROM {{tables.agents}}
        WHERE project_id = $1 AND deleted_at IS NULL
        ORDER BY alias
        """,
        UUID(project_id),
    )

    used_prefixes: set[str] = set()
    for row in rows:
        alias = (row.get("alias") or "").strip()
        if not alias:
            continue
        parts = alias.split("-")
        if len(parts) >= 2 and parts[1].isdigit():
            prefix = f"{parts[0]}-{parts[1]}".lower()
        else:
            prefix = parts[0].lower()
        if prefix:
            used_prefixes.add(prefix)

    for name in CLASSIC_NAMES:
        if name not in used_prefixes:
            return name

    for num in range(1, 100):
        for name in CLASSIC_NAMES:
            numbered = f"{name}-{num:02d}"
            if numbered not in used_prefixes:
                return numbered

    raise HTTPException(
        status_code=409,
        detail=f"All name prefixes are taken (tried {len(CLASSIC_NAMES)} names × 100 variants).",
    )


@bootstrap_router.post("/create-project", response_model=InitResponse)
async def create_project(
    request: Request,
    payload: CreateProjectRequest,
    db_infra: DatabaseInfra = Depends(get_db_infra),
    redis=Depends(get_redis),
) -> InitResponse:
    """Create a project, attach its namespace, and bootstrap the first identity."""
    await enforce_init_rate_limit(request, redis)

    aweb_db = db_infra.get_manager("aweb")
    server_db = db_infra.get_manager("server")

    existing = await aweb_db.fetch_one(
        """
        SELECT project_id
        FROM {{tables.projects}}
        WHERE slug = $1 AND deleted_at IS NULL
        """,
        payload.project_slug,
    )
    if existing is not None:
        raise HTTPException(status_code=409, detail="project_slug_conflict: project already exists")

    bootstrap_alias, response_name = _response_identity_handle(payload)
    requested_namespace_slug = payload.namespace_slug or payload.project_slug
    requested_namespace_domain = _managed_namespace_domain(requested_namespace_slug)

    try:
        identity = await bootstrap_identity(
            db_infra,
            project_slug=payload.project_slug,
            project_name=payload.project_slug,
            alias=bootstrap_alias,
            human_name=payload.human_name or "",
            agent_type=payload.agent_type,
            did=payload.did,
            public_key=payload.public_key,
            custody=payload.custody,
            lifetime=payload.lifetime,
            namespace=requested_namespace_slug if payload.lifetime == "persistent" else None,
            address_reachability=payload.address_reachability,
            registry_client=_registry_client_for_request(request)
            if payload.lifetime == "persistent"
            else None,
            registry_server_url=_server_url(request) if payload.lifetime == "persistent" else None,
        )
    except AliasExhaustedError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except asyncpg.exceptions.UniqueViolationError as exc:
        namespace_claim = await aweb_db.fetch_one(
            """
            SELECT scope_id
            FROM {{tables.dns_namespaces}}
            WHERE domain = $1 AND deleted_at IS NULL
            """,
            requested_namespace_domain,
        )
        if namespace_claim is not None:
            raise HTTPException(status_code=409, detail="namespace_slug_conflict: namespace already claimed") from exc
        raise HTTPException(status_code=409, detail="project_slug_conflict: project already exists") from exc
    except ValueError as exc:
        raise _translate_bootstrap_value_error(exc) from exc

    namespace_slug, namespace_domain = await _ensure_project_namespace(
        db_infra,
        project_id=identity.project_id,
        project_slug=identity.project_slug,
        requested_namespace_slug=requested_namespace_slug,
    )
    async with server_db.transaction() as tx:
        await ensure_server_project_row(
            server_db=tx,
            aweb_db=aweb_db,
            project_id=identity.project_id,
            project_slug=identity.project_slug,
            project_name=identity.project_name or "",
        )
        await get_active_project_roles(tx, identity.project_id, bootstrap_if_missing=True)
        await get_active_project_instructions(tx, identity.project_id, bootstrap_if_missing=True)
        await tx.execute(
            """
            INSERT INTO {{tables.workspaces}}
                (workspace_id, project_id, repo_id, alias, human_name, role, hostname, workspace_path, workspace_type, last_seen_at)
            VALUES ($1, $2, NULL, $3, $4, NULL, NULL, NULL, 'manual', NOW())
            ON CONFLICT (workspace_id) DO UPDATE SET
                human_name = EXCLUDED.human_name,
                deleted_at = NULL,
                workspace_type = 'manual',
                last_seen_at = NOW(),
                updated_at = NOW()
            """,
            UUID(identity.agent_id),
            UUID(identity.project_id),
            identity.alias,
            payload.human_name or "",
        )

    return _build_init_response(
        request=request,
        identity=identity,
        namespace_slug=namespace_slug,
        namespace_domain=namespace_domain,
        response_name=response_name,
        workspace_id=identity.agent_id,
        workspace_created=True,
    )


@router.post("", response_model=InitResponse)
async def init(
    request: Request,
    payload: InitRequest,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> InitResponse:
    """Initialize a local workspace into an existing project using project authority."""
    canonical_origin: str | None = None
    if payload.repo_origin is not None:
        canonical_origin = canonicalize_git_url(payload.repo_origin)

    try:
        identity_ctx = await get_identity_from_auth(request, db_infra)
    except HTTPException as exc:
        if exc.status_code == 401:
            raise HTTPException(status_code=401, detail="Project authority required") from exc
        raise

    auth_project_id = (identity_ctx.project_id or "").strip()
    if not auth_project_id:
        raise HTTPException(status_code=401, detail="Project authority required")

    tenant_id, project_slug, project_name, owner_type, owner_ref = await _resolve_aweb_project(
        db_infra,
        project_id=auth_project_id,
    )
    if payload.project_id and payload.project_id != auth_project_id:
        raise HTTPException(
            status_code=403,
            detail="project_authority_mismatch: project_id does not match credential",
        )
    if payload.project_slug and payload.project_slug != project_slug:
        raise HTTPException(
            status_code=403,
            detail="project_authority_mismatch: project_slug does not match credential",
        )
    requested_project_name = (payload.project_name or "").strip()
    if requested_project_name and requested_project_name != project_name:
        raise HTTPException(
            status_code=403,
            detail="project_authority_mismatch: project_name does not match credential",
        )

    bootstrap_alias, response_name = _response_identity_handle(payload)
    if bootstrap_alias is None and canonical_origin is not None:
        prefix = await _suggest_name_prefix_for_project(db_infra, project_id=auth_project_id)
        bootstrap_alias = f"{prefix}-{role_to_alias_prefix(payload.role)}"

    namespace_slug, namespace_domain = await _ensure_project_namespace(
        db_infra,
        project_id=auth_project_id,
        project_slug=project_slug,
        requested_namespace_slug=payload.namespace_slug or payload.namespace,
    )

    try:
        identity: BootstrapIdentityResult = await bootstrap_identity(
            db_infra,
            project_slug=project_slug,
            project_name=project_name,
            project_id=auth_project_id,
            tenant_id=tenant_id,
            owner_type=owner_type,
            owner_ref=owner_ref,
            alias=bootstrap_alias,
            human_name=payload.human_name or "",
            agent_type=payload.agent_type,
            did=payload.did,
            public_key=payload.public_key,
            custody=payload.custody,
            lifetime=payload.lifetime,
            namespace=namespace_slug if payload.lifetime == "persistent" else None,
            address_reachability=payload.address_reachability,
            registry_client=_registry_client_for_request(request)
            if payload.lifetime == "persistent"
            else None,
            registry_server_url=_server_url(request) if payload.lifetime == "persistent" else None,
        )
    except AliasExhaustedError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise _translate_bootstrap_value_error(exc) from exc

    if canonical_origin is None:
        return _build_init_response(
            request=request,
            identity=identity,
            namespace_slug=namespace_slug,
            namespace_domain=namespace_domain,
            response_name=response_name,
        )

    server_db = db_infra.get_manager("server")
    repo_name = extract_repo_name(canonical_origin)
    workspace_created = False

    async with server_db.transaction() as tx:
        await ensure_server_project_row(
            server_db=tx,
            aweb_db=db_infra.get_manager("aweb"),
            project_id=identity.project_id,
            project_slug=identity.project_slug,
            project_name=identity.project_name or "",
        )

        repo = await tx.fetch_one(
            """
            INSERT INTO {{tables.repos}} (project_id, origin_url, canonical_origin, name)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (project_id, canonical_origin)
            DO UPDATE SET origin_url = EXCLUDED.origin_url, deleted_at = NULL
            RETURNING id
            """,
            UUID(identity.project_id),
            payload.repo_origin,
            canonical_origin,
            repo_name,
        )
        repo_id = str(repo["id"])

        existing = await tx.fetch_one(
            """
            SELECT
                w.workspace_id,
                w.repo_id,
                w.alias,
                r.canonical_origin AS existing_canonical_origin
            FROM {{tables.workspaces}} w
            LEFT JOIN {{tables.repos}} r ON w.repo_id = r.id
            WHERE w.workspace_id = $1 AND w.project_id = $2
            """,
            UUID(identity.agent_id),
            UUID(identity.project_id),
        )

        if existing is None:
            workspace_created = True
            await tx.execute(
                """
                INSERT INTO {{tables.workspaces}}
                    (workspace_id, project_id, repo_id, alias, human_name, role, hostname, workspace_path)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                """,
                UUID(identity.agent_id),
                UUID(identity.project_id),
                UUID(repo_id),
                identity.alias,
                payload.human_name or "",
                payload.role,
                payload.hostname or None,
                payload.workspace_path or None,
            )
        else:
            existing_repo_id = existing.get("repo_id")
            existing_canonical = existing.get("existing_canonical_origin")
            if existing_repo_id is None or str(existing_repo_id) != repo_id:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "workspace_repo_mismatch: "
                        f"alias '{identity.alias}' (workspace_id={identity.agent_id}) is already registered "
                        f"for repo '{existing_canonical or existing_repo_id}'. "
                        f"Cannot initialize the same agent for repo '{canonical_origin}'. "
                        "Choose a different alias (new agent/worktree) or initialize from the original repo."
                    ),
                )

            await tx.execute(
                """
                UPDATE {{tables.workspaces}}
                SET repo_id = $3,
                    alias = $4,
                    human_name = $5,
                    role = $6,
                    hostname = $7,
                    workspace_path = $8,
                    deleted_at = NULL
                WHERE workspace_id = $1 AND project_id = $2
                """,
                UUID(identity.agent_id),
                UUID(identity.project_id),
                UUID(repo_id),
                identity.alias,
                payload.human_name or "",
                payload.role,
                payload.hostname or None,
                payload.workspace_path or None,
            )

    return _build_init_response(
        request=request,
        identity=identity,
        namespace_slug=namespace_slug,
        namespace_domain=namespace_domain,
        response_name=response_name,
        repo_id=repo_id,
        canonical_origin=canonical_origin,
        workspace_id=identity.agent_id,
        workspace_created=workspace_created,
    )
