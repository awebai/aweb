"""Aweb coordination project roles endpoints."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from pgdbm import AsyncDatabaseManager
from pydantic import BaseModel, Field, model_validator

from aweb.auth import enforce_actor_binding, validate_workspace_id
from aweb.aweb_introspection import get_identity_from_auth, get_project_from_auth

from ...db import DatabaseInfra, get_db_infra
from ...role_name_compat import normalize_optional_role_name, resolve_role_name_aliases
from ..defaults import get_default_bundle

logger = logging.getLogger(__name__)

roles_router = APIRouter(prefix="/v1/roles", tags=["roles"])
router = roles_router

DEFAULT_PROJECT_ROLES_BUNDLE: Dict[str, Any] = get_default_bundle()


def _resolve_alias_pair(
    *,
    canonical: Optional[str],
    legacy: Optional[str],
    canonical_name: str,
    legacy_name: str,
) -> Optional[str]:
    if canonical is not None and legacy is not None and canonical != legacy:
        raise ValueError(f"{canonical_name} and {legacy_name} must match when both are provided")
    return canonical if canonical is not None else legacy


def _resolve_selected_role_name(
    *,
    role: Optional[str],
    role_name: Optional[str],
) -> Optional[str]:
    normalized_role = normalize_optional_role_name(role)
    normalized_role_name = normalize_optional_role_name(role_name)
    return resolve_role_name_aliases(role=normalized_role, role_name=normalized_role_name)


class ProjectRolesBundle(BaseModel):
    """Versioned project roles bundle containing roles and adapters."""

    roles: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    adapters: Dict[str, Any] = Field(default_factory=dict)


class ProjectRolesVersion(BaseModel):
    """A versioned project roles record."""

    project_roles_id: str
    project_id: str
    version: int
    bundle: ProjectRolesBundle
    created_by_workspace_id: Optional[str]
    created_at: datetime
    updated_at: datetime


async def get_active_project_roles(
    db: AsyncDatabaseManager,
    project_id: str,
    *,
    bootstrap_if_missing: bool = True,
) -> Optional[ProjectRolesVersion]:
    """Get the active project roles bundle for a project."""
    result = await db.fetch_one(
        """
        SELECT pr.project_roles_id, pr.project_id, pr.version, pr.bundle_json,
               pr.created_by_workspace_id, pr.created_at, pr.updated_at
        FROM {{tables.projects}} p
        JOIN {{tables.project_roles}} pr
          ON pr.project_roles_id = p.active_project_roles_id
        WHERE p.id = $1
        """,
        project_id,
    )

    if result:
        bundle_data = result["bundle_json"]
        if isinstance(bundle_data, str):
            bundle_data = json.loads(bundle_data)

        return ProjectRolesVersion(
            project_roles_id=str(result["project_roles_id"]),
            project_id=str(result["project_id"]),
            version=result["version"],
            bundle=ProjectRolesBundle(**bundle_data),
            created_by_workspace_id=(
                str(result["created_by_workspace_id"])
                if result["created_by_workspace_id"]
                else None
            ),
            created_at=result["created_at"],
            updated_at=result["updated_at"],
        )

    if not bootstrap_if_missing:
        return None

    logger.info("Bootstrapping default project roles for project %s", project_id)
    project_roles_version = await create_project_roles_version(
        db,
        project_id=project_id,
        base_project_roles_id=None,
        bundle=get_default_bundle(),
        created_by_workspace_id=None,
    )
    await activate_project_roles(
        db,
        project_id=project_id,
        project_roles_id=project_roles_version.project_roles_id,
    )
    return project_roles_version


async def create_project_roles_version(
    db: AsyncDatabaseManager,
    *,
    project_id: str,
    base_project_roles_id: Optional[str],
    bundle: Dict[str, Any],
    created_by_workspace_id: Optional[str],
) -> ProjectRolesVersion:
    """Create a new project roles version for a project."""
    project = await db.fetch_one(
        "SELECT id FROM {{tables.projects}} WHERE id = $1 AND deleted_at IS NULL",
        project_id,
    )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    result = await db.fetch_one(
        """
        WITH locked_project AS (
            SELECT id, active_project_roles_id
            FROM {{tables.projects}}
            WHERE id = $1 AND deleted_at IS NULL
            FOR UPDATE
        ),
        base_check AS (
            SELECT id FROM locked_project
            WHERE $4::UUID IS NULL OR active_project_roles_id = $4::UUID
        ),
        next_version AS (
            SELECT COALESCE(MAX(version), 0) + 1 AS version
            FROM {{tables.project_roles}}
            WHERE project_id = $1
        )
        INSERT INTO {{tables.project_roles}} (
            project_id,
            version,
            bundle_json,
            created_by_workspace_id
        )
        SELECT $1, nv.version, $2::jsonb, $3
        FROM next_version nv, base_check bc
        RETURNING project_roles_id, project_id, version, bundle_json,
                  created_by_workspace_id, created_at, updated_at
        """,
        project_id,
        json.dumps(bundle),
        created_by_workspace_id,
        base_project_roles_id,
    )

    if not result:
        active = await db.fetch_one(
            "SELECT active_project_roles_id FROM {{tables.projects}} WHERE id = $1",
            project_id,
        )
        active_id = (
            str(active["active_project_roles_id"])
            if active and active["active_project_roles_id"]
            else "none"
        )
        raise HTTPException(
            status_code=409,
            detail=(
                f"Project roles conflict: base_project_roles_id {base_project_roles_id} "
                f"does not match active project roles {active_id}. "
                f"Another agent may have updated the project roles. "
                f"Re-read the active project roles and retry."
            ),
        )

    logger.info(
        "Created project roles version %d for project %s (project_roles_id=%s)",
        result["version"],
        project_id,
        result["project_roles_id"],
    )

    bundle_data = result["bundle_json"]
    if isinstance(bundle_data, str):
        bundle_data = json.loads(bundle_data)

    return ProjectRolesVersion(
        project_roles_id=str(result["project_roles_id"]),
        project_id=str(result["project_id"]),
        version=result["version"],
        bundle=ProjectRolesBundle(**bundle_data),
        created_by_workspace_id=(
            str(result["created_by_workspace_id"]) if result["created_by_workspace_id"] else None
        ),
        created_at=result["created_at"],
        updated_at=result["updated_at"],
    )


async def activate_project_roles(
    db: AsyncDatabaseManager,
    *,
    project_id: str,
    project_roles_id: str,
) -> bool:
    """Set the active project roles bundle for a project."""
    project_roles_version = await db.fetch_one(
        """
        SELECT project_roles_id, project_id
        FROM {{tables.project_roles}}
        WHERE project_roles_id = $1
        """,
        project_roles_id,
    )
    if not project_roles_version:
        raise HTTPException(status_code=404, detail="Project roles not found")

    if str(project_roles_version["project_id"]) != project_id:
        raise HTTPException(
            status_code=400,
            detail="Project roles do not belong to this project",
        )

    result = await db.fetch_one(
        """
        UPDATE {{tables.projects}}
        SET active_project_roles_id = $2
        WHERE id = $1
        RETURNING id
        """,
        project_id,
        project_roles_id,
    )

    if not result:
        raise HTTPException(status_code=404, detail="Project not found")

    logger.info("Activated project roles %s for project %s", project_roles_id, project_id)
    return True


def _generate_etag(project_roles_id: str, updated_at: datetime) -> str:
    """Generate ETag from project_roles_id and updated_at timestamp."""
    content = f"{project_roles_id}:{updated_at.isoformat()}"
    return f'"{hashlib.sha256(content.encode()).hexdigest()[:16]}"'


class RoleDefinition(BaseModel):
    """A single named role definition."""

    title: str
    playbook_md: str


class SelectedRoleInfo(BaseModel):
    """Selected role information."""

    role_name: str
    role: Optional[str] = None
    title: str
    playbook_md: str

    @model_validator(mode="after")
    def sync_role_aliases(self):
        resolved = _resolve_alias_pair(
            canonical=self.role_name,
            legacy=self.role,
            canonical_name="role_name",
            legacy_name="role",
        )
        if resolved is None:
            raise ValueError("role_name or role is required")
        self.role_name = resolved
        self.role = resolved
        return self


class ActiveProjectRolesResponse(BaseModel):
    """Response for GET /v1/roles/active."""

    project_roles_id: str
    active_project_roles_id: Optional[str] = None
    project_id: str
    version: int
    updated_at: datetime
    roles: Dict[str, RoleDefinition]
    selected_role: Optional[SelectedRoleInfo] = None
    adapters: Dict[str, Any] = Field(default_factory=dict)


class CreateProjectRolesRequest(BaseModel):
    """Request body for POST /v1/roles."""

    bundle: ProjectRolesBundle = Field(
        ...,
        description="Project roles bundle containing roles and adapters.",
    )
    base_project_roles_id: Optional[str] = Field(
        None,
        description="Optional bundle ID that this version is based on.",
    )
    created_by_workspace_id: Optional[str] = Field(
        None,
        description="Optional workspace_id of the creator for audit trail.",
    )


class CreateProjectRolesResponse(BaseModel):
    """Response for POST /v1/roles."""

    project_roles_id: str
    project_id: str
    version: int
    created: bool = True


class ActivateProjectRolesResponse(BaseModel):
    """Response for POST /v1/roles/{id}/activate."""

    activated: bool
    active_project_roles_id: str


class ResetProjectRolesResponse(BaseModel):
    """Response for POST /v1/roles/reset."""

    reset: bool
    active_project_roles_id: str
    version: int


class DeactivateProjectRolesResponse(BaseModel):
    """Response for POST /v1/roles/deactivate."""

    deactivated: bool
    active_project_roles_id: str
    version: int


class ProjectRolesHistoryItem(BaseModel):
    """A project roles version in the history list."""

    project_roles_id: str
    version: int
    created_at: datetime
    created_by_workspace_id: Optional[str]
    is_active: bool


class ProjectRolesHistoryResponse(BaseModel):
    """Response for GET /v1/roles/history."""

    project_roles_versions: List[ProjectRolesHistoryItem]


@roles_router.get("/active")
async def get_active_project_roles_endpoint(
    request: Request,
    response: Response,
    role: Optional[str] = Query(
        None,
        description="Legacy selector alias. If provided, includes selected_role in response.",
    ),
    role_name: Optional[str] = Query(
        None,
        description="Canonical selector name. If provided, includes selected_role in response.",
    ),
    only_selected: bool = Query(
        False,
        description="If true, return only the selected role.",
    ),
    if_none_match: Optional[str] = Header(None, alias="If-None-Match"),
    db: DatabaseInfra = Depends(get_db_infra),
) -> ActiveProjectRolesResponse:
    """Get the active project roles bundle for the project."""
    project_id = await get_project_from_auth(request, db)
    server_db = db.get_manager("server")

    project_roles_version = await get_active_project_roles(server_db, project_id)
    if not project_roles_version:
        raise HTTPException(status_code=404, detail="Project not found")

    etag = _generate_etag(
        project_roles_version.project_roles_id,
        project_roles_version.updated_at,
    )
    response.headers["ETag"] = etag

    if if_none_match and if_none_match == etag:
        return Response(status_code=304, headers={"ETag": etag})

    available_roles = list(project_roles_version.bundle.roles.keys())
    selected_role_data = None
    try:
        selected_role_name = _resolve_selected_role_name(role=role, role_name=role_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if selected_role_name:
        if selected_role_name not in project_roles_version.bundle.roles:
            raise HTTPException(
                status_code=400,
                detail=f"Role '{selected_role_name}' not found. Available roles: {available_roles}",
            )
        role_info = project_roles_version.bundle.roles[selected_role_name]
        selected_role_data = SelectedRoleInfo(
            role_name=selected_role_name,
            role=selected_role_name,
            title=role_info.get("title", selected_role_name),
            playbook_md=role_info.get("playbook_md", ""),
        )

    if only_selected and not selected_role_name:
        raise HTTPException(
            status_code=400,
            detail="only_selected=true requires a role or role_name parameter",
        )

    if only_selected:
        assert selected_role_name is not None
        roles = {
            selected_role_name: RoleDefinition(
                **project_roles_version.bundle.roles[selected_role_name]
            )
        }
    else:
        roles = {
            name: RoleDefinition(
                title=info.get("title", name),
                playbook_md=info.get("playbook_md", ""),
            )
            for name, info in project_roles_version.bundle.roles.items()
        }

    return ActiveProjectRolesResponse(
        project_roles_id=project_roles_version.project_roles_id,
        active_project_roles_id=project_roles_version.project_roles_id,
        project_id=project_roles_version.project_id,
        version=project_roles_version.version,
        updated_at=project_roles_version.updated_at,
        roles=roles,
        selected_role=selected_role_data,
        adapters=project_roles_version.bundle.adapters,
    )


@roles_router.get("/history")
async def list_project_roles_history(
    request: Request,
    limit: int = Query(20, ge=1, le=100, description="Max number of versions to return"),
    db: DatabaseInfra = Depends(get_db_infra),
) -> ProjectRolesHistoryResponse:
    """List project roles version history for the project."""
    project_id = await get_project_from_auth(request, db)
    server_db = db.get_manager("server")

    await get_active_project_roles(server_db, project_id, bootstrap_if_missing=True)

    active_result = await server_db.fetch_one(
        """
        SELECT active_project_roles_id
        FROM {{tables.projects}}
        WHERE id = $1 AND deleted_at IS NULL
        """,
        project_id,
    )
    active_project_roles_id = (
        str(active_result["active_project_roles_id"])
        if active_result and active_result["active_project_roles_id"]
        else None
    )

    rows = await server_db.fetch_all(
        """
        SELECT project_roles_id, version, created_at, created_by_workspace_id
        FROM {{tables.project_roles}}
        WHERE project_id = $1
        ORDER BY version DESC
        LIMIT $2
        """,
        project_id,
        limit,
    )

    project_roles_versions = [
        ProjectRolesHistoryItem(
            project_roles_id=str(row["project_roles_id"]),
            version=row["version"],
            created_at=row["created_at"],
            created_by_workspace_id=(
                str(row["created_by_workspace_id"]) if row["created_by_workspace_id"] else None
            ),
            is_active=(str(row["project_roles_id"]) == active_project_roles_id),
        )
        for row in rows
    ]

    return ProjectRolesHistoryResponse(project_roles_versions=project_roles_versions)


@roles_router.post("")
async def create_project_roles_endpoint(
    request: Request,
    payload: CreateProjectRolesRequest,
    db: DatabaseInfra = Depends(get_db_infra),
) -> CreateProjectRolesResponse:
    """Create a new project roles version for the project."""
    identity = await get_identity_from_auth(request, db)
    project_id = identity.project_id
    server_db = db.get_manager("server")

    bundle_dict = payload.bundle.model_dump()

    created_by_workspace_id: Optional[str] = identity.agent_id if identity.agent_id else None
    if payload.created_by_workspace_id:
        try:
            created_by_workspace_id = validate_workspace_id(payload.created_by_workspace_id)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        enforce_actor_binding(
            identity,
            created_by_workspace_id,
            detail="created_by_workspace_id does not match API key identity",
        )

        workspace = await server_db.fetch_one(
            """
            SELECT workspace_id
            FROM {{tables.workspaces}}
            WHERE workspace_id = $1 AND project_id = $2 AND deleted_at IS NULL
            """,
            created_by_workspace_id,
            project_id,
        )
        if not workspace:
            raise HTTPException(
                status_code=403,
                detail="Workspace not found or does not belong to your project",
            )

    project_roles_version = await create_project_roles_version(
        server_db,
        project_id=project_id,
        base_project_roles_id=payload.base_project_roles_id,
        bundle=bundle_dict,
        created_by_workspace_id=created_by_workspace_id,
    )

    await server_db.execute(
        """
        INSERT INTO {{tables.audit_log}} (project_id, workspace_id, event_type, details)
        VALUES ($1, $2, $3, $4::jsonb)
        """,
        project_id,
        created_by_workspace_id,
        "project_roles_created",
        json.dumps(
            {
                "project_id": project_id,
                "project_roles_id": project_roles_version.project_roles_id,
                "version": project_roles_version.version,
                "base_project_roles_id": payload.base_project_roles_id,
            }
        ),
    )

    logger.info(
        "Project roles created via API: project=%s project_roles_id=%s version=%d",
        project_id,
        project_roles_version.project_roles_id,
        project_roles_version.version,
    )

    return CreateProjectRolesResponse(
        project_roles_id=project_roles_version.project_roles_id,
        project_id=project_roles_version.project_id,
        version=project_roles_version.version,
    )


@roles_router.get("/{project_roles_id}")
async def get_project_roles_by_id_endpoint(
    request: Request,
    project_roles_id: str,
    db: DatabaseInfra = Depends(get_db_infra),
) -> ActiveProjectRolesResponse:
    """Get a specific project roles version by ID."""
    project_id = await get_project_from_auth(request, db)
    server_db = db.get_manager("server")

    result = await server_db.fetch_one(
        """
        SELECT pr.project_roles_id, pr.project_id, pr.version, pr.bundle_json,
               pr.created_by_workspace_id, pr.created_at, pr.updated_at
        FROM {{tables.project_roles}} pr
        WHERE pr.project_roles_id = $1 AND pr.project_id = $2
        """,
        project_roles_id,
        project_id,
    )

    if not result:
        raise HTTPException(
            status_code=404,
            detail="Project roles not found or do not belong to this project",
        )

    bundle_data = result["bundle_json"]
    if isinstance(bundle_data, str):
        bundle_data = json.loads(bundle_data)

    bundle = ProjectRolesBundle(**bundle_data)

    roles = {
        name: RoleDefinition(
            title=info.get("title", name),
            playbook_md=info.get("playbook_md", ""),
        )
        for name, info in bundle.roles.items()
    }

    return ActiveProjectRolesResponse(
        project_roles_id=str(result["project_roles_id"]),
        active_project_roles_id=None,
        project_id=str(result["project_id"]),
        version=result["version"],
        updated_at=result["updated_at"],
        roles=roles,
        selected_role=None,
        adapters=bundle.adapters,
    )


@roles_router.post("/{project_roles_id}/activate")
async def activate_project_roles_endpoint(
    request: Request,
    project_roles_id: str,
    db: DatabaseInfra = Depends(get_db_infra),
) -> ActivateProjectRolesResponse:
    """Set a project roles version as the active bundle for the project."""
    project_id = await get_project_from_auth(request, db)
    server_db = db.get_manager("server")

    current_active = await server_db.fetch_one(
        """
        SELECT active_project_roles_id
        FROM {{tables.projects}}
        WHERE id = $1 AND deleted_at IS NULL
        """,
        project_id,
    )
    previous_project_roles_id = (
        str(current_active["active_project_roles_id"])
        if current_active and current_active["active_project_roles_id"]
        else None
    )

    await activate_project_roles(
        server_db,
        project_id=project_id,
        project_roles_id=project_roles_id,
    )

    await server_db.execute(
        """
        INSERT INTO {{tables.audit_log}} (project_id, event_type, details)
        VALUES ($1, $2, $3::jsonb)
        """,
        project_id,
        "project_roles_activated",
        json.dumps(
            {
                "project_id": project_id,
                "project_roles_id": project_roles_id,
                "previous_project_roles_id": previous_project_roles_id,
            }
        ),
    )

    logger.info(
        "Project roles activated via API: project=%s project_roles_id=%s (was: %s)",
        project_id,
        project_roles_id,
        previous_project_roles_id,
    )

    return ActivateProjectRolesResponse(
        activated=True,
        active_project_roles_id=project_roles_id,
    )


@roles_router.post("/reset")
async def reset_project_roles_to_default_endpoint(
    request: Request,
    db: DatabaseInfra = Depends(get_db_infra),
) -> ResetProjectRolesResponse:
    """Reset the project's active project roles to the current default bundle."""
    project_id = await get_project_from_auth(request, db)
    server_db = db.get_manager("server")

    current_active = await server_db.fetch_one(
        """
        SELECT active_project_roles_id
        FROM {{tables.projects}}
        WHERE id = $1 AND deleted_at IS NULL
        """,
        project_id,
    )
    previous_project_roles_id = (
        str(current_active["active_project_roles_id"])
        if current_active and current_active["active_project_roles_id"]
        else None
    )

    try:
        fresh_bundle = get_default_bundle(force_reload=True)
    except Exception as exc:
        logger.error("Failed to reload default bundle: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to reload default project roles bundle: {exc}",
        ) from exc

    project_roles_version = await create_project_roles_version(
        server_db,
        project_id=project_id,
        base_project_roles_id=previous_project_roles_id,
        bundle=fresh_bundle,
        created_by_workspace_id=None,
    )
    await activate_project_roles(
        server_db,
        project_id=project_id,
        project_roles_id=project_roles_version.project_roles_id,
    )

    await server_db.execute(
        """
        INSERT INTO {{tables.audit_log}} (project_id, event_type, details)
        VALUES ($1, $2, $3::jsonb)
        """,
        project_id,
        "project_roles_reset_to_default",
        json.dumps(
            {
                "project_id": project_id,
                "project_roles_id": project_roles_version.project_roles_id,
                "version": project_roles_version.version,
                "previous_project_roles_id": previous_project_roles_id,
            }
        ),
    )

    logger.info(
        "Project roles reset to default via API: project=%s project_roles_id=%s version=%d (was: %s)",
        project_id,
        project_roles_version.project_roles_id,
        project_roles_version.version,
        previous_project_roles_id,
    )

    return ResetProjectRolesResponse(
        reset=True,
        active_project_roles_id=project_roles_version.project_roles_id,
        version=project_roles_version.version,
    )


@roles_router.post("/deactivate")
async def deactivate_project_roles_endpoint(
    request: Request,
    db: DatabaseInfra = Depends(get_db_infra),
) -> DeactivateProjectRolesResponse:
    """Deactivate project roles by replacing the active bundle with an empty bundle."""
    identity = await get_identity_from_auth(request, db)
    project_id = identity.project_id
    server_db = db.get_manager("server")

    current_active = await server_db.fetch_one(
        """
        SELECT active_project_roles_id
        FROM {{tables.projects}}
        WHERE id = $1 AND deleted_at IS NULL
        """,
        project_id,
    )
    previous_project_roles_id = (
        str(current_active["active_project_roles_id"])
        if current_active and current_active["active_project_roles_id"]
        else None
    )

    project_roles_version = await create_project_roles_version(
        server_db,
        project_id=project_id,
        base_project_roles_id=previous_project_roles_id,
        bundle={"roles": {}, "adapters": {}},
        created_by_workspace_id=identity.agent_id if identity.agent_id else None,
    )
    await activate_project_roles(
        server_db,
        project_id=project_id,
        project_roles_id=project_roles_version.project_roles_id,
    )

    await server_db.execute(
        """
        INSERT INTO {{tables.audit_log}} (project_id, event_type, details)
        VALUES ($1, $2, $3::jsonb)
        """,
        project_id,
        "project_roles_deactivated",
        json.dumps(
            {
                "project_id": project_id,
                "project_roles_id": project_roles_version.project_roles_id,
                "version": project_roles_version.version,
                "previous_project_roles_id": previous_project_roles_id,
            }
        ),
    )

    logger.info(
        "Project roles deactivated via API: project=%s project_roles_id=%s version=%d (was: %s)",
        project_id,
        project_roles_version.project_roles_id,
        project_roles_version.version,
        previous_project_roles_id,
    )

    return DeactivateProjectRolesResponse(
        deactivated=True,
        active_project_roles_id=project_roles_version.project_roles_id,
        version=project_roles_version.version,
    )
