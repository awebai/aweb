"""Aweb coordination project roles endpoints."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import asyncpg.exceptions
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from pgdbm import AsyncDatabaseManager
from pgdbm.errors import QueryError
from pydantic import BaseModel, Field, model_validator

from aweb.team_auth_deps import get_team_identity

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

    id: str
    team_address: str
    version: int
    bundle: ProjectRolesBundle
    created_by_alias: Optional[str]
    created_at: datetime
    updated_at: Optional[datetime] = None


async def get_active_project_roles(
    db: AsyncDatabaseManager,
    team_address: str,
    *,
    bootstrap_if_missing: bool = True,
) -> Optional[ProjectRolesVersion]:
    """Get the active project roles bundle for a team."""
    result = await db.fetch_one(
        """
        SELECT pr.id, pr.team_address, pr.version, pr.bundle_json,
               pr.created_by_alias, pr.created_at, pr.updated_at
        FROM {{tables.project_roles}} pr
        WHERE pr.team_address = $1 AND pr.is_active = true
        """,
        team_address,
    )

    if result:
        bundle_data = result["bundle_json"]
        if isinstance(bundle_data, str):
            bundle_data = json.loads(bundle_data)

        return ProjectRolesVersion(
            id=str(result["id"]),
            team_address=result["team_address"],
            version=result["version"],
            bundle=ProjectRolesBundle(**bundle_data),
            created_by_alias=result["created_by_alias"],
            created_at=result["created_at"],
            updated_at=result["updated_at"],
        )

    if not bootstrap_if_missing:
        return None

    logger.info("Bootstrapping default project roles for team %s", team_address)
    try:
        project_roles_version = await create_project_roles_version(
            db,
            team_address=team_address,
            base_roles_id=None,
            bundle=get_default_bundle(),
            created_by_alias=None,
        )
    except (QueryError, asyncpg.exceptions.UniqueViolationError) as exc:
        if isinstance(exc, QueryError) and not isinstance(
            exc.__cause__, asyncpg.exceptions.UniqueViolationError
        ):
            raise
        # A concurrent bootstrap already created the version -- read it
        logger.info("Concurrent bootstrap for team %s, retrying read", team_address)
        return await get_active_project_roles(
            db, team_address, bootstrap_if_missing=False
        )
    await activate_project_roles(
        db,
        team_address=team_address,
        roles_id=project_roles_version.id,
    )
    return project_roles_version


async def create_project_roles_version(
    db: AsyncDatabaseManager,
    *,
    team_address: str,
    base_roles_id: Optional[str],
    bundle: Dict[str, Any],
    created_by_alias: Optional[str],
) -> ProjectRolesVersion:
    """Create a versioned project roles record for a team."""
    result = await db.fetch_one(
        """
        WITH active_check AS (
            SELECT id
            FROM {{tables.project_roles}}
            WHERE team_address = $1 AND is_active = true
        ),
        base_check AS (
            SELECT 1 AS ok
            WHERE $4::TEXT IS NULL
               OR EXISTS (SELECT 1 FROM active_check WHERE id::text = $4)
        ),
        next_version AS (
            SELECT COALESCE(MAX(version), 0) + 1 AS version
            FROM {{tables.project_roles}}
            WHERE team_address = $1
        )
        INSERT INTO {{tables.project_roles}} (
            team_address,
            version,
            bundle_json,
            created_by_alias
        )
        SELECT $1, nv.version, $2::jsonb, $3
        FROM next_version nv, base_check bc
        RETURNING id, team_address, version, bundle_json,
                  created_by_alias, created_at, updated_at
        """,
        team_address,
        json.dumps(bundle),
        created_by_alias,
        base_roles_id,
    )

    if not result:
        active = await db.fetch_one(
            """
            SELECT id FROM {{tables.project_roles}}
            WHERE team_address = $1 AND is_active = true
            """,
            team_address,
        )
        active_id = str(active["id"]) if active else "none"
        raise HTTPException(
            status_code=409,
            detail=(
                f"Project roles conflict: base_roles_id {base_roles_id} "
                f"does not match active project roles {active_id}. "
                f"Another agent may have updated the project roles. "
                f"Re-read the active project roles and retry."
            ),
        )

    logger.info(
        "Created project roles version %d for team %s (id=%s)",
        result["version"],
        team_address,
        result["id"],
    )

    bundle_data = result["bundle_json"]
    if isinstance(bundle_data, str):
        bundle_data = json.loads(bundle_data)

    return ProjectRolesVersion(
        id=str(result["id"]),
        team_address=result["team_address"],
        version=result["version"],
        bundle=ProjectRolesBundle(**bundle_data),
        created_by_alias=result["created_by_alias"],
        created_at=result["created_at"],
        updated_at=result["updated_at"],
    )


async def activate_project_roles(
    db: AsyncDatabaseManager,
    *,
    team_address: str,
    roles_id: str,
) -> bool:
    """Set the active project roles bundle for a team."""
    target = await db.fetch_one(
        """
        SELECT id, team_address
        FROM {{tables.project_roles}}
        WHERE id = $1
        """,
        roles_id,
    )
    if not target:
        raise HTTPException(status_code=404, detail="Project roles not found")

    if target["team_address"] != team_address:
        raise HTTPException(
            status_code=400,
            detail="Project roles do not belong to this team",
        )

    # Deactivate the currently active version (if any)
    await db.execute(
        """
        UPDATE {{tables.project_roles}}
        SET is_active = false
        WHERE team_address = $1 AND is_active = true
        """,
        team_address,
    )

    # Activate the target version
    await db.execute(
        """
        UPDATE {{tables.project_roles}}
        SET is_active = true
        WHERE id = $1
        """,
        roles_id,
    )

    logger.info("Activated project roles %s for team %s", roles_id, team_address)
    return True


def _generate_etag(roles_id: str, updated_at: datetime) -> str:
    """Generate ETag from roles id and updated_at timestamp."""
    content = f"{roles_id}:{updated_at.isoformat()}"
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
    team_address: str
    version: int
    updated_at: Optional[datetime] = None
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


class CreateProjectRolesResponse(BaseModel):
    """Response for POST /v1/roles."""

    project_roles_id: str
    team_address: str
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
    created_by_alias: Optional[str]
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
    """Get the active project roles bundle for the team."""
    identity = await get_team_identity(request, db)
    aweb_db = db.get_manager("aweb")

    project_roles_version = await get_active_project_roles(aweb_db, identity.team_address)
    if not project_roles_version:
        raise HTTPException(status_code=404, detail="No active project roles found")

    etag = _generate_etag(
        project_roles_version.id,
        project_roles_version.updated_at or project_roles_version.created_at,
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
        project_roles_id=project_roles_version.id,
        active_project_roles_id=project_roles_version.id,
        team_address=project_roles_version.team_address,
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
    """List project roles version history for the team."""
    identity = await get_team_identity(request, db)
    aweb_db = db.get_manager("aweb")

    await get_active_project_roles(aweb_db, identity.team_address, bootstrap_if_missing=True)

    rows = await aweb_db.fetch_all(
        """
        SELECT id, version, created_at, created_by_alias, is_active
        FROM {{tables.project_roles}}
        WHERE team_address = $1
        ORDER BY version DESC
        LIMIT $2
        """,
        identity.team_address,
        limit,
    )

    project_roles_versions = [
        ProjectRolesHistoryItem(
            project_roles_id=str(row["id"]),
            version=row["version"],
            created_at=row["created_at"],
            created_by_alias=row["created_by_alias"],
            is_active=row["is_active"],
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
    """Create a versioned project roles record for the team."""
    identity = await get_team_identity(request, db)
    aweb_db = db.get_manager("aweb")

    bundle_dict = payload.bundle.model_dump()

    project_roles_version = await create_project_roles_version(
        aweb_db,
        team_address=identity.team_address,
        base_roles_id=payload.base_project_roles_id,
        bundle=bundle_dict,
        created_by_alias=identity.alias,
    )

    logger.info(
        "Project roles created via API: team=%s id=%s version=%d",
        identity.team_address,
        project_roles_version.id,
        project_roles_version.version,
    )

    return CreateProjectRolesResponse(
        project_roles_id=project_roles_version.id,
        team_address=project_roles_version.team_address,
        version=project_roles_version.version,
    )


@roles_router.get("/{project_roles_id}")
async def get_project_roles_by_id_endpoint(
    request: Request,
    project_roles_id: str,
    db: DatabaseInfra = Depends(get_db_infra),
) -> ActiveProjectRolesResponse:
    """Get a specific project roles version by ID."""
    identity = await get_team_identity(request, db)
    aweb_db = db.get_manager("aweb")

    result = await aweb_db.fetch_one(
        """
        SELECT pr.id, pr.team_address, pr.version, pr.bundle_json,
               pr.created_by_alias, pr.created_at, pr.updated_at
        FROM {{tables.project_roles}} pr
        WHERE pr.id = $1 AND pr.team_address = $2
        """,
        project_roles_id,
        identity.team_address,
    )

    if not result:
        raise HTTPException(
            status_code=404,
            detail="Project roles not found or do not belong to this team",
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
        project_roles_id=str(result["id"]),
        active_project_roles_id=None,
        team_address=result["team_address"],
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
    """Set a project roles version as the active bundle for the team."""
    identity = await get_team_identity(request, db)
    aweb_db = db.get_manager("aweb")

    previous_active = await aweb_db.fetch_one(
        """
        SELECT id FROM {{tables.project_roles}}
        WHERE team_address = $1 AND is_active = true
        """,
        identity.team_address,
    )
    previous_roles_id = str(previous_active["id"]) if previous_active else None

    await activate_project_roles(
        aweb_db,
        team_address=identity.team_address,
        roles_id=project_roles_id,
    )

    logger.info(
        "Project roles activated via API: team=%s id=%s (was: %s)",
        identity.team_address,
        project_roles_id,
        previous_roles_id,
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
    """Reset the team's active project roles to the current default bundle."""
    identity = await get_team_identity(request, db)
    aweb_db = db.get_manager("aweb")

    previous_active = await aweb_db.fetch_one(
        """
        SELECT id FROM {{tables.project_roles}}
        WHERE team_address = $1 AND is_active = true
        """,
        identity.team_address,
    )
    previous_roles_id = str(previous_active["id"]) if previous_active else None

    try:
        fresh_bundle = get_default_bundle(force_reload=True)
    except Exception as exc:
        logger.error("Failed to reload default bundle: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to reload default project roles bundle: {exc}",
        ) from exc

    project_roles_version = await create_project_roles_version(
        aweb_db,
        team_address=identity.team_address,
        base_roles_id=previous_roles_id,
        bundle=fresh_bundle,
        created_by_alias=None,
    )
    await activate_project_roles(
        aweb_db,
        team_address=identity.team_address,
        roles_id=project_roles_version.id,
    )

    logger.info(
        "Project roles reset to default via API: team=%s id=%s version=%d (was: %s)",
        identity.team_address,
        project_roles_version.id,
        project_roles_version.version,
        previous_roles_id,
    )

    return ResetProjectRolesResponse(
        reset=True,
        active_project_roles_id=project_roles_version.id,
        version=project_roles_version.version,
    )


@roles_router.post("/deactivate")
async def deactivate_project_roles_endpoint(
    request: Request,
    db: DatabaseInfra = Depends(get_db_infra),
) -> DeactivateProjectRolesResponse:
    """Deactivate project roles by replacing the active bundle with an empty bundle."""
    identity = await get_team_identity(request, db)
    aweb_db = db.get_manager("aweb")

    previous_active = await aweb_db.fetch_one(
        """
        SELECT id FROM {{tables.project_roles}}
        WHERE team_address = $1 AND is_active = true
        """,
        identity.team_address,
    )
    previous_roles_id = str(previous_active["id"]) if previous_active else None

    project_roles_version = await create_project_roles_version(
        aweb_db,
        team_address=identity.team_address,
        base_roles_id=previous_roles_id,
        bundle={"roles": {}, "adapters": {}},
        created_by_alias=identity.alias,
    )
    await activate_project_roles(
        aweb_db,
        team_address=identity.team_address,
        roles_id=project_roles_version.id,
    )

    logger.info(
        "Project roles deactivated via API: team=%s id=%s version=%d (was: %s)",
        identity.team_address,
        project_roles_version.id,
        project_roles_version.version,
        previous_roles_id,
    )

    return DeactivateProjectRolesResponse(
        deactivated=True,
        active_project_roles_id=project_roles_version.id,
        version=project_roles_version.version,
    )
