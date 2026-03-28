"""Aweb coordination project policy endpoints.

Provides server-backed project policies with versioned bundles containing:
- Global invariants (guidance for all workspaces)
- Role playbooks (role-specific guidance)
- Adapters (tool-specific templates)

Security:
- All reads are project-scoped via `get_project_from_auth`
- Writes (POST /v1/policies, POST /v1/policies/{id}/activate) require admin permission
"""

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
policies_router = APIRouter(prefix="/v1/policies", tags=["policies"])
router = roles_router
compat_router = policies_router


# Default policy bundle for new projects.
# Loaded from markdown files in aweb/defaults/ for easier editing.
# This is a backward-compatible alias for code that imports DEFAULT_POLICY_BUNDLE.
DEFAULT_POLICY_BUNDLE: Dict[str, Any] = get_default_bundle()


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
    """Versioned project roles bundle containing invariants, roles, and adapters."""

    invariants: List[Dict[str, Any]] = Field(default_factory=list)
    roles: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    adapters: Dict[str, Any] = Field(default_factory=dict)


class ProjectRolesVersion(BaseModel):
    """A versioned project roles record."""

    project_roles_id: str
    policy_id: str
    project_id: str
    version: int
    bundle: ProjectRolesBundle
    created_by_workspace_id: Optional[str]
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="after")
    def sync_project_roles_id(self):
        resolved = _resolve_alias_pair(
            canonical=self.project_roles_id,
            legacy=self.policy_id,
            canonical_name="project_roles_id",
            legacy_name="policy_id",
        )
        if resolved is None:
            raise ValueError("project_roles_id or policy_id is required")
        self.project_roles_id = resolved
        self.policy_id = resolved
        return self


PolicyBundle = ProjectRolesBundle
PolicyVersion = ProjectRolesVersion


async def get_active_policy(
    db: AsyncDatabaseManager,
    project_id: str,
    *,
    bootstrap_if_missing: bool = True,
) -> Optional[PolicyVersion]:
    """
    Get the active policy for a project.

    If no policy exists and bootstrap_if_missing is True, creates a default
    policy and sets it as active.

    Args:
        db: The server database manager
        project_id: The project UUID
        bootstrap_if_missing: If True, create default policy when none exists

    Returns:
        The active PolicyVersion, or None if no policy and bootstrap disabled
    """
    # Check if project has an active policy
    result = await db.fetch_one(
        """
        SELECT pp.policy_id, pp.project_id, pp.version, pp.bundle_json,
               pp.created_by_workspace_id, pp.created_at, pp.updated_at
        FROM {{tables.projects}} p
        JOIN {{tables.project_policies}} pp ON pp.policy_id = p.active_policy_id
        WHERE p.id = $1
        """,
        project_id,
    )

    if result:
        # Parse bundle_json - may be dict or string depending on asyncpg codec
        bundle_data = result["bundle_json"]
        if isinstance(bundle_data, str):
            bundle_data = json.loads(bundle_data)

        return PolicyVersion(
            project_roles_id=str(result["policy_id"]),
            policy_id=str(result["policy_id"]),
            project_id=str(result["project_id"]),
            version=result["version"],
            bundle=PolicyBundle(**bundle_data),
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

    # Bootstrap default policy
    logger.info("Bootstrapping default policy for project %s", project_id)
    policy = await create_policy_version(
        db,
        project_id=project_id,
        base_policy_id=None,
        bundle=get_default_bundle(),
        created_by_workspace_id=None,
    )
    await activate_policy(db, project_id=project_id, policy_id=policy.policy_id)
    return policy


async def create_policy_version(
    db: AsyncDatabaseManager,
    *,
    project_id: str,
    base_policy_id: Optional[str],
    bundle: Dict[str, Any],
    created_by_workspace_id: Optional[str],
) -> PolicyVersion:
    """
    Create a new policy version for a project.

    Version numbers are allocated atomically to prevent races. Each new version
    is one greater than the current maximum for the project.

    If base_policy_id is provided, the insert is gated on it matching the
    project's current active_policy_id (optimistic concurrency). When the IDs
    don't match, no row is inserted and an HTTP 409 is raised. When
    base_policy_id is None the optimistic concurrency check is skipped.

    Args:
        db: The server database manager
        project_id: The project UUID
        base_policy_id: If provided, the active policy this version is based on.
            Used for optimistic concurrency and audit trail.
        bundle: The policy bundle (invariants, roles, adapters)
        created_by_workspace_id: The workspace creating this version (optional)

    Returns:
        The created PolicyVersion

    Raises:
        HTTPException 404: If project doesn't exist
        HTTPException 409: If base_policy_id doesn't match the active policy
    """
    # Verify project exists and is not soft-deleted
    project = await db.fetch_one(
        "SELECT id FROM {{tables.projects}} WHERE id = $1 AND deleted_at IS NULL",
        project_id,
    )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Allocate version atomically by locking the project row, then computing max+1.
    # The base_check CTE gates the INSERT on optimistic concurrency: if
    # base_policy_id ($4) is provided it must match active_policy_id, otherwise
    # the INSERT produces no rows and we raise 409 below.
    # The unique constraint on (project_id, version) provides final safety.
    result = await db.fetch_one(
        """
        WITH locked_project AS (
            SELECT id, active_policy_id FROM {{tables.projects}}
            WHERE id = $1 AND deleted_at IS NULL
            FOR UPDATE
        ),
        base_check AS (
            SELECT id FROM locked_project
            WHERE $4::UUID IS NULL OR active_policy_id = $4::UUID
        ),
        next_version AS (
            SELECT COALESCE(MAX(version), 0) + 1 AS version
            FROM {{tables.project_policies}}
            WHERE project_id = $1
        )
        INSERT INTO {{tables.project_policies}} (project_id, version, bundle_json, created_by_workspace_id)
        SELECT $1, nv.version, $2::jsonb, $3
        FROM next_version nv, base_check bc
        RETURNING policy_id, project_id, version, bundle_json, created_by_workspace_id, created_at, updated_at
        """,
        project_id,
        json.dumps(bundle),
        created_by_workspace_id,
        base_policy_id,
    )

    if not result:
        # Project exists (checked above) but INSERT produced no rows — the
        # base_check CTE filtered it out, meaning base_policy_id doesn't
        # match the current active_policy_id.
        active = await db.fetch_one(
            "SELECT active_policy_id FROM {{tables.projects}} WHERE id = $1",
            project_id,
        )
        active_id = (
            str(active["active_policy_id"]) if active and active["active_policy_id"] else "none"
        )
        raise HTTPException(
            status_code=409,
            detail=(
                f"Policy conflict: base_policy_id {base_policy_id} "
                f"does not match active policy {active_id}. "
                f"Another agent may have updated the policy. "
                f"Re-read the active policy and retry."
            ),
        )

    logger.info(
        "Created policy version %d for project %s (policy_id=%s)",
        result["version"],
        project_id,
        result["policy_id"],
    )

    # Parse bundle_json - may be dict or string depending on asyncpg codec
    bundle_data = result["bundle_json"]
    if isinstance(bundle_data, str):
        bundle_data = json.loads(bundle_data)

    return PolicyVersion(
        project_roles_id=str(result["policy_id"]),
        policy_id=str(result["policy_id"]),
        project_id=str(result["project_id"]),
        version=result["version"],
        bundle=PolicyBundle(**bundle_data),
        created_by_workspace_id=(
            str(result["created_by_workspace_id"]) if result["created_by_workspace_id"] else None
        ),
        created_at=result["created_at"],
        updated_at=result["updated_at"],
    )


async def activate_policy(
    db: AsyncDatabaseManager,
    *,
    project_id: str,
    policy_id: str,
) -> bool:
    """
    Set the active policy for a project.

    Args:
        db: The server database manager
        project_id: The project UUID
        policy_id: The policy UUID to activate

    Returns:
        True if activation succeeded

    Raises:
        HTTPException 404: If project or policy doesn't exist
        HTTPException 400: If policy doesn't belong to the project
    """
    # Verify policy exists and belongs to project
    policy = await db.fetch_one(
        """
        SELECT policy_id, project_id FROM {{tables.project_policies}}
        WHERE policy_id = $1
        """,
        policy_id,
    )
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    if str(policy["project_id"]) != project_id:
        raise HTTPException(
            status_code=400,
            detail="Policy does not belong to this project",
        )

    # Update project's active policy
    result = await db.fetch_one(
        """
        UPDATE {{tables.projects}}
        SET active_policy_id = $2
        WHERE id = $1
        RETURNING id
        """,
        project_id,
        policy_id,
    )

    if not result:
        raise HTTPException(status_code=404, detail="Project not found")

    logger.info("Activated policy %s for project %s", policy_id, project_id)
    return True


def _generate_etag(policy_id: str, updated_at: datetime) -> str:
    """Generate ETag from policy_id and updated_at timestamp."""
    content = f"{policy_id}:{updated_at.isoformat()}"
    return f'"{hashlib.sha256(content.encode()).hexdigest()[:16]}"'


class Invariant(BaseModel):
    """A policy invariant."""

    id: str
    title: str
    body_md: str


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
    """Response for GET /v1/roles/active and compatibility aliases."""

    project_roles_id: str
    policy_id: str
    active_project_roles_id: Optional[str] = None
    active_policy_id: Optional[str] = None
    project_id: str
    version: int
    updated_at: datetime
    invariants: List[Invariant]
    roles: Dict[str, RoleDefinition]
    selected_role: Optional[SelectedRoleInfo] = None
    adapters: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def sync_project_roles_aliases(self):
        resolved = _resolve_alias_pair(
            canonical=self.project_roles_id,
            legacy=self.policy_id,
            canonical_name="project_roles_id",
            legacy_name="policy_id",
        )
        if resolved is None:
            raise ValueError("project_roles_id or policy_id is required")
        self.project_roles_id = resolved
        self.policy_id = resolved

        active_resolved = _resolve_alias_pair(
            canonical=self.active_project_roles_id,
            legacy=self.active_policy_id,
            canonical_name="active_project_roles_id",
            legacy_name="active_policy_id",
        )
        self.active_project_roles_id = active_resolved
        self.active_policy_id = active_resolved
        return self


class CreateProjectRolesRequest(BaseModel):
    """Request body for POST /v1/roles and compatibility aliases."""

    bundle: ProjectRolesBundle = Field(
        ...,
        description="Project roles bundle containing invariants, roles, and adapters.",
    )
    base_project_roles_id: Optional[str] = Field(
        None,
        description="Optional canonical ID of the bundle this version is based on.",
    )
    base_policy_id: Optional[str] = Field(
        None,
        description="Legacy alias for base_project_roles_id.",
    )
    created_by_workspace_id: Optional[str] = Field(
        None,
        description="Optional: workspace_id of the creator (for audit trail).",
    )

    @model_validator(mode="after")
    def sync_base_ids(self):
        resolved = _resolve_alias_pair(
            canonical=self.base_project_roles_id,
            legacy=self.base_policy_id,
            canonical_name="base_project_roles_id",
            legacy_name="base_policy_id",
        )
        self.base_project_roles_id = resolved
        self.base_policy_id = resolved
        return self


class CreateProjectRolesResponse(BaseModel):
    """Response for POST /v1/roles and compatibility aliases."""

    project_roles_id: str
    policy_id: str
    project_id: str
    version: int
    created: bool = True

    @model_validator(mode="after")
    def sync_project_roles_aliases(self):
        resolved = _resolve_alias_pair(
            canonical=self.project_roles_id,
            legacy=self.policy_id,
            canonical_name="project_roles_id",
            legacy_name="policy_id",
        )
        if resolved is None:
            raise ValueError("project_roles_id or policy_id is required")
        self.project_roles_id = resolved
        self.policy_id = resolved
        return self


class ActivateProjectRolesResponse(BaseModel):
    """Response for POST /v1/roles/{id}/activate and compatibility aliases."""

    activated: bool
    active_project_roles_id: str
    active_policy_id: str

    @model_validator(mode="after")
    def sync_active_ids(self):
        resolved = _resolve_alias_pair(
            canonical=self.active_project_roles_id,
            legacy=self.active_policy_id,
            canonical_name="active_project_roles_id",
            legacy_name="active_policy_id",
        )
        if resolved is None:
            raise ValueError("active_project_roles_id or active_policy_id is required")
        self.active_project_roles_id = resolved
        self.active_policy_id = resolved
        return self


class ResetProjectRolesResponse(BaseModel):
    """Response for POST /v1/roles/reset and compatibility aliases."""

    reset: bool
    active_project_roles_id: str
    active_policy_id: str
    version: int

    @model_validator(mode="after")
    def sync_active_ids(self):
        resolved = _resolve_alias_pair(
            canonical=self.active_project_roles_id,
            legacy=self.active_policy_id,
            canonical_name="active_project_roles_id",
            legacy_name="active_policy_id",
        )
        if resolved is None:
            raise ValueError("active_project_roles_id or active_policy_id is required")
        self.active_project_roles_id = resolved
        self.active_policy_id = resolved
        return self


class ProjectRolesHistoryItem(BaseModel):
    """A project roles version in the history list."""

    project_roles_id: str
    policy_id: str
    version: int
    created_at: datetime
    created_by_workspace_id: Optional[str]
    is_active: bool

    @model_validator(mode="after")
    def sync_project_roles_aliases(self):
        resolved = _resolve_alias_pair(
            canonical=self.project_roles_id,
            legacy=self.policy_id,
            canonical_name="project_roles_id",
            legacy_name="policy_id",
        )
        if resolved is None:
            raise ValueError("project_roles_id or policy_id is required")
        self.project_roles_id = resolved
        self.policy_id = resolved
        return self


class ProjectRolesHistoryResponse(BaseModel):
    """Response for GET /v1/roles/history and compatibility aliases."""

    project_roles_versions: Optional[List[ProjectRolesHistoryItem]] = None
    policies: Optional[List[ProjectRolesHistoryItem]] = None

    @model_validator(mode="after")
    def sync_history_lists(self):
        project_roles_versions = self.project_roles_versions or self.policies
        if project_roles_versions is None:
            raise ValueError("project_roles_versions or policies is required")
        self.project_roles_versions = project_roles_versions
        self.policies = project_roles_versions
        return self


RolePlaybook = RoleDefinition
SelectedRole = SelectedRoleInfo
ActivePolicyResponse = ActiveProjectRolesResponse
CreatePolicyRequest = CreateProjectRolesRequest
CreatePolicyResponse = CreateProjectRolesResponse
ActivatePolicyResponse = ActivateProjectRolesResponse
ResetPolicyResponse = ResetProjectRolesResponse
PolicyHistoryItem = ProjectRolesHistoryItem
PolicyHistoryResponse = ProjectRolesHistoryResponse


@roles_router.get("/active")
@policies_router.get("/active")
async def get_active_policy_endpoint(
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
        description="If true, return only invariants + selected role (requires role param).",
    ),
    if_none_match: Optional[str] = Header(None, alias="If-None-Match"),
    db: DatabaseInfra = Depends(get_db_infra),
) -> ActiveProjectRolesResponse:
    """
    Get the active policy for the project.

    Returns the active policy bundle including invariants, role playbooks, and adapters.
    If no policy exists, bootstraps a default policy and returns it.

    Supports conditional requests via ETag/If-None-Match for efficient caching.

    Requires an authenticated project context.
    """
    project_id = await get_project_from_auth(request, db)
    server_db = db.get_manager("server")

    # Get or bootstrap active policy
    policy = await get_active_policy(server_db, project_id)
    if not policy:
        # This shouldn't happen since get_active_policy bootstraps by default
        raise HTTPException(status_code=404, detail="Project not found")

    # Generate ETag
    etag = _generate_etag(policy.policy_id, policy.updated_at)
    response.headers["ETag"] = etag

    # Check If-None-Match for conditional GET
    if if_none_match and if_none_match == etag:
        return Response(status_code=304, headers={"ETag": etag})

    # Validate role selection
    available_roles = list(policy.bundle.roles.keys())
    selected_role_data = None
    try:
        selected_role_name = _resolve_selected_role_name(role=role, role_name=role_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if selected_role_name:
        if selected_role_name not in policy.bundle.roles:
            raise HTTPException(
                status_code=400,
                detail=f"Role '{selected_role_name}' not found. Available roles: {available_roles}",
            )
        role_info = policy.bundle.roles[selected_role_name]
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

    # Build response
    invariants = [
        Invariant(
            id=inv.get("id", ""),
            title=inv.get("title", ""),
            body_md=inv.get("body_md", ""),
        )
        for inv in policy.bundle.invariants
    ]

    if only_selected:
        # Return only invariants + selected role
        assert selected_role_name is not None
        roles = {selected_role_name: RoleDefinition(**policy.bundle.roles[selected_role_name])}
    else:
        roles = {
            k: RoleDefinition(
                title=v.get("title", k),
                playbook_md=v.get("playbook_md", ""),
            )
            for k, v in policy.bundle.roles.items()
        }

    return ActiveProjectRolesResponse(
        project_roles_id=policy.project_roles_id,
        policy_id=policy.policy_id,
        active_project_roles_id=policy.project_roles_id,
        active_policy_id=policy.policy_id,
        project_id=policy.project_id,
        version=policy.version,
        updated_at=policy.updated_at,
        invariants=invariants,
        roles=roles,
        selected_role=selected_role_data,
        adapters=policy.bundle.adapters,
    )


# Admin endpoints for policy management


@roles_router.get("/history")
@policies_router.get("/history")
async def list_policy_history(
    request: Request,
    limit: int = Query(20, ge=1, le=100, description="Max number of versions to return"),
    db: DatabaseInfra = Depends(get_db_infra),
) -> ProjectRolesHistoryResponse:
    """
    List policy version history for the project.

    Returns policy versions ordered by version descending (newest first).
    Each entry indicates whether it's the currently active policy.

    Requires an authenticated project context.
    """
    project_id = await get_project_from_auth(request, db)
    server_db = db.get_manager("server")

    # Ensure the project has a default policy (v1) so newly-registered projects
    # have a consistent policy history surface.
    await get_active_policy(server_db, project_id, bootstrap_if_missing=True)

    # Get active policy ID for this project
    active_result = await server_db.fetch_one(
        "SELECT active_policy_id FROM {{tables.projects}} WHERE id = $1 AND deleted_at IS NULL",
        project_id,
    )
    active_policy_id = (
        str(active_result["active_policy_id"])
        if active_result and active_result["active_policy_id"]
        else None
    )

    # Fetch policy versions
    rows = await server_db.fetch_all(
        """
        SELECT policy_id, version, created_at, created_by_workspace_id
        FROM {{tables.project_policies}}
        WHERE project_id = $1
        ORDER BY version DESC
        LIMIT $2
        """,
        project_id,
        limit,
    )

    policies = [
        ProjectRolesHistoryItem(
            project_roles_id=str(row["policy_id"]),
            policy_id=str(row["policy_id"]),
            version=row["version"],
            created_at=row["created_at"],
            created_by_workspace_id=(
                str(row["created_by_workspace_id"]) if row["created_by_workspace_id"] else None
            ),
            is_active=(str(row["policy_id"]) == active_policy_id),
        )
        for row in rows
    ]

    return ProjectRolesHistoryResponse(project_roles_versions=policies, policies=policies)


@roles_router.post("")
@policies_router.post("")
async def create_policy_endpoint(
    request: Request,
    payload: CreateProjectRolesRequest,
    db: DatabaseInfra = Depends(get_db_infra),
) -> CreateProjectRolesResponse:
    """
    Create a new policy version for the project.

    Requires an authenticated project context.

    The new policy is NOT automatically activated. Use POST /v1/policies/{id}/activate
    to set it as the active policy.
    """
    identity = await get_identity_from_auth(request, db)
    project_id = identity.project_id
    server_db = db.get_manager("server")

    # Convert Pydantic model to dict for storage
    bundle_dict = payload.bundle.model_dump()

    created_by_workspace_id: Optional[str] = identity.agent_id if identity.agent_id else None
    if payload.created_by_workspace_id:
        try:
            created_by_workspace_id = validate_workspace_id(payload.created_by_workspace_id)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
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

    # Create the policy version
    policy = await create_policy_version(
        server_db,
        project_id=project_id,
        base_policy_id=payload.base_project_roles_id,
        bundle=bundle_dict,
        created_by_workspace_id=created_by_workspace_id,
    )

    # Add audit log entry
    await server_db.execute(
        """
        INSERT INTO {{tables.audit_log}} (project_id, workspace_id, event_type, details)
        VALUES ($1, $2, $3, $4::jsonb)
        """,
        project_id,
        created_by_workspace_id,
        "policy_created",
        json.dumps(
            {
                "project_id": project_id,
                "policy_id": policy.policy_id,
                "version": policy.version,
                "base_policy_id": payload.base_policy_id,
            }
        ),
    )

    logger.info(
        "Policy created via API: project=%s policy_id=%s version=%d",
        project_id,
        policy.policy_id,
        policy.version,
    )

    return CreateProjectRolesResponse(
        project_roles_id=policy.project_roles_id,
        policy_id=policy.policy_id,
        project_id=policy.project_id,
        version=policy.version,
    )


@roles_router.get("/{project_roles_id}")
@policies_router.get("/{project_roles_id}")
async def get_policy_by_id_endpoint(
    request: Request,
    response: Response,
    project_roles_id: str,
    db: DatabaseInfra = Depends(get_db_infra),
) -> ActiveProjectRolesResponse:
    """
    Get a specific policy version by ID.

    Used for previewing previous policy versions without activating them.
    Requires an authenticated project context.
    Returns 404 if policy doesn't exist or belongs to a different project.
    """
    project_id = await get_project_from_auth(request, db)
    server_db = db.get_manager("server")

    # Fetch the policy, scoped to the project
    result = await server_db.fetch_one(
        """
        SELECT pp.policy_id, pp.project_id, pp.version, pp.bundle_json,
               pp.created_by_workspace_id, pp.created_at, pp.updated_at
        FROM {{tables.project_policies}} pp
        WHERE pp.policy_id = $1 AND pp.project_id = $2
        """,
        project_roles_id,
        project_id,
    )

    if not result:
        raise HTTPException(
            status_code=404,
            detail="Policy not found or does not belong to this project",
        )

    # Parse bundle_json
    bundle_data = result["bundle_json"]
    if isinstance(bundle_data, str):
        bundle_data = json.loads(bundle_data)

    bundle = PolicyBundle(**bundle_data)

    # Build response (same shape as GET /active)
    invariants = [
        Invariant(
            id=inv.get("id", ""),
            title=inv.get("title", ""),
            body_md=inv.get("body_md", ""),
        )
        for inv in bundle.invariants
    ]

    roles = {
        k: RoleDefinition(
            title=v.get("title", k),
            playbook_md=v.get("playbook_md", ""),
        )
        for k, v in bundle.roles.items()
    }

    return ActiveProjectRolesResponse(
        project_roles_id=str(result["policy_id"]),
        policy_id=str(result["policy_id"]),
        project_id=str(result["project_id"]),
        version=result["version"],
        updated_at=result["updated_at"],
        invariants=invariants,
        roles=roles,
        selected_role=None,
        adapters=bundle.adapters,
    )


@roles_router.post("/{project_roles_id}/activate")
@policies_router.post("/{project_roles_id}/activate")
async def activate_policy_endpoint(
    request: Request,
    project_roles_id: str,
    db: DatabaseInfra = Depends(get_db_infra),
) -> ActivateProjectRolesResponse:
    """
    Set a policy as the active policy for the project.

    Requires an authenticated project context.
    """
    project_id = await get_project_from_auth(request, db)
    server_db = db.get_manager("server")

    # Get current active policy for audit
    current_active = await server_db.fetch_one(
        "SELECT active_policy_id FROM {{tables.projects}} WHERE id = $1 AND deleted_at IS NULL",
        project_id,
    )
    previous_policy_id = (
        str(current_active["active_policy_id"])
        if current_active and current_active["active_policy_id"]
        else None
    )

    # Activate the policy (validates ownership)
    await activate_policy(
        server_db,
        project_id=project_id,
        policy_id=project_roles_id,
    )

    # Add audit log entry
    await server_db.execute(
        """
        INSERT INTO {{tables.audit_log}} (project_id, event_type, details)
        VALUES ($1, $2, $3::jsonb)
        """,
        project_id,
        "policy_activated",
        json.dumps(
            {
                "project_id": project_id,
                "policy_id": project_roles_id,
                "previous_policy_id": previous_policy_id,
            }
        ),
    )

    logger.info(
        "Policy activated via API: project=%s policy_id=%s (was: %s)",
        project_id,
        project_roles_id,
        previous_policy_id,
    )

    return ActivateProjectRolesResponse(
        activated=True,
        active_project_roles_id=project_roles_id,
        active_policy_id=project_roles_id,
    )


@roles_router.post("/reset")
@policies_router.post("/reset")
async def reset_policy_to_default_endpoint(
    request: Request,
    db: DatabaseInfra = Depends(get_db_infra),
) -> ResetProjectRolesResponse:
    """
    Reset the project's policy to the current default bundle.

    Reloads default invariants and roles from markdown files on disk, creates
    a new policy version, and activates it. Prior versions are preserved.

    Requires an authenticated project context.
    """
    project_id = await get_project_from_auth(request, db)
    server_db = db.get_manager("server")

    current_active = await server_db.fetch_one(
        "SELECT active_policy_id FROM {{tables.projects}} WHERE id = $1 AND deleted_at IS NULL",
        project_id,
    )
    previous_policy_id = (
        str(current_active["active_policy_id"])
        if current_active and current_active["active_policy_id"]
        else None
    )

    # Reload defaults from disk (atomic, protected by lock)
    try:
        fresh_bundle = get_default_bundle(force_reload=True)
    except Exception as e:
        logger.error("Failed to reload default bundle: %s", e, exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to reload default policy bundle: {e}",
        )

    policy = await create_policy_version(
        server_db,
        project_id=project_id,
        base_policy_id=previous_policy_id,
        bundle=fresh_bundle,
        created_by_workspace_id=None,
    )
    await activate_policy(server_db, project_id=project_id, policy_id=policy.policy_id)

    await server_db.execute(
        """
        INSERT INTO {{tables.audit_log}} (project_id, event_type, details)
        VALUES ($1, $2, $3::jsonb)
        """,
        project_id,
        "policy_reset_to_default",
        json.dumps(
            {
                "project_id": project_id,
                "policy_id": policy.policy_id,
                "version": policy.version,
                "previous_policy_id": previous_policy_id,
            }
        ),
    )

    logger.info(
        "Policy reset to default via API: project=%s policy_id=%s version=%d (was: %s)",
        project_id,
        policy.policy_id,
        policy.version,
        previous_policy_id,
    )

    return ResetProjectRolesResponse(
        reset=True,
        active_project_roles_id=policy.project_roles_id,
        active_policy_id=policy.policy_id,
        version=policy.version,
    )
