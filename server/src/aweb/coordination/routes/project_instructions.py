"""Project-wide shared instructions endpoints."""

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
from pydantic import BaseModel, Field, field_validator

from aweb.auth import enforce_actor_binding, validate_workspace_id
from aweb.aweb_introspection import get_identity_from_auth, get_project_from_auth

from ...db import DatabaseInfra, get_db_infra
from ..defaults import get_default_project_instructions

logger = logging.getLogger(__name__)

instructions_router = APIRouter(prefix="/v1/instructions", tags=["instructions"])
router = instructions_router


def _generate_etag(resource_id: str, updated_at: datetime) -> str:
    content = f"{resource_id}:{updated_at.isoformat()}"
    return f'"{hashlib.sha256(content.encode()).hexdigest()[:16]}"'


class ProjectInstructionsDocument(BaseModel):
    body_md: str = ""
    format: str = "markdown"

    @field_validator("format")
    @classmethod
    def _validate_format(cls, value: str) -> str:
        normalized = (value or "").strip().lower()
        if normalized != "markdown":
            raise ValueError("project instructions only support format=markdown")
        return normalized


class ProjectInstructionsVersion(BaseModel):
    project_instructions_id: str
    project_id: str
    version: int
    document: ProjectInstructionsDocument
    created_by_workspace_id: Optional[str]
    created_at: datetime
    updated_at: datetime


class ActiveProjectInstructionsResponse(BaseModel):
    project_instructions_id: str
    active_project_instructions_id: Optional[str] = None
    project_id: str
    version: int
    updated_at: datetime
    document: ProjectInstructionsDocument


class CreateProjectInstructionsRequest(BaseModel):
    document: ProjectInstructionsDocument
    base_project_instructions_id: Optional[str] = Field(
        None,
        description="Optional project_instructions_id that this version is based on.",
    )
    created_by_workspace_id: Optional[str] = Field(
        None,
        description="Optional workspace_id of the creator for audit trail.",
    )


class CreateProjectInstructionsResponse(BaseModel):
    project_instructions_id: str
    project_id: str
    version: int
    created: bool = True


class ActivateProjectInstructionsResponse(BaseModel):
    activated: bool
    active_project_instructions_id: str


class ResetProjectInstructionsResponse(BaseModel):
    reset: bool
    active_project_instructions_id: str
    version: int


class ProjectInstructionsHistoryItem(BaseModel):
    project_instructions_id: str
    version: int
    created_at: datetime
    created_by_workspace_id: Optional[str]
    is_active: bool


class ProjectInstructionsHistoryResponse(BaseModel):
    project_instructions_versions: List[ProjectInstructionsHistoryItem]


def _normalize_document_data(document_data: Any) -> Dict[str, Any]:
    if isinstance(document_data, str):
        return {"body_md": document_data, "format": "markdown"}
    if isinstance(document_data, dict):
        normalized = dict(document_data)
        normalized.setdefault("format", "markdown")
        normalized.setdefault("body_md", "")
        return normalized
    raise ValueError("project instructions document must be a JSON object or markdown string")


def _legacy_invariants_to_markdown(bundle_data: Dict[str, Any]) -> str:
    invariants = bundle_data.get("invariants")
    if not isinstance(invariants, list):
        return ""

    sections: List[str] = []
    for item in invariants:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or item.get("id") or "").strip()
        body = str(item.get("body_md") or "").strip()
        if title and body:
            sections.append(f"## {title}\n\n{body}")
        elif title:
            sections.append(f"## {title}")
        elif body:
            sections.append(body)
    return "\n\n".join(section for section in sections if section.strip()).strip()


async def create_project_instructions_version(
    db: AsyncDatabaseManager,
    *,
    project_id: str,
    base_project_instructions_id: Optional[str],
    document: Dict[str, Any],
    created_by_workspace_id: Optional[str],
) -> ProjectInstructionsVersion:
    project = await db.fetch_one(
        "SELECT id FROM {{tables.projects}} WHERE id = $1 AND deleted_at IS NULL",
        project_id,
    )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    result = await db.fetch_one(
        """
        WITH locked_project AS (
            SELECT id, active_project_instructions_id
            FROM {{tables.projects}}
            WHERE id = $1 AND deleted_at IS NULL
            FOR UPDATE
        ),
        base_check AS (
            SELECT id FROM locked_project
            WHERE $4::UUID IS NULL OR active_project_instructions_id = $4::UUID
        ),
        next_version AS (
            SELECT COALESCE(MAX(version), 0) + 1 AS version
            FROM {{tables.project_instructions}}
            WHERE project_id = $1
        )
        INSERT INTO {{tables.project_instructions}} (
            project_id,
            version,
            document_json,
            created_by_workspace_id
        )
        SELECT $1, nv.version, $2::jsonb, $3
        FROM next_version nv, base_check bc
        RETURNING project_instructions_id, project_id, version, document_json,
                  created_by_workspace_id, created_at, updated_at
        """,
        project_id,
        json.dumps(document),
        created_by_workspace_id,
        base_project_instructions_id,
    )

    if not result:
        active = await db.fetch_one(
            "SELECT active_project_instructions_id FROM {{tables.projects}} WHERE id = $1",
            project_id,
        )
        active_id = (
            str(active["active_project_instructions_id"])
            if active and active["active_project_instructions_id"]
            else "none"
        )
        raise HTTPException(
            status_code=409,
            detail=(
                "Project instructions conflict: base_project_instructions_id "
                f"{base_project_instructions_id} does not match active project instructions "
                f"{active_id}. Re-read the active project instructions and retry."
            ),
        )

    document_data = result["document_json"]
    if isinstance(document_data, str):
        document_data = json.loads(document_data)

    return ProjectInstructionsVersion(
        project_instructions_id=str(result["project_instructions_id"]),
        project_id=str(result["project_id"]),
        version=result["version"],
        document=ProjectInstructionsDocument(**_normalize_document_data(document_data)),
        created_by_workspace_id=(
            str(result["created_by_workspace_id"]) if result["created_by_workspace_id"] else None
        ),
        created_at=result["created_at"],
        updated_at=result["updated_at"],
    )


async def activate_project_instructions(
    db: AsyncDatabaseManager,
    *,
    project_id: str,
    project_instructions_id: str,
) -> bool:
    project_instructions_version = await db.fetch_one(
        """
        SELECT project_instructions_id, project_id
        FROM {{tables.project_instructions}}
        WHERE project_instructions_id = $1
        """,
        project_instructions_id,
    )
    if not project_instructions_version:
        raise HTTPException(status_code=404, detail="Project instructions not found")

    if str(project_instructions_version["project_id"]) != project_id:
        raise HTTPException(
            status_code=400,
            detail="Project instructions do not belong to this project",
        )

    result = await db.fetch_one(
        """
        UPDATE {{tables.projects}}
        SET active_project_instructions_id = $2
        WHERE id = $1
        RETURNING id
        """,
        project_id,
        project_instructions_id,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Project not found")
    return True


async def get_active_project_instructions(
    db: AsyncDatabaseManager,
    project_id: str,
    *,
    bootstrap_if_missing: bool = True,
) -> Optional[ProjectInstructionsVersion]:
    result = await db.fetch_one(
        """
        SELECT pi.project_instructions_id, pi.project_id, pi.version, pi.document_json,
               pi.created_by_workspace_id, pi.created_at, pi.updated_at
        FROM {{tables.projects}} p
        JOIN {{tables.project_instructions}} pi
          ON pi.project_instructions_id = p.active_project_instructions_id
        WHERE p.id = $1
        """,
        project_id,
    )

    if result:
        document_data = result["document_json"]
        if isinstance(document_data, str):
            document_data = json.loads(document_data)

        return ProjectInstructionsVersion(
            project_instructions_id=str(result["project_instructions_id"]),
            project_id=str(result["project_id"]),
            version=result["version"],
            document=ProjectInstructionsDocument(**_normalize_document_data(document_data)),
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

    from .project_roles import get_active_project_roles

    await get_active_project_roles(db, project_id, bootstrap_if_missing=True)
    raw_roles_result = await db.fetch_one(
        """
        SELECT pr.bundle_json
        FROM {{tables.projects}} p
        LEFT JOIN {{tables.project_roles}} pr
          ON pr.project_roles_id = p.active_project_roles_id
        WHERE p.id = $1
        """,
        project_id,
    )
    default_document = get_default_project_instructions()
    document = dict(default_document)
    if raw_roles_result and raw_roles_result["bundle_json"] is not None:
        bundle_data = raw_roles_result["bundle_json"]
        if isinstance(bundle_data, str):
            bundle_data = json.loads(bundle_data)
        legacy_body = _legacy_invariants_to_markdown(bundle_data)
        if legacy_body:
            document["body_md"] = legacy_body

    try:
        instructions_version = await create_project_instructions_version(
            db,
            project_id=project_id,
            base_project_instructions_id=None,
            document=document,
            created_by_workspace_id=None,
        )
    except (QueryError, asyncpg.exceptions.UniqueViolationError) as exc:
        if isinstance(exc, QueryError) and not isinstance(
            exc.__cause__, asyncpg.exceptions.UniqueViolationError
        ):
            raise
        # A concurrent bootstrap already created the version — read it
        logger.info("Concurrent bootstrap for project %s, retrying read", project_id)
        return await get_active_project_instructions(
            db, project_id, bootstrap_if_missing=False
        )
    await activate_project_instructions(
        db,
        project_id=project_id,
        project_instructions_id=instructions_version.project_instructions_id,
    )
    return instructions_version


@instructions_router.get("/active")
async def get_active_project_instructions_endpoint(
    request: Request,
    response: Response,
    if_none_match: Optional[str] = Header(None, alias="If-None-Match"),
    db: DatabaseInfra = Depends(get_db_infra),
) -> ActiveProjectInstructionsResponse:
    project_id = await get_project_from_auth(request, db)
    server_db = db.get_manager("server")

    version = await get_active_project_instructions(server_db, project_id)
    if not version:
        raise HTTPException(status_code=404, detail="Project not found")

    etag = _generate_etag(version.project_instructions_id, version.updated_at)
    response.headers["ETag"] = etag
    if if_none_match and if_none_match == etag:
        return Response(status_code=304, headers={"ETag": etag})

    return ActiveProjectInstructionsResponse(
        project_instructions_id=version.project_instructions_id,
        active_project_instructions_id=version.project_instructions_id,
        project_id=version.project_id,
        version=version.version,
        updated_at=version.updated_at,
        document=version.document,
    )


@instructions_router.get("/history")
async def list_project_instructions_history(
    request: Request,
    limit: int = Query(20, ge=1, le=100, description="Max number of versions to return"),
    db: DatabaseInfra = Depends(get_db_infra),
) -> ProjectInstructionsHistoryResponse:
    project_id = await get_project_from_auth(request, db)
    server_db = db.get_manager("server")

    await get_active_project_instructions(server_db, project_id, bootstrap_if_missing=True)

    active_result = await server_db.fetch_one(
        """
        SELECT active_project_instructions_id
        FROM {{tables.projects}}
        WHERE id = $1 AND deleted_at IS NULL
        """,
        project_id,
    )
    active_project_instructions_id = (
        str(active_result["active_project_instructions_id"])
        if active_result and active_result["active_project_instructions_id"]
        else None
    )

    rows = await server_db.fetch_all(
        """
        SELECT project_instructions_id, version, created_at, created_by_workspace_id
        FROM {{tables.project_instructions}}
        WHERE project_id = $1
        ORDER BY version DESC
        LIMIT $2
        """,
        project_id,
        limit,
    )

    return ProjectInstructionsHistoryResponse(
        project_instructions_versions=[
            ProjectInstructionsHistoryItem(
                project_instructions_id=str(row["project_instructions_id"]),
                version=row["version"],
                created_at=row["created_at"],
                created_by_workspace_id=(
                    str(row["created_by_workspace_id"]) if row["created_by_workspace_id"] else None
                ),
                is_active=(str(row["project_instructions_id"]) == active_project_instructions_id),
            )
            for row in rows
        ]
    )


@instructions_router.post("")
async def create_project_instructions_endpoint(
    request: Request,
    payload: CreateProjectInstructionsRequest,
    db: DatabaseInfra = Depends(get_db_infra),
) -> CreateProjectInstructionsResponse:
    identity = await get_identity_from_auth(request, db)
    project_id = identity.project_id
    server_db = db.get_manager("server")

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

    version = await create_project_instructions_version(
        server_db,
        project_id=project_id,
        base_project_instructions_id=payload.base_project_instructions_id,
        document=payload.document.model_dump(),
        created_by_workspace_id=created_by_workspace_id,
    )

    await server_db.execute(
        """
        INSERT INTO {{tables.audit_log}} (project_id, workspace_id, event_type, details)
        VALUES ($1, $2, $3, $4::jsonb)
        """,
        project_id,
        created_by_workspace_id,
        "project_instructions_created",
        json.dumps(
            {
                "project_id": project_id,
                "project_instructions_id": version.project_instructions_id,
                "version": version.version,
                "base_project_instructions_id": payload.base_project_instructions_id,
            }
        ),
    )

    return CreateProjectInstructionsResponse(
        project_instructions_id=version.project_instructions_id,
        project_id=version.project_id,
        version=version.version,
    )


@instructions_router.get("/{project_instructions_id}")
async def get_project_instructions_by_id_endpoint(
    request: Request,
    project_instructions_id: str,
    db: DatabaseInfra = Depends(get_db_infra),
) -> ActiveProjectInstructionsResponse:
    project_id = await get_project_from_auth(request, db)
    server_db = db.get_manager("server")

    result = await server_db.fetch_one(
        """
        SELECT pi.project_instructions_id, pi.project_id, pi.version, pi.document_json,
               pi.created_by_workspace_id, pi.created_at, pi.updated_at
        FROM {{tables.project_instructions}} pi
        WHERE pi.project_instructions_id = $1 AND pi.project_id = $2
        """,
        project_instructions_id,
        project_id,
    )
    if not result:
        raise HTTPException(
            status_code=404,
            detail="Project instructions not found or do not belong to this project",
        )

    document_data = result["document_json"]
    if isinstance(document_data, str):
        document_data = json.loads(document_data)

    return ActiveProjectInstructionsResponse(
        project_instructions_id=str(result["project_instructions_id"]),
        active_project_instructions_id=None,
        project_id=str(result["project_id"]),
        version=result["version"],
        updated_at=result["updated_at"],
        document=ProjectInstructionsDocument(**_normalize_document_data(document_data)),
    )


@instructions_router.post("/{project_instructions_id}/activate")
async def activate_project_instructions_endpoint(
    request: Request,
    project_instructions_id: str,
    db: DatabaseInfra = Depends(get_db_infra),
) -> ActivateProjectInstructionsResponse:
    project_id = await get_project_from_auth(request, db)
    server_db = db.get_manager("server")

    current_active = await server_db.fetch_one(
        """
        SELECT active_project_instructions_id
        FROM {{tables.projects}}
        WHERE id = $1 AND deleted_at IS NULL
        """,
        project_id,
    )
    previous_project_instructions_id = (
        str(current_active["active_project_instructions_id"])
        if current_active and current_active["active_project_instructions_id"]
        else None
    )

    await activate_project_instructions(
        server_db,
        project_id=project_id,
        project_instructions_id=project_instructions_id,
    )

    await server_db.execute(
        """
        INSERT INTO {{tables.audit_log}} (project_id, event_type, details)
        VALUES ($1, $2, $3::jsonb)
        """,
        project_id,
        "project_instructions_activated",
        json.dumps(
            {
                "project_id": project_id,
                "project_instructions_id": project_instructions_id,
                "previous_project_instructions_id": previous_project_instructions_id,
            }
        ),
    )

    return ActivateProjectInstructionsResponse(
        activated=True,
        active_project_instructions_id=project_instructions_id,
    )


@instructions_router.post("/reset")
async def reset_project_instructions_to_default_endpoint(
    request: Request,
    db: DatabaseInfra = Depends(get_db_infra),
) -> ResetProjectInstructionsResponse:
    project_id = await get_project_from_auth(request, db)
    server_db = db.get_manager("server")

    current_active = await server_db.fetch_one(
        """
        SELECT active_project_instructions_id
        FROM {{tables.projects}}
        WHERE id = $1 AND deleted_at IS NULL
        """,
        project_id,
    )
    previous_project_instructions_id = (
        str(current_active["active_project_instructions_id"])
        if current_active and current_active["active_project_instructions_id"]
        else None
    )

    version = await create_project_instructions_version(
        server_db,
        project_id=project_id,
        base_project_instructions_id=previous_project_instructions_id,
        document=get_default_project_instructions(),
        created_by_workspace_id=None,
    )
    await activate_project_instructions(
        server_db,
        project_id=project_id,
        project_instructions_id=version.project_instructions_id,
    )

    await server_db.execute(
        """
        INSERT INTO {{tables.audit_log}} (project_id, event_type, details)
        VALUES ($1, $2, $3::jsonb)
        """,
        project_id,
        "project_instructions_reset_to_default",
        json.dumps(
            {
                "project_id": project_id,
                "project_instructions_id": version.project_instructions_id,
                "version": version.version,
                "previous_project_instructions_id": previous_project_instructions_id,
            }
        ),
    )

    return ResetProjectInstructionsResponse(
        reset=True,
        active_project_instructions_id=version.project_instructions_id,
        version=version.version,
    )
