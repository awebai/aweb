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

from aweb.team_auth_deps import get_team_identity

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
    id: str
    team_address: str
    version: int
    document: ProjectInstructionsDocument
    created_by_alias: Optional[str]
    created_at: datetime
    updated_at: Optional[datetime] = None


class ActiveProjectInstructionsResponse(BaseModel):
    project_instructions_id: str
    active_project_instructions_id: Optional[str] = None
    team_address: str
    version: int
    updated_at: Optional[datetime] = None
    document: ProjectInstructionsDocument


class CreateProjectInstructionsRequest(BaseModel):
    document: ProjectInstructionsDocument
    base_project_instructions_id: Optional[str] = Field(
        None,
        description="Optional project_instructions_id that this version is based on.",
    )


class CreateProjectInstructionsResponse(BaseModel):
    project_instructions_id: str
    team_address: str
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
    created_by_alias: Optional[str]
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
    team_address: str,
    base_instructions_id: Optional[str],
    document: Dict[str, Any],
    created_by_alias: Optional[str],
) -> ProjectInstructionsVersion:
    result = await db.fetch_one(
        """
        WITH active_check AS (
            SELECT id
            FROM {{tables.project_instructions}}
            WHERE team_address = $1 AND is_active = true
        ),
        base_check AS (
            SELECT 1 AS ok
            WHERE $4::TEXT IS NULL
               OR EXISTS (SELECT 1 FROM active_check WHERE id::text = $4)
        ),
        next_version AS (
            SELECT COALESCE(MAX(version), 0) + 1 AS version
            FROM {{tables.project_instructions}}
            WHERE team_address = $1
        )
        INSERT INTO {{tables.project_instructions}} (
            team_address,
            version,
            document_json,
            created_by_alias
        )
        SELECT $1, nv.version, $2::jsonb, $3
        FROM next_version nv, base_check bc
        RETURNING id, team_address, version, document_json,
                  created_by_alias, created_at, updated_at
        """,
        team_address,
        json.dumps(document),
        created_by_alias,
        base_instructions_id,
    )

    if not result:
        active = await db.fetch_one(
            """
            SELECT id FROM {{tables.project_instructions}}
            WHERE team_address = $1 AND is_active = true
            """,
            team_address,
        )
        active_id = str(active["id"]) if active else "none"
        raise HTTPException(
            status_code=409,
            detail=(
                "Project instructions conflict: base_instructions_id "
                f"{base_instructions_id} does not match active project instructions "
                f"{active_id}. Re-read the active project instructions and retry."
            ),
        )

    document_data = result["document_json"]
    if isinstance(document_data, str):
        document_data = json.loads(document_data)

    return ProjectInstructionsVersion(
        id=str(result["id"]),
        team_address=result["team_address"],
        version=result["version"],
        document=ProjectInstructionsDocument(**_normalize_document_data(document_data)),
        created_by_alias=result["created_by_alias"],
        created_at=result["created_at"],
        updated_at=result["updated_at"],
    )


async def activate_project_instructions(
    db: AsyncDatabaseManager,
    *,
    team_address: str,
    instructions_id: str,
) -> bool:
    target = await db.fetch_one(
        """
        SELECT id, team_address
        FROM {{tables.project_instructions}}
        WHERE id = $1
        """,
        instructions_id,
    )
    if not target:
        raise HTTPException(status_code=404, detail="Project instructions not found")

    if target["team_address"] != team_address:
        raise HTTPException(
            status_code=400,
            detail="Project instructions do not belong to this team",
        )

    # Deactivate the currently active version (if any)
    await db.execute(
        """
        UPDATE {{tables.project_instructions}}
        SET is_active = false
        WHERE team_address = $1 AND is_active = true
        """,
        team_address,
    )

    # Activate the target version
    await db.execute(
        """
        UPDATE {{tables.project_instructions}}
        SET is_active = true
        WHERE id = $1
        """,
        instructions_id,
    )

    return True


async def get_active_project_instructions(
    db: AsyncDatabaseManager,
    team_address: str,
    *,
    bootstrap_if_missing: bool = True,
) -> Optional[ProjectInstructionsVersion]:
    result = await db.fetch_one(
        """
        SELECT pi.id, pi.team_address, pi.version, pi.document_json,
               pi.created_by_alias, pi.created_at, pi.updated_at
        FROM {{tables.project_instructions}} pi
        WHERE pi.team_address = $1 AND pi.is_active = true
        """,
        team_address,
    )

    if result:
        document_data = result["document_json"]
        if isinstance(document_data, str):
            document_data = json.loads(document_data)

        return ProjectInstructionsVersion(
            id=str(result["id"]),
            team_address=result["team_address"],
            version=result["version"],
            document=ProjectInstructionsDocument(**_normalize_document_data(document_data)),
            created_by_alias=result["created_by_alias"],
            created_at=result["created_at"],
            updated_at=result["updated_at"],
        )

    if not bootstrap_if_missing:
        return None

    from .project_roles import get_active_project_roles

    await get_active_project_roles(db, team_address, bootstrap_if_missing=True)
    raw_roles_result = await db.fetch_one(
        """
        SELECT pr.bundle_json
        FROM {{tables.project_roles}} pr
        WHERE pr.team_address = $1 AND pr.is_active = true
        """,
        team_address,
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
            team_address=team_address,
            base_instructions_id=None,
            document=document,
            created_by_alias=None,
        )
    except (QueryError, asyncpg.exceptions.UniqueViolationError) as exc:
        if isinstance(exc, QueryError) and not isinstance(
            exc.__cause__, asyncpg.exceptions.UniqueViolationError
        ):
            raise
        # A concurrent bootstrap already created the version -- read it
        logger.info("Concurrent bootstrap for team %s, retrying read", team_address)
        return await get_active_project_instructions(
            db, team_address, bootstrap_if_missing=False
        )
    await activate_project_instructions(
        db,
        team_address=team_address,
        instructions_id=instructions_version.id,
    )
    return instructions_version


@instructions_router.get("/active")
async def get_active_project_instructions_endpoint(
    request: Request,
    response: Response,
    if_none_match: Optional[str] = Header(None, alias="If-None-Match"),
    db: DatabaseInfra = Depends(get_db_infra),
) -> ActiveProjectInstructionsResponse:
    identity = await get_team_identity(request, db)
    aweb_db = db.get_manager("aweb")

    version = await get_active_project_instructions(aweb_db, identity.team_address)
    if not version:
        raise HTTPException(status_code=404, detail="No active project instructions found")

    etag = _generate_etag(version.id, version.updated_at or version.created_at)
    response.headers["ETag"] = etag
    if if_none_match and if_none_match == etag:
        return Response(status_code=304, headers={"ETag": etag})

    return ActiveProjectInstructionsResponse(
        project_instructions_id=version.id,
        active_project_instructions_id=version.id,
        team_address=version.team_address,
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
    identity = await get_team_identity(request, db)
    aweb_db = db.get_manager("aweb")

    await get_active_project_instructions(aweb_db, identity.team_address, bootstrap_if_missing=True)

    rows = await aweb_db.fetch_all(
        """
        SELECT id, version, created_at, created_by_alias, is_active
        FROM {{tables.project_instructions}}
        WHERE team_address = $1
        ORDER BY version DESC
        LIMIT $2
        """,
        identity.team_address,
        limit,
    )

    return ProjectInstructionsHistoryResponse(
        project_instructions_versions=[
            ProjectInstructionsHistoryItem(
                project_instructions_id=str(row["id"]),
                version=row["version"],
                created_at=row["created_at"],
                created_by_alias=row["created_by_alias"],
                is_active=row["is_active"],
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
    identity = await get_team_identity(request, db)
    aweb_db = db.get_manager("aweb")

    version = await create_project_instructions_version(
        aweb_db,
        team_address=identity.team_address,
        base_instructions_id=payload.base_project_instructions_id,
        document=payload.document.model_dump(),
        created_by_alias=identity.alias,
    )

    logger.info(
        "Project instructions created via API: team=%s id=%s version=%d",
        identity.team_address,
        version.id,
        version.version,
    )

    return CreateProjectInstructionsResponse(
        project_instructions_id=version.id,
        team_address=version.team_address,
        version=version.version,
    )


@instructions_router.get("/{project_instructions_id}")
async def get_project_instructions_by_id_endpoint(
    request: Request,
    project_instructions_id: str,
    db: DatabaseInfra = Depends(get_db_infra),
) -> ActiveProjectInstructionsResponse:
    identity = await get_team_identity(request, db)
    aweb_db = db.get_manager("aweb")

    result = await aweb_db.fetch_one(
        """
        SELECT pi.id, pi.team_address, pi.version, pi.document_json,
               pi.created_by_alias, pi.created_at, pi.updated_at
        FROM {{tables.project_instructions}} pi
        WHERE pi.id = $1 AND pi.team_address = $2
        """,
        project_instructions_id,
        identity.team_address,
    )
    if not result:
        raise HTTPException(
            status_code=404,
            detail="Project instructions not found or do not belong to this team",
        )

    document_data = result["document_json"]
    if isinstance(document_data, str):
        document_data = json.loads(document_data)

    return ActiveProjectInstructionsResponse(
        project_instructions_id=str(result["id"]),
        active_project_instructions_id=None,
        team_address=result["team_address"],
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
    identity = await get_team_identity(request, db)
    aweb_db = db.get_manager("aweb")

    previous_active = await aweb_db.fetch_one(
        """
        SELECT id FROM {{tables.project_instructions}}
        WHERE team_address = $1 AND is_active = true
        """,
        identity.team_address,
    )
    previous_instructions_id = str(previous_active["id"]) if previous_active else None

    await activate_project_instructions(
        aweb_db,
        team_address=identity.team_address,
        instructions_id=project_instructions_id,
    )

    logger.info(
        "Project instructions activated via API: team=%s id=%s (was: %s)",
        identity.team_address,
        project_instructions_id,
        previous_instructions_id,
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
    identity = await get_team_identity(request, db)
    aweb_db = db.get_manager("aweb")

    previous_active = await aweb_db.fetch_one(
        """
        SELECT id FROM {{tables.project_instructions}}
        WHERE team_address = $1 AND is_active = true
        """,
        identity.team_address,
    )
    previous_instructions_id = str(previous_active["id"]) if previous_active else None

    version = await create_project_instructions_version(
        aweb_db,
        team_address=identity.team_address,
        base_instructions_id=previous_instructions_id,
        document=get_default_project_instructions(),
        created_by_alias=None,
    )
    await activate_project_instructions(
        aweb_db,
        team_address=identity.team_address,
        instructions_id=version.id,
    )

    logger.info(
        "Project instructions reset to default via API: team=%s id=%s version=%d (was: %s)",
        identity.team_address,
        version.id,
        version.version,
        previous_instructions_id,
    )

    return ResetProjectInstructionsResponse(
        reset=True,
        active_project_instructions_id=version.id,
        version=version.version,
    )
