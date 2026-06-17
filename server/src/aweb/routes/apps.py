"""Core app registry and app grants routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from aweb.app_registry import AppInstall, install_app, list_installed_apps, validate_team_id
from aweb.db import DatabaseInfra, get_db_infra
from aweb.internal_auth import parse_internal_auth_context
from aweb.service_errors import ServiceError
from aweb.team_auth_deps import get_team_identity

router = APIRouter(prefix="/v1/apps", tags=["apps"])


class AppInstallRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    app_id: str = Field(..., min_length=1, max_length=63)
    origin: str = Field(..., min_length=1, max_length=512)
    app_version: str = Field(..., min_length=1, max_length=128)
    manifest_version: int = Field(..., gt=0)
    digest: str = Field(..., min_length=71, max_length=71)
    granted_scopes: list[str] = Field(default_factory=list)


class InstalledAppResponse(BaseModel):
    app_id: str
    origin: str
    app_version: str
    manifest_version: int
    digest: str
    granted_scopes: list[str]


class InstalledAppsResponse(BaseModel):
    team_id: str
    apps: list[InstalledAppResponse]


def _as_response(app: AppInstall) -> InstalledAppResponse:
    return InstalledAppResponse(
        app_id=app.app_id,
        origin=app.origin,
        app_version=app.app_version,
        manifest_version=app.manifest_version,
        digest=app.digest,
        granted_scopes=app.granted_scopes,
    )


async def _authorized_team_id(request: Request, db_infra: DatabaseInfra, requested_team_id: str) -> tuple[str, str | None]:
    team_id = validate_team_id(requested_team_id)

    internal = parse_internal_auth_context(request)
    if internal is not None:
        if internal["team_id"] != team_id:
            raise HTTPException(status_code=403, detail="Not authorized for requested team_id")
        return team_id, internal.get("actor_id")

    identity = await get_team_identity(request, db_infra)
    if identity.team_id != team_id:
        raise HTTPException(status_code=403, detail="Not authorized for requested team_id")
    return team_id, identity.agent_id


@router.get("/installed", response_model=InstalledAppsResponse)
async def list_installed_apps_route(
    request: Request,
    team_id: str = Query(..., min_length=1),
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> InstalledAppsResponse:
    try:
        authorized_team_id, _ = await _authorized_team_id(request, db_infra, team_id)
        db = db_infra.get_manager("aweb")
        apps = await list_installed_apps(db, team_id=authorized_team_id)
    except ServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    return InstalledAppsResponse(
        team_id=authorized_team_id,
        apps=[_as_response(app) for app in apps],
    )


@router.post("/install", response_model=InstalledAppResponse)
async def install_app_route(
    request: Request,
    payload: AppInstallRequest,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> InstalledAppResponse:
    try:
        identity = await get_team_identity(request, db_infra)
        db = db_infra.get_manager("aweb")
        app = await install_app(
            db,
            team_id=identity.team_id,
            app_id=payload.app_id,
            origin=payload.origin,
            app_version=payload.app_version,
            manifest_version=payload.manifest_version,
            digest=payload.digest,
            granted_scopes=payload.granted_scopes,
            installed_by_agent_id=identity.agent_id,
        )
    except ServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    return _as_response(app)
