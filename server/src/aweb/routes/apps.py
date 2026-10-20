"""Core app registry and app grants routes."""

from __future__ import annotations

import base64
import binascii

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from aweb.app_registry import (
    APP_ID_RE,
    AppEmitKey,
    AppEventType,
    AppInstall,
    install_app,
    list_installed_apps,
    validate_team_id,
)
from aweb.audit import OperatorAuditRoute, audit_success
from aweb.db import DatabaseInfra, get_db_infra
from aweb.internal_auth import parse_internal_auth_context
from aweb.service_errors import RESOURCE_NOT_FOUND_DETAIL, ServiceError
from aweb.team_auth_deps import get_team_identity

router = APIRouter(prefix="/v1/apps", tags=["apps"], route_class=OperatorAuditRoute)

MAX_MANIFEST_BYTES = 10 << 20


class AppEventTypeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str = Field(..., min_length=1, max_length=128)
    default_delivery_intent: str = "ambient"
    description: str = ""


class AppEmitKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kid: str = Field(..., min_length=1, max_length=128)
    did_key: str = Field(..., min_length=1, max_length=512)


class AppInstallRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    app_id: str = Field(..., min_length=1, max_length=63)
    origin: str = Field(..., min_length=1, max_length=512)
    app_version: str = Field(..., min_length=1, max_length=128)
    manifest_version: int = Field(..., gt=0)
    digest: str = Field(..., min_length=71, max_length=71)
    granted_scopes: list[str] = Field(default_factory=list)
    events: list[AppEventTypeRequest] = Field(default_factory=list)
    event_emitters: list[AppEmitKeyRequest] = Field(default_factory=list)
    # Standard base64 of the exact manifest bytes that hash to ``digest``.
    manifest: str | None = Field(default=None, max_length=(MAX_MANIFEST_BYTES // 3 + 1) * 4)


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
            raise HTTPException(status_code=404, detail=RESOURCE_NOT_FOUND_DETAIL)
        return team_id, internal.get("actor_id")

    identity = await get_team_identity(request, db_infra)
    if identity.team_id != team_id:
        raise HTTPException(status_code=404, detail=RESOURCE_NOT_FOUND_DETAIL)
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


def _decode_manifest(value: str | None) -> bytes | None:
    if value is None:
        return None
    try:
        manifest = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status_code=422, detail="manifest must be standard base64") from exc
    if len(manifest) > MAX_MANIFEST_BYTES:
        raise HTTPException(status_code=413, detail="manifest exceeds the size bound")
    return manifest


@router.post("/install", response_model=InstalledAppResponse)
async def install_app_route(
    request: Request,
    payload: AppInstallRequest,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> InstalledAppResponse:
    app_id = payload.app_id.strip().lower()
    request.state.operator_audit_target = f"app:{app_id}" if APP_ID_RE.fullmatch(app_id) else "app:invalid"
    try:
        identity = await get_team_identity(request, db_infra)
        manifest = _decode_manifest(payload.manifest)
        db = db_infra.get_manager("aweb")

        async def audit(tx) -> None:
            await audit_success(tx, request, identity.team_id)

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
            event_types=[
                AppEventType(
                    type=item.type,
                    default_delivery_intent=item.default_delivery_intent,
                    description=item.description,
                )
                for item in payload.events
            ],
            emit_keys=[AppEmitKey(kid=item.kid, did_key=item.did_key) for item in payload.event_emitters],
            manifest=manifest,
            audit=audit,
        )
    except ServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    return _as_response(app)
