"""Origin-verified app installation and management routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ConfigDict, Field, StrictInt
from pydantic import ValidationError as PydanticValidationError

from aweb.app_manifests import ManifestFetcher
from aweb.app_registry import (
    APP_ID_RE, get_installation_on, list_installed_apps, normalize_app_id, validate_team_id,
)
from aweb.audit import AuditActor, OperatorAuditRoute, audit_success, set_verified_audit_actor
from aweb.db import DatabaseInfra, get_db_infra
from aweb.install_authority import require_install_admin
from aweb.installations import install_verified_manifest_on
from aweb.internal_auth import parse_internal_auth_context
from aweb.service_errors import RESOURCE_NOT_FOUND_DETAIL, ServiceError
from aweb.team_auth_deps import get_team_identity

router = APIRouter(prefix="/v1/apps", tags=["apps"], route_class=OperatorAuditRoute)
MAX_INSTALL_BODY_BYTES = 1 << 20


class AppInstallRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    app_id: str = Field(..., min_length=1, max_length=63)
    origin: str = Field(..., min_length=1, max_length=512)
    digest: str = Field(..., min_length=71, max_length=71)
    granted_scopes: list[str] = Field(default_factory=list)
    expected_generation: StrictInt | None = Field(None, ge=1, le=9223372036854775807)


class AppPreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    origin: str = Field(..., min_length=1, max_length=512)


class InstalledAppResponse(BaseModel):
    app_id: str
    origin: str
    app_version: str
    manifest_version: int
    digest: str
    granted_scopes: list[str]
    installation_id: str
    generation: int
    state: str
    origin_verified: bool
    origin_verification_error: str | None = None


class InstalledAppsResponse(BaseModel):
    team_id: str
    apps: list[InstalledAppResponse]


def _failure(exc: ServiceError) -> HTTPException:
    code = getattr(exc, "code", None)
    detail = {"code": code, "message": str(exc)} if code is not None else exc.detail
    return HTTPException(status_code=exc.status_code, detail=detail)


async def _caller(request: Request, infra: DatabaseInfra, requested: str | None):
    internal = parse_internal_auth_context(request)
    if internal is not None:
        team_id = internal["team_id"]
        set_verified_audit_actor(request, AuditActor(
            team_id=team_id, principal_type=internal["principal_type"], auth_mode="internal",
            user_id=internal["principal_id"],
        ))
        identity = None
    else:
        identity = await get_team_identity(request, infra)
        team_id = identity.team_id
    if requested is not None and validate_team_id(requested) != team_id:
        raise HTTPException(status_code=404, detail=RESOURCE_NOT_FOUND_DETAIL)
    return team_id, identity


def _fetcher(request: Request) -> ManifestFetcher:
    configured = getattr(request.app.state, "manifest_fetcher", None)
    return configured if configured is not None else ManifestFetcher()


async def _payload(request: Request, model):
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_INSTALL_BODY_BYTES:
            raise HTTPException(status_code=413, detail="install request exceeds the size bound")
    try:
        return model.model_validate_json(bytes(body))
    except PydanticValidationError as exc:
        raise RequestValidationError(exc.errors()) from exc


@router.get("/installed", response_model=InstalledAppsResponse)
async def list_installed_apps_route(
    request: Request,
    team_id: str = Query(..., min_length=1),
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> InstalledAppsResponse:
    try:
        authorized, _ = await _caller(request, db_infra, team_id)
        apps = await list_installed_apps(db_infra.get_manager("aweb"), team_id=authorized)
        return InstalledAppsResponse(team_id=authorized, apps=[InstalledAppResponse(**vars(app)) for app in apps])
    except ServiceError as exc:
        raise _failure(exc) from exc


@router.get("/installations")
async def list_installations_route(
    request: Request,
    team_id: str | None = Query(None),
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> dict[str, Any]:
    try:
        authorized, _ = await _caller(request, db_infra, team_id)
        db = db_infra.get_manager("aweb")
        names = await db.fetch_all(
            "SELECT app_id FROM {{tables.team_app_installs}} WHERE team_id = $1 ORDER BY app_id", authorized,
        )
        async with db.transaction() as tx:
            records = [await get_installation_on(tx, team_id=authorized, app_id=row["app_id"]) for row in names]
        return {"team_id": authorized, "installations": [record for record in records if record is not None]}
    except ServiceError as exc:
        raise _failure(exc) from exc


@router.get("/{app_id}/installation", response_model=InstalledAppResponse)
async def get_installation_route(
    app_id: str, request: Request,
    team_id: str | None = Query(None),
    db_infra: DatabaseInfra = Depends(get_db_infra),
):
    try:
        authorized, _ = await _caller(request, db_infra, team_id)
        async with db_infra.get_manager("aweb").transaction() as tx:
            row = await get_installation_on(tx, team_id=authorized, app_id=app_id)
        if row is None:
            raise HTTPException(status_code=404, detail=RESOURCE_NOT_FOUND_DETAIL)
        return row
    except ServiceError as exc:
        raise _failure(exc) from exc


@router.post("/preview")
async def preview_installation_route(
    request: Request,
    team_id: str | None = Query(None),
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> dict[str, Any]:
    payload = await _payload(request, AppPreviewRequest)
    try:
        authorized, _ = await _caller(request, db_infra, team_id)
        fetched = await _fetcher(request).fetch(payload.origin)
        async with db_infra.get_manager("aweb").transaction() as tx:
            current = await get_installation_on(tx, team_id=authorized, app_id=fetched.manifest.app_id)
        return {
            "app_id": fetched.manifest.app_id, "origin": fetched.origin,
            "digest": fetched.digest, "origin_verified": True,
            "manifest": fetched.manifest.document, "resolved": fetched.manifest.view(),
            "current": current,
        }
    except ServiceError as exc:
        raise _failure(exc) from exc


@router.post("/install", response_model=InstalledAppResponse)
async def install_app_route(
    request: Request,
    team_id: str | None = Query(None),
    db_infra: DatabaseInfra = Depends(get_db_infra),
):
    payload = await _payload(request, AppInstallRequest)
    supplied_id = payload.app_id.strip().lower()
    request.state.operator_audit_target = f"app:{supplied_id}" if APP_ID_RE.fullmatch(supplied_id) else "app:invalid"
    try:
        authorized, identity = await _caller(request, db_infra, team_id)
        app_id = normalize_app_id(payload.app_id)
        db = db_infra.get_manager("aweb")
        # Refuse non-admins before network work, then re-read authority in the
        # transaction that writes. No policy result survives the fetch interval.
        async with db.transaction() as tx:
            await require_install_admin(tx, request, identity, authorized, action="apps.install", app_id=app_id)
        fetched = await _fetcher(request).fetch(payload.origin, expected_digest=payload.digest)
        if fetched.manifest.app_id != app_id:
            raise HTTPException(status_code=422, detail={"code":"manifest_app_mismatch", "message":"Manifest names another app"})
        async with db.transaction() as tx:
            await require_install_admin(tx, request, identity, authorized, action="apps.install", app_id=app_id)
            row = await install_verified_manifest_on(
                tx, team_id=authorized, fetched=fetched, granted_scopes=payload.granted_scopes,
                expected_generation=payload.expected_generation,
                installed_by_agent_id=identity.agent_id if identity is not None else None,
            )
            await audit_success(tx, request, authorized)
        return row
    except ServiceError as exc:
        raise _failure(exc) from exc
