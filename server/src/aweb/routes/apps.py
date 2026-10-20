"""Core app registry and app grants routes."""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ConfigDict, Field
from pydantic import ValidationError as PydanticValidationError

from aweb.app_credentials import APP_GRANT_READ, PURPOSES, verify_app_credential
from aweb.app_registry import (
    APP_ID_RE,
    AppEmitKey,
    AppEventType,
    AppInstall,
    get_installed_app,
    install_app,
    list_installed_apps,
    validate_team_id,
)
from aweb.config import get_app_grant_max_age_seconds
from aweb.audit import OperatorAuditRoute, audit_success
from aweb.db import DatabaseInfra, get_db_infra
from aweb.internal_auth import parse_internal_auth_context
from aweb.service_errors import RESOURCE_NOT_FOUND_DETAIL, ServiceError
from aweb.team_auth_deps import get_team_identity

router = APIRouter(prefix="/v1/apps", tags=["apps"], route_class=OperatorAuditRoute)

MAX_MANIFEST_BYTES = 10 << 20
# Standard base64 of MAX_MANIFEST_BYTES bytes, padded.
MAX_MANIFEST_BASE64_CHARS = 4 * -(-MAX_MANIFEST_BYTES // 3)
# The install body: the encoded manifest plus the rest of the request.
MAX_INSTALL_BODY_BYTES = MAX_MANIFEST_BASE64_CHARS + (1 << 20)


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
    manifest: str | None = None


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


class AppGrantStatusResponse(BaseModel):
    team_id: str
    app_id: str
    state: str
    origin: str
    app_version: str
    manifest_version: int
    digest: str
    granted_scopes: list[str]
    # Present from the start and null until installations carry an identity
    # and generation; consumers that bind them refuse null.
    installation_id: str | None
    generation: int | None
    as_of: str
    max_age_seconds: int


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
    if len(value) > MAX_MANIFEST_BASE64_CHARS:
        raise HTTPException(status_code=413, detail="manifest exceeds the size bound")
    try:
        manifest = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status_code=422, detail="manifest must be standard base64") from exc
    if len(manifest) > MAX_MANIFEST_BYTES:
        raise HTTPException(status_code=413, detail="manifest exceeds the size bound")
    return manifest


async def _install_request(request: Request) -> AppInstallRequest:
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_INSTALL_BODY_BYTES:
            raise HTTPException(status_code=413, detail="install request exceeds the size bound")
    try:
        return AppInstallRequest.model_validate_json(bytes(body))
    except PydanticValidationError as exc:
        raise RequestValidationError(exc.errors()) from exc


@router.post("/install", response_model=InstalledAppResponse)
async def install_app_route(
    request: Request,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> InstalledAppResponse:
    payload = await _install_request(request)
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


@router.get("/self/grant", response_model=AppGrantStatusResponse)
async def app_grant_status_route(
    request: Request,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> AppGrantStatusResponse:
    """The calling app's grant in the calling team; both come from the credential."""
    db = db_infra.get_manager("aweb")
    try:
        credential = await verify_app_credential(request, db, APP_GRANT_READ)
        app = await get_installed_app(db, team_id=credential.team_id, app_id=credential.app_id, digest=credential.digest)
    except ServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    if app is None:
        # The installation moved to another digest, or went away, after the key
        # was checked: the key no longer belongs to an installed digest.
        raise HTTPException(status_code=403, detail=PURPOSES[APP_GRANT_READ].key_not_registered)

    return AppGrantStatusResponse(
        team_id=credential.team_id,
        app_id=app.app_id,
        state="active",
        origin=app.origin,
        app_version=app.app_version,
        manifest_version=app.manifest_version,
        digest=app.digest,
        granted_scopes=app.granted_scopes,
        installation_id=None,
        generation=None,
        as_of=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        max_age_seconds=get_app_grant_max_age_seconds(),
    )
