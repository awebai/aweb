"""Hook-binding routes: read a team's bindings, and activate or revoke one under
the team owner's ``aweb.owner-act/1`` (docs/design/audit-substrate.md §A3).

A team member reads the bindings to build the act's subject. The act, not the
caller's membership, is the authority to change one; the caller's team only
scopes which bindings the request can name.
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from aweb.db import DatabaseInfra, get_db_infra
from aweb.hook_bindings import (
    HookBinding,
    activate_binding,
    core_owner_act_verifier,
    list_app_bindings,
    revoke_binding,
)
from aweb.routes.apps import _authorized_team_id
from aweb.service_errors import ServiceError
from aweb.team_auth_deps import get_team_identity

# The owner act's own record is the binding row (the act's SHA-256) and the
# hook_binding.activated / .revoked events core enqueues in the same
# transaction (audit-substrate.md §A3); these are not operator-audit actions.
router = APIRouter(prefix="/v1/apps/hook-bindings", tags=["apps"])

# An owner act is a few hundred bytes of canonical JSON; this bounds the request.
MAX_ACT_BASE64_CHARS = 16 << 10


class OwnerActRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Standard base64 of the exact signed bytes: the prefix and the canonical act.
    act: str = Field(..., min_length=1, max_length=MAX_ACT_BASE64_CHARS)
    signature: str = Field(..., min_length=1, max_length=128)


class HookBindingResponse(BaseModel):
    binding_id: str
    kind: str
    team_id: str
    installation_id: str | None
    generation: int | None
    app_id: str
    origin: str
    digest: str
    catalog_id: str
    catalog_version: int
    hook: str
    tool: str | None
    method: str | None
    path: str | None
    scopes: list[str]
    reads: list[str]
    state: str
    ended_by: str | None
    activated_at: str | None
    active_from: str | None
    revoked_at: str | None


class HookBindingsResponse(BaseModel):
    team_id: str
    bindings: list[HookBindingResponse]


def _time(value: datetime | None) -> str | None:
    """The hook-event millisecond form, YYYY-MM-DDTHH:MM:SS.mmmZ."""
    if value is None:
        return None
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def _as_response(binding: HookBinding) -> HookBindingResponse:
    return HookBindingResponse(
        binding_id=str(binding.binding_id),
        kind=binding.kind,
        team_id=binding.team_id,
        installation_id=binding.installation_id,
        generation=binding.generation,
        app_id=binding.app_id,
        origin=binding.origin,
        digest=binding.digest,
        catalog_id=binding.catalog_id,
        catalog_version=binding.catalog_version,
        hook=binding.hook,
        tool=binding.tool,
        method=binding.method,
        path=binding.path,
        scopes=list(binding.scopes),
        reads=list(binding.reads),
        state=binding.state,
        ended_by=binding.ended_by,
        activated_at=_time(binding.activated_at),
        active_from=_time(binding.active_from),
        revoked_at=_time(binding.revoked_at),
    )


def _signing(act: str) -> bytes:
    try:
        return base64.b64decode(act, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status_code=422, detail="act must be standard base64 of the signed bytes") from exc


@router.get("", response_model=HookBindingsResponse)
async def list_hook_bindings_route(
    request: Request,
    team_id: str = Query(..., min_length=1),
    app_id: str = Query(..., min_length=1, max_length=63),
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> HookBindingsResponse:
    try:
        authorized_team_id, _ = await _authorized_team_id(request, db_infra, team_id)
        bindings = await list_app_bindings(db_infra.get_manager("aweb"), team_id=authorized_team_id, app_id=app_id)
    except ServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    return HookBindingsResponse(team_id=authorized_team_id, bindings=[_as_response(b) for b in bindings])


async def _owner_act_route(request: Request, db_infra: DatabaseInfra, binding_id: str, payload: OwnerActRequest, change):
    signing = _signing(payload.act)
    try:
        identity = await get_team_identity(request, db_infra)
        verifier = core_owner_act_verifier(
            audience=request.app.state.public_origin,
            registry_client=request.app.state.awid_registry_client,
        )
        binding = await change(
            db_infra.get_manager("aweb"), verifier, team_id=identity.team_id, binding_id=binding_id,
            signing=signing, signature=payload.signature,
        )
    except ServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    return _as_response(binding)


@router.post("/{binding_id}/activate", response_model=HookBindingResponse)
async def activate_hook_binding_route(
    binding_id: str,
    payload: OwnerActRequest,
    request: Request,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> HookBindingResponse:
    return await _owner_act_route(request, db_infra, binding_id, payload, activate_binding)


@router.post("/{binding_id}/revoke", response_model=HookBindingResponse)
async def revoke_hook_binding_route(
    binding_id: str,
    payload: OwnerActRequest,
    request: Request,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> HookBindingResponse:
    return await _owner_act_route(request, db_infra, binding_id, payload, revoke_binding)
