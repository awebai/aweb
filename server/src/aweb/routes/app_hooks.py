"""Hook resolution: where a team's hook events go, who may produce them, and the core producer's keys."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from pydantic import BaseModel

from aweb.app_credentials import HOOK_RESOLVE, PURPOSES, verify_app_credential
from aweb.app_registry import get_installed_app
from aweb.config import get_app_grant_max_age_seconds, get_hook_producer_keys
from aweb.db import DatabaseInfra, get_db_infra
from aweb.hook_bindings import PRODUCTION, REGISTRATION, HookBinding
from aweb.hook_resolution import (
    HookSelector,
    active_bindings,
    complement,
    hook_keys,
    holds_active_binding,
    own_bindings,
)
from aweb.service_errors import ServiceError

router = APIRouter(tags=["hooks"])


class HookProducerKeyResponse(BaseModel):
    kid: str
    did_key: str
    valid_from: str
    # Null while the key has no end, never omitted.
    valid_until: str | None


class HookProducerKeysResponse(BaseModel):
    keys: list[HookProducerKeyResponse]
    as_of: str
    max_age_seconds: int


def _as_of() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


HOOK_BINDING_REQUIRED = "hook_binding_required"
_CATALOG_ID = re.compile(r"[a-z][a-z0-9.-]{0,63}")
_HOOK = re.compile(r"[a-z][a-z0-9-]{0,63}")


def _milliseconds(moment: datetime | None, *, round_up: bool = False) -> str | None:
    """A binding time in UTC to the millisecond, the hook event spelling.

    ``active_from`` rounds up to the next millisecond, never down, so a binding
    never reads as active earlier than it is; the other times truncate."""
    if moment is None:
        return None
    utc = moment.astimezone(timezone.utc)
    spare = utc.microsecond % 1000
    utc = utc.replace(microsecond=utc.microsecond - spare)
    if round_up and spare:
        utc += timedelta(milliseconds=1)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


class HookKeyResponse(BaseModel):
    kid: str
    did_key: str
    purposes: list[str]


class HookBindingResponse(BaseModel):
    binding_id: str
    kind: str
    app_id: str
    installation_id: str | None
    generation: int | None
    origin: str
    method: str | None
    path: str | None
    digest: str
    active_from: str | None


class HookProductionResponse(HookBindingResponse):
    keys: list[HookKeyResponse]


class OwnHookBindingResponse(HookBindingResponse):
    catalog: dict[str, str | int]
    hook: str
    state: str
    ended_by: str | None
    activated_at: str | None
    revoked_at: str | None


class HookResolutionResponse(BaseModel):
    team_id: str
    catalog: dict[str, str | int]
    hook: str
    bindings: list[HookProductionResponse] | list[HookBindingResponse]
    as_of: str
    max_age_seconds: int


class OwnHookBindingsResponse(BaseModel):
    team_id: str
    bindings: list[OwnHookBindingResponse]
    as_of: str
    max_age_seconds: int


def _binding_fields(binding: HookBinding) -> dict:
    return {
        "binding_id": str(binding.binding_id),
        "kind": binding.kind,
        "app_id": binding.app_id,
        "installation_id": binding.installation_id,
        "generation": binding.generation,
        "origin": binding.origin,
        "method": binding.method,
        "path": binding.path,
        "digest": binding.digest,
        "active_from": _milliseconds(binding.active_from, round_up=True),
    }


async def _caller(request: Request, db_infra: DatabaseInfra):
    """The verified hook-resolve caller, installed at the digest its key is registered under."""
    db = db_infra.get_manager("aweb")
    try:
        credential = await verify_app_credential(request, db, HOOK_RESOLVE)
        installed = await get_installed_app(
            db, team_id=credential.team_id, app_id=credential.app_id, digest=credential.digest
        )
    except ServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    if installed is None:
        raise HTTPException(status_code=403, detail=PURPOSES[HOOK_RESOLVE].key_not_registered)
    return db, credential


async def _resolve(
    kind: str, request: Request, db_infra: DatabaseInfra, selector: HookSelector
) -> HookResolutionResponse:
    db, credential = await _caller(request, db_infra)
    if not await holds_active_binding(
        db,
        team_id=credential.team_id,
        app_id=credential.app_id,
        digest=credential.digest,
        kind=complement(kind),
        selector=selector,
    ):
        raise HTTPException(status_code=403, detail=HOOK_BINDING_REQUIRED)
    found = await active_bindings(db, team_id=credential.team_id, kind=kind, selector=selector)
    bindings: list[HookProductionResponse] | list[HookBindingResponse]
    if kind == PRODUCTION:
        bindings = [
            HookProductionResponse(
                **_binding_fields(binding),
                keys=[
                    HookKeyResponse(kid=key.kid, did_key=key.did_key, purposes=list(key.purposes))
                    for key in await hook_keys(db, binding)
                ],
            )
            for binding in found
        ]
    else:
        bindings = [HookBindingResponse(**_binding_fields(binding)) for binding in found]
    return HookResolutionResponse(
        team_id=credential.team_id,
        catalog={"id": selector.catalog_id, "version": selector.catalog_version},
        hook=selector.hook,
        bindings=bindings,
        as_of=_as_of(),
        max_age_seconds=get_app_grant_max_age_seconds(),
    )


CatalogId = Annotated[str, Path(pattern=_CATALOG_ID.pattern)]
CatalogVersion = Annotated[int, Path(ge=1)]
HookName = Annotated[str, Path(pattern=_HOOK.pattern)]


@router.get(
    "/v1/apps/self/hooks/{catalog_id}/{catalog_version}/{hook}/registrations",
    response_model=HookResolutionResponse,
)
async def hook_registrations_route(
    catalog_id: CatalogId,
    catalog_version: CatalogVersion,
    hook: HookName,
    request: Request,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> HookResolutionResponse:
    """Where to deliver: the team's active registrations of the hook, for a caller
    holding an active production of it."""
    return await _resolve(REGISTRATION, request, db_infra, HookSelector(catalog_id, catalog_version, hook))


@router.get(
    "/v1/apps/self/hooks/{catalog_id}/{catalog_version}/{hook}/productions",
    response_model=HookResolutionResponse,
)
async def hook_productions_route(
    catalog_id: CatalogId,
    catalog_version: CatalogVersion,
    hook: HookName,
    request: Request,
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> HookResolutionResponse:
    """Who may produce: the team's active productions of the hook with their hook
    keys, for a caller holding an active registration of it."""
    return await _resolve(PRODUCTION, request, db_infra, HookSelector(catalog_id, catalog_version, hook))


def _selector(hook: str) -> HookSelector:
    parts = hook.split("/")
    if (
        len(parts) != 3
        or not _CATALOG_ID.fullmatch(parts[0])
        or not re.fullmatch(r"[1-9][0-9]{0,8}", parts[1])
        or not _HOOK.fullmatch(parts[2])
    ):
        raise HTTPException(status_code=400, detail="hook is <catalog_id>/<catalog_version>/<hook>")
    return HookSelector(parts[0], int(parts[1]), parts[2])


@router.get("/v1/apps/self/hooks/bindings", response_model=OwnHookBindingsResponse)
async def own_hook_bindings_route(
    request: Request,
    binding_id: str | None = Query(default=None),
    hook: str | None = Query(default=None),
    db_infra: DatabaseInfra = Depends(get_db_infra),
) -> OwnHookBindingsResponse:
    """The caller's own bindings in the team, in every state, by ``binding_id`` or by ``hook``."""
    if (binding_id is None) == (hook is None):
        raise HTTPException(status_code=400, detail="give exactly one of binding_id or hook")
    selector = _selector(hook) if hook is not None else None
    parsed_id = None
    if binding_id is not None:
        try:
            parsed_id = UUID(binding_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="binding_id is a UUID") from None
    db, credential = await _caller(request, db_infra)
    bindings = await own_bindings(
        db, team_id=credential.team_id, app_id=credential.app_id, binding_id=parsed_id, selector=selector
    )
    return OwnHookBindingsResponse(
        team_id=credential.team_id,
        bindings=[
            OwnHookBindingResponse(
                **_binding_fields(binding),
                catalog={"id": binding.catalog_id, "version": binding.catalog_version},
                hook=binding.hook,
                state=binding.state,
                ended_by=binding.ended_by,
                activated_at=_milliseconds(binding.activated_at),
                revoked_at=_milliseconds(binding.revoked_at),
            )
            for binding in bindings
        ],
        as_of=_as_of(),
        max_age_seconds=get_app_grant_max_age_seconds(),
    )


@router.get("/v1/hooks/producer-keys", response_model=HookProducerKeysResponse)
async def hook_producer_keys_route() -> HookProducerKeysResponse:
    """The core hook producer's public keys, retired ones included. Anyone may
    read them; a consumer reaches this server only through the team's anchored
    server record."""
    return HookProducerKeysResponse(
        keys=[
            HookProducerKeyResponse(
                kid=key.kid,
                did_key=key.did_key,
                valid_from=key.valid_from,
                valid_until=key.valid_until,
            )
            for key in get_hook_producer_keys()
        ],
        as_of=_as_of(),
        max_age_seconds=get_app_grant_max_age_seconds(),
    )
