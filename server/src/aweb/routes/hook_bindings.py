"""Hook-binding routes: read a team's bindings, and activate or revoke one under
the team owner's ``aweb.owner-act/1`` (docs/design/audit-substrate.md §A3).

A team member reads the bindings to build the act's subject. The act, not the
caller's membership, is the authority to change one; the caller's team only
scopes which bindings the request can name.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
from uuid import UUID

from aweb_naapp.hooks.owner_act import PREFIX
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from aweb.awid_error_handling import (
    awid_dependency_http_exception,
    awid_registry_not_configured_exception,
)
from aweb.db import DatabaseInfra, get_db_infra
from aweb.hook_bindings import (
    BINDING_COLUMNS,
    HookBinding,
    OwnerActTeamKeyUnavailable,
    activate_binding,
    binding_from_row,
    core_owner_act_verifier,
    list_app_bindings,
    revoke_binding,
)
from aweb.hook_producer import (
    MUTATION_HOOK,
    MutationHookContext,
    enqueue_mutation_hook,
    request_hook_context,
    require_core_hook_signer,
)
from aweb.hook_times import format_hook_time
from aweb.routes.apps import _caller
from aweb.service_errors import ServiceError
from aweb.team_auth_deps import get_team_identity

# The owner act's record is the binding row, which keeps the act's SHA-256.
# The hook_binding.activated / .revoked events of §A3 are enqueued through the
# change's in_transaction callback by core's producer (aweb-acgh.16.11). These
# are owner acts, not operator-audit actions.
router = APIRouter(prefix="/v1/apps/hook-bindings", tags=["apps"])
logger = logging.getLogger(__name__)

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
        activated_at=format_hook_time(binding.activated_at),
        active_from=format_hook_time(binding.active_from, round_up=True),
        revoked_at=format_hook_time(binding.revoked_at),
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
        authorized_team_id, _ = await _caller(request, db_infra, team_id)
        bindings = await list_app_bindings(db_infra.get_manager("aweb"), team_id=authorized_team_id, app_id=app_id)
    except ServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    return HookBindingsResponse(team_id=authorized_team_id, bindings=[_as_response(b) for b in bindings])


async def _owner_act_route(
    request: Request,
    db_infra: DatabaseInfra,
    binding_id: str,
    payload: OwnerActRequest,
    change,
):
    signing = _signing(payload.act)
    try:
        identity = await get_team_identity(request, db_infra)
        registry_client = getattr(request.app.state, "awid_registry_client", None)
        if registry_client is None:
            raise awid_registry_not_configured_exception(operation="AWID owner-act team key")
        verifier = core_owner_act_verifier(
            audience=request.app.state.public_origin, registry_client=registry_client
        )

        async def enqueue_on(tx):
            # This callback runs only after the owner act is verified and its
            # nonce consumed, inside the binding change's own transaction.
            row = await tx.fetch_one(
                f"SELECT {BINDING_COLUMNS} FROM {{{{tables.app_hook_bindings}}}} WHERE binding_id=$1 AND team_id=$2",
                UUID(binding_id), identity.team_id,
            )
            changed = binding_from_row(row)
            request_context = request_hook_context(request)
            if (
                changed.state == "active"
                and changed.kind == "registration"
                and changed.catalog_id == "aweb.hooks"
                and changed.catalog_version == 1
                and changed.hook == MUTATION_HOOK
            ):
                # Owner/subject verification and nonce consumption have run in
                # this tx. Readiness refusal rolls all writes back with them.
                require_core_hook_signer(request_context.hooks)
            act = json.loads(signing[len(PREFIX) :])
            payload = {
                "mutation_type": "hook_binding.activated" if changed.state == "active" else "hook_binding.revoked",
                "target_ref": "binding:" + str(changed.binding_id), "binding_id": str(changed.binding_id),
                "kind": changed.kind, "app_id": changed.app_id, "installation_id": changed.installation_id,
                "generation": changed.generation, "catalog_id": changed.catalog_id,
                "catalog_version": changed.catalog_version, "hook": changed.hook,
            }
            if changed.state == "active":
                payload.update(active_from=format_hook_time(changed.active_from, round_up=True),
                               owner_act_sha256=hashlib.sha256(signing).hexdigest())
            else:
                payload.update(reason="owner_act", owner_act_sha256=hashlib.sha256(signing).hexdigest())
            context = MutationHookContext(
                request_context.hooks,
                {
                    "authority_mode": "owner_act",
                    "did_key": act["team_key_did"],
                    "attestations": [],
                },
                getattr(request.state, "verified_hook_trace_id", None),
                request_context.origin,
                request_context.diagnostics,
            )
            await enqueue_mutation_hook(
                tx, team_id=identity.team_id, payload=payload, hook_context=context
            )

        binding = await change(
            db_infra.get_manager("aweb"), verifier, team_id=identity.team_id, binding_id=binding_id,
            signing=signing, signature=payload.signature,
            in_transaction=enqueue_on,
        )
    except ServiceError as exc:
        if exc.status_code >= 500:
            logger.error("Hook-binding owner act failed: %s", exc.detail, exc_info=True)
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    except OwnerActTeamKeyUnavailable as exc:
        # The team key is read before any transaction, so nothing was written.
        logger.warning("AWID registry dependency failed reading the owner-act team key", exc_info=True)
        raise awid_dependency_http_exception(exc.dependency_error, operation="AWID owner-act team key") from exc
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
