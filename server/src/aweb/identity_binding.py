"""Attribute stable identity claims only through current registry evidence."""

from __future__ import annotations

import logging
import math
import re
from collections import OrderedDict
from dataclasses import replace
from enum import StrEnum
from time import monotonic

from awid.did import validate_stable_id
from awid.identity_observation import (
    IdentityBinding,
    IdentityObservationRefused,
)
from awid.identity_observation import (
    observe_identity_binding as observe_public_identity_binding,
)
from awid.registry_types import RegistryError
from fastapi import Request

from aweb.application_state import application_registry_client
from aweb.service_errors import IdentityBindingCode, IdentityBindingError

from aweb.application_state import native_application_state

logger = logging.getLogger(__name__)
_BINDING_TTL = 60
_CACHE_LIMIT = 4096


class IdentityProjectionField(StrEnum):
    STABLE_DID = "did_aw"
    ADDRESS = "address"


class _AddressMissing(IdentityObservationRefused):
    """A recognized address 404, as distinct from other binding refusals."""


class _RegisteredBindingRegistry:
    """Adapt two exact lookups while the SDK owns the binding comparison."""

    def __init__(self, client):
        self._client = client

    async def resolve_key_fresh(self, did_aw: str):
        try:
            return await self._client.resolve_key_fresh(did_aw)
        except RegistryError as exc:
            if exc.status_code == 404:
                raise IdentityObservationRefused("identity_binding_mismatch") from exc
            raise

    async def resolve_address_fresh(self, domain: str, name: str):
        address = await self._client.resolve_address_fresh(domain, name)
        if address is None:
            raise _AddressMissing("identity_binding_mismatch")
        return address


def verified_key_sql(agent: str = "") -> str:
    """The SQL form of verified_projection's current-key guard.

    docs/identity.md:598-607 makes global claims conditional on this marker.
    ``agent`` is a source-code SQL alias, never a value from a request.
    """
    if agent and not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", agent):
        raise ValueError("Invalid identity projection SQL alias")
    prefix = agent + "." if agent else ""
    return (
        f"NULLIF({prefix}did_key, '') IS NOT NULL AND {prefix}did_aw_verified_key = {prefix}did_key"
    )


def verified_identity_field_sql(field: IdentityProjectionField, *, agent: str = "") -> str:
    """Attribute a stable DID/address through the same verified-key guard."""
    if not isinstance(field, IdentityProjectionField):
        raise ValueError("Invalid identity projection field")
    prefix = agent + "." if agent else ""
    return f"CASE WHEN {verified_key_sql(agent)} THEN {prefix}{field.value} END"


def verified_principal_did_sql(*, agent: str = "") -> str:
    """Project a member principal without adopting a raw stable-DID claim.

    docs/identity.md:598-609 requires registry-verified marker evidence for
    stable identity. A local principal remains its literal signing did:key.
    """
    stable = verified_identity_field_sql(IdentityProjectionField.STABLE_DID, agent=agent)
    prefix = agent + "." if agent else ""
    return f"COALESCE(NULLIF(({stable}), ''), {prefix}did_key)"


def verified_projection(row):
    """Keep local key/agent authority, withholding unverified global claims."""
    if row is None:
        return None
    result = dict(row)
    if not result.get("did_key") or result.get("did_aw_verified_key") != result["did_key"]:
        result["did_aw"] = None
        result["address"] = None
    return result


async def verify_identity_binding(
    request: Request,
    *,
    did_key: str,
    did_aw: str = "",
    address: str = "",
    fresh: bool = False,
    registry_client=None,
    require_registered_did: bool = False,
) -> IdentityBinding:
    """Verify the claimed stable identity and address against the supplied registry evidence."""
    did_aw, address = (did_aw or "").strip(), (address or "").strip()
    if not did_aw and not address:
        return IdentityBinding(did_key=did_key)
    if not did_aw or not did_aw.startswith("did:aw:"):
        raise IdentityBindingError(IdentityBindingCode.MISMATCH)
    if require_registered_did:
        try:
            validate_stable_id(did_aw)
        except ValueError as exc:
            raise IdentityBindingError(IdentityBindingCode.MISMATCH) from exc
        if address:
            domain, separator, name = address.partition("/")
            if not separator or not domain or not name or "/" in name or max(len(domain), len(name)) > 256:
                raise IdentityBindingError(IdentityBindingCode.MISMATCH)
    client = (
        registry_client
        if registry_client is not None
        else application_registry_client(request.app.state)
    )
    cache = identity_binding_cache(request.app.state)
    key: tuple[str, ...] = (did_aw, did_key, address)
    if registry_client is not None:
        key += (getattr(registry_client, "registry_url", "federation"),)
    observations = getattr(request.state, "identity_binding_observations", None)
    if observations is None:
        observations = {}
        request.state.identity_binding_observations = observations
    if not fresh and key in observations:
        if require_registered_did and observations[key].self_derived:
            raise IdentityBindingError(IdentityBindingCode.MISMATCH)
        return observations[key]
    started = monotonic()
    cached = cache.get(key)
    # Unknown enrollment is refetched rather than pinned by this positive cache.
    if not fresh and cached is not None and cached[0] > started and cached[1].id_tree is not None:
        if require_registered_did and cached[1].self_derived:
            raise IdentityBindingError(IdentityBindingCode.MISMATCH)
        return replace(cached[1], fresh_observation=False)
    binding = await _observe_into_cache(
        client, cache, key, started, require_registered_did=require_registered_did,
    )
    observations[key] = binding
    return binding


def identity_binding_cache(app_state) -> OrderedDict:
    """The application's cache of observed identity bindings, kept on its state."""

    app_state = native_application_state(app_state)
    cache = getattr(app_state, "identity_binding_cache", None)
    if cache is None:
        cache = OrderedDict()
        app_state.identity_binding_cache = cache
    return cache


async def observe_current_identity_binding(
    registry_client,
    cache: OrderedDict,
    *,
    did_key: str,
    did_aw: str,
    address: str = "",
) -> IdentityBinding:
    """Observe a did:aw's binding at the registry now and cache it for the application.

    For callers that hold no request. It never answers from the cache.
    """
    did_aw, address = (did_aw or "").strip(), (address or "").strip()
    if not did_aw.startswith("did:aw:"):
        raise IdentityBindingError(IdentityBindingCode.MISMATCH)
    if registry_client is None:
        raise IdentityBindingError(IdentityBindingCode.UNAVAILABLE)
    return await _observe_into_cache(
        registry_client, cache, (did_aw, did_key, address), monotonic()
    )


async def _observe_into_cache(
    client, cache: OrderedDict, key: tuple, started: float, *, require_registered_did: bool = False,
) -> IdentityBinding:
    did_aw, did_key, address = key[:3]
    cache.pop(key, None)
    binding = await observe_identity_binding(
        _RegisteredBindingRegistry(client) if require_registered_did else client,
        did_key=did_key, did_aw=did_aw, address=address,
    )
    # A newly observed current key supersedes older positive cache entries.
    for cached_key in list(cache):
        if cached_key[0] == did_aw and cached_key[1] != did_key:
            cache.pop(cached_key, None)
    cache[key] = (started + _BINDING_TTL, binding)
    cache.move_to_end(key)
    while len(cache) > _CACHE_LIMIT:
        cache.popitem(last=False)
    return binding


async def observe_identity_binding(
    client, *, did_key: str, did_aw: str, address: str = "",
) -> IdentityBinding:
    """The compatible server adapter for the shared public AWID observation."""
    try:
        return await observe_public_identity_binding(
            client,
            did_key=did_key,
            did_aw=did_aw,
            address=address,
        )
    except IdentityObservationRefused as exc:
        code = IdentityBindingCode(exc.code)
        status = 403 if code is IdentityBindingCode.MISMATCH else 503
        delay = getattr(exc, "retry_after_seconds", None)
        headers = None
        if (
            status == 503
            and isinstance(delay, (int, float))
            and not isinstance(delay, bool)
            and math.isfinite(delay)
            and delay >= 0
        ):
            # Never shorten an upstream window or busy-loop a zero hint.
            headers = {"Retry-After": str(max(1, math.ceil(delay)))}
        raise IdentityBindingError(
            code, headers=headers, address_missing=isinstance(exc, _AddressMissing),
        ) from exc


async def refresh_projection_binding(db, *, agent_id, did_key: str, binding: IdentityBinding):
    """A verified request refreshes only its own key's projection."""
    if not binding.fresh_observation:
        return None
    async with db.transaction() as tx:
        if binding.did_aw:
            await tx.execute(
                """
                UPDATE {{tables.agents}} SET did_aw_verified_key=NULL
                WHERE did_aw=$1 AND did_key<>$2 AND did_aw_verified_key IS NOT NULL
                """,
                binding.did_aw,
                did_key,
            )
        return await tx.execute(
            """
            UPDATE {{tables.agents}}
            SET did_aw=$3, address=$4, did_aw_verified_key=$5
            WHERE agent_id=$1::uuid AND did_key=$2 AND deleted_at IS NULL
              AND (did_aw IS DISTINCT FROM $3 OR address IS DISTINCT FROM $4
                   OR did_aw_verified_key IS DISTINCT FROM $5)
            """,
            agent_id,
            did_key,
            binding.did_aw or None,
            binding.address or None,
            did_key if binding.did_aw else None,
        )


async def verify_pending_identity_bindings(
    db, registry_client, *, dry_run: bool = False
) -> dict[str, int]:
    """Verify historical projections; write only their own marker, never claims."""
    counts = dict(verified=0, self_derived=0, unbound=0, awid_error=0)
    rows = await db.fetch_all(
        """
        SELECT agent_id, did_key, did_aw, address FROM {{tables.agents}}
        WHERE deleted_at IS NULL AND did_aw_verified_key IS NULL
          AND (NULLIF(did_aw,'') IS NOT NULL OR NULLIF(address,'') IS NOT NULL)
        ORDER BY agent_id
        """
    )
    for row in rows:
        try:
            binding = await observe_identity_binding(
                registry_client,
                did_key=row["did_key"],
                did_aw=row["did_aw"] or "",
                address=row["address"] or "",
            )
        except IdentityBindingError as exc:
            counts["awid_error" if exc.status_code == 503 else "unbound"] += 1
            continue
        if not dry_run:
            async with db.transaction() as tx:
                current = await tx.fetch_one(
                    """
                    SELECT did_key, did_aw, address FROM {{tables.agents}}
                    WHERE agent_id=$1 AND deleted_at IS NULL AND did_aw_verified_key IS NULL
                    FOR UPDATE
                    """,
                    row["agent_id"],
                )
                if current is None:
                    continue
                if any(current[field] != row[field] for field in ("did_key", "did_aw", "address")):
                    counts["unbound"] += 1
                    continue
                await tx.execute(
                    "UPDATE {{tables.agents}} SET did_aw_verified_key=did_key WHERE agent_id=$1",
                    row["agent_id"],
                )
        counts["self_derived" if binding.self_derived else "verified"] += 1
    return counts
