"""Attribute stable identity claims only through current registry evidence."""

from __future__ import annotations

import logging
from collections import OrderedDict
from dataclasses import replace
from time import monotonic

from awid.identity_observation import (
    IdentityBinding,
    IdentityObservationRefused,
)
from awid.identity_observation import (
    observe_identity_binding as observe_public_identity_binding,
)
from fastapi import HTTPException, Request

logger = logging.getLogger(__name__)
_BINDING_TTL = 60
_CACHE_LIMIT = 4096


def verified_projection(row):
    """Keep local key/agent authority, withholding unverified global claims."""
    if row is None:
        return None
    result = dict(row)
    if (
        not result.get("did_key")
        or result.get("did_aw_verified_key") != result["did_key"]
    ):
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
) -> IdentityBinding:
    did_aw, address = (did_aw or "").strip(), (address or "").strip()
    if not did_aw and not address:
        return IdentityBinding(did_key=did_key)
    if not did_aw or not did_aw.startswith("did:aw:"):
        raise HTTPException(status_code=403, detail="identity_binding_mismatch")
    client = registry_client if registry_client is not None else getattr(request.app.state, "awid_registry_client", None)
    if client is None:
        raise HTTPException(status_code=503, detail="identity_binding_unavailable")
    cache = getattr(request.app.state, "identity_binding_cache", None)
    if cache is None:
        cache = OrderedDict()
        request.app.state.identity_binding_cache = cache
    key = (did_aw, did_key, address)
    if registry_client is not None:
        key += (getattr(registry_client, "registry_url", "federation"),)
    observations = getattr(request.state, "identity_binding_observations", None)
    if observations is None:
        observations = {}
        request.state.identity_binding_observations = observations
    if not fresh and key in observations:
        return observations[key]
    started = monotonic()
    cached = cache.get(key)
    # Unknown enrollment is refetched rather than pinned by this positive cache.
    if (not fresh and cached is not None and cached[0] > started
            and cached[1].id_tree is not None):
        return replace(cached[1], fresh_observation=False)
    cache.pop(key, None)
    binding = await observe_identity_binding(client, did_key=did_key, did_aw=did_aw, address=address)
    observations[key] = binding
    # A newly observed current key supersedes older positive cache entries.
    for cached_key in list(cache):
        if cached_key[0] == did_aw and cached_key[1] != did_key:
            cache.pop(cached_key, None)
    cache[key] = (started + _BINDING_TTL, binding)
    cache.move_to_end(key)
    while len(cache) > _CACHE_LIMIT:
        cache.popitem(last=False)
    return binding


async def observe_identity_binding(client, *, did_key: str, did_aw: str, address: str = "") -> IdentityBinding:
    """The compatible server adapter for the shared public AWID observation."""
    try:
        return await observe_public_identity_binding(
            client, did_key=did_key, did_aw=did_aw, address=address,
        )
    except IdentityObservationRefused as exc:
        status = 403 if exc.code == "identity_binding_mismatch" else 503
        raise HTTPException(status_code=status, detail=exc.code) from exc


async def refresh_projection_binding(
    db, *, agent_id, did_key: str, binding: IdentityBinding
):
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


async def verify_pending_identity_bindings(db, registry_client, *, dry_run: bool = False) -> dict[str, int]:
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
                registry_client, did_key=row["did_key"],
                did_aw=row["did_aw"] or "", address=row["address"] or "",
            )
        except HTTPException as exc:
            counts["awid_error" if exc.status_code == 503 else "unbound"] += 1
            continue
        if not dry_run:
            async with db.transaction() as tx:
                current = await tx.fetch_one(
                    """
                    SELECT did_key, did_aw, address FROM {{tables.agents}}
                    WHERE agent_id=$1 AND deleted_at IS NULL AND did_aw_verified_key IS NULL
                    FOR UPDATE
                    """, row["agent_id"],
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
