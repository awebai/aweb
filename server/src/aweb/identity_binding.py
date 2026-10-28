"""Attribute stable identity claims only through current registry evidence."""

from __future__ import annotations

import logging
from collections import OrderedDict
from dataclasses import dataclass, replace
from time import monotonic

from awid.did import stable_id_from_did_key
from awid.registry import DIDKeyNotFoundError, IDTreeEnrollment, RegistryError
from fastapi import HTTPException, Request

logger = logging.getLogger(__name__)
_BINDING_TTL = 60
_CACHE_LIMIT = 4096


@dataclass(frozen=True)
class IdentityBinding:
    did_aw: str = ""
    address: str = ""
    fresh_observation: bool = False
    self_derived: bool = False
    did_key: str = ""
    id_tree: IDTreeEnrollment | None = None


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
) -> IdentityBinding:
    did_aw, address = (did_aw or "").strip(), (address or "").strip()
    if not did_aw and not address:
        return IdentityBinding(did_key=did_key)
    if not did_aw or not did_aw.startswith("did:aw:"):
        raise HTTPException(status_code=403, detail="identity_binding_mismatch")
    client = getattr(request.app.state, "awid_registry_client", None)
    if client is None:
        raise HTTPException(status_code=503, detail="identity_binding_unavailable")
    cache = getattr(request.app.state, "identity_binding_cache", None)
    if cache is None:
        cache = OrderedDict()
        request.app.state.identity_binding_cache = cache
    key = (did_aw, did_key, address)
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
    """Return a fresh key-bound observation for trusted in-process provisioning.

    Call before opening a provisioning transaction. This is the authoritative
    producer of IdentityBinding: it reads AWID fresh and applies the same
    identity/address rules as request authentication. A mismatch raises 403;
    unavailable evidence raises 503. Pass the returned object to connect_agent;
    never construct a fresh observation from a certificate or transport input.
    """
    if not did_aw or not did_aw.startswith("did:aw:"):
        raise HTTPException(status_code=403, detail="identity_binding_mismatch")
    self_derived = False
    enrollment = None
    try:
        try:
            # The SDK's ordinary key/address caches have a longer lifetime
            # and can serve stale values. They cannot establish this binding.
            resolution = await client.resolve_key_fresh(did_aw)
        except RegistryError as exc:
            if exc.status_code != 404:
                raise
            if did_aw != stable_id_from_did_key(did_key):
                raise HTTPException(
                    status_code=403, detail="identity_binding_mismatch"
                ) from exc
            self_derived = True
            # Key absence proves no enrollment only when AWID states it.
            enrollment = exc.id_tree if isinstance(exc, DIDKeyNotFoundError) else None
        else:
            if resolution.did_aw != did_aw or resolution.current_did_key != did_key:
                raise HTTPException(status_code=403, detail="identity_binding_mismatch")
            enrollment = resolution.id_tree
        if address:
            domain, separator, name = address.partition("/")
            if not separator or not domain or not name or "/" in name:
                raise HTTPException(status_code=403, detail="identity_binding_mismatch")
            resolved_address = await client.resolve_address_fresh(domain, name)
            if (
                resolved_address is None
                or resolved_address.did_aw != did_aw
                or resolved_address.current_did_key != did_key
                or f"{resolved_address.domain}/{resolved_address.name}" != address
            ):
                raise HTTPException(status_code=403, detail="identity_binding_mismatch")
    except HTTPException:
        raise
    except RegistryError as exc:
        if exc.status_code == 404:
            raise HTTPException(
                status_code=403, detail="identity_binding_mismatch"
            ) from exc
        logger.warning("Identity binding registry dependency failed", exc_info=True)
        raise HTTPException(
            status_code=503, detail="identity_binding_unavailable"
        ) from exc
    except Exception as exc:
        logger.warning("Identity binding registry dependency failed", exc_info=True)
        raise HTTPException(
            status_code=503, detail="identity_binding_unavailable"
        ) from exc
    return IdentityBinding(
        did_aw, address, fresh_observation=True, self_derived=self_derived,
        did_key=did_key, id_tree=enrollment,
    )


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
