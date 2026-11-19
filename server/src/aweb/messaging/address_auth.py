from __future__ import annotations

import json
import logging
from typing import Any, Mapping
from types import SimpleNamespace

from awid.registry import RegistryError
from fastapi import HTTPException
from awid.signing import verify_did_key_signature
from aweb.identity_binding import observe_current_identity_binding
from aweb.federation.errors import RecipientNotResidentError
from aweb.federation.origins import is_own_origin
from aweb.messaging.runtime import MessagingRuntime


def identity_recipient(row: Mapping[str, Any], address: str | None = None) -> dict:
    """Project an admitted identity/route, never a team actor as a participant."""
    recipient = dict(row)
    recipient["agent_id"] = None
    if recipient.get("did_aw"):
        recipient["team_id"] = None
    if address is not None:
        recipient["address"] = address or None
        recipient["alias"] = address.split("/", 1)[-1] if address else (recipient.get("did_aw") or recipient.get("did_key"))
    return recipient


async def local_recipient_for_address_binding(db, resolution: Any, address: str) -> dict | None:
    """Find residence for an independently admitted address identity.

    The registry supplies the canonical DID and current signature key. A local
    membership's old key/verification marker cannot decide whether that DID
    still lives here after rotation. This lookup grants no membership or actor
    authority and does not refresh any key projection.
    """
    row = await db.get_manager("aweb").fetch_one(
        """
        SELECT did_aw, identity_scope, inbound_mode, status, deleted_at,
               did_aw AS policy_did_aw, true AS has_global_claim
        FROM {{tables.agents}}
        WHERE did_aw=$1 AND deleted_at IS NULL
        ORDER BY agent_id
        LIMIT 1
        """, resolution.did_aw,
    )
    if row is None:
        return None
    recipient = identity_recipient(row, address)
    recipient["did_key"] = resolution.current_did_key
    return recipient


def refuse_same_origin_nonresident(delivery_origin: str, *, origins: set[str]) -> None:
    """After an exact-DID residence miss, an own-origin route is not external."""
    if is_own_origin(delivery_origin, origins):
        logging.getLogger(__name__).warning(
            "Refusing same-origin nonresident recipient: recipient_identity_not_found"
        )
        raise RecipientNotResidentError()


async def local_recipient_for_own_route(db, route: Mapping[str, Any], runtime: MessagingRuntime) -> dict | None:
    """Classify a stored/refreshed route before forwarding or persisting it.

    The stored route supplies identity, never current-key evidence. Residence
    and delivery policy remain separate. A foreign route is unchanged.
    """
    origin = str(route.get("delivery_origin") or "")
    if not is_own_origin(origin, runtime.public_origins):
        return None
    did = str(route.get("did_aw") or route.get("did") or route.get("did_key") or "")
    if did.startswith("did:aw:"):
        recipient = await local_recipient_for_address_binding(
            db, SimpleNamespace(did_aw=did, current_did_key=None),
            str(route.get("address") or ""),
        )
    else:
        # A did:key return route is already an established participant; this
        # does not create bare-key first-contact authority.
        from aweb.messaging.messages import resolve_agent_by_did
        recipient = await resolve_agent_by_did(db, did)
    if recipient is None:
        refuse_same_origin_nonresident(origin, origins=runtime.public_origins)
    if did.startswith("did:aw:"):
        # As with a stable-only signed continuation, discover the current key
        # through the existing binding authority, outside database transactions.
        # This validation context never repairs a participant or agent marker.
        try:
            resolution = await runtime.registry_client.resolve_key_fresh(did)
        except Exception as exc:
            mismatch = isinstance(exc, RegistryError) and exc.status_code == 404
            if not mismatch:
                logging.getLogger(__name__).warning("Own-route recipient binding unavailable", exc_info=True)
            raise HTTPException(
                status_code=403 if mismatch else 503,
                detail="identity_binding_mismatch" if mismatch else "identity_binding_unavailable",
            ) from exc
        address = str(route.get("address") or "")
        binding = await observe_current_identity_binding(
            runtime.registry_client, runtime.identity_binding_cache,
            did_key=resolution.current_did_key, did_aw=did,
            address=address if "/" in address else "",
        )
        recipient["did_key"] = binding.did_key
    return recipient


def unreachable_address_refusal(address: str) -> str:
    """Why a full address reaches no one, in words that do not say whether a
    local identity holds that name."""
    return (
        f"{address} is not a registered address. A local identity has no address and "
        "is reachable only from inside its own team, by alias; a global identity is "
        "reachable by address once one is assigned."
    )


def verified_signed_payload_json(
    *,
    signed_payload: str | None,
    signature: str | None,
    did_key: str | None,
) -> dict[str, Any] | None:
    if not signed_payload or not signature or not did_key:
        return None
    try:
        verify_did_key_signature(
            did_key=did_key,
            payload=signed_payload.encode("utf-8"),
            signature_b64=signature,
        )
        payload = json.loads(signed_payload)
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None
