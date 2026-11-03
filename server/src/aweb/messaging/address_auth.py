from __future__ import annotations

import json
import logging
from typing import Any, Mapping
from types import SimpleNamespace

from awid.federation_errors import FederationAuthorityError
from awid.registry import RegistryError
from fastapi import HTTPException
from awid.log import canonical_server_origin
from awid.signing import verify_did_key_signature
from aweb.identity_binding import verify_identity_binding
from aweb.awid_error_handling import AWID_DEPENDENCY_ERRORS
from aweb.federation.errors import RecipientNotResidentError, TeamRouteError
from aweb.federation.origins import is_own_origin
from aweb.messaging.alias_targets import namespace_exists


def local_recipient_visible_to_auth(row: Mapping[str, Any] | None, auth: Any) -> bool:
    row_team_id = str((row or {}).get("team_id") or "").strip()
    auth_team_id = str(getattr(auth, "team_id", None) or "").strip()
    return bool(row_team_id and auth_team_id and row_team_id == auth_team_id)


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


def requires_registry_address_binding(row: Mapping[str, Any] | None) -> bool:
    return str((row or {}).get("identity_scope") or "").strip().lower() == "global"


def refuse_same_origin_nonresident(delivery_origin: str, *, origins: set[str]) -> None:
    """After an exact-DID residence miss, an own-origin route is not external."""
    if is_own_origin(delivery_origin, origins):
        logging.getLogger(__name__).warning(
            "Refusing same-origin nonresident recipient: recipient_identity_not_found"
        )
        raise RecipientNotResidentError()


async def local_recipient_for_own_route(db, route: Mapping[str, Any], *, request, origins: set[str]) -> dict | None:
    """Classify a stored/refreshed route before forwarding or persisting it.

    The stored route supplies identity, never current-key evidence. Residence
    and delivery policy remain separate. A foreign route is unchanged.
    """
    origin = str(route.get("delivery_origin") or "")
    if not is_own_origin(origin, origins):
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
        if route.get("route_team_id"):
            raise TeamRouteError("local_recipient_route_missing")
        refuse_same_origin_nonresident(origin, origins=origins)
    if did.startswith("did:aw:"):
        # As with a stable-only signed continuation, discover the current key
        # through the existing binding authority, outside database transactions.
        # This validation context never repairs a participant or agent marker.
        try:
            client = request.app.state.awid_registry_client
            resolution = await client.resolve_key_fresh(did)
        except Exception as exc:
            mismatch = isinstance(exc, RegistryError) and exc.status_code == 404
            if not mismatch:
                logging.getLogger(__name__).warning("Own-route recipient binding unavailable", exc_info=True)
            raise HTTPException(
                status_code=403 if mismatch else 503,
                detail="identity_binding_mismatch" if mismatch else "identity_binding_unavailable",
            ) from exc
        address = str(route.get("address") or "")
        binding = await verify_identity_binding(
            request, did_key=resolution.current_did_key, did_aw=did,
            address=address if "/" in address else "", fresh=True,
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


async def namespace_uses_home_registry(db, registry_client, domain: str) -> bool:
    # A local team label alone is not authority. Use the configured registry
    # only when it is the selected origin and actually serves this namespace.
    if registry_client is None or not await namespace_exists(db, domain):
        return False
    try:
        if await registry_client.registry_audience(domain) != canonical_server_origin(registry_client.registry_url):
            return False
        namespace = await registry_client.get_namespace_fresh(domain)
    except AWID_DEPENDENCY_ERRORS as exc:
        logging.getLogger(__name__).warning("Messaging home namespace lookup unavailable for %s", domain, exc_info=True)
        raise FederationAuthorityError("sender_registry_unavailable") from exc
    return bool(
        namespace and namespace.domain == domain
        and namespace.verification_status == "verified" and namespace.controller_did
    )
