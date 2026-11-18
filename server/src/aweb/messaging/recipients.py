"""One address-to-identity resolver for plaintext and encrypted mail/chat."""

from __future__ import annotations

import logging

from fastapi import HTTPException
from awid.federation_errors import FederationAuthorityError

from aweb.awid_error_handling import AWID_DEPENDENCY_ERRORS, awid_registry_not_configured_exception
from aweb.messaging.address_auth import (
    identity_recipient, local_recipient_for_address_binding,
    local_recipient_visible_to_auth, namespace_uses_home_registry,
    refuse_same_origin_nonresident, requires_registry_address_binding,
    verified_signed_payload_json,
)
from aweb.messaging.alias_targets import AmbiguousLocalAddressError, get_agent_by_namespace_alias, namespace_exists
from aweb.messaging.recipient_bindings import signed_recipient_matches

logger = logging.getLogger(__name__)


async def _local_address(db, *, domain: str, name: str) -> dict | None:
    try:
        return await get_agent_by_namespace_alias(db, namespace=domain, alias=name)
    except AmbiguousLocalAddressError as exc:
        raise HTTPException(
            status_code=409, detail=f"{exc}. Use a team-qualified alias or ask the recipient to check their address.",
        ) from exc


def _signed_address_binding(signed, *, address: str, recipient: dict, kind: str) -> bool:
    return bool(
        isinstance(signed, dict) and signed.get("type") == kind
        and signed_recipient_matches(signed, recipients=[recipient], allowed_to={address}, require_identity=True)
    )


async def resolve_address_recipient(
    db, auth, runtime, *, address: str, source: str, kind: str,
    signed_payload: str | None = None, signature: str | None = None,
) -> dict:
    """Return the exact admitted identity and route for the sender's address.

    Local visibility, signed identity binding and strict authority discovery are
    shared by both message kinds. The returned participant is identity-scoped;
    its membership row does not become actor authority.
    """
    address = address.strip()
    if "/" not in address:
        raise HTTPException(status_code=422, detail="Recipient address must be domain/name. Check the address and try again.")
    domain, name = address.split("/", 1)
    registry = runtime.registry_client
    signed = verified_signed_payload_json(signed_payload=signed_payload, signature=signature, did_key=auth.did_key)
    local = await _local_address(db, domain=domain, name=name)
    if local is not None:
        bound = _signed_address_binding(signed, address=address, recipient=local, kind=kind)
        needs_current = (
            requires_registry_address_binding(local) and signed is not None
            and bool(signed.get("to_did") or signed.get("to_stable_id")) and not bound
        )
        if bound or (local_recipient_visible_to_auth(local, auth) and not needs_current):
            recipient = identity_recipient(local, address)
            recipient["requires_local_address_authority"] = True
            return recipient

    authority = runtime.federation_authority
    home_namespace = await namespace_uses_home_registry(db, registry, domain)
    resolution = None
    if home_namespace:
        try:
            resolution = await registry.resolve_address(domain, name, did_key=auth.did_key)
        except AWID_DEPENDENCY_ERRORS as exc:
            logger.warning("Messaging home address lookup unavailable", exc_info=True)
            raise FederationAuthorityError("sender_registry_unavailable") from exc
    elif authority is not None:
        try:
            resolution = await authority.resolve_contact(address, source_ip=source)
        except FederationAuthorityError as exc:
            if exc.reason != "recipient_identity_not_found":
                raise
    elif registry is not None:
        resolution = await registry.resolve_address(domain, name, did_key=auth.did_key)

    if resolution is not None and resolution.did_aw:
        recipient = await local_recipient_for_address_binding(db, resolution, address)
        if recipient is None:
            delivery = getattr(resolution, "delivery", None)
            origin = str(getattr(resolution, "delivery_origin", None) or getattr(delivery, "origin", "") or "").strip()
            refuse_same_origin_nonresident(origin, origins=runtime.public_origins)
            recipient = {
                "agent_id": None, "team_id": None, "alias": name, "address": address,
                "did_aw": resolution.did_aw.strip(),
                "did_key": str(getattr(resolution, "current_did_key", "") or "").strip(),
                "delivery_origin": origin, "external": True,
                "_authority_route_current": home_namespace or authority is not None,
            }
        recipient["authority_controller_did"] = str(getattr(resolution, "controller_did", "") or "").strip()
        return recipient

    # Preserve the released local fallback, with the same visibility and signed
    # recipient rule used before discovery. An absent registry grants no new key.
    local = await _local_address(db, domain=domain, name=name)
    if local is None:
        if await namespace_exists(db, domain):
            raise FederationAuthorityError("recipient_identity_not_found")
        if registry is None:
            raise awid_registry_not_configured_exception(operation="AWID messaging recipient address lookup")
        raise HTTPException(status_code=404, detail=f"Recipient address not found: {address}. Check the address and try again.")
    if registry is not None and requires_registry_address_binding(local) and not (
        local_recipient_visible_to_auth(local, auth)
        or _signed_address_binding(signed, address=address, recipient=local, kind=kind)
    ):
        raise HTTPException(status_code=404, detail=f"Recipient address not found: {address}. Check the address and try again.")
    recipient = identity_recipient(local, address)
    if not (recipient.get("did_aw") or recipient.get("did_key")):
        raise HTTPException(status_code=404, detail="Recipient agent not found. Ask the recipient to reconnect and try again.")
    return recipient
