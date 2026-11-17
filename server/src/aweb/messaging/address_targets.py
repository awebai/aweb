"""Registry-first explicit-address selection shared by mail and chat."""

from __future__ import annotations

import logging

from awid.federation_errors import FederationAuthorityError
from fastapi import HTTPException

from aweb.awid_error_handling import (
    AWID_DEPENDENCY_ERRORS,
    awid_registry_not_configured_exception,
)
from aweb.messaging.address_auth import (
    identity_recipient,
    local_recipient_for_address_binding,
    namespace_uses_home_registry,
    refuse_same_origin_nonresident,
)
from aweb.messaging.alias_targets import get_local_agent_by_derived_address
from aweb.messaging.runtime import MessagingRuntime


async def resolve_address_target(db, *, runtime: MessagingRuntime, auth, address: str, source: str) -> dict:
    """Select the registered identity, or a derived local address on coded absence.

    The AWID readers own the absence protocol: resolve_address returns None,
    and resolve_contact raises recipient_identity_not_found, ONLY for the
    address endpoint's coded address_not_found response. Missing namespace,
    generic HTTP 404 and incomplete identity evidence are not that signal.
    Never inspect HTTP status here or fall back after an unavailable read.
    """
    domain, name = address.split("/", 1)
    registry = runtime.registry_client
    authority = runtime.federation_authority
    home_namespace = await namespace_uses_home_registry(db, registry, domain)
    resolution = None
    try:
        if home_namespace:
            resolution = await registry.resolve_address(domain, name, did_key=auth.did_key)
        elif authority is not None:
            try:
                resolution = await authority.resolve_contact(address, source_ip=source)
                if resolution is None:
                    raise FederationAuthorityError("sender_registry_protocol_invalid")
            except FederationAuthorityError as exc:
                if exc.reason != "recipient_identity_not_found":
                    raise
        elif registry is not None:
            resolution = await registry.resolve_address(domain, name, did_key=auth.did_key)
        else:
            raise awid_registry_not_configured_exception(operation="AWID recipient address lookup")
    except AWID_DEPENDENCY_ERRORS as exc:
        logging.getLogger(__name__).warning("Recipient address lookup unavailable for %s", address, exc_info=True)
        raise FederationAuthorityError("sender_registry_unavailable") from exc

    if resolution is not None:
        if not getattr(resolution, "did_aw", None):
            raise FederationAuthorityError("sender_registry_protocol_invalid")
        recipient = await local_recipient_for_address_binding(db, resolution, address)
        if recipient is None:
            delivery = getattr(resolution, "delivery", None)
            origin = str(getattr(resolution, "delivery_origin", None) or getattr(delivery, "origin", "") or "").strip()
            refuse_same_origin_nonresident(origin, origins=runtime.public_origins)
            recipient = {
                "agent_id": None,
                "team_id": None,
                "alias": name,
                "address": address,
                "did_aw": resolution.did_aw.strip(),
                "did_key": str(getattr(resolution, "current_did_key", "") or "").strip(),
                "delivery_origin": origin,
                "external": True,
                "_authority_route_current": home_namespace or authority is not None,
            }
        recipient["authority_controller_did"] = str(getattr(resolution, "controller_did", "") or "").strip()
        return recipient

    # A positive binding, including a nonresident one, can never reach here.
    # The derived reading is exclusively for local identities without claims
    # in the sender's own team. Absence and out-of-team names are indistinguishable.
    local = await get_local_agent_by_derived_address(
        db, team_id=auth.team_id, namespace=domain, alias=name,
    )
    if local is None:
        raise FederationAuthorityError("recipient_identity_not_found")
    recipient = identity_recipient(local, address)
    if not recipient.get("did_key"):
        raise HTTPException(status_code=404, detail="Recipient agent not found")
    recipient["requires_local_address_authority"] = True
    return recipient
