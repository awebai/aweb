"""Explicit-address selection shared by mail and chat; delivery admits separately."""

from __future__ import annotations

import logging

from awid.federation_errors import FederationAuthorityError
from awid.team_ids import parse_team_id
from fastapi import HTTPException

from aweb.messaging.alias_targets import namespace_exists

from aweb.awid_error_handling import (
    AWID_DEPENDENCY_ERRORS,
    awid_registry_not_configured_exception,
)
from aweb.messaging.address_auth import (
    identity_recipient,
    local_recipient_for_address_binding,
    refuse_same_origin_nonresident,
    verified_signed_payload_json,
)
from aweb.messaging.runtime import MessagingRuntime


async def _address_candidates(db, *, domain: str, name: str) -> list[dict]:
    return await db.get_manager("aweb").fetch_all(
        """
        SELECT a.agent_id, a.team_id, a.alias, a.did_key,
               CASE WHEN a.did_aw_verified_key = a.did_key THEN a.did_aw END AS did_aw,
               CASE WHEN a.did_aw_verified_key = a.did_key THEN a.address END AS address,
               a.identity_scope, (NULLIF(a.did_aw, '') IS NOT NULL) AS has_global_claim,
               a.did_aw AS policy_did_aw, a.inbound_mode, a.status, a.deleted_at
        FROM {{tables.agents}} a
        JOIN {{tables.teams}} t ON t.team_id = a.team_id
        WHERE t.namespace = $1 AND a.deleted_at IS NULL
          AND (a.alias = $2 OR a.address = $1 || '/' || $2)
          AND ((NULLIF(a.did_aw, '') IS NULL AND NULLIF(a.address, '') IS NULL)
               OR a.did_aw_verified_key = a.did_key)
        """, domain, name,
    )


def _matches_signed_binding(signed: dict | None, row: dict, *, address: str, message_type: str) -> bool:
    if not signed or signed.get("type") != message_type:
        return False
    signed_to = str(signed.get("to") or "").strip()
    if signed_to and signed_to != address:
        return False
    key = str(signed.get("to_did") or "").strip()
    stable = str(signed.get("to_stable_id") or "").strip()
    row_stable = str(row.get("did_aw") or "").strip()
    row_key = str(row.get("did_key") or "").strip()
    return bool(key or stable) and (not key or key in {row_stable, row_key}) and (
        not stable or stable == row_stable
    )


async def resolve_address_target(
    db, *, runtime: MessagingRuntime, auth, address: str,
    message_type: str, signed_payload: str | None = None, signature: str | None = None,
) -> dict:
    """Use a verified signed binding offline, otherwise resolve the address.

    The outbound SDK reader selects the registry and classifies address absence.
    Strict inbound discovery is never used to select an outbound recipient.
    Signed selection may cross teams, but delivery admission still decides.
    This function does not grant delivery admission or contact authority.
    """
    domain, name = address.split("/", 1)
    candidates = await _address_candidates(db, domain=domain, name=name)
    signed = verified_signed_payload_json(
        signed_payload=signed_payload, signature=signature, did_key=auth.did_key,
    )
    for candidate in candidates:
        if _matches_signed_binding(signed, candidate, address=address, message_type=message_type):
            recipient = identity_recipient(candidate, address)
            recipient["requires_local_address_authority"] = True
            return recipient

    registry = runtime.registry_client
    if registry is None:
        raise awid_registry_not_configured_exception(operation="AWID recipient address lookup")
    # The authenticated team supplies this local identity's own domain, not
    # authority over the target. Foreign targets follow outbound DNS policy.
    own_domain = (
        auth.address.split("/", 1)[0] if auth.address
        else parse_team_id(auth.team_id)[0] if auth.team_id else None
    )
    try:
        resolution = await registry.resolve_outbound_address(domain, name, own_domain=own_domain)
    except AWID_DEPENDENCY_ERRORS as exc:
        logging.getLogger(__name__).warning("Recipient address lookup unavailable", exc_info=True)
        raise FederationAuthorityError("sender_registry_unavailable") from exc

    if resolution is not None:
        recipient = await local_recipient_for_address_binding(db, resolution, address)
        if recipient is None:
            origin = (resolution.delivery.origin or "").strip()
            refuse_same_origin_nonresident(origin, origins=runtime.public_origins)
            recipient = {
                "agent_id": None, "team_id": None, "alias": name, "address": address,
                "did_aw": resolution.did_aw.strip(),
                "did_key": resolution.current_did_key,
                "delivery_origin": origin, "external": True,
                "_authority_route_current": True,
            }
        recipient["authority_controller_did"] = resolution.controller_did
        return recipient

    # Unsigned label selection is team-scoped. Other teams cannot contribute
    # an ambiguity or grant delivery; retain their documented refusal answer.
    local_candidates = [
        candidate for candidate in candidates
        if candidate.get("identity_scope") == "local" and not candidate.get("has_global_claim")
        and not candidate.get("address") and candidate.get("alias") == name
    ]
    for candidate in local_candidates:
        if auth.team_id and candidate.get("team_id") == auth.team_id:
            recipient = identity_recipient(candidate, address)
            recipient["requires_local_address_authority"] = True
            return recipient
    if local_candidates:
        raise FederationAuthorityError("local_recipient_route_missing")
    if not candidates and await namespace_exists(db, domain):
        raise FederationAuthorityError("recipient_identity_not_found")
    detail = "Recipient address not found" if message_type == "mail" else f"Recipient address not found: {address}"
    raise HTTPException(status_code=404, detail=detail)
