"""Explicit-address selection shared by mail and chat; delivery admits separately."""

from __future__ import annotations

import logging

from awid.federation_errors import FederationAuthorityError

from aweb.awid_error_handling import (
    AWID_DEPENDENCY_ERRORS,
    awid_registry_not_configured_exception,
)
from aweb.messaging.address_auth import (
    identity_recipient,
    local_recipient_for_address_binding,
    namespace_uses_home_registry,
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
    db, *, runtime: MessagingRuntime, auth, address: str, source: str,
    message_type: str, signed_payload: str | None = None, signature: str | None = None,
) -> dict:
    """Use a verified signed binding offline, otherwise resolve the address.

    The SDK reader classifies address absence. The strict reader's not-found
    keeps its existing fallback meaning; it is not proof of coded absence.
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
    authority = runtime.federation_authority
    # Keep the existing registry-selection rule: a team label alone does not
    # authorize the configured registry. Foreign authority remains strict.
    home_namespace = await namespace_uses_home_registry(db, registry, domain)
    try:
        if registry is not None and (home_namespace or authority is None):
            resolution = await registry.resolve_address(domain, name, did_key=auth.did_key)
        elif authority is not None:
            try:
                resolution = await authority.resolve_contact(address, source_ip=source)
            except FederationAuthorityError as exc:
                # Preserve main's strict-reader not-found, without claiming
                # it distinguishes address absence from every other HTTP 404.
                if exc.reason != "recipient_identity_not_found":
                    raise
                resolution = None
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
                "agent_id": None, "team_id": None, "alias": name, "address": address,
                "did_aw": resolution.did_aw.strip(),
                "did_key": str(getattr(resolution, "current_did_key", "") or "").strip(),
                "delivery_origin": origin, "external": True,
                "_authority_route_current": home_namespace or authority is not None,
            }
        recipient["authority_controller_did"] = str(getattr(resolution, "controller_did", "") or "").strip()
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
    raise FederationAuthorityError("recipient_identity_not_found")
