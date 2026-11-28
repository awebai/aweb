from __future__ import annotations

from aweb.messaging.refusals import (
    RecipientIdentityBindingError,
    registry_dependency_refusal,
)

from aweb.messaging.refusals import (
    unreachable_address_refusal as unreachable_address_refusal,
)

import json
import logging
from dataclasses import replace
from typing import TYPE_CHECKING, Any, Mapping
from collections.abc import Set

from awid.registry import Address
from awid.log import canonical_server_origin
from awid.registry import RegistryError
from awid.signing import verify_did_key_signature

from aweb.awid_error_handling import AWID_DEPENDENCY_ERRORS
from aweb.federation.errors import RecipientNotResidentError
from aweb.federation.origins import is_own_origin
from aweb.identity_binding import observe_current_identity_binding
from aweb.messaging.alias_targets import namespace_exists
from aweb.messaging.runtime import MessagingRuntime
from aweb.messaging.recipient import Recipient
from aweb.service_errors import IdentityBindingCode, IdentityBindingError

if TYPE_CHECKING:
    from aweb.federation.activation import ResolvedContactIdentity
    from aweb.identity_auth_deps import MessagingAuth


def resolved_recipient_delivery_origin(
    resolution: Address | ResolvedContactIdentity,
) -> str:
    """Read either admitted address projection, preserving an absent origin."""
    if isinstance(resolution, Address):
        return (
            (resolution.delivery.origin if resolution.delivery is not None else "")
            or ""
        ).strip()
    return (resolution.delivery_origin or "").strip()


def resolved_recipient_controller_did(
    resolution: Address | ResolvedContactIdentity,
) -> str:
    """Only strict external resolution carries its verified controller here."""
    return (
        ""
        if isinstance(resolution, Address)
        else (resolution.controller_did or "").strip()
    )


def local_recipient_visible_to_auth(
    row: Mapping[str, Any] | None, auth: MessagingAuth
) -> bool:
    """Check same-team visibility only; this does not establish an address binding."""
    row_team_id = str((row or {}).get("team_id") or "").strip()
    auth_team_id = str(auth.team_id or "").strip()
    return bool(row_team_id and auth_team_id and row_team_id == auth_team_id)


def identity_recipient(row: Mapping[str, Any], address: str | None = None) -> Recipient:
    """Project an admitted identity/route, never a team actor as a participant."""
    recipient = (
        row if isinstance(row, Recipient) else Recipient.from_local_projection(row)
    )
    return recipient.as_identity(address=address)


async def local_recipient_for_address_binding(
    db, *, did_aw: str, current_did_key: str | None, address: str
) -> Recipient | None:
    """Find residence for an independently admitted address identity.

    Continuations (docs/identity-messaging-contract.md:305-310): "locality is residence of that
    exact DID, independent of a membership's superseded key or invalidated marker."
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
        """,
        did_aw,
    )
    if row is None:
        return None
    recipient = identity_recipient(row, address)
    return replace(recipient, did_key=current_did_key)


def requires_registry_address_binding(row: Mapping[str, Any] | None) -> bool:
    """Identify global projections whose address needs registry binding evidence."""
    return str((row or {}).get("identity_scope") or "").strip().lower() == "global"


def refuse_same_origin_nonresident(delivery_origin: str, *, origins: Set[str]) -> None:
    """After an exact-DID residence miss, an own-origin route is not external."""
    if is_own_origin(delivery_origin, origins):
        logging.getLogger(__name__).warning(
            "Refusing same-origin nonresident recipient: recipient_identity_not_found"
        )
        raise RecipientNotResidentError()


async def local_recipient_for_own_route(
    db, route: Mapping[str, Any], runtime: MessagingRuntime
) -> Recipient | None:
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
            db,
            did_aw=did,
            current_did_key=None,
            address=str(route.get("address") or ""),
        )
    else:
        # A did:key return route is already an established participant; this
        # does not create bare-key first-contact authority.
        from aweb.member_team_key import read_participant_identity_projection

        projection = await read_participant_identity_projection(db, participant_did=did)
        recipient = (
            Recipient.from_local_projection(projection)
            if projection is not None
            else None
        )
    if recipient is None:
        refuse_same_origin_nonresident(origin, origins=runtime.public_origins)
        return None
    if did.startswith("did:aw:"):
        # As with a stable-only signed continuation, discover the current key
        # through the existing binding authority, outside database transactions.
        # This validation context never repairs a participant or agent marker.
        if runtime.registry_client is None:
            raise RecipientIdentityBindingError(IdentityBindingCode.UNAVAILABLE)
        try:
            resolution = await runtime.registry_client.resolve_key_fresh(did)
        except AWID_DEPENDENCY_ERRORS as exc:
            mismatch = isinstance(exc, RegistryError) and exc.status_code == 404
            if not mismatch:
                logging.getLogger(__name__).warning(
                    "Own-route recipient binding unavailable failure_type=%s",
                    type(exc).__name__,
                )
            raise RecipientIdentityBindingError(
                IdentityBindingCode.MISMATCH
                if mismatch
                else IdentityBindingCode.UNAVAILABLE
            ) from exc
        address = str(route.get("address") or "")
        try:
            binding = await observe_current_identity_binding(
                runtime.registry_client,
                runtime.identity_binding_cache,
                did_key=resolution.current_did_key,
                did_aw=did,
                address=address if "/" in address else "",
            )
        except IdentityBindingError as exc:
            raise RecipientIdentityBindingError(exc.code, headers=exc.headers) from exc
        recipient = replace(recipient, did_key=binding.did_key)
    return recipient


def verified_signed_payload_json(
    *,
    signed_payload: str | None,
    signature: str | None,
    did_key: str | None,
) -> dict[str, Any] | None:
    """Decode a cryptographically verified object, returning no evidence on invalid input."""
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
    """Compare fresh canonical namespace authority with this client's registry origin."""
    if registry_client is None or not await namespace_exists(db, domain):
        return False
    try:
        if await registry_client.registry_audience(domain) != canonical_server_origin(
            registry_client.registry_url
        ):
            return False
        namespace = await registry_client.get_namespace_fresh(domain)
    except AWID_DEPENDENCY_ERRORS as exc:
        raise registry_dependency_refusal(
            exc, operation="AWID recipient namespace lookup"
        ) from exc
    return bool(
        namespace
        and namespace.domain == domain
        and namespace.verification_status == "verified"
        and namespace.controller_did
    )
