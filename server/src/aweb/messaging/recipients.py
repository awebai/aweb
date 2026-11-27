"""One address-to-identity resolver for plaintext and encrypted mail/chat."""

from __future__ import annotations

from dataclasses import dataclass, replace
from collections.abc import Mapping

from aweb.application_state import RegistryClientUnavailable
from aweb.messaging.refusals import (
    ContactIdentityBindingRequired,
    DeliveryRefusal,
    RecipientAddressNotFound,
    registry_dependency_refusal,
)
from http import HTTPStatus
from awid.federation_errors import FederationAuthorityError
from aweb.federation.errors import LocalRecipientNotFoundError

from aweb.awid_error_handling import (
    AWID_DEPENDENCY_ERRORS,
)
from aweb.messaging.address_auth import (
    identity_recipient,
    local_recipient_for_address_binding,
    resolved_recipient_delivery_origin,
    resolved_recipient_controller_did,
    local_recipient_visible_to_auth,
    namespace_uses_home_registry,
    refuse_same_origin_nonresident,
    requires_registry_address_binding,
    verified_signed_payload_json,
)
from aweb.messaging.alias_targets import (
    AmbiguousLocalAddressError,
    get_agent_by_namespace_alias,
    namespace_exists,
)
from aweb.messaging.kinds import MessageKind
from aweb.messaging.recipient import Recipient
from aweb.messaging.recipient_bindings import (
    RecipientBindingUse,
    signed_recipient_matches,
)


@dataclass(frozen=True, kw_only=True)
class RecipientIdentityBinding:
    """The identity a saved contact expects, never a routing authority."""

    did: str

    def matches(self, recipient: Mapping) -> bool:
        return self.did in {recipient.get("did_aw"), recipient.get("did_key")}


async def _local_recipient_at_address(db, *, domain: str, name: str) -> Mapping | None:
    try:
        return await get_agent_by_namespace_alias(db, namespace=domain, alias=name)
    except AmbiguousLocalAddressError as exc:
        raise DeliveryRefusal(
            status_code=HTTPStatus.CONFLICT,
            detail=f"{exc}. Use a team-qualified alias or ask the recipient to check their address.",
        ) from exc


def _signature_binds_recipient_address(
    signed, *, address: str, recipient: Mapping, kind: MessageKind
) -> bool:
    return bool(
        isinstance(signed, dict)
        and signed.get("type") == kind
        and signed_recipient_matches(
            signed,
            recipients=[recipient],
            allowed_to={address},
            use=RecipientBindingUse.ADDRESS_VISIBILITY,
        )
    )


async def resolve_address_recipient(
    db,
    auth,
    runtime,
    *,
    address: str,
    source: str,
    kind: MessageKind,
    signed_payload: str | None = None,
    signature: str | None = None,
    binding: RecipientIdentityBinding | None = None,
) -> Recipient:
    """Resolve once, keeping any saved identity constraint through the send.

    Global And Local Identities (docs/identity-messaging-contract.md:116-144) requires an
    exact bound identity.
    A saved constraint stays attached to the one admitted identity; a second
    address resolution cannot silently replace it before signing or delivery.
    """
    recipient = await _resolve_address_identity(
        db,
        auth,
        runtime,
        address=address,
        source=source,
        kind=kind,
        signed_payload=signed_payload,
        signature=signature,
    )
    if binding is not None and not binding.matches(recipient):
        raise ContactIdentityBindingRequired()
    return recipient


async def _resolve_address_identity(
    db,
    auth,
    runtime,
    *,
    address: str,
    source: str,
    kind: MessageKind,
    signed_payload: str | None = None,
    signature: str | None = None,
) -> Recipient:
    """Return the exact admitted identity and route for the sender's address.

    Implements Global And Local Identities (docs/identity-messaging-contract.md:116-144) and
    Strict Cross-Registry Sender Authority (docs/identity-messaging-contract.md:206-222).

    Local visibility, signed identity binding and strict authority discovery are
    shared by both message kinds. The returned participant is identity-scoped;
    its membership row does not become actor authority.
    """
    recipient: Recipient | None
    address = address.strip()
    if "/" not in address:
        raise DeliveryRefusal(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="Recipient address must be domain/name. Check the address and try again.",
        )
    domain, name = address.split("/", 1)
    registry = runtime.registry_client
    signed = verified_signed_payload_json(
        signed_payload=signed_payload, signature=signature, did_key=auth.did_key
    )
    local = await _local_recipient_at_address(db, domain=domain, name=name)
    if local is not None:
        bound = _signature_binds_recipient_address(
            signed, address=address, recipient=local, kind=kind
        )
        needs_current = (
            requires_registry_address_binding(local)
            and signed is not None
            and bool(signed.get("to_did") or signed.get("to_stable_id"))
            and not bound
        )
        if bound or (
            local_recipient_visible_to_auth(local, auth) and not needs_current
        ):
            recipient = identity_recipient(local, address)
            return replace(recipient, requires_local_address_authority=True)

    authority = runtime.federation_authority
    home_namespace = await namespace_uses_home_registry(db, registry, domain)
    resolution = None
    if registry is not None and (home_namespace or authority is None):
        try:
            resolution = await registry.resolve_address(
                domain, name, did_key=auth.did_key
            )
        except AWID_DEPENDENCY_ERRORS as exc:
            raise registry_dependency_refusal(
                exc, operation="AWID recipient address lookup"
            ) from exc
    elif authority is not None:
        try:
            resolution = await authority.resolve_contact(address, source_ip=source)
        except FederationAuthorityError as exc:
            if exc.reason != "recipient_identity_not_found":
                raise

    if resolution is not None and resolution.did_aw:
        recipient = await local_recipient_for_address_binding(
            db,
            did_aw=resolution.did_aw,
            current_did_key=resolution.current_did_key,
            address=address,
        )
        if recipient is None:
            origin = resolved_recipient_delivery_origin(resolution)
            refuse_same_origin_nonresident(origin, origins=runtime.public_origins)
            recipient = Recipient.from_remote_projection(
                {
                    "agent_id": None,
                    "team_id": None,
                    "alias": name,
                    "address": address,
                    "did_aw": resolution.did_aw.strip(),
                    "did_key": (resolution.current_did_key or "").strip(),
                    "delivery_origin": origin,
                    "external": True,
                    "_authority_route_current": home_namespace or authority is not None,
                }
            )
        return replace(
            recipient,
            authority_controller_did=resolved_recipient_controller_did(resolution),
        )

    # A local projection supplies residence, not visibility or membership.
    # The caller still applies delivery policy and signed-recipient binding;
    # an absent registry grants no new key.
    local = await _local_recipient_at_address(db, domain=domain, name=name)
    if local is None:
        if await namespace_exists(db, domain):
            raise LocalRecipientNotFoundError(address=address)
        if registry is None:
            raise RegistryClientUnavailable()
        raise RecipientAddressNotFound(address=address)
    if (
        registry is not None
        and requires_registry_address_binding(local)
        and not (
            local_recipient_visible_to_auth(local, auth)
            or _signature_binds_recipient_address(
                signed, address=address, recipient=local, kind=kind
            )
        )
    ):
        raise RecipientAddressNotFound(address=address)
    recipient = identity_recipient(local, address)
    if not (recipient.get("did_aw") or recipient.get("did_key")):
        raise DeliveryRefusal(
            status_code=HTTPStatus.NOT_FOUND,
            detail="Recipient agent not found. Ask the recipient to reconnect and try again.",
        )
    return recipient
