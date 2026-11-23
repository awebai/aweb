"""One recipient policy decision for native and federated mail/chat."""

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum, auto

from fastapi import HTTPException
from aweb.application_state import RegistryClientUnavailable

from aweb.inbound_modes import (
    InboundMode,
    effective_inbound_mode,
    normalize_inbound_mode,
)
from aweb.member_team_key import MemberReadLock, current_member_team_ids_for_identities
from aweb.messaging.contacts import IdentityContactMatch, identity_contact_match
from aweb.messaging.refusals import (
    CONTACT_REBIND_ACTION,
    DeliveryRefusalCode,
    unreachable_address_refusal,
)
from aweb.service_errors import ForbiddenError

logger = logging.getLogger(__name__)
_POLICY_ACTION = (
    "Ask the recipient to add your exact address as a contact or check their inbound policy."
)


class DeliveryAttempt(Enum):
    FIRST_CONTACT = auto()
    STORED_ROUTE = auto()


@dataclass(frozen=True, kw_only=True)
class DeliverySender:
    """Authenticated identity facts; no caller-selected team grants admission."""

    did: str
    address: str | None
    verified_dids: tuple[str, ...] = ()

    def identity_dids(self) -> list[str]:
        return list(
            dict.fromkeys(
                value.strip() for value in (*self.verified_dids, self.did) if value.strip()
            )
        )

    def contact_did(self) -> str:
        dids = self.identity_dids()
        return next((did for did in dids if did.startswith("did:aw:")), self.did)


class DeliveryPolicyRefused(ForbiddenError):
    detail: str

    def __init__(self, *, code: DeliveryRefusalCode, detail: str):
        self.code = code
        self.status_code = 404 if code is DeliveryRefusalCode.LOCAL_RECIPIENT_ROUTE_MISSING else 403
        logger.warning("delivery_policy_refused reason=%s", code.value)
        super().__init__(detail)


def is_global_recipient(recipient: Mapping) -> bool:
    """Raw claims select stricter policy, never an identity or route."""
    return (
        recipient.get("identity_scope") == "global"
        or bool(recipient.get("has_global_claim"))
        or bool(str(recipient.get("did_aw") or "").strip())
    )


async def recipient_inbound_mode(db, recipient: Mapping) -> InboundMode:
    """Read strictest nondeleted identity policy, regardless of membership status."""
    policy_did = recipient.get("policy_did_aw", recipient.get("did_aw"))
    try:
        mode = (
            await effective_inbound_mode(db.get_manager("aweb"), str(policy_did), for_share=True)
            if policy_did
            else normalize_inbound_mode(recipient.get("inbound_mode"), default="")
        )
        return InboundMode(mode)
    except (ValueError, ForbiddenError) as exc:
        raise DeliveryPolicyRefused(
            code=DeliveryRefusalCode.RECIPIENT_POLICY_REJECTED,
            detail="Recipient inbound policy is unavailable. Ask the recipient to reconnect or the server operator to check the recipient's policy.",
        ) from exc


async def has_current_shared_team(
    db,
    *,
    recipient: Mapping,
    sender_dids: list[str],
    registry_client,
) -> bool:
    """Intersect all current active memberships using R2's single selector."""
    recipient_dids = [
        str(recipient[field]) for field in ("did_aw", "did_key") if recipient.get(field)
    ]
    recipient_teams, sender_teams = await current_member_team_ids_for_identities(
        db, recipient_dids, sender_dids, registry_client=registry_client, read_lock=MemberReadLock.SHARE
    )
    return bool(recipient_teams & sender_teams)


async def authorize_delivery(
    db,
    *,
    recipient: Mapping,
    sender: DeliverySender,
    attempt: DeliveryAttempt,
    registry_client,
) -> None:
    """Enforce Global And Local Identities (docs/identity-messaging-contract.md:81-99) on
    every transport.

    Global contacts-only always applies to continuations. Local participants
    may continue a stored route. Otherwise only current team intersection or an
    exact active identity contact authorizes a restricted recipient.
    """
    global_recipient = is_global_recipient(recipient)
    mode = await recipient_inbound_mode(db, recipient) if global_recipient else None
    if mode is InboundMode.OPEN:
        return
    if not global_recipient and attempt is DeliveryAttempt.STORED_ROUTE:
        return
    membership_error = None
    if mode is not InboundMode.CONTACTS_ONLY:
        try:
            if await has_current_shared_team(
                db,
                recipient=recipient,
                sender_dids=sender.identity_dids(),
                registry_client=registry_client,
            ):
                return
        except (HTTPException, RegistryClientUnavailable) as exc:
            # An exact contact independently admits the sender. Otherwise an
            # unavailable membership read must retain its cause and retry status.
            membership_error = exc
    owner_dids = [str(recipient[field]) for field in ("did_aw", "did_key") if recipient.get(field)]
    match = await identity_contact_match(
        db,
        owner_dids=owner_dids,
        address=sender.address,
        sender_did=sender.contact_did(),
    )
    if match is IdentityContactMatch.MATCHED:
        return
    if membership_error is not None:
        raise membership_error
    if match is IdentityContactMatch.NEEDS_BINDING:
        raise DeliveryPolicyRefused(
            code=DeliveryRefusalCode.CONTACT_IDENTITY_BINDING_REQUIRED,
            detail=CONTACT_REBIND_ACTION,
        )
    if not global_recipient:
        # Preserve the published local-only 404 (federation-error-reference.md:40).
        # Missing identities retain their distinct released error code.
        raise DeliveryPolicyRefused(
            code=DeliveryRefusalCode.LOCAL_RECIPIENT_ROUTE_MISSING,
            detail=unreachable_address_refusal(str(recipient.get("address") or "")),
        )
    detail = (
        "Recipient only accepts messages from exact active contacts. "
        if mode is InboundMode.CONTACTS_ONLY
        else "Recipient only accepts messages from verified team members or exact active contacts. "
    ) + _POLICY_ACTION
    raise DeliveryPolicyRefused(code=DeliveryRefusalCode.RECIPIENT_POLICY_REJECTED, detail=detail)
