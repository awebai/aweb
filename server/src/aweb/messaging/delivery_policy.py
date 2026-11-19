"""One recipient policy decision for native and federated mail/chat."""

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum, auto

from aweb.inbound_modes import (
    InboundMode,
    effective_inbound_mode,
    normalize_inbound_mode,
)
from aweb.member_team_key import current_member_team_ids_for_identity
from aweb.messaging.contacts import IdentityContactMatch, identity_contact_match
from aweb.messaging.refusals import CONTACT_REBIND_ACTION, DeliveryRefusalCode
from aweb.service_errors import ForbiddenError

logger = logging.getLogger(__name__)
_POLICY_ACTION = "Ask the recipient to add your exact address as a contact or check their inbound policy."


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
                value.strip()
                for value in (*self.verified_dids, self.did)
                if value.strip()
            )
        )

    def contact_did(self) -> str:
        dids = self.identity_dids()
        return next((did for did in dids if did.startswith("did:aw:")), self.did)


class DeliveryPolicyRefused(ForbiddenError):
    detail: str

    def __init__(self, *, code: DeliveryRefusalCode, detail: str):
        self.code = code
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
            await effective_inbound_mode(db.get_manager("aweb"), str(policy_did))
            if policy_did
            else normalize_inbound_mode(recipient.get("inbound_mode"), default="")
        )
        return InboundMode(mode)
    except (ValueError, ForbiddenError) as exc:
        raise DeliveryPolicyRefused(
            code=DeliveryRefusalCode.RECIPIENT_POLICY_REJECTED,
            detail="Recipient inbound_mode migration required. Ask the server operator to complete the inbound policy migration and retry.",
        ) from exc


async def has_current_shared_team(
    db,
    *,
    recipient: Mapping,
    sender_dids: list[str],
) -> bool:
    """Intersect all current active memberships using R2's single selector."""
    recipient_dids = [
        str(recipient[field]) for field in ("did_aw", "did_key") if recipient.get(field)
    ]
    recipient_teams = await current_member_team_ids_for_identity(db, recipient_dids)
    sender_teams = await current_member_team_ids_for_identity(db, sender_dids)
    return bool(recipient_teams & sender_teams)


async def authorize_delivery(
    db,
    *,
    recipient: Mapping,
    sender: DeliverySender,
    attempt: DeliveryAttempt,
) -> None:
    """Enforce docs/identity-messaging-contract.md:69-93 on every transport.

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
    if mode is not InboundMode.CONTACTS_ONLY and await has_current_shared_team(
        db,
        recipient=recipient,
        sender_dids=sender.identity_dids(),
    ):
        return
    owner_dids = [
        str(recipient[field]) for field in ("did_aw", "did_key") if recipient.get(field)
    ]
    match = await identity_contact_match(
        db,
        owner_dids=owner_dids,
        address=sender.address,
        sender_did=sender.contact_did(),
    )
    if match is IdentityContactMatch.MATCHED:
        return
    if match is IdentityContactMatch.NEEDS_BINDING:
        raise DeliveryPolicyRefused(
            code=DeliveryRefusalCode.CONTACT_IDENTITY_BINDING_REQUIRED,
            detail=CONTACT_REBIND_ACTION,
        )
    if mode is InboundMode.CONTACTS_ONLY:
        detail = (
            "Recipient only accepts messages from exact active contacts. "
            + _POLICY_ACTION
        )
    elif global_recipient:
        detail = (
            "Recipient only accepts messages from verified team members or exact active contacts. "
            + _POLICY_ACTION
        )
    else:
        detail = (
            "Local recipient only accepts same-team, exact-contact, or stored-route continuation delivery. "
            + _POLICY_ACTION
        )
    raise DeliveryPolicyRefused(
        code=DeliveryRefusalCode.RECIPIENT_POLICY_REJECTED, detail=detail
    )
