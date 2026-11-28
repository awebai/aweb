"""One recipient policy decision for native and federated mail/chat."""

import logging
from collections.abc import Mapping
from dataclasses import dataclass, replace
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
        self.status_code = (
            404 if code is DeliveryRefusalCode.LOCAL_RECIPIENT_ROUTE_MISSING else 403
        )
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
            await effective_inbound_mode(
                db.get_manager("aweb"), str(policy_did), for_share=True
            )
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
        db,
        recipient_dids,
        sender_dids,
        registry_client=registry_client,
        read_lock=MemberReadLock.SHARE,
    )
    return bool(recipient_teams & sender_teams)


class _Unread(Enum):
    UNREAD = auto()


UNREAD = _Unread.UNREAD
"""A fact the caller has not read yet."""


class DeliveryFact(Enum):
    """A read the rule may need, in the order it needs them."""

    INBOUND_MODE = "inbound_mode"
    SHARED_TEAM = "shared_team"
    CONTACT_MATCH = "contact_match"


class SharedTeam(Enum):
    """What the current-membership read found."""

    SHARED = auto()
    NOT_SHARED = auto()
    UNAVAILABLE = auto()


@dataclass(frozen=True, kw_only=True)
class DeliveryFacts:
    global_recipient: bool
    attempt: DeliveryAttempt
    recipient_address: str = ""
    inbound_mode: InboundMode | _Unread = UNREAD
    shared_team: SharedTeam | _Unread = UNREAD
    contact_match: IdentityContactMatch | _Unread = UNREAD


@dataclass(frozen=True)
class NeedDeliveryFact:
    fact: DeliveryFact


@dataclass(frozen=True)
class DeliveryAdmitted:
    pass


@dataclass(frozen=True)
class DeliveryMembershipUnavailable:
    """No contact admits the sender and the membership read failed: its error stands."""


@dataclass(frozen=True)
class DeliveryDenied:
    code: DeliveryRefusalCode
    detail: str


DeliveryStep = (
    NeedDeliveryFact | DeliveryAdmitted | DeliveryMembershipUnavailable | DeliveryDenied
)


def decide_delivery(facts: DeliveryFacts) -> DeliveryStep:
    """Global And Local Identities (docs/identity-messaging-contract.md:81-99).

    Global contacts-only always applies to continuations. Local participants
    may continue a stored route. Otherwise only current team intersection or an
    exact active identity contact authorizes a restricted recipient. Returns
    the next fact the rule needs, or its verdict.
    """
    mode = None
    if facts.global_recipient:
        if facts.inbound_mode is UNREAD:
            return NeedDeliveryFact(DeliveryFact.INBOUND_MODE)
        mode = facts.inbound_mode
    if mode is InboundMode.OPEN:
        return DeliveryAdmitted()
    if not facts.global_recipient and facts.attempt is DeliveryAttempt.STORED_ROUTE:
        return DeliveryAdmitted()
    if mode is not InboundMode.CONTACTS_ONLY:
        if facts.shared_team is UNREAD:
            return NeedDeliveryFact(DeliveryFact.SHARED_TEAM)
        if facts.shared_team is SharedTeam.SHARED:
            return DeliveryAdmitted()
    if facts.contact_match is UNREAD:
        return NeedDeliveryFact(DeliveryFact.CONTACT_MATCH)
    if facts.contact_match is IdentityContactMatch.MATCHED:
        return DeliveryAdmitted()
    # An exact contact independently admits the sender. Otherwise an
    # unavailable membership read must retain its cause and retry status.
    if facts.shared_team is SharedTeam.UNAVAILABLE:
        return DeliveryMembershipUnavailable()
    if facts.contact_match is IdentityContactMatch.NEEDS_BINDING:
        return DeliveryDenied(
            DeliveryRefusalCode.CONTACT_IDENTITY_BINDING_REQUIRED,
            CONTACT_REBIND_ACTION,
        )
    if not facts.global_recipient:
        # Preserve the published local-only 404 (federation-error-reference.md:40).
        # Missing identities retain their distinct released error code.
        return DeliveryDenied(
            DeliveryRefusalCode.LOCAL_RECIPIENT_ROUTE_MISSING,
            unreachable_address_refusal(facts.recipient_address),
        )
    detail = (
        "Recipient only accepts messages from exact active contacts. "
        if mode is InboundMode.CONTACTS_ONLY
        else "Recipient only accepts messages from verified team members or exact active contacts. "
    ) + _POLICY_ACTION
    return DeliveryDenied(DeliveryRefusalCode.RECIPIENT_POLICY_REJECTED, detail)


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

    Reads the facts ``decide_delivery`` asks for, in its order, and acts on
    its verdict.
    """
    facts = DeliveryFacts(
        global_recipient=is_global_recipient(recipient),
        attempt=attempt,
        recipient_address=str(recipient.get("address") or ""),
    )
    membership_error = None
    while isinstance(step := decide_delivery(facts), NeedDeliveryFact):
        if step.fact is DeliveryFact.INBOUND_MODE:
            facts = replace(
                facts, inbound_mode=await recipient_inbound_mode(db, recipient)
            )
        elif step.fact is DeliveryFact.SHARED_TEAM:
            try:
                shared = await has_current_shared_team(
                    db,
                    recipient=recipient,
                    sender_dids=sender.identity_dids(),
                    registry_client=registry_client,
                )
            except (HTTPException, RegistryClientUnavailable) as exc:
                membership_error = exc
                facts = replace(facts, shared_team=SharedTeam.UNAVAILABLE)
            else:
                facts = replace(
                    facts,
                    shared_team=SharedTeam.SHARED if shared else SharedTeam.NOT_SHARED,
                )
        else:
            owner_dids = [
                str(recipient[field])
                for field in ("did_aw", "did_key")
                if recipient.get(field)
            ]
            facts = replace(
                facts,
                contact_match=await identity_contact_match(
                    db,
                    owner_dids=owner_dids,
                    address=sender.address,
                    sender_did=sender.contact_did(),
                ),
            )
    if isinstance(step, DeliveryAdmitted):
        return
    if isinstance(step, DeliveryMembershipUnavailable):
        raise membership_error
    raise DeliveryPolicyRefused(code=step.code, detail=step.detail)
