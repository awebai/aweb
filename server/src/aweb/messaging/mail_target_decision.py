"""Which recipient a new mail names: the rule, apart from the lookups it needs.

A send may name its recipient by stable id, DID, address, agent id or alias,
and may name it more than once. ``decide_mail_target`` chooses the selector
that leads, checks that every other selector names the same identity, and
says which refusal applies when one does not. It reads nothing itself: it
returns ``NeedFact`` for each lookup it needs, in the order the rule needs
them, and the caller reads that fact and asks again. A lookup the rule does
not reach is never made, so a send with two faults is refused for the first.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import Enum, StrEnum
from typing import Any

from aweb.messaging.recipient_bindings import RecipientSelectorField


class _Unread(Enum):
    UNREAD = "unread"


UNREAD = _Unread.UNREAD
"""A fact the caller has not read yet."""


class MailTargetFact(Enum):
    """A lookup the rule may need.

    PRIMARY reads the recipient the leading selector names. DID_BINDING and
    ALIAS_BINDING read the recipient a further to_did or to_alias names.
    SELECTED_MEMBER reads the team member a further to_agent_id names.
    """

    PRIMARY = "primary"
    DID_BINDING = "did_binding"
    ALIAS_BINDING = "alias_binding"
    SELECTED_MEMBER = "selected_member"


class MailTargetRefusalCode(StrEnum):
    NO_SELECTOR = "no_selector"
    ADDRESS_NOT_DOMAIN_NAME = "address_not_domain_name"
    RECIPIENT_NOT_FOUND = "recipient_not_found"
    BARE_DID_FIRST_CONTACT = "bare_did_first_contact"
    SELECTOR_MISMATCH = "selector_mismatch"


@dataclass(frozen=True)
class MailSelectors:
    """The recipient fields of a send, as the sender gave them."""

    to_stable_id: str | None = None
    to_did: str | None = None
    to_address: str | None = None
    to_agent_id: str | None = None
    to_alias: str | None = None


@dataclass(frozen=True)
class MailTargetFacts:
    """What the lookups returned so far. None means the lookup found nobody."""

    primary: Mapping[str, Any] | None | _Unread = UNREAD
    did_binding: Mapping[str, Any] | None | _Unread = UNREAD
    alias_binding: Mapping[str, Any] | None | _Unread = UNREAD
    selected_member: Mapping[str, Any] | None | _Unread = UNREAD

    def with_fact(
        self, fact: MailTargetFact, value: Mapping[str, Any] | None
    ) -> MailTargetFacts:
        return replace(self, **{fact.value: value})


@dataclass(frozen=True)
class NeedFact:
    """Read ``fact``: the recipient ``selector`` names with ``value``."""

    fact: MailTargetFact
    selector: RecipientSelectorField
    value: str


@dataclass(frozen=True)
class MailTargetRefusal:
    code: MailTargetRefusalCode
    supplied: RecipientSelectorField | None = None
    resolved: RecipientSelectorField | None = None


@dataclass(frozen=True)
class MailTargetChoice:
    recipient: Mapping[str, Any]
    recipient_did: str
    to_agent_id: str | None
    to_alias: str | None


MailTargetStep = NeedFact | MailTargetRefusal | MailTargetChoice


def _given(value: str | None) -> str | None:
    """A selector counts as given for a binding check when it is not blank."""
    if value is None or not value.strip():
        return None
    return value.strip()


def _did(recipient: Mapping[str, Any] | None) -> str:
    if recipient is None:
        return ""
    return str(recipient.get("did_aw") or recipient.get("did_key") or "").strip()


def _same_identity(
    left: Mapping[str, Any] | None, right: Mapping[str, Any] | None
) -> bool:
    left_did, right_did = _did(left), _did(right)
    return bool(left_did and right_did and left_did == right_did)


def _mismatch(
    supplied: RecipientSelectorField, resolved: RecipientSelectorField
) -> MailTargetRefusal:
    return MailTargetRefusal(
        MailTargetRefusalCode.SELECTOR_MISMATCH, supplied=supplied, resolved=resolved
    )


def leading_selector(selectors: MailSelectors) -> RecipientSelectorField | None:
    """The selector the target is resolved by; the others must agree with it."""
    if selectors.to_address is None and selectors.to_stable_id is not None:
        return RecipientSelectorField.STABLE_ID
    if selectors.to_address is None and selectors.to_did is not None:
        return RecipientSelectorField.DID
    if selectors.to_address is not None:
        return RecipientSelectorField.ADDRESS
    if selectors.to_agent_id is not None:
        return RecipientSelectorField.AGENT_ID
    if selectors.to_alias is not None:
        return RecipientSelectorField.ALIAS
    return None


def _leading_value(selectors: MailSelectors, leading: RecipientSelectorField) -> str:
    if leading is RecipientSelectorField.STABLE_ID:
        return str(selectors.to_stable_id).strip()
    if leading is RecipientSelectorField.DID:
        return str(selectors.to_did).strip()
    if leading is RecipientSelectorField.ADDRESS:
        return str(selectors.to_address).strip()
    if leading is RecipientSelectorField.AGENT_ID:
        return str(selectors.to_agent_id)
    # The alias selector is looked up as given; binding checks strip it.
    return str(selectors.to_alias)


def _binding_refusal(
    facts: MailTargetFacts,
    fact: MailTargetFact,
    supplied: RecipientSelectorField,
    value: str,
    leading: RecipientSelectorField,
    recipient: Mapping[str, Any],
) -> NeedFact | MailTargetRefusal | None:
    """Ask for a further selector's recipient, or refuse it if it is someone else."""
    bound = getattr(facts, fact.value)
    if bound is UNREAD:
        return NeedFact(fact, supplied, value)
    if not _same_identity(bound, recipient):
        return _mismatch(supplied, leading)
    return None


def decide_mail_target(
    selectors: MailSelectors, facts: MailTargetFacts
) -> MailTargetStep:
    """The next lookup the rule needs, the refusal it reaches, or the target."""
    leading = leading_selector(selectors)
    if leading is None:
        return MailTargetRefusal(MailTargetRefusalCode.NO_SELECTOR)
    value = _leading_value(selectors, leading)
    if leading is RecipientSelectorField.ADDRESS and "/" not in value:
        return MailTargetRefusal(MailTargetRefusalCode.ADDRESS_NOT_DOMAIN_NAME)

    recipient = facts.primary
    if recipient is UNREAD:
        return NeedFact(MailTargetFact.PRIMARY, leading, value)
    if recipient is None:
        if leading in (
            RecipientSelectorField.STABLE_ID,
            RecipientSelectorField.DID,
        ) and value.startswith("did:aw:"):
            return MailTargetRefusal(MailTargetRefusalCode.BARE_DID_FIRST_CONTACT)
        return MailTargetRefusal(MailTargetRefusalCode.RECIPIENT_NOT_FOUND)

    alias = _given(selectors.to_alias)
    if leading is RecipientSelectorField.STABLE_ID:
        did = _given(selectors.to_did)
        if did is not None:
            step = _binding_refusal(
                facts,
                MailTargetFact.DID_BINDING,
                RecipientSelectorField.DID,
                did,
                leading,
                recipient,
            )
            if step is not None:
                return step
    if leading is RecipientSelectorField.ADDRESS and alias is not None:
        if recipient.get("external"):
            if alias != recipient["alias"]:
                return _mismatch(RecipientSelectorField.ALIAS, leading)
        else:
            step = _binding_refusal(
                facts,
                MailTargetFact.ALIAS_BINDING,
                RecipientSelectorField.ALIAS,
                alias,
                leading,
                recipient,
            )
            if step is not None:
                return step
    elif leading is not RecipientSelectorField.ALIAS and alias is not None:
        step = _binding_refusal(
            facts,
            MailTargetFact.ALIAS_BINDING,
            RecipientSelectorField.ALIAS,
            alias,
            leading,
            recipient,
        )
        if step is not None:
            return step
    if leading is RecipientSelectorField.ADDRESS:
        stable_id = _given(selectors.to_stable_id)
        if (
            stable_id is not None
            and stable_id != str(recipient.get("did_aw") or "").strip()
        ):
            return _mismatch(RecipientSelectorField.STABLE_ID, leading)
        did = _given(selectors.to_did)
        if did is not None and did not in {
            str(recipient.get("did_aw") or "").strip(),
            str(recipient.get("did_key") or "").strip(),
        }:
            return _mismatch(RecipientSelectorField.DID, leading)

    if selectors.to_agent_id and any(
        given is not None
        for given in (selectors.to_address, selectors.to_did, selectors.to_stable_id)
    ):
        member = facts.selected_member
        if member is UNREAD:
            return NeedFact(
                MailTargetFact.SELECTED_MEMBER,
                RecipientSelectorField.AGENT_ID,
                selectors.to_agent_id,
            )
        if recipient.get("external") or not _same_identity(member, recipient):
            return _mismatch(RecipientSelectorField.AGENT_ID, leading)

    return _choice(selectors, leading, value, recipient)


def _choice(
    selectors: MailSelectors,
    leading: RecipientSelectorField,
    value: str,
    recipient: Mapping[str, Any],
) -> MailTargetChoice:
    agent_id = str(recipient["agent_id"]) if recipient.get("agent_id") else None
    if leading is RecipientSelectorField.STABLE_ID:
        return MailTargetChoice(recipient, value, agent_id, recipient.get("alias"))
    if leading is RecipientSelectorField.DID:
        recipient_did = str(
            recipient.get("did_aw") or recipient.get("did_key") or value
        ).strip()
        return MailTargetChoice(
            recipient, recipient_did, agent_id, recipient.get("alias")
        )
    if leading is RecipientSelectorField.ADDRESS:
        return MailTargetChoice(
            recipient, _did(recipient), agent_id, recipient.get("alias") or value
        )
    if leading is RecipientSelectorField.AGENT_ID:
        return MailTargetChoice(
            recipient, _did(recipient), selectors.to_agent_id, recipient.get("alias")
        )
    return MailTargetChoice(
        recipient, _did(recipient), str(recipient["agent_id"]), recipient["alias"]
    )
