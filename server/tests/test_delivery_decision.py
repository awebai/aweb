"""Every branch of the recipient delivery rule, on facts given in the table."""

from __future__ import annotations

from dataclasses import replace

import pytest

from aweb.inbound_modes import InboundMode
from aweb.messaging.contacts import IdentityContactMatch
from aweb.messaging.delivery_policy import (
    DeliveryAdmitted,
    DeliveryAttempt,
    DeliveryDenied,
    DeliveryFact,
    DeliveryFacts,
    DeliveryMembershipUnavailable,
    NeedDeliveryFact,
    SharedTeam,
    decide_delivery,
    is_global_recipient,
)
from aweb.messaging.refusals import (
    CONTACT_REBIND_ACTION,
    DeliveryRefusalCode,
    unreachable_address_refusal,
)

FIRST = DeliveryAttempt.FIRST_CONTACT
STORED = DeliveryAttempt.STORED_ROUTE
OPEN = InboundMode.OPEN
TEAM = InboundMode.TEAM_AND_CONTACTS
CONTACTS = InboundMode.CONTACTS_ONLY
SHARED, NOT_SHARED, UNAVAILABLE = (
    SharedTeam.SHARED,
    SharedTeam.NOT_SHARED,
    SharedTeam.UNAVAILABLE,
)
MATCHED, NEEDS_BINDING, NO_CONTACT = (
    IdentityContactMatch.MATCHED,
    IdentityContactMatch.NEEDS_BINDING,
    IdentityContactMatch.NOT_FOUND,
)
MODE, TEAM_READ, CONTACT_READ = (
    DeliveryFact.INBOUND_MODE,
    DeliveryFact.SHARED_TEAM,
    DeliveryFact.CONTACT_MATCH,
)

ADMITTED = DeliveryAdmitted()
MEMBERSHIP_ERROR = DeliveryMembershipUnavailable()
REBIND = DeliveryDenied(
    DeliveryRefusalCode.CONTACT_IDENTITY_BINDING_REQUIRED, CONTACT_REBIND_ACTION
)
_ACTION = "Ask the recipient to add your exact address as a contact or check their inbound policy."
TEAM_REJECTED = DeliveryDenied(
    DeliveryRefusalCode.RECIPIENT_POLICY_REJECTED,
    "Recipient only accepts messages from verified team members or exact active contacts. "
    + _ACTION,
)
CONTACTS_REJECTED = DeliveryDenied(
    DeliveryRefusalCode.RECIPIENT_POLICY_REJECTED,
    "Recipient only accepts messages from exact active contacts. " + _ACTION,
)


def local_route_missing(address):
    return DeliveryDenied(
        DeliveryRefusalCode.LOCAL_RECIPIENT_ROUTE_MISSING,
        unreachable_address_refusal(address),
    )


def drive(facts, answers):
    """Run the rule to its verdict, answering each read from ``answers``.

    Returns the verdict and the reads asked for, in order. A read not in
    ``answers`` fails the test: the rule asked for something it should not.
    """
    asked = []
    while isinstance(step := decide_delivery(facts), NeedDeliveryFact):
        asked.append(step.fact)
        assert step.fact in answers, f"unexpected read {step.fact}"
        facts = replace(facts, **{step.fact.value: answers[step.fact]})
    return step, asked


@pytest.mark.parametrize("attempt", [FIRST, STORED])
@pytest.mark.parametrize(
    "answers,verdict,asked",
    [
        # Open admits on the mode alone.
        ({MODE: OPEN}, ADMITTED, [MODE]),
        # Team and contacts: a shared current team admits before any contact read.
        ({MODE: TEAM, TEAM_READ: SHARED}, ADMITTED, [MODE, TEAM_READ]),
        (
            {MODE: TEAM, TEAM_READ: NOT_SHARED, CONTACT_READ: MATCHED},
            ADMITTED,
            [MODE, TEAM_READ, CONTACT_READ],
        ),
        (
            {MODE: TEAM, TEAM_READ: NOT_SHARED, CONTACT_READ: NEEDS_BINDING},
            REBIND,
            [MODE, TEAM_READ, CONTACT_READ],
        ),
        (
            {MODE: TEAM, TEAM_READ: NOT_SHARED, CONTACT_READ: NO_CONTACT},
            TEAM_REJECTED,
            [MODE, TEAM_READ, CONTACT_READ],
        ),
        # A failed membership read is overridden only by an exact contact.
        (
            {MODE: TEAM, TEAM_READ: UNAVAILABLE, CONTACT_READ: MATCHED},
            ADMITTED,
            [MODE, TEAM_READ, CONTACT_READ],
        ),
        (
            {MODE: TEAM, TEAM_READ: UNAVAILABLE, CONTACT_READ: NEEDS_BINDING},
            MEMBERSHIP_ERROR,
            [MODE, TEAM_READ, CONTACT_READ],
        ),
        (
            {MODE: TEAM, TEAM_READ: UNAVAILABLE, CONTACT_READ: NO_CONTACT},
            MEMBERSHIP_ERROR,
            [MODE, TEAM_READ, CONTACT_READ],
        ),
        # Contacts only: membership is never read, and a team does not admit.
        ({MODE: CONTACTS, CONTACT_READ: MATCHED}, ADMITTED, [MODE, CONTACT_READ]),
        ({MODE: CONTACTS, CONTACT_READ: NEEDS_BINDING}, REBIND, [MODE, CONTACT_READ]),
        (
            {MODE: CONTACTS, CONTACT_READ: NO_CONTACT},
            CONTACTS_REJECTED,
            [MODE, CONTACT_READ],
        ),
    ],
)
def test_a_global_recipient_applies_its_mode_on_every_attempt(
    attempt, answers, verdict, asked
):
    facts = DeliveryFacts(
        global_recipient=True, attempt=attempt, recipient_address="acme.com/bob"
    )
    assert drive(facts, answers) == (verdict, asked)


def test_a_local_recipient_admits_a_stored_route_without_reading_anything():
    facts = DeliveryFacts(global_recipient=False, attempt=STORED)
    assert drive(facts, {}) == (ADMITTED, [])


@pytest.mark.parametrize(
    "answers,verdict,asked",
    [
        # A local recipient has no mode: a shared team or an exact contact admits.
        ({TEAM_READ: SHARED}, ADMITTED, [TEAM_READ]),
        (
            {TEAM_READ: NOT_SHARED, CONTACT_READ: MATCHED},
            ADMITTED,
            [TEAM_READ, CONTACT_READ],
        ),
        (
            {TEAM_READ: UNAVAILABLE, CONTACT_READ: MATCHED},
            ADMITTED,
            [TEAM_READ, CONTACT_READ],
        ),
        (
            {TEAM_READ: UNAVAILABLE, CONTACT_READ: NO_CONTACT},
            MEMBERSHIP_ERROR,
            [TEAM_READ, CONTACT_READ],
        ),
        (
            {TEAM_READ: NOT_SHARED, CONTACT_READ: NEEDS_BINDING},
            REBIND,
            [TEAM_READ, CONTACT_READ],
        ),
        # Otherwise it is not reachable from here: the published local-only 404.
        (
            {TEAM_READ: NOT_SHARED, CONTACT_READ: NO_CONTACT},
            local_route_missing("acme.com/bob"),
            [TEAM_READ, CONTACT_READ],
        ),
    ],
)
def test_a_local_recipient_on_first_contact(answers, verdict, asked):
    facts = DeliveryFacts(
        global_recipient=False, attempt=FIRST, recipient_address="acme.com/bob"
    )
    assert drive(facts, answers) == (verdict, asked)


def test_a_local_recipient_without_an_address_gets_the_team_only_refusal():
    facts = DeliveryFacts(global_recipient=False, attempt=FIRST)
    verdict, _ = drive(facts, {TEAM_READ: NOT_SHARED, CONTACT_READ: NO_CONTACT})
    assert verdict == local_route_missing("")
    assert verdict.detail.startswith(
        "The recipient is not reachable from outside its team."
    )


@pytest.mark.parametrize(
    "recipient,is_global",
    [
        ({"identity_scope": "global"}, True),
        ({"has_global_claim": True}, True),
        ({"did_aw": " did:aw:bob "}, True),
        ({"identity_scope": "local", "did_aw": "  ", "did_key": "did:key:bob"}, False),
        ({}, False),
    ],
)
def test_any_global_claim_makes_the_recipient_global(recipient, is_global):
    assert is_global_recipient(recipient) is is_global
