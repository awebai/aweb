"""Every branch of the mail target rule, on facts given in the table."""

from __future__ import annotations

import pytest

from aweb.messaging.mail_target_decision import (
    MailSelectors,
    MailTargetChoice,
    MailTargetFact,
    MailTargetFacts,
    MailTargetRefusal,
    MailTargetRefusalCode,
    NeedFact,
    decide_mail_target,
    leading_selector,
)
from aweb.messaging.recipient_bindings import RecipientSelectorField as F

BOB = {
    "did_aw": "did:aw:bob",
    "did_key": "did:key:bob",
    "agent_id": "a-bob",
    "alias": "bob",
}
CAROL = {
    "did_aw": "did:aw:carol",
    "did_key": "did:key:carol",
    "agent_id": "a-carol",
    "alias": "carol",
}
BOB_KEY_ONLY = {
    "did_aw": None,
    "did_key": "did:key:bob",
    "agent_id": "a-bob",
    "alias": "bob",
}
EXTERNAL_BOB = {
    "did_aw": "did:aw:bob",
    "did_key": "did:key:bob",
    "agent_id": None,
    "alias": "bob",
    "external": True,
}

NOT_FOUND = MailTargetRefusal(MailTargetRefusalCode.RECIPIENT_NOT_FOUND)
BARE_DID = MailTargetRefusal(MailTargetRefusalCode.BARE_DID_FIRST_CONTACT)


def mismatch(supplied, resolved):
    return MailTargetRefusal(
        MailTargetRefusalCode.SELECTOR_MISMATCH, supplied, resolved
    )


def drive(selectors, answers):
    """Run the rule to its end, answering each lookup from ``answers``.

    Returns the final step and the lookups asked for, in order. A lookup not
    in ``answers`` fails the test: the rule asked for something it should not.
    """
    facts, asked = MailTargetFacts(), []
    while True:
        step = decide_mail_target(selectors, facts)
        if not isinstance(step, NeedFact):
            return step, asked
        asked.append((step.fact, step.selector, step.value))
        key = (step.fact, step.value)
        assert key in answers, f"unexpected lookup {key}"
        facts = facts.with_fact(step.fact, answers[key])


PRIMARY = MailTargetFact.PRIMARY
DID_BINDING = MailTargetFact.DID_BINDING
ALIAS_BINDING = MailTargetFact.ALIAS_BINDING
SELECTED_MEMBER = MailTargetFact.SELECTED_MEMBER


@pytest.mark.parametrize(
    "selectors,leading",
    [
        (MailSelectors(), None),
        (
            MailSelectors(
                to_stable_id="did:aw:bob", to_did="did:key:bob", to_alias="bob"
            ),
            F.STABLE_ID,
        ),
        (
            MailSelectors(to_did="did:key:bob", to_agent_id="a-bob", to_alias="bob"),
            F.DID,
        ),
        (
            MailSelectors(
                to_address="acme.com/bob", to_stable_id="did:aw:bob", to_did="x"
            ),
            F.ADDRESS,
        ),
        (MailSelectors(to_agent_id="a-bob", to_alias="bob"), F.AGENT_ID),
        (MailSelectors(to_alias="bob"), F.ALIAS),
        # A blank selector still leads: it is given, and found by nobody.
        (MailSelectors(to_stable_id="", to_alias="bob"), F.STABLE_ID),
    ],
)
def test_the_leading_selector_follows_the_fixed_precedence(selectors, leading):
    assert leading_selector(selectors) is leading


@pytest.mark.parametrize(
    "selectors,answers,result,asked",
    [
        # No selector, and an address that is not domain/name, refuse before any lookup.
        (MailSelectors(), {}, MailTargetRefusal(MailTargetRefusalCode.NO_SELECTOR), []),
        (
            MailSelectors(to_address="missing-domain"),
            {},
            MailTargetRefusal(MailTargetRefusalCode.ADDRESS_NOT_DOMAIN_NAME),
            [],
        ),
        # Nobody found: a bare did:aw is first contact, which is unsupported.
        (
            MailSelectors(to_stable_id=" did:aw:bob "),
            {(PRIMARY, "did:aw:bob"): None},
            BARE_DID,
            [(PRIMARY, F.STABLE_ID, "did:aw:bob")],
        ),
        (
            MailSelectors(to_did="did:aw:bob"),
            {(PRIMARY, "did:aw:bob"): None},
            BARE_DID,
            [(PRIMARY, F.DID, "did:aw:bob")],
        ),
        (
            MailSelectors(to_stable_id="did:key:bob"),
            {(PRIMARY, "did:key:bob"): None},
            NOT_FOUND,
            [(PRIMARY, F.STABLE_ID, "did:key:bob")],
        ),
        (
            MailSelectors(to_did="did:key:bob"),
            {(PRIMARY, "did:key:bob"): None},
            NOT_FOUND,
            [(PRIMARY, F.DID, "did:key:bob")],
        ),
        (
            MailSelectors(to_agent_id="a-bob"),
            {(PRIMARY, "a-bob"): None},
            NOT_FOUND,
            [(PRIMARY, F.AGENT_ID, "a-bob")],
        ),
        (
            MailSelectors(to_alias="bob"),
            {(PRIMARY, "bob"): None},
            NOT_FOUND,
            [(PRIMARY, F.ALIAS, "bob")],
        ),
        # A not-found leader stops the rule before any binding lookup.
        (
            MailSelectors(
                to_stable_id="did:aw:bob", to_did="did:key:bob", to_alias="bob"
            ),
            {(PRIMARY, "did:aw:bob"): None},
            BARE_DID,
            [(PRIMARY, F.STABLE_ID, "did:aw:bob")],
        ),
    ],
)
def test_refusals_before_or_at_the_leading_lookup(selectors, answers, result, asked):
    step, lookups = drive(selectors, answers)
    assert step == result
    assert lookups == asked


@pytest.mark.parametrize(
    "selectors,answers,result,asked",
    [
        # to_stable_id leads; to_did is checked first, then to_alias.
        (
            MailSelectors(to_stable_id="did:aw:bob", to_did=" did:key:carol "),
            {(PRIMARY, "did:aw:bob"): BOB, (DID_BINDING, "did:key:carol"): CAROL},
            mismatch(F.DID, F.STABLE_ID),
            [
                (PRIMARY, F.STABLE_ID, "did:aw:bob"),
                (DID_BINDING, F.DID, "did:key:carol"),
            ],
        ),
        (
            MailSelectors(to_stable_id="did:aw:bob", to_did="did:key:nobody"),
            {(PRIMARY, "did:aw:bob"): BOB, (DID_BINDING, "did:key:nobody"): None},
            mismatch(F.DID, F.STABLE_ID),
            [
                (PRIMARY, F.STABLE_ID, "did:aw:bob"),
                (DID_BINDING, F.DID, "did:key:nobody"),
            ],
        ),
        (
            # A to_did mismatch is refused before the alias is looked up.
            MailSelectors(
                to_stable_id="did:aw:bob", to_did="did:key:carol", to_alias="bob"
            ),
            {(PRIMARY, "did:aw:bob"): BOB, (DID_BINDING, "did:key:carol"): CAROL},
            mismatch(F.DID, F.STABLE_ID),
            [
                (PRIMARY, F.STABLE_ID, "did:aw:bob"),
                (DID_BINDING, F.DID, "did:key:carol"),
            ],
        ),
        (
            MailSelectors(to_stable_id="did:aw:bob", to_alias=" carol "),
            {(PRIMARY, "did:aw:bob"): BOB, (ALIAS_BINDING, "carol"): CAROL},
            mismatch(F.ALIAS, F.STABLE_ID),
            [(PRIMARY, F.STABLE_ID, "did:aw:bob"), (ALIAS_BINDING, F.ALIAS, "carol")],
        ),
        # to_did leads: only to_alias is checked against it.
        (
            MailSelectors(to_did="did:key:bob", to_alias="carol"),
            {(PRIMARY, "did:key:bob"): BOB, (ALIAS_BINDING, "carol"): CAROL},
            mismatch(F.ALIAS, F.DID),
            [(PRIMARY, F.DID, "did:key:bob"), (ALIAS_BINDING, F.ALIAS, "carol")],
        ),
        # to_agent_id leads: only to_alias is checked against it.
        (
            # An alias naming another member's existing identity.
            MailSelectors(to_agent_id="a-bob", to_alias="carol"),
            {(PRIMARY, "a-bob"): BOB, (ALIAS_BINDING, "carol"): CAROL},
            mismatch(F.ALIAS, F.AGENT_ID),
            [(PRIMARY, F.AGENT_ID, "a-bob"), (ALIAS_BINDING, F.ALIAS, "carol")],
        ),
        (
            MailSelectors(to_agent_id="a-bob", to_alias="carol"),
            {(PRIMARY, "a-bob"): BOB, (ALIAS_BINDING, "carol"): None},
            mismatch(F.ALIAS, F.AGENT_ID),
            [(PRIMARY, F.AGENT_ID, "a-bob"), (ALIAS_BINDING, F.ALIAS, "carol")],
        ),
        # Identities compare by did_aw, else did_key; one without either never matches.
        (
            MailSelectors(to_agent_id="a-bob", to_alias="bob"),
            {
                (PRIMARY, "a-bob"): BOB_KEY_ONLY,
                (ALIAS_BINDING, "bob"): {"did_aw": None, "did_key": None},
            },
            mismatch(F.ALIAS, F.AGENT_ID),
            [(PRIMARY, F.AGENT_ID, "a-bob"), (ALIAS_BINDING, F.ALIAS, "bob")],
        ),
    ],
)
def test_a_further_selector_must_name_the_same_identity(
    selectors, answers, result, asked
):
    step, lookups = drive(selectors, answers)
    assert step == result
    assert lookups == asked


@pytest.mark.parametrize(
    "selectors,answers,result",
    [
        # An external recipient's alias is compared as given, with no lookup.
        (
            MailSelectors(to_address="other.com/bob", to_alias=" bob "),
            {(PRIMARY, "other.com/bob"): EXTERNAL_BOB},
            MailTargetChoice(EXTERNAL_BOB, "did:aw:bob", None, "bob"),
        ),
        (
            MailSelectors(to_address="other.com/bob", to_alias="robert"),
            {(PRIMARY, "other.com/bob"): EXTERNAL_BOB},
            mismatch(F.ALIAS, F.ADDRESS),
        ),
        # A local address's alias is looked up and compared by identity.
        (
            MailSelectors(to_address="acme.com/bob", to_alias="carol"),
            {(PRIMARY, "acme.com/bob"): BOB, (ALIAS_BINDING, "carol"): CAROL},
            mismatch(F.ALIAS, F.ADDRESS),
        ),
        # to_stable_id must be the address's did:aw; to_did its did:aw or did:key.
        (
            MailSelectors(to_address="acme.com/bob", to_stable_id="did:aw:carol"),
            {(PRIMARY, "acme.com/bob"): BOB},
            mismatch(F.STABLE_ID, F.ADDRESS),
        ),
        (
            MailSelectors(to_address="acme.com/bob", to_did="did:key:carol"),
            {(PRIMARY, "acme.com/bob"): BOB},
            mismatch(F.DID, F.ADDRESS),
        ),
        (
            MailSelectors(
                to_address="acme.com/bob",
                to_did="did:key:bob",
                to_stable_id="did:aw:bob",
            ),
            {(PRIMARY, "acme.com/bob"): BOB},
            MailTargetChoice(BOB, "did:aw:bob", "a-bob", "bob"),
        ),
        (
            # The alias check comes before the stable id check.
            MailSelectors(
                to_address="acme.com/bob", to_alias="carol", to_stable_id="did:aw:carol"
            ),
            {(PRIMARY, "acme.com/bob"): BOB, (ALIAS_BINDING, "carol"): CAROL},
            mismatch(F.ALIAS, F.ADDRESS),
        ),
    ],
)
def test_an_address_must_agree_with_every_other_selector(selectors, answers, result):
    step, _ = drive(selectors, answers)
    assert step == result


@pytest.mark.parametrize(
    "selectors,answers,result,asked",
    [
        (
            MailSelectors(to_did="did:key:bob", to_agent_id="a-carol"),
            {(PRIMARY, "did:key:bob"): BOB, (SELECTED_MEMBER, "a-carol"): CAROL},
            mismatch(F.AGENT_ID, F.DID),
            [(PRIMARY, F.DID, "did:key:bob"), (SELECTED_MEMBER, F.AGENT_ID, "a-carol")],
        ),
        (
            # Another member's existing agent id.
            MailSelectors(to_stable_id="did:aw:bob", to_agent_id="a-carol"),
            {(PRIMARY, "did:aw:bob"): BOB, (SELECTED_MEMBER, "a-carol"): CAROL},
            mismatch(F.AGENT_ID, F.STABLE_ID),
            [
                (PRIMARY, F.STABLE_ID, "did:aw:bob"),
                (SELECTED_MEMBER, F.AGENT_ID, "a-carol"),
            ],
        ),
        (
            # An agent id that names nobody.
            MailSelectors(to_stable_id="did:aw:bob", to_agent_id="a-nobody"),
            {(PRIMARY, "did:aw:bob"): BOB, (SELECTED_MEMBER, "a-nobody"): None},
            mismatch(F.AGENT_ID, F.STABLE_ID),
            [
                (PRIMARY, F.STABLE_ID, "did:aw:bob"),
                (SELECTED_MEMBER, F.AGENT_ID, "a-nobody"),
            ],
        ),
        (
            # An external address is never a team member's agent.
            MailSelectors(to_address="other.com/bob", to_agent_id="a-bob"),
            {(PRIMARY, "other.com/bob"): EXTERNAL_BOB, (SELECTED_MEMBER, "a-bob"): BOB},
            mismatch(F.AGENT_ID, F.ADDRESS),
            [
                (PRIMARY, F.ADDRESS, "other.com/bob"),
                (SELECTED_MEMBER, F.AGENT_ID, "a-bob"),
            ],
        ),
        (
            # A local address with another member's agent id.
            MailSelectors(to_address="acme.com/bob", to_agent_id="a-carol"),
            {(PRIMARY, "acme.com/bob"): BOB, (SELECTED_MEMBER, "a-carol"): CAROL},
            mismatch(F.AGENT_ID, F.ADDRESS),
            [
                (PRIMARY, F.ADDRESS, "acme.com/bob"),
                (SELECTED_MEMBER, F.AGENT_ID, "a-carol"),
            ],
        ),
        (
            # A local address with its own member's agent id.
            MailSelectors(to_address="acme.com/bob", to_agent_id="a-bob"),
            {(PRIMARY, "acme.com/bob"): BOB, (SELECTED_MEMBER, "a-bob"): BOB},
            MailTargetChoice(BOB, "did:aw:bob", "a-bob", "bob"),
            [
                (PRIMARY, F.ADDRESS, "acme.com/bob"),
                (SELECTED_MEMBER, F.AGENT_ID, "a-bob"),
            ],
        ),
    ],
)
def test_an_agent_id_beside_another_selector_must_be_that_member(
    selectors, answers, result, asked
):
    step, lookups = drive(selectors, answers)
    assert step == result
    assert lookups == asked


@pytest.mark.parametrize(
    "selectors,answers,choice",
    [
        # The stable id is the recipient DID; the agent id and alias come from the record.
        (
            MailSelectors(
                to_stable_id=" did:aw:bob ", to_did="did:key:bob", to_alias="bob"
            ),
            {
                (PRIMARY, "did:aw:bob"): BOB,
                (DID_BINDING, "did:key:bob"): BOB,
                (ALIAS_BINDING, "bob"): BOB,
            },
            MailTargetChoice(BOB, "did:aw:bob", "a-bob", "bob"),
        ),
        (
            MailSelectors(to_stable_id="did:aw:bob"),
            {(PRIMARY, "did:aw:bob"): {**BOB, "agent_id": None}},
            MailTargetChoice({**BOB, "agent_id": None}, "did:aw:bob", None, "bob"),
        ),
        # A DID selects did_aw, then did_key, then the DID as given.
        (
            MailSelectors(to_did="did:key:bob"),
            {(PRIMARY, "did:key:bob"): BOB_KEY_ONLY},
            MailTargetChoice(BOB_KEY_ONLY, "did:key:bob", "a-bob", "bob"),
        ),
        (
            MailSelectors(to_did=" did:key:x "),
            {(PRIMARY, "did:key:x"): {"agent_id": None, "alias": None}},
            MailTargetChoice(
                {"agent_id": None, "alias": None}, "did:key:x", None, None
            ),
        ),
        # An address keeps the address as its alias when the record has none.
        (
            MailSelectors(to_address=" other.com/bob "),
            {(PRIMARY, "other.com/bob"): {**EXTERNAL_BOB, "alias": None}},
            MailTargetChoice(
                {**EXTERNAL_BOB, "alias": None}, "did:aw:bob", None, "other.com/bob"
            ),
        ),
        # An agent id keeps the agent id the sender gave.
        (
            MailSelectors(to_agent_id="a-bob"),
            {(PRIMARY, "a-bob"): BOB},
            MailTargetChoice(BOB, "did:aw:bob", "a-bob", "bob"),
        ),
        # An alias is looked up as given, unstripped.
        (
            MailSelectors(to_alias=" bob "),
            {(PRIMARY, " bob "): BOB},
            MailTargetChoice(BOB, "did:aw:bob", "a-bob", "bob"),
        ),
        # A blank further selector is not checked.
        (
            MailSelectors(to_agent_id="a-bob", to_alias="  "),
            {(PRIMARY, "a-bob"): BOB},
            MailTargetChoice(BOB, "did:aw:bob", "a-bob", "bob"),
        ),
    ],
)
def test_the_chosen_target(selectors, answers, choice):
    step, _ = drive(selectors, answers)
    assert step == choice
