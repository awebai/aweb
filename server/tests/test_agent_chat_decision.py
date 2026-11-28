"""Every branch of the human-kind chat rule, on facts given in the table."""

from __future__ import annotations

import pytest

from aweb.messaging.chat_policy import (
    AgentChatAllowed,
    AgentChatRefused,
    HumanChatRefused,
    NeedHumanKind,
    decide_agent_chat,
)

ALLOWED = AgentChatAllowed()

HUMAN_ROW = {
    "agent_type": "human",
    "did_key": "did:key:bob",
    "did_aw": "did:aw:bob",
    "human_verified_key": "did:key:bob",
}


def refused(*labels):
    return AgentChatRefused(tuple(labels))


def drive(recipients, answers, locked=None):
    """Run the rule to its verdict, answering each read by recipient index.

    Returns the verdict and the reads asked for, in order. A read not in
    ``answers`` fails the test: the rule asked for something it should not.
    """
    decision = decide_agent_chat(recipients, locked_policy_rows=locked)
    asked = []
    try:
        step = next(decision)
        while True:
            assert isinstance(step, NeedHumanKind), step
            asked.append((step.index, step.did))
            assert step.index in answers, f"unexpected read {step}"
            step = decision.send(answers[step.index])
    except StopIteration as finished:
        return finished.value, asked


@pytest.mark.parametrize(
    "recipients,answers,verdict,asked",
    [
        ([], {}, ALLOWED, []),
        # A recipient with no DID is never read and never refused.
        ([{"alias": "nobody", "did_aw": " ", "did_key": ""}], {}, ALLOWED, []),
        # The DID read is did_aw, else did, else did_key, stripped.
        (
            [{"did_aw": " did:aw:bob ", "did": "did:x", "did_key": "did:key:bob"}],
            {0: False},
            ALLOWED,
            [(0, "did:aw:bob")],
        ),
        (
            [{"did": "did:x", "did_key": "did:key:bob"}],
            {0: False},
            ALLOWED,
            [(0, "did:x")],
        ),
        ([{"did_key": "did:key:bob"}], {0: False}, ALLOWED, [(0, "did:key:bob")]),
        # A verified human is refused by its label.
        (
            [{"did_key": "did:key:bob", "alias": "bob"}],
            {0: True},
            refused("bob"),
            [(0, "did:key:bob")],
        ),
        # Every recipient is read, in order, even after a human: all are named.
        (
            [
                {"did_key": "did:key:bob", "alias": "bob"},
                {"did_key": "did:key:carol", "alias": "carol"},
                {"did_key": "did:key:dave", "alias": "dave"},
            ],
            {0: True, 1: False, 2: True},
            refused("bob", "dave"),
            [(0, "did:key:bob"), (1, "did:key:carol"), (2, "did:key:dave")],
        ),
        # A repeated recipient is read and named once per row.
        (
            [
                {"did_key": "did:key:bob", "alias": "bob"},
                {"did_key": "did:key:bob", "alias": "bob"},
            ],
            {0: True, 1: True},
            refused("bob", "bob"),
            [(0, "did:key:bob"), (1, "did:key:bob")],
        ),
    ],
)
def test_each_recipient_with_a_did_is_read_in_order(
    recipients, answers, verdict, asked
):
    assert drive(recipients, answers) == (verdict, asked)


@pytest.mark.parametrize(
    "row,label",
    [
        (
            {
                "address": "acme.com/bob",
                "alias": "bob",
                "did_aw": "did:aw:bob",
                "did_key": "did:key:bob",
            },
            "acme.com/bob",
        ),
        ({"alias": "bob", "did_aw": "did:aw:bob", "did_key": "did:key:bob"}, "bob"),
        (
            {"did_aw": "did:aw:bob", "did": "did:x", "did_key": "did:key:bob"},
            "did:aw:bob",
        ),
        ({"did": "did:x", "did_key": "did:key:bob"}, "did:x"),
        ({"did_key": "did:key:bob"}, "did:key:bob"),
    ],
)
def test_a_human_is_named_by_address_then_alias_then_did(row, label):
    verdict, _ = drive([row], {0: True})
    assert verdict == refused(label)


@pytest.mark.parametrize(
    "policies,human",
    [
        ([HUMAN_ROW], True),
        # The recipient's DID must be the verified row's stable DID or key:
        # a raw claim of the same DID on another identity's row is not enough.
        ([{**HUMAN_ROW, "did_aw": "did:aw:other"}], False),
        (
            [
                {
                    **HUMAN_ROW,
                    "did_aw": "did:aw:other",
                    "did_key": "did:key:other",
                    "human_verified_key": "did:key:other",
                }
            ],
            False,
        ),
        # Only a current-key human marker establishes human kind.
        ([{**HUMAN_ROW, "agent_type": "agent"}], False),
        ([{**HUMAN_ROW, "human_verified_key": "did:key:old"}], False),
        ([{**HUMAN_ROW, "human_verified_key": None}], False),
        ([{**HUMAN_ROW, "did_key": ""}], False),
        # Any one verified row of several is enough.
        ([{**HUMAN_ROW, "agent_type": "agent"}, HUMAN_ROW], True),
        ([], False),
    ],
)
def test_locked_policy_rows_decide_without_a_read(policies, human):
    recipients = [{"did_aw": "did:aw:bob", "did_key": "did:key:bob", "alias": "bob"}]
    verdict = drive(recipients, {}, locked={"did:aw:bob": policies})
    assert verdict == ((refused("bob") if human else ALLOWED), [])


def test_locked_policy_rows_matched_by_the_literal_key():
    recipients = [{"did_key": "did:key:bob", "alias": "bob"}]
    policy = {**HUMAN_ROW, "did_aw": None}
    assert drive(recipients, {}, locked={"did:key:bob": [policy]}) == (
        refused("bob"),
        [],
    )


@pytest.mark.parametrize("locked", [None, {}, {"did:aw:carol": [HUMAN_ROW]}])
def test_a_recipient_absent_from_the_locked_rows_is_read(locked):
    recipients = [{"did_aw": "did:aw:bob", "alias": "bob"}]
    assert drive(recipients, {0: True}, locked=locked) == (
        refused("bob"),
        [(0, "did:aw:bob")],
    )


def test_locked_and_read_recipients_are_named_together():
    recipients = [
        {"did_aw": "did:aw:bob", "alias": "bob"},
        {"did_key": "did:key:carol", "alias": "carol"},
    ]
    verdict = drive(recipients, {1: True}, locked={"did:aw:bob": [HUMAN_ROW]})
    assert verdict == (refused("bob", "carol"), [(1, "did:key:carol")])


@pytest.mark.parametrize(
    "labels,recipients,detail",
    [
        (
            ["bob", " bob ", "", "alice"],
            ["alice", "bob"],
            "alice, bob are people; aweb reaches people by mail: aw mail send --to alice",
        ),
        (
            ["bob"],
            ["bob"],
            "bob is a person; aweb reaches people by mail: aw mail send --to bob",
        ),
        (
            ["", " "],
            [],
            "This chat includes a person; aweb reaches people by mail: aw mail send --to <their alias>",
        ),
    ],
)
def test_the_refusal_names_each_person_once_in_stable_order(labels, recipients, detail):
    error = HumanChatRefused(labels)
    assert error.recipients == recipients
    assert error.detail == detail
    assert error.body()["recipients"] == recipients
    assert (
        error.body()["reason"]
        == AgentChatRefused(()).code
        == "recipient_human_mail_only"
    )


class CountingRow(dict):
    """A recipient row that counts how often the rule reads its DID."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.did_reads = 0

    def get(self, key, default=None):
        if key == "did_aw":
            self.did_reads += 1
        return super().get(key, default)


@pytest.mark.parametrize(
    "locked", [None, {"did:aw:locked": [{**HUMAN_ROW, "did_aw": "did:aw:locked"}]}]
)
def test_each_recipient_is_decided_once(locked):
    recipients = [CountingRow(did_aw=f"did:aw:agent-{i}") for i in range(64)]
    recipients.insert(10, CountingRow(did_aw="did:aw:locked", alias="locked"))
    answers = {i: False for i in range(len(recipients))}
    verdict, asked = drive(recipients, answers, locked=locked)
    assert [row.did_reads for row in recipients] == [1] * len(recipients)
    assert len(asked) == len(recipients) - (1 if locked else 0)
    assert verdict == (refused("locked") if locked else ALLOWED)
