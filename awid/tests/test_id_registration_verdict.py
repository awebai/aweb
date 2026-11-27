"""The registration rule, apart from the reads that answer it.

Every branch of ``registration_rule`` is a row here, and the boundary rows
show that a deciding check asks for no later fact. Where a frozen
operation case states the rule, the row is built from that case by name, so
the case is consumed here (see the partition test in
test_id_certificate_registration). The database tests of registration keep
what only they prove: the reads under the gate's locks, the writes, the
witness times and the races.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, replace
from datetime import datetime

import pytest

from awid_service.id_registration import (
    HEAD,
    INVITATION_USED,
    PARENT,
    PARENT_CHAIN,
    PARENT_EPOCH,
    RECEIPT,
    ROOT,
    Admitted,
    Ancestor,
    ParentIdentity,
    Receipt,
    Refused,
    RegistrationRequest,
    Repeated,
    RootEpoch,
    Subject,
    registration_rule,
)
from id_tree_support import (
    CONSUMED,
    DOMAIN,
    at,
    certificate,
    certificate_id,
    did_aw,
    did_key,
    operation_case,
)

T0 = at("2026-10-26T00:01:00Z")
ALICE_KEY_EPOCH = (1, at("2026-10-26T00:00:30Z"))
REGISTERED_AT = at("2026-10-26T00:03:00Z")
VALID = {"outcome": "nearest_human", "identity_valid": True, "reason": "verified"}
INVITATION = operation_case("first-exact-invitation-registration")["input"][
    "invitation_id"
]


@dataclass(frozen=True)
class Facts:
    """A row: the request and locks, and the answer to each fact the rule may ask."""

    chain: list[dict]
    signer: str
    expected_head: str | None
    invitation_id: str | None
    keys: dict[str, str]
    subject: Subject | None
    receipt: Receipt | None
    invitation_used: bool
    head: str | None
    root: RootEpoch | None
    parent: ParentIdentity | None
    parent_epoch: tuple[int, datetime] | None
    registered: list[dict | None]
    parent_chain: dict | None


def decide(facts: Facts):
    """Run the rule on ``facts``; return its verdict and the facts it asked for."""
    answers = {
        RECEIPT: facts.receipt,
        INVITATION_USED: facts.invitation_used,
        HEAD: facts.head,
        ROOT: facts.root,
        PARENT: facts.parent,
        PARENT_EPOCH: facts.parent_epoch,
        PARENT_CHAIN: facts.parent_chain,
        **{Ancestor(i): value for i, value in enumerate(facts.registered)},
    }
    rule = registration_rule(
        RegistrationRequest(
            chain=facts.chain,
            signer=facts.signer,
            expected_head=facts.expected_head,
            invitation_id=facts.invitation_id,
            keys=facts.keys,
            subject=facts.subject,
        )
    )
    asked = []
    try:
        ask = next(rule)
        while True:
            asked.append(ask)
            ask = rule.send(answers[ask])
    except StopIteration as done:
        return done.value, asked


def case(name: str) -> dict:
    """The frozen operation case ``name``, consumed by this module."""
    CONSUMED.add(name)
    return operation_case(name)


def bob_under_alice(**changes) -> Facts:
    """A first registration of bob, issued by alice, that the rule admits."""
    facts = Facts(
        chain=[certificate("alice"), certificate("bob")],
        signer=did_key("bob"),
        expected_head=None,
        invitation_id=None,
        keys={did_aw("alice"): did_key("alice"), did_aw("bob"): did_key("bob")},
        receipt=None,
        invitation_used=False,
        subject=None,
        head=None,
        root=RootEpoch(did_key("root"), 1, T0),
        parent=ParentIdentity(DOMAIN, "human", None),
        parent_epoch=ALICE_KEY_EPOCH,
        registered=[certificate("alice")],
        parent_chain=VALID,
    )
    return replace(facts, **changes)


def alice_under_root(**changes) -> Facts:
    """A first registration of alice, issued by the namespace root, that the rule admits."""
    facts = Facts(
        chain=[certificate("alice")],
        signer=did_key("alice"),
        expected_head=None,
        invitation_id=None,
        keys={did_aw("alice"): did_key("alice")},
        receipt=None,
        invitation_used=False,
        subject=None,
        head=None,
        root=RootEpoch(did_key("root"), 1, T0),
        parent=None,
        parent_epoch=None,
        registered=[],
        parent_chain=None,
    )
    return replace(facts, **changes)


def global_agent_reparented(**changes) -> Facts:
    """global-agent's registered head replaced by one issued by bob."""
    facts = bob_under_alice(
        chain=[
            certificate("alice"),
            certificate("bob"),
            certificate("global-agent-reparented"),
        ],
        signer=did_key("global_agent"),
        expected_head=certificate_id("global-agent"),
        keys={
            did_aw("bob"): did_key("bob"),
            did_aw("global_agent"): did_key("global_agent"),
        },
        subject=Subject("agent", DOMAIN, None),
        head=certificate_id("global-agent"),
        registered=[certificate("alice"), certificate("bob")],
    )
    return replace(facts, **changes)


def leaf(facts: Facts, **fields) -> Facts:
    """``facts`` with its presented leaf certificate's fields changed."""
    chain = copy.deepcopy(facts.chain)
    chain[-1]["certificate"].update(fields)
    return replace(facts, chain=chain)


def kind_change() -> Facts:
    given = case("registered-kind-change-refuses")["input"]
    assert given["id"] == did_aw("alice")
    return leaf(
        alice_under_root(
            subject=Subject(given["old_kind"], DOMAIN, None),
            expected_head=certificate_id("alice"),
            head=certificate_id("alice"),
        ),
        kind=given["requested_kind"],
    )


def domain_change() -> Facts:
    given = case("registered-domain-change-refuses")["input"]
    assert (given["id"], given["old_domain"]) == (did_aw("alice"), DOMAIN)
    return leaf(
        alice_under_root(
            subject=Subject("human", given["old_domain"], None),
            expected_head=certificate_id("alice"),
            head=certificate_id("alice"),
        ),
        domain=given["requested_domain"],
        parent={"kind": "namespace", "id": given["requested_domain"]},
    )


def invitation_conflict(name: str) -> Facts:
    """Another certificate already registered under the presented invitation."""
    changed = case(name)["input"]["changed"]
    facts = bob_under_alice(invitation_id=INVITATION, invitation_used=True)
    if changed == "child":
        return replace(
            facts,
            chain=[certificate("alice"), certificate("global-agent")],
            signer=did_key("global_agent"),
            keys={**facts.keys, did_aw("global_agent"): did_key("global_agent")},
        )
    if changed == "parent":
        return leaf(
            facts,
            parent={"kind": "namespace", "id": DOMAIN},
            issuer_key=did_key("root"),
        )
    if changed == "domain":
        return leaf(
            facts,
            domain="other.example",
            parent={"kind": "namespace", "id": "other.example"},
            issuer_key=did_key("root"),
        )
    assert changed == "certificate"
    return leaf(facts, issued_at="2026-10-26T00:09:00Z")


def local_parent() -> Facts:
    given = case("registered-child-under-local-parent-refuses")["input"]
    child = certificate("global-from-local")
    assert (child["certificate"]["id"], child["certificate"]["parent"]["id"]) == (
        given["child_id"],
        given["parent"],
    )
    return bob_under_alice(
        chain=[certificate("alice"), certificate("coordinator"), child],
        signer=did_key("global_from_local"),
        # A did:key parent has no did:aw mapping, so the gate holds no key for it.
        keys={did_aw("global_from_local"): did_key("global_from_local")},
        parent=None,
        registered=[certificate("alice"), None],
        parent_chain=None,
    )


def parent_rotated() -> Facts:
    given = case("registration-after-parent-rotate-refuses-old-key")["input"]
    assert given["certificate"] == "bob"
    facts = bob_under_alice()
    return replace(
        facts, keys={**facts.keys, did_aw("alice"): did_key("alice_rotated")}
    )


def parent_revoked(name: str) -> Facts:
    """alice was revoked before bob's registration; bob's signing time does not matter."""
    given = case(name)["input"]
    assert given["certificate"] == "bob"
    facts = bob_under_alice(
        parent=ParentIdentity(DOMAIN, "human", at("2026-10-26T00:02:00Z"))
    )
    if "issued_at" in given:
        facts = leaf(facts, issued_at=given["issued_at"])
    return facts


def subject_revoked() -> Facts:
    given = case("directly-revoked-subject-cannot-reopen-head")["input"]
    assert given["certificate"] == "global-agent-reparented"
    return global_agent_reparented(
        subject=Subject("agent", DOMAIN, at("2026-10-26T00:20:00Z"))
    )


def retry_after_inviter_revoked() -> Facts:
    """A receipt answers before any later check, even with the inviter now revoked."""
    given = case("accepted-human-invite-retry-after-inviter-revoke")["input"]
    assert given["certificate"] == "bob" and given["same_invitation"] is True
    return bob_under_alice(
        invitation_id=INVITATION,
        receipt=Receipt(at(given["original_registered_at"]), INVITATION),
        invitation_used=True,
        parent=ParentIdentity(DOMAIN, "human", at("2026-10-26T00:20:00Z")),
        parent_chain={
            "outcome": "unknown",
            "identity_valid": False,
            "reason": "revoked",
        },
    )


ROWS: list[tuple[str, Facts, object]] = [
    # Admitted.
    ("an identity child is admitted", bob_under_alice(), Admitted(*ALICE_KEY_EPOCH)),
    ("a root child is admitted", alice_under_root(), Admitted(1, T0)),
    (
        "a re-parent onto the current head is admitted",
        global_agent_reparented(),
        Admitted(*ALICE_KEY_EPOCH),
    ),
    (
        "an agent may issue an agent",
        replace(
            global_agent_reparented(),
            parent=ParentIdentity(DOMAIN, "agent", None),
        ),
        Admitted(*ALICE_KEY_EPOCH),
    ),
    # The covering envelope must be signed by the subject's current key.
    (
        "a request signed by another key",
        bob_under_alice(signer=did_key("alice")),
        Refused("subject_mismatch", 403),
    ),
    (
        "a subject without a current key",
        bob_under_alice(keys={did_aw("alice"): did_key("alice")}),
        Refused("subject_mismatch", 403),
    ),
    (
        "the subject check comes before the receipt",
        bob_under_alice(signer=did_key("alice"), receipt=Receipt(REGISTERED_AT, None)),
        Refused("subject_mismatch", 403),
    ),
    # A receipt for the exact certificate answers with its original time.
    (
        "an exact retry without an invitation",
        bob_under_alice(receipt=Receipt(REGISTERED_AT, None)),
        Repeated(REGISTERED_AT),
    ),
    (
        "an exact retry with its invitation",
        bob_under_alice(
            invitation_id=INVITATION,
            receipt=Receipt(REGISTERED_AT, INVITATION),
            invitation_used=True,
        ),
        Repeated(REGISTERED_AT),
    ),
    (
        "accepted-human-invite-retry-after-inviter-revoke",
        retry_after_inviter_revoked(),
        Repeated(at("2026-10-26T00:03:00Z")),
    ),
    (
        "a retry naming an invitation the receipt does not hold",
        bob_under_alice(invitation_id=INVITATION, receipt=Receipt(REGISTERED_AT, None)),
        Refused("invitation_conflict", 409),
    ),
    (
        "a retry without the invitation the receipt holds",
        bob_under_alice(receipt=Receipt(REGISTERED_AT, INVITATION)),
        Refused("invitation_conflict", 409),
    ),
    # An invitation registers one certificate.
    *(
        (name, invitation_conflict(name), Refused("invitation_conflict", 409))
        for name in (
            "invitation-conflict-child",
            "invitation-conflict-parent",
            "invitation-conflict-domain",
            "invitation-conflict-certificate",
        )
    ),
    (
        "an invitation conflict comes before the subject's checks",
        replace(kind_change(), invitation_id=INVITATION, invitation_used=True),
        Refused("invitation_conflict", 409),
    ),
    # A registered subject keeps its kind and domain and is not revoked.
    (
        "registered-kind-change-refuses",
        kind_change(),
        Refused(case("registered-kind-change-refuses")["expected"]["reason"]),
    ),
    (
        "registered-domain-change-refuses",
        domain_change(),
        Refused(case("registered-domain-change-refuses")["expected"]["reason"]),
    ),
    (
        "directly-revoked-subject-cannot-reopen-head",
        subject_revoked(),
        Refused(
            case("directly-revoked-subject-cannot-reopen-head")["expected"]["reason"]
        ),
    ),
    # The expected head is the subject's current head, or None for a new subject.
    (
        "a missing expected head for a registered subject",
        global_agent_reparented(expected_head=None),
        Refused("head_conflict", 409),
    ),
    (
        "a stale expected head",
        global_agent_reparented(expected_head=certificate_id("bob")),
        Refused("head_conflict", 409),
    ),
    (
        "an expected head for a subject with none",
        bob_under_alice(expected_head=certificate_id("alice")),
        Refused("head_conflict", 409),
    ),
    (
        "a head conflict comes before root authority",
        global_agent_reparented(expected_head=None, root=None),
        Refused("head_conflict", 409),
    ),
    # Every registration needs current root authority.
    (
        "no current root authority",
        bob_under_alice(root=None),
        Refused("evidence_unavailable", 503),
    ),
    (
        "no current root authority for a root child",
        alice_under_root(root=None),
        Refused("evidence_unavailable", 503),
    ),
    # A root child is signed by the open epoch's key.
    (
        "a root child signed by a key other than the open epoch's",
        alice_under_root(root=RootEpoch(did_key("root_rotated"), 2, T0)),
        Refused("issuer_key_not_current"),
    ),
    # An identity child's issuer is registered, unrevoked and holds the key now.
    (
        "an issuer with no registered head",
        bob_under_alice(parent=None),
        Refused("unregistered_parent"),
    ),
    (
        "an issuer registered without a current key",
        bob_under_alice(keys={did_aw("bob"): did_key("bob")}, parent_chain=None),
        Refused("unregistered_parent"),
    ),
    (
        "registered-child-under-local-parent-refuses",
        local_parent(),
        Refused(
            case("registered-child-under-local-parent-refuses")["expected"]["reason"]
        ),
    ),
    (
        "an issuer registered in another domain",
        bob_under_alice(parent=ParentIdentity("other.example", "human", None)),
        Refused("domain_mismatch"),
    ),
    (
        "a human issued by a registered agent",
        bob_under_alice(parent=ParentIdentity(DOMAIN, "agent", None)),
        Refused("human_issuer_is_agent"),
    ),
    *(
        (name, parent_revoked(name), Refused(case(name)["expected"]["reason"]))
        for name in (
            "registration-after-sign-then-parent-revoke",
            "signed-issued-at-cannot-backdate",
        )
    ),
    (
        "registration-after-parent-rotate-refuses-old-key",
        parent_rotated(),
        Refused(
            case("registration-after-parent-rotate-refuses-old-key")["expected"][
                "reason"
            ]
        ),
    ),
    (
        "the issuer's checks come before the ancestry",
        bob_under_alice(parent=None, registered=[None]),
        Refused("unregistered_parent"),
    ),
    # The presented ancestors are exactly the registered current heads.
    (
        "a presented ancestor with no registered head",
        bob_under_alice(registered=[None]),
        Refused("unregistered_parent"),
    ),
    (
        "a presented ancestor that is not its registered head",
        bob_under_alice(registered=[certificate("bob")]),
        Refused("superseded_certificate"),
    ),
    (
        "the ancestry comes before the parent's chain",
        bob_under_alice(
            registered=[certificate("bob")],
            parent_chain={
                "outcome": "unknown",
                "identity_valid": False,
                "reason": "revoked",
            },
        ),
        Refused("superseded_certificate"),
    ),
    # S1's verdict on the parent's whole current chain.
    (
        "a parent chain whose evidence is unavailable",
        bob_under_alice(
            parent_chain={
                "outcome": "unavailable",
                "identity_valid": None,
                "reason": "evidence_unavailable",
            }
        ),
        Refused("evidence_unavailable", 503),
    ),
    (
        "a parent chain with a revoked ancestor",
        bob_under_alice(
            parent_chain={
                "outcome": "unknown",
                "identity_valid": False,
                "reason": "revoked",
            }
        ),
        Refused("revoked"),
    ),
    (
        "a parent chain cut off by a root replacement",
        bob_under_alice(
            parent_chain={
                "outcome": "unknown",
                "identity_valid": False,
                "reason": "root_replaced",
            }
        ),
        Refused("root_replaced"),
    ),
    (
        "a parent chain whose validity is unknown",
        bob_under_alice(
            parent_chain={
                "outcome": "unknown",
                "identity_valid": None,
                "reason": "unregistered_identity",
            }
        ),
        Refused("unregistered_identity"),
    ),
    (
        "a root child does not consult a parent chain",
        alice_under_root(
            parent_chain={
                "outcome": "unknown",
                "identity_valid": False,
                "reason": "revoked",
            }
        ),
        Admitted(1, T0),
    ),
]


def test_each_row_names_one_branch():
    names = [name for name, _, _ in ROWS]
    assert len(names) == len(set(names))


@pytest.mark.parametrize(
    ("facts", "expected"),
    [(facts, expected) for _, facts, expected in ROWS],
    ids=[name for name, _, _ in ROWS],
)
def test_registration_rule(facts: Facts, expected: object):
    verdict, _ = decide(facts)
    assert verdict == expected


def test_the_fixtures_name_the_vector_issuers():
    """The base rows are the vector certificates their issuers really signed."""
    bob = bob_under_alice().chain[-1]["certificate"]
    alice = alice_under_root().chain[-1]["certificate"]
    assert (bob["issuer_key"], bob["parent"]["id"]) == (
        did_key("alice"),
        did_aw("alice"),
    )
    assert (alice["issuer_key"], alice["parent"]) == (
        did_key("root"),
        {"kind": "namespace", "id": DOMAIN},
    )


BOUNDARY = [
    (
        "a request signed by another key asks for nothing",
        bob_under_alice(signer=did_key("alice")),
        [],
    ),
    (
        "an exact repeat asks only for its receipt",
        bob_under_alice(receipt=Receipt(REGISTERED_AT, None)),
        [RECEIPT],
    ),
    (
        "a used invitation stops before the subject's head",
        bob_under_alice(invitation_id=INVITATION, invitation_used=True),
        [RECEIPT, INVITATION_USED],
    ),
    (
        "a registered subject's changed kind stops before its head",
        kind_change(),
        [RECEIPT],
    ),
    (
        "a head conflict stops before root authority",
        global_agent_reparented(expected_head=None),
        [RECEIPT, HEAD],
    ),
    (
        "missing root authority stops before the issuer",
        bob_under_alice(root=None),
        [RECEIPT, ROOT],
    ),
    (
        "a revoked issuer stops before its key version",
        parent_revoked("registration-after-sign-then-parent-revoke"),
        [RECEIPT, ROOT, PARENT],
    ),
    (
        "the first invalid ancestor stops the ancestry and the parent's chain",
        global_agent_reparented(registered=[None, certificate("bob")]),
        [RECEIPT, HEAD, ROOT, PARENT, PARENT_EPOCH, Ancestor(0)],
    ),
    (
        "an admitted identity child asks for every fact once, in order",
        bob_under_alice(),
        [RECEIPT, ROOT, PARENT, PARENT_EPOCH, Ancestor(0), PARENT_CHAIN],
    ),
    (
        "an admitted root child asks for no issuer identity",
        alice_under_root(),
        [RECEIPT, ROOT],
    ),
]


@pytest.mark.parametrize(
    ("facts", "asked"),
    [row[1:] for row in BOUNDARY],
    ids=[row[0] for row in BOUNDARY],
)
def test_a_deciding_check_asks_for_no_later_fact(facts: Facts, asked: list):
    assert decide(facts)[1] == asked
