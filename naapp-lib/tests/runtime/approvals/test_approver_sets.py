"""Approver sets: any one of several individually designated approvers decides.

Each candidate is one designated person with their own link to their own
contact. The set is frozen at mint, the requester is excluded unless the policy
allows otherwise, and exactly one decision is ever recorded.
"""

from __future__ import annotations

import asyncio

import asyncpg
import pytest

from aweb_naapp.runtime.approvals import (
    ApprovalRefused,
    ApprovalRevocation,
    ApprovalState,
    Approver,
    Assurance,
    DecidedBy,
    Decision,
    DeliveryStatus,
    PresentationKind,
    Purpose,
    Refusal,
    challenge_binding,
)
from tests.runtime.approvals.support import World, policy, sign

REQUEST = {"operation": "deploy", "destination": {"host": "api.example.com"}, "executor": "broker"}
SCOPES = ("ops.alice", "ops.bob", "ops.carol")


def person(scope: str) -> Approver:
    name = scope.split(".")[-1]
    return Approver(
        scope=scope,
        subject=f"human-{name}",
        subject_type="app_local",
        contact=f"{name}@example.com",
    )


def designate_all(w: World, scopes=SCOPES, **policy_changes) -> dict[str, tuple[Approver, object]]:
    """Designate one person per scope and a policy whose approvers are those scopes."""
    w.policies.set(policy(policy_ref="deploy", approver_scopes=tuple(scopes), **policy_changes))
    people = {}
    for scope in scopes:
        approver = person(scope)
        w.directory.designate(approver)
        people[scope] = (approver, w.passkey.register(approver.subject))
    return people


async def mint(w: World, requested_by: str = "agent-1"):
    view = await w.approvals.mint(request=REQUEST, policy_ref="deploy", requested_by=requested_by)
    return await w.approvals.for_request(view.request_id)


def link(w: World, approval, approver: Approver) -> str:
    return w.mailbox.links[(approval.approval_id, approver.subject)]


async def decide(w: World, approval, approver: Approver, key, decision=Decision.APPROVE, via=None):
    """`approver` signs, through the link sent to `via` (their own by default)."""
    token = link(w, approval, via or approver)
    issued = await w.approvals.challenge(
        approval.approval_id, decision, Assurance.PASSKEY, link_token=token
    )
    return await w.approvals.decide(
        approval.approval_id,
        decision,
        Assurance.PASSKEY,
        sign(key, approver.subject, issued),
        link_token=token,
    )


async def refusal(awaitable) -> Refusal:
    with pytest.raises(ApprovalRefused) as raised:
        await awaitable
    return raised.value.reason


async def test_each_candidate_gets_their_own_link_at_their_own_contact(world: World):
    people = designate_all(world)
    approval = await mint(world)
    assert {(c.scope, c.subject) for c in approval.candidates} == {
        (scope, approver.subject) for scope, (approver, _) in people.items()
    }
    recipients = [approver for approver, _ in world.mailbox.sent]
    assert sorted(a.contact for a in recipients) == sorted(a.contact for a, _ in people.values())
    tokens = [token for _, token in world.mailbox.sent]
    assert len(set(tokens)) == len(tokens)
    view = await world.approvals.requester_view(approval.request_ref, "agent-1")
    assert view.delivery_status is DeliveryStatus.DELIVERED
    assert not any(token in repr(view) for token in tokens)


async def test_the_requester_is_not_a_candidate(world: World):
    people = designate_all(world)
    bob, _ = people["ops.bob"]
    approval = await mint(world, requested_by=bob.subject)
    assert bob.subject not in {c.subject for c in approval.candidates}
    assert bob.contact not in {a.contact for a, _ in world.mailbox.sent}


async def test_a_policy_can_keep_the_requester_eligible(world: World):
    people = designate_all(world, allow_requester_approval=True)
    bob, bob_key = people["ops.bob"]
    approval = await mint(world, requested_by=bob.subject)
    assert bob.subject in {c.subject for c in approval.candidates}
    assert (await decide(world, approval, bob, bob_key)).state is ApprovalState.APPROVED


async def test_mint_needs_an_eligible_approver(world: World):
    world.policies.set(policy(policy_ref="deploy", approver_scopes=SCOPES))
    assert await refusal(mint(world)) is Refusal.NO_ELIGIBLE_APPROVER
    alice = person("ops.alice")
    world.directory.designate(alice)
    assert await refusal(mint(world, requested_by=alice.subject)) is Refusal.NO_ELIGIBLE_APPROVER
    assert world.mailbox.sent == []


async def test_any_candidate_decides_and_is_recorded_as_the_decider(world: World):
    people = designate_all(world)
    carol, carol_key = people["ops.carol"]
    approval = await mint(world)
    decided = await decide(world, approval, carol, carol_key)
    assert decided.state is ApprovalState.APPROVED
    assert (decided.decided_by.scope, decided.decided_by.subject) == ("ops.carol", carol.subject)
    assert decided.decided_by.assurance is Assurance.PASSKEY


async def test_the_first_decision_kills_every_other_candidates_link(world: World):
    people = designate_all(world)
    (alice, _), (bob, bob_key) = people["ops.alice"], people["ops.bob"]
    approval = await mint(world)
    await decide(world, approval, bob, bob_key)
    with pytest.raises(ApprovalRefused) as raised:
        await world.approvals.open_link(link(world, approval, alice))
    assert raised.value.reason is Refusal.LINK_UNAVAILABLE
    challenged = world.approvals.challenge(
        approval.approval_id,
        Decision.REJECT,
        Assurance.PASSKEY,
        link_token=link(world, approval, alice),
    )
    assert await refusal(challenged) is Refusal.LINK_UNAVAILABLE


async def test_any_one_rejection_is_final(world: World):
    people = designate_all(world)
    (alice, alice_key), (carol, carol_key) = people["ops.alice"], people["ops.carol"]
    approval = await mint(world)
    assert (await decide(world, approval, alice, alice_key, Decision.REJECT)).state is (
        ApprovalState.REJECTED
    )
    assert await refusal(decide(world, approval, carol, carol_key)) is Refusal.LINK_UNAVAILABLE
    assert await refusal(world.approvals.admit(approval.approval_id, REQUEST, "op-1")) is (
        Refusal.NOT_APPROVED
    )


async def test_a_link_decides_only_for_its_own_candidate(world: World):
    people = designate_all(world)
    (alice, alice_key), (bob, bob_key) = people["ops.alice"], people["ops.bob"]
    approval = await mint(world)
    stolen = decide(world, approval, alice, alice_key, via=bob)
    assert await refusal(stolen) is Refusal.APPROVER_MISMATCH
    assert (await world.approvals.get(approval.approval_id)).state is ApprovalState.PENDING
    assert (await decide(world, approval, bob, bob_key)).decided_by.subject == bob.subject


async def test_a_failed_ceremony_consumes_nothing(world: World):
    people = designate_all(world)
    alice, alice_key = people["ops.alice"]
    _, other_key = people["ops.bob"]
    approval = await mint(world)
    assert await refusal(decide(world, approval, alice, other_key)) is (
        Refusal.AUTHENTICATION_FAILED
    )
    assert (await decide(world, approval, alice, alice_key)).state is ApprovalState.APPROVED


async def test_a_candidate_no_longer_designated_cannot_decide(world: World):
    people = designate_all(world)
    (alice, alice_key), (bob, bob_key) = people["ops.alice"], people["ops.bob"]
    approval = await mint(world)
    world.directory.undesignate(alice)
    assert await refusal(decide(world, approval, alice, alice_key)) is Refusal.APPROVER_RETIRED
    assert (await decide(world, approval, bob, bob_key)).decided_by.subject == bob.subject


async def test_decide_rechecks_the_requester_rule(world: World):
    people = designate_all(world, allow_requester_approval=True)
    bob, bob_key = people["ops.bob"]
    approval = await mint(world, requested_by=bob.subject)
    world.policies.set(policy(policy_ref="deploy", approver_scopes=SCOPES))
    assert await refusal(decide(world, approval, bob, bob_key)) is Refusal.NO_ELIGIBLE_APPROVER


async def test_retiring_a_candidate_takes_only_their_link(world: World):
    people = designate_all(world)
    (alice, _), (bob, bob_key) = people["ops.alice"], people["ops.bob"]
    approval = await mint(world)
    world.directory.undesignate(alice)
    retirement = ApprovalRevocation(world.store, world.audit, world.clock)
    async with world.store.db.transaction() as tx:
        await retirement.approver_retired(alice.subject, retired_by="owner-1", tx=tx)
    with pytest.raises(ApprovalRefused) as raised:
        await world.approvals.open_link(link(world, approval, alice))
    assert raised.value.reason is Refusal.LINK_UNAVAILABLE
    assert (await world.approvals.get(approval.approval_id)).state is ApprovalState.PENDING
    assert (await decide(world, approval, bob, bob_key)).state is ApprovalState.APPROVED


async def test_retiring_every_candidate_leaves_no_link_that_decides(world: World):
    people = designate_all(world, scopes=("ops.alice", "ops.bob"))
    alice, alice_key = people["ops.alice"]
    approval = await mint(world)
    retirement = ApprovalRevocation(world.store, world.audit, world.clock)
    for approver, _ in people.values():
        world.directory.undesignate(approver)
        async with world.store.db.transaction() as tx:
            await retirement.approver_retired(approver.subject, retired_by="owner-1", tx=tx)
    view = await world.approvals.requester_view(approval.request_ref, "agent-1")
    assert view.approval_state is ApprovalState.PENDING
    world.directory.designate(alice)
    assert await refusal(decide(world, approval, alice, alice_key)) is Refusal.LINK_UNAVAILABLE


async def test_no_eligible_approver_once_no_candidate_is_designated(world: World):
    people = designate_all(world, scopes=("ops.alice", "ops.bob"))
    alice, alice_key = people["ops.alice"]
    approval = await mint(world)
    token = link(world, approval, alice)
    issued = await world.approvals.challenge(
        approval.approval_id, Decision.APPROVE, Assurance.PASSKEY, link_token=token
    )
    for approver, _ in people.values():
        world.directory.undesignate(approver)
    decided = world.approvals.decide(
        approval.approval_id,
        Decision.APPROVE,
        Assurance.PASSKEY,
        sign(alice_key, alice.subject, issued),
        link_token=token,
    )
    assert await refusal(decided) is Refusal.NO_ELIGIBLE_APPROVER


async def test_retiring_the_decider_voids_the_approved_approval(world: World):
    people = designate_all(world)
    bob, bob_key = people["ops.bob"]
    approval = await mint(world)
    await decide(world, approval, bob, bob_key)
    retirement = ApprovalRevocation(world.store, world.audit, world.clock)
    async with world.store.db.transaction() as tx:
        await retirement.approver_retired(bob.subject, retired_by="owner-1", tx=tx)
    assert await refusal(world.approvals.admit(approval.approval_id, REQUEST, "op-1")) is (
        Refusal.REVOKED
    )


async def test_sixteen_candidates_are_a_first_class_set(world: World):
    scopes = tuple(f"ops.person{i:02d}" for i in range(16))
    people = designate_all(world, scopes=scopes)
    approval = await mint(world)
    assert len(approval.candidates) == 16
    assert len(world.mailbox.sent) == 16
    last, last_key = people[scopes[-1]]
    assert (await decide(world, approval, last, last_key)).decided_by.subject == last.subject


async def test_two_candidates_deciding_at_once_record_one_decision(world: World):
    people = designate_all(world)
    (alice, alice_key), (bob, bob_key) = people["ops.alice"], people["ops.bob"]
    approval = await mint(world)
    issued = {}
    for approver, key, decision in (
        (alice, alice_key, Decision.APPROVE),
        (bob, bob_key, Decision.REJECT),
    ):
        token = link(world, approval, approver)
        challenge = await world.approvals.challenge(
            approval.approval_id, decision, Assurance.PASSKEY, link_token=token
        )
        issued[approver.subject] = (decision, token, sign(key, approver.subject, challenge))
    results = await asyncio.gather(
        *(
            world.approvals.decide(
                approval.approval_id, decision, Assurance.PASSKEY, proof, link_token=token
            )
            for decision, token, proof in issued.values()
        ),
        return_exceptions=True,
    )
    decided = [r for r in results if not isinstance(r, Exception)]
    refused = [r for r in results if isinstance(r, ApprovalRefused)]
    assert len(decided) == 1 and len(refused) == 1
    assert refused[0].reason in (Refusal.LINK_UNAVAILABLE, Refusal.NOT_PENDING)
    final = await world.approvals.get(approval.approval_id)
    assert final.decided_by.subject == decided[0].decided_by.subject


# Task presentation: the caller names the candidate, the answer names its principal


def principal(scope: str) -> Approver:
    approver = person(scope)
    return Approver(
        scope=approver.scope,
        subject=approver.subject,
        subject_type=approver.subject_type,
        contact=approver.contact,
        principal_did=f"did:aw:{approver.subject}",
    )


async def task_approval(w: World, scopes=("ops.alice", "ops.bob")):
    w.policies.set(policy(policy_ref="deploy", approver_scopes=scopes))
    people = {}
    for scope in scopes:
        approver = principal(scope)
        w.directory.designate(approver)
        people[scope] = (approver, w.passkey.register(approver.subject))
    view = await w.approvals.mint(
        request=REQUEST,
        policy_ref="deploy",
        requested_by="agent-1",
        presentation=PresentationKind.TASK,
        presentation_ref="task-1",
    )
    return people, await w.approvals.for_request(view.request_id)


async def decide_task(w: World, approval, approver: Approver, key, answer_ref: str):
    issued = await w.approvals.challenge(
        approval.approval_id,
        Decision.APPROVE,
        Assurance.PASSKEY,
        task_answer_ref=answer_ref,
        subject=approver.subject,
    )
    return await w.approvals.decide(
        approval.approval_id,
        Decision.APPROVE,
        Assurance.PASSKEY,
        sign(key, approver.subject, issued),
        task_answer_ref=answer_ref,
        subject=approver.subject,
    )


async def test_a_task_answer_decides_for_the_candidate_whose_principal_gave_it(world: World):
    people, approval = await task_approval(world)
    bob, bob_key = people["ops.bob"]
    world.task_answers.record("answer-1", approval, Decision.APPROVE, bob.principal_did)
    decided = await decide_task(world, approval, bob, bob_key, "answer-1")
    assert decided.decided_by.subject == bob.subject
    assert world.mailbox.sent == []


async def test_a_task_answer_by_another_principal_decides_nothing(world: World):
    people, approval = await task_approval(world)
    (alice, alice_key), (bob, _) = people["ops.alice"], people["ops.bob"]
    world.task_answers.record("answer-1", approval, Decision.APPROVE, bob.principal_did)
    assert await refusal(decide_task(world, approval, alice, alice_key, "answer-1")) is (
        Refusal.TASK_ANSWER_UNVERIFIED
    )
    assert (await world.approvals.get(approval.approval_id)).state is ApprovalState.PENDING


async def test_a_task_presentation_names_a_frozen_candidate(world: World):
    _, approval = await task_approval(world)
    outsider = principal("ops.mallory")
    key = world.passkey.register(outsider.subject)
    world.task_answers.record("answer-1", approval, Decision.APPROVE, outsider.principal_did)
    assert await refusal(decide_task(world, approval, outsider, key, "answer-1")) is (
        Refusal.APPROVER_MISMATCH
    )
    nameless = world.approvals.challenge(
        approval.approval_id, Decision.APPROVE, Assurance.PASSKEY, task_answer_ref="answer-1"
    )
    assert await refusal(nameless) is Refusal.PRESENTATION_MISMATCH


async def test_a_task_presentation_leaves_out_candidates_without_a_principal(world: World):
    world.policies.set(policy(policy_ref="deploy", approver_scopes=("ops.alice", "ops.bob")))
    world.directory.designate(person("ops.alice"))
    world.directory.designate(principal("ops.bob"))
    view = await world.approvals.mint(
        request=REQUEST,
        policy_ref="deploy",
        requested_by="agent-1",
        presentation=PresentationKind.TASK,
        presentation_ref="task-1",
    )
    approval = await world.approvals.for_request(view.request_id)
    assert [c.subject for c in approval.candidates] == [principal("ops.bob").subject]


async def test_the_challenge_binding_commits_to_the_candidate(world: World):
    designate_all(world)
    approval = await mint(world)
    alice, bob = approval.candidates[0], approval.candidates[1]
    nonce = b"n" * 16
    assert challenge_binding(approval, alice, Purpose.APPROVE, nonce) != challenge_binding(
        approval, bob, Purpose.APPROVE, nonce
    )


async def test_a_retired_candidate_stays_out_even_if_designated_again(world: World):
    people, approval = await task_approval(world)
    (alice, alice_key), (bob, _) = people["ops.alice"], people["ops.bob"]
    retirement = ApprovalRevocation(world.store, world.audit, world.clock)
    world.directory.undesignate(alice)
    async with world.store.db.transaction() as tx:
        await retirement.approver_retired(alice.subject, retired_by="owner-1", tx=tx)
    world.directory.designate(alice)
    world.task_answers.record("answer-1", approval, Decision.APPROVE, alice.principal_did)
    assert await refusal(decide_task(world, approval, alice, alice_key, "answer-1")) is (
        Refusal.APPROVER_RETIRED
    )
    assert bob.subject in {c.subject for c in approval.candidates}


async def test_one_person_designated_in_two_scopes_is_one_candidate(world: World):
    world.policies.set(policy(policy_ref="deploy", approver_scopes=("ops.alice", "ops.backup")))
    alice = person("ops.alice")
    world.directory.designate(alice)
    world.directory.designate(
        Approver(
            scope="ops.backup",
            subject=alice.subject,
            subject_type=alice.subject_type,
            contact=alice.contact,
        )
    )
    approval = await mint(world)
    assert [(c.scope, c.subject) for c in approval.candidates] == [("ops.alice", alice.subject)]
    assert len(world.mailbox.sent) == 1


# Retirement and decision serialise


async def test_a_retirement_committed_during_the_ceremony_stops_the_decision(world: World):
    people, approval = await task_approval(world)
    (alice, alice_key), (bob, _) = people["ops.alice"], people["ops.bob"]
    world.task_answers.record("answer-1", approval, Decision.REJECT, alice.principal_did)
    retirement = ApprovalRevocation(world.store, world.audit, world.clock)

    async def retire_alice() -> None:
        async with world.store.db.transaction() as tx:
            await retirement.approver_retired(alice.subject, retired_by="owner-1", tx=tx)

    issued = await world.approvals.challenge(
        approval.approval_id,
        Decision.REJECT,
        Assurance.PASSKEY,
        task_answer_ref="answer-1",
        subject=alice.subject,
    )
    world.passkey.after_verify = retire_alice
    decided = world.approvals.decide(
        approval.approval_id,
        Decision.REJECT,
        Assurance.PASSKEY,
        sign(alice_key, alice.subject, issued),
        task_answer_ref="answer-1",
        subject=alice.subject,
    )
    assert await refusal(decided) is Refusal.APPROVER_RETIRED
    after = await world.approvals.get(approval.approval_id)
    assert after.state is ApprovalState.PENDING
    assert bob.subject in {c.subject for c in after.candidates if c.retired_at is None}


async def waiting_on_a_lock(w: World) -> bool:
    return bool(
        await w.store.db.fetch_value(
            "SELECT EXISTS (SELECT 1 FROM pg_stat_activity "
            "WHERE datname = current_database() AND wait_event_type = 'Lock')"
        )
    )


async def test_a_decision_waits_for_a_retirement_in_flight(world: World):
    people, approval = await task_approval(world)
    alice, alice_key = people["ops.alice"]
    world.task_answers.record("answer-1", approval, Decision.APPROVE, alice.principal_did)
    issued = await world.approvals.challenge(
        approval.approval_id,
        Decision.APPROVE,
        Assurance.PASSKEY,
        task_answer_ref="answer-1",
        subject=alice.subject,
    )
    retirement = ApprovalRevocation(world.store, world.audit, world.clock)
    async with world.store.db.transaction() as tx:
        await retirement.approver_retired(alice.subject, retired_by="owner-1", tx=tx)
        deciding = asyncio.create_task(
            world.approvals.decide(
                approval.approval_id,
                Decision.APPROVE,
                Assurance.PASSKEY,
                sign(alice_key, alice.subject, issued),
                task_answer_ref="answer-1",
                subject=alice.subject,
            )
        )
        for _ in range(200):
            if await waiting_on_a_lock(world) or deciding.done():
                break
            await asyncio.sleep(0.01)
        assert not deciding.done()
    assert await refusal(deciding) is Refusal.APPROVER_RETIRED
    assert (await world.approvals.get(approval.approval_id)).state is ApprovalState.PENDING


async def test_mint_keeps_only_candidates_in_the_policys_scopes(world: World):
    world.policies.set(policy(policy_ref="deploy", approver_scopes=("ops.alice",)))
    world.directory.designate(person("ops.alice"))
    world.directory.designate(person("owners.mallory"))
    world.directory.candidates = lambda policy, request: _all_designated(world)  # type: ignore[method-assign]
    approval = await mint(world)
    assert [c.scope for c in approval.candidates] == ["ops.alice"]


async def _all_designated(w: World) -> list[Approver]:
    return list(w.directory.by_scope.values())


async def test_a_link_view_shows_only_its_own_candidate(world: World):
    people = designate_all(world, link_reveals_request=True)
    alice, _ = people["ops.alice"]
    approval = await mint(world)
    linked = await world.approvals.open_link(link(world, approval, alice))
    assert linked.request == REQUEST
    assert [c.subject for c in linked.approval.candidates] == [alice.subject]


async def test_the_store_records_a_decider_only_in_their_candidate_scope(world: World):
    people = designate_all(world)
    alice, _ = people["ops.alice"]
    approval = await mint(world)
    with pytest.raises(asyncpg.ForeignKeyViolationError):
        async with world.store.locked(approval.approval_id, None) as locked:
            await locked.set_decision(
                ApprovalState.APPROVED,
                DecidedBy("owners.root", alice.subject, Assurance.PASSKEY, "e"),
                None,
                None,
                world.clock(),
            )
    assert (await world.approvals.get(approval.approval_id)).state is ApprovalState.PENDING


async def test_a_candidate_standing_for_the_requester_is_excluded(world: World):
    world.policies.set(policy(policy_ref="deploy", approver_scopes=("ops.alice", "ops.bob")))
    alice, bob = principal("ops.alice"), principal("ops.bob")
    world.directory.designate(alice)
    world.directory.designate(bob)
    approval = await mint(world, requested_by=alice.principal_did)
    assert [c.subject for c in approval.candidates] == [bob.subject]


async def test_a_policy_can_keep_a_candidate_standing_for_the_requester(world: World):
    world.policies.set(
        policy(policy_ref="deploy", approver_scopes=("ops.alice",), allow_requester_approval=True)
    )
    alice = principal("ops.alice")
    world.directory.designate(alice)
    alice_key = world.passkey.register(alice.subject)
    approval = await mint(world, requested_by=alice.principal_did)
    assert [c.subject for c in approval.candidates] == [alice.subject]
    world.policies.set(policy(policy_ref="deploy", approver_scopes=("ops.alice",)))
    assert await refusal(decide(world, approval, alice, alice_key)) is (
        Refusal.NO_ELIGIBLE_APPROVER
    )
