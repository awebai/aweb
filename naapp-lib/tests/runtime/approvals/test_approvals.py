"""The approval primitive against a real PostgreSQL store."""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import timedelta

import asyncpg
import pytest
from pgdbm.errors import QueryError

from aweb_naapp.runtime.approvals import (
    ApprovalRefused,
    Approvals,
    ApprovalState,
    Assurance,
    Decision,
    DeliveryStatus,
    DispatchOutcome,
    Evidence,
    LinkAlreadyUsed,
    PresentationKind,
    Purpose,
    Refusal,
)
from aweb_naapp.runtime.links import link_verifier
from tests.runtime.approvals.support import APPROVER, SUCCESSOR, World, policy, sign

REQUEST = {
    "operation": "charge",
    "destination": {"host": "api.example.com", "path": "/v1/charges"},
    "constraints": {"max_amount_cents": 500},
    "source_version": 1,
    "executor": "broker",
}


async def mint(w: World, request=REQUEST, policy_ref="send-charge", **kw):
    view = await w.approvals.mint(
        request=request, policy_ref=policy_ref, requested_by="agent-1", **kw
    )
    approval = await w.approvals.for_request(view.request_id)
    return view, approval


def link_of(w: World, approval) -> str | None:
    return w.mailbox.by_approval.get(approval.approval_id)


async def challenge(
    w: World, approval, decision=Decision.APPROVE, assurance=Assurance.PASSKEY, task_answer_ref=None
):
    return await w.approvals.challenge(
        approval.approval_id,
        decision,
        assurance,
        link_token=link_of(w, approval),
        task_answer_ref=task_answer_ref,
    )


async def decide(w: World, approval, decision=Decision.APPROVE, assurance=Assurance.PASSKEY, **kw):
    key = w.approver_key if assurance is Assurance.PASSKEY else w.approver_session_key
    issued = await challenge(w, approval, decision, assurance, kw.get("task_answer_ref"))
    proof = sign(key, APPROVER.subject, issued)
    kw.setdefault("link_token", link_of(w, approval))
    return await w.approvals.decide(approval.approval_id, decision, assurance, proof, **kw)


async def approved(w: World, request=REQUEST):
    _, approval = await mint(w, request)
    return await decide(w, approval)


async def refusal(awaitable) -> Refusal:
    with pytest.raises(ApprovalRefused) as raised:
        await awaitable
    return raised.value.reason


# Minting and the requester's view


async def test_mint_delivers_the_link_to_the_designated_approver_only(world: World):
    view, approval = await mint(world)
    assert view.approval_state is ApprovalState.PENDING
    assert view.delivery_status is DeliveryStatus.DELIVERED
    [(recipient, token)] = world.mailbox.sent
    assert recipient == APPROVER
    assert approval.approver_subject == APPROVER.subject
    assert approval.requested_by == "agent-1"
    assert token not in repr(view)
    assert token not in repr(approval)
    assert token not in repr(await world.audit.rows())


async def test_mint_refuses_an_unknown_policy_or_a_missing_approver(world: World):
    assert await refusal(mint(world, policy_ref="nope")) is Refusal.POLICY_UNKNOWN
    world.directory.approver = None
    assert await refusal(mint(world)) is Refusal.NO_APPROVER
    assert world.mailbox.sent == []


async def test_mint_refuses_a_requester_who_is_the_approver(world: World):
    minted = world.approvals.mint(
        request=REQUEST, policy_ref="send-charge", requested_by=APPROVER.subject
    )
    assert await refusal(minted) is Refusal.REQUESTER_IS_APPROVER
    assert world.mailbox.sent == []
    assert await world.audit.rows() == []


async def test_a_policy_can_let_the_requester_approve(world: World):
    world.policies.set(policy(allow_requester_approval=True))
    view = await world.approvals.mint(
        request=REQUEST, policy_ref="send-charge", requested_by=APPROVER.subject
    )
    approval = await world.approvals.for_request(view.request_id)
    assert (await decide(world, approval)).state is ApprovalState.APPROVED


async def test_a_failed_delivery_is_visible_to_the_requester(world: World):
    world.mailbox.status = DeliveryStatus.FAILED
    view, _ = await mint(world)
    assert view.delivery_status is DeliveryStatus.FAILED
    assert (await world.approvals.requester_view(view.request_id, "agent-1")).delivery_status is (
        DeliveryStatus.FAILED
    )


async def test_the_request_is_frozen_at_mint(world: World):
    request = {**REQUEST, "constraints": {"max_amount_cents": 500}}
    _, approval = await mint(world, request, policy_ref="internal-edit")
    request["constraints"]["max_amount_cents"] = 9999
    linked = await world.approvals.open_link(world.mailbox.last_token())
    assert linked.request == REQUEST
    with pytest.raises(QueryError) as raised:
        await world.store.db.execute(
            "UPDATE {{tables.approval_requests}} SET canonical = $1", b"{}"
        )
    assert isinstance(raised.value.__context__, asyncpg.exceptions.RaiseError)


async def test_link_tokens_are_stored_only_as_verifier_hashes(world: World):
    await mint(world)
    token = world.mailbox.last_token()
    rows = await world.store.db.fetch_all("SELECT * FROM {{tables.approval_links}}")
    assert len(rows) == 1
    assert all(token not in str(value) for value in rows[0].values())
    assert rows[0]["verifier_sha256"] == hashlib.sha256(token.encode()).hexdigest()


# The approver's link


async def test_opening_the_link_consumes_nothing(world: World):
    view, _ = await mint(world)
    token = world.mailbox.last_token()
    for _ in range(3):
        linked = await world.approvals.open_link(token)
        assert linked.approval.state is ApprovalState.PENDING
    approval = await decide(world, linked.approval)
    admission = await world.approvals.admit(approval.approval_id, REQUEST, "op-1")
    assert admission.first


async def test_unknown_expired_or_revoked_links_are_unavailable(world: World):
    assert await refusal(world.approvals.open_link("not-a-token")) is Refusal.LINK_UNAVAILABLE
    _, approval = await mint(world)
    token = world.mailbox.last_token()
    await world.approvals.revoke(approval.approval_id, revoked_by="owner-1")
    assert await refusal(world.approvals.open_link(token)) is Refusal.LINK_UNAVAILABLE
    await mint(world)
    world.clock.advance(timedelta(minutes=10))
    assert await refusal(world.approvals.open_link(world.mailbox.last_token())) is (
        Refusal.LINK_UNAVAILABLE
    )


# Deciding


async def test_a_passkey_approval_records_its_evidence(world: World):
    _, approval = await mint(world)
    decided = await decide(world, approval)
    assert decided.state is ApprovalState.APPROVED
    assert decided.authenticator is Assurance.PASSKEY
    assert decided.auth_evidence_ref
    assert "approval_decided" in (await world.audit.kinds())


async def test_a_weaker_assurance_than_the_policy_minimum_is_refused(world: World):
    _, approval = await mint(world)
    assert await refusal(challenge(world, approval, assurance=Assurance.MEMBER_SESSION)) is (
        Refusal.ASSURANCE_INSUFFICIENT
    )
    issued = await world.session.challenge(approval, Purpose.APPROVE, None)
    proof = sign(world.approver_session_key, APPROVER.subject, issued)
    assert (
        await refusal(
            world.approvals.decide(
                approval.approval_id,
                Decision.APPROVE,
                Assurance.MEMBER_SESSION,
                proof,
                link_token=link_of(world, approval),
            )
        )
        is Refusal.ASSURANCE_INSUFFICIENT
    )
    assert (await world.approvals.for_request(approval.request_ref)).state is ApprovalState.PENDING


async def test_a_member_session_meets_a_member_session_policy(world: World):
    _, approval = await mint(world, policy_ref="internal-edit")
    decided = await decide(world, approval, assurance=Assurance.MEMBER_SESSION)
    assert decided.authenticator is Assurance.MEMBER_SESSION


async def test_only_the_designated_approver_can_decide(world: World):
    _, approval = await mint(world)
    intruder = world.passkey.register("someone-else")
    proof = sign(intruder, "someone-else", await challenge(world, approval))
    assert (
        await refusal(
            world.approvals.decide(
                approval.approval_id,
                Decision.APPROVE,
                Assurance.PASSKEY,
                proof,
                link_token=link_of(world, approval),
            )
        )
        is Refusal.APPROVER_MISMATCH
    )


async def test_a_proof_for_one_decision_cannot_make_another(world: World):
    _, approval = await mint(world)
    proof = sign(
        world.approver_key, APPROVER.subject, await challenge(world, approval, Decision.REJECT)
    )
    assert (
        await refusal(
            world.approvals.decide(
                approval.approval_id,
                Decision.APPROVE,
                Assurance.PASSKEY,
                proof,
                link_token=link_of(world, approval),
            )
        )
        is Refusal.AUTHENTICATION_FAILED
    )


async def test_a_failed_authentication_leaves_the_approval_pending(world: World):
    _, approval = await mint(world)
    issued = await challenge(world, approval)
    forged = {**sign(world.approver_key, APPROVER.subject, issued), "signature": "00" * 64}
    assert (
        await refusal(
            world.approvals.decide(
                approval.approval_id,
                Decision.APPROVE,
                Assurance.PASSKEY,
                forged,
                link_token=link_of(world, approval),
            )
        )
        is Refusal.AUTHENTICATION_FAILED
    )
    assert (await world.approvals.open_link(link_of(world, approval))).approval.approval_id == (
        approval.approval_id
    )
    assert (await decide(world, approval)).state is ApprovalState.APPROVED


async def test_an_approval_is_decided_once_and_not_after_expiry(world: World):
    approval = await approved(world)
    assert await refusal(decide(world, approval, Decision.REJECT)) is Refusal.NOT_PENDING
    _, late = await mint(world)
    world.clock.advance(timedelta(minutes=10))
    assert await refusal(decide(world, late)) is Refusal.EXPIRED


async def test_a_policy_change_after_mint_requires_a_new_approval(world: World):
    _, approval = await mint(world)
    world.policies.set(policy(version=2))
    assert await refusal(decide(world, approval)) is Refusal.POLICY_CHANGED


async def test_task_presentation_needs_the_task_answer_and_sends_no_link(world: World):
    assert await refusal(mint(world, presentation=PresentationKind.TASK)) is (
        Refusal.PRESENTATION_MISMATCH
    )
    view, approval = await mint(
        world, presentation=PresentationKind.TASK, presentation_ref="task-1"
    )
    assert view.delivery_status is DeliveryStatus.NOT_REQUIRED
    assert world.mailbox.sent == []
    assert await refusal(decide(world, approval)) is Refusal.PRESENTATION_MISMATCH
    world.task_answers.record("answer-1", approval, Decision.APPROVE)
    decided = await decide(world, approval, task_answer_ref="answer-1")
    assert decided.task_answer_ref == "answer-1"
    _, linked = await mint(world)
    assert await refusal(decide(world, linked, task_answer_ref="answer-2")) is (
        Refusal.PRESENTATION_MISMATCH
    )


# Admission


async def test_admission_consumes_the_approval_once(world: World):
    approval = await approved(world)
    admission = await world.approvals.admit(approval.approval_id, REQUEST, "op-1")
    assert admission.first and admission.operation_id == "op-1"
    record = await world.approvals.for_request(approval.request_ref)
    assert record.state is ApprovalState.CONSUMED
    assert record.consumed_operation_id == "op-1"
    assert await refusal(world.approvals.admit(approval.approval_id, REQUEST, "op-2")) is (
        Refusal.CONSUMED
    )


async def test_retrieving_the_same_admitted_attempt_is_not_a_new_dispatch(world: World):
    approval = await approved(world)
    await world.approvals.admit(approval.approval_id, REQUEST, "op-1")
    again = await world.approvals.admit(approval.approval_id, REQUEST, "op-1")
    assert not again.first
    assert (await world.audit.kinds()).count("dispatch_admitted") == 1


async def test_admission_requires_the_exact_approved_request(world: World):
    approval = await approved(world)
    changed = {**REQUEST, "destination": {"host": "evil.example.com", "path": "/v1/charges"}}
    assert await refusal(world.approvals.admit(approval.approval_id, changed, "op-1")) is (
        Refusal.REQUEST_MISMATCH
    )
    assert (await world.approvals.admit(approval.approval_id, REQUEST, "op-1")).first


async def test_admission_refuses_pending_rejected_expired_and_revoked(world: World):
    _, pending = await mint(world)
    assert await refusal(world.approvals.admit(pending.approval_id, REQUEST, "op")) is (
        Refusal.NOT_APPROVED
    )
    _, rejected = await mint(world)
    await decide(world, rejected, Decision.REJECT)
    assert await refusal(world.approvals.admit(rejected.approval_id, REQUEST, "op")) is (
        Refusal.NOT_APPROVED
    )
    revoked = await approved(world)
    await world.approvals.revoke(revoked.approval_id, revoked_by="owner-1")
    assert await refusal(world.approvals.admit(revoked.approval_id, REQUEST, "op")) is (
        Refusal.REVOKED
    )
    expired = await approved(world)
    world.clock.advance(timedelta(minutes=10))
    assert await refusal(world.approvals.admit(expired.approval_id, REQUEST, "op")) is (
        Refusal.EXPIRED
    )


async def test_admission_rechecks_the_current_policy(world: World):
    bumped = await approved(world)
    world.policies.set(policy(version=2))
    assert await refusal(world.approvals.admit(bumped.approval_id, REQUEST, "op")) is (
        Refusal.POLICY_CHANGED
    )
    world.policies.set(policy(policy_ref="internal-edit", min_assurance=Assurance.MEMBER_SESSION))
    _, internal = await mint(world, policy_ref="internal-edit")
    internal = await decide(world, internal, assurance=Assurance.MEMBER_SESSION)
    world.policies.set(policy(policy_ref="internal-edit", min_assurance=Assurance.PASSKEY))
    assert await refusal(world.approvals.admit(internal.approval_id, REQUEST, "op")) is (
        Refusal.ASSURANCE_INSUFFICIENT
    )


async def test_an_unknown_value_cannot_be_admitted(world: World):
    assert await refusal(world.approvals.admit("missing", REQUEST, "op")) is Refusal.NOT_FOUND


# Outcomes and reconciliation


async def complete(w: World, approval, operation_id="op-1", status="200"):
    return await w.approvals.record_outcome(
        approval.approval_id, operation_id, DispatchOutcome.COMPLETED, response_status=status
    )


async def test_admission_starts_dispatching_and_completion_records_the_response(world: World):
    approval = await approved(world)
    admission = await world.approvals.admit(approval.approval_id, REQUEST, "op-1")
    assert admission.may_send and admission.dispatch_outcome is DispatchOutcome.DISPATCHING
    await complete(world, approval, status="402")
    retrieved = await world.approvals.admit(approval.approval_id, REQUEST, "op-1")
    assert not retrieved.first and not retrieved.may_send
    assert retrieved.dispatch_outcome is DispatchOutcome.COMPLETED
    assert retrieved.response_status == "402"


async def test_completed_needs_a_response_status_and_only_dispatcher_outcomes_are_recorded(
    world: World,
):
    approval = await approved(world)
    await world.approvals.admit(approval.approval_id, REQUEST, "op-1")
    for outcome, status in (
        (DispatchOutcome.COMPLETED, None),
        (DispatchOutcome.NOT_SENT, "200"),
        (DispatchOutcome.RECONCILED_COMPLETED, None),
        (DispatchOutcome.DISPATCHING, None),
    ):
        assert (
            await refusal(
                world.approvals.record_outcome(
                    approval.approval_id, "op-1", outcome, response_status=status
                )
            )
            is Refusal.OUTCOME_INVALID
        )


async def test_not_sent_allows_a_transport_retry_under_the_same_operation(world: World):
    approval = await approved(world)
    await world.approvals.admit(approval.approval_id, REQUEST, "op-1")
    await world.approvals.record_outcome(approval.approval_id, "op-1", DispatchOutcome.NOT_SENT)
    retry = await world.approvals.admit(approval.approval_id, REQUEST, "op-1")
    assert retry.may_send and not retry.first
    assert retry.dispatch_outcome is DispatchOutcome.DISPATCHING
    assert await refusal(world.approvals.admit(approval.approval_id, REQUEST, "op-2")) is (
        Refusal.CONSUMED
    )
    await complete(world, approval)


async def test_a_dispatch_in_flight_is_not_sent_twice(world: World):
    approval = await approved(world)
    await world.approvals.admit(approval.approval_id, REQUEST, "op-1")
    again = await world.approvals.admit(approval.approval_id, REQUEST, "op-1")
    assert not again.may_send and again.dispatch_outcome is DispatchOutcome.DISPATCHING


async def test_an_unknown_outcome_blocks_new_dispatch_until_the_owner_reconciles(world: World):
    first = await approved(world)
    await world.approvals.admit(first.approval_id, REQUEST, "op-1")
    await world.approvals.record_outcome(first.approval_id, "op-1", DispatchOutcome.OUTCOME_UNKNOWN)
    assert not (await world.approvals.admit(first.approval_id, REQUEST, "op-1")).may_send
    fresh = await approved(world)
    assert await refusal(world.approvals.admit(fresh.approval_id, REQUEST, "op-2")) is (
        Refusal.UNRECONCILED_DISPATCH
    )
    assert (
        await refusal(
            world.approvals.reconcile(
                first.approval_id, "op-1", DispatchOutcome.COMPLETED, reconciled_by="owner-1"
            )
        )
        is Refusal.OUTCOME_INVALID
    )
    reconciled = await world.approvals.reconcile(
        first.approval_id, "op-1", DispatchOutcome.RECONCILED_FAILED, reconciled_by="owner-1"
    )
    assert reconciled.dispatch_outcome is DispatchOutcome.RECONCILED_FAILED
    assert (await world.audit.rows())[-1]["actor"] == "owner-1"
    assert (await world.approvals.admit(fresh.approval_id, REQUEST, "op-2")).first


async def test_a_dispatch_with_no_recorded_outcome_also_blocks(world: World):
    first = await approved(world)
    await world.approvals.admit(first.approval_id, REQUEST, "op-1")
    fresh = await approved(world)
    assert await refusal(world.approvals.admit(fresh.approval_id, REQUEST, "op-2")) is (
        Refusal.UNRECONCILED_DISPATCH
    )
    await world.approvals.reconcile(
        first.approval_id, "op-1", DispatchOutcome.RECONCILED_UNKNOWN, reconciled_by="owner-1"
    )
    assert (await world.approvals.admit(fresh.approval_id, REQUEST, "op-2")).first


async def test_not_sent_and_completed_do_not_block_other_approvals(world: World):
    first = await approved(world)
    await world.approvals.admit(first.approval_id, REQUEST, "op-1")
    await world.approvals.record_outcome(first.approval_id, "op-1", DispatchOutcome.NOT_SENT)
    second = await approved(world)
    assert (await world.approvals.admit(second.approval_id, REQUEST, "op-2")).first
    await complete(world, second, "op-2")
    third = await approved(world)
    assert (await world.approvals.admit(third.approval_id, REQUEST, "op-3")).first


async def test_a_retry_after_not_sent_waits_for_another_unreconciled_dispatch(world: World):
    first = await approved(world)
    await world.approvals.admit(first.approval_id, REQUEST, "op-1")
    await world.approvals.record_outcome(first.approval_id, "op-1", DispatchOutcome.NOT_SENT)
    second = await approved(world)
    await world.approvals.admit(second.approval_id, REQUEST, "op-2")
    assert await refusal(world.approvals.admit(first.approval_id, REQUEST, "op-1")) is (
        Refusal.UNRECONCILED_DISPATCH
    )


async def test_an_unreconciled_dispatch_does_not_block_other_requests(world: World):
    first = await approved(world)
    await world.approvals.admit(first.approval_id, REQUEST, "op-1")
    other_request = {**REQUEST, "constraints": {"max_amount_cents": 100}}
    other = await approved(world, other_request)
    assert (await world.approvals.admit(other.approval_id, other_request, "op-2")).first


async def test_no_outcome_rearms_the_approval(world: World):
    approval = await approved(world)
    await world.approvals.admit(approval.approval_id, REQUEST, "op-1")
    await world.approvals.record_outcome(
        approval.approval_id, "op-1", DispatchOutcome.OUTCOME_UNKNOWN
    )
    await world.approvals.reconcile(
        approval.approval_id, "op-1", DispatchOutcome.RECONCILED_FAILED, reconciled_by="owner-1"
    )
    assert await refusal(world.approvals.admit(approval.approval_id, REQUEST, "op-2")) is (
        Refusal.CONSUMED
    )
    assert not (await world.approvals.admit(approval.approval_id, REQUEST, "op-1")).may_send
    fresh = await approved(world)
    assert (await world.approvals.admit(fresh.approval_id, REQUEST, "op-2")).first


async def test_a_final_outcome_stays_final(world: World):
    approval = await approved(world)
    await world.approvals.admit(approval.approval_id, REQUEST, "op-1")
    assert await refusal(complete(world, approval, operation_id="op-other")) is (
        Refusal.OPERATION_MISMATCH
    )
    await complete(world, approval)
    await complete(world, approval)
    assert (
        await refusal(
            world.approvals.record_outcome(
                approval.approval_id, "op-1", DispatchOutcome.OUTCOME_UNKNOWN
            )
        )
        is Refusal.OUTCOME_FINAL
    )
    assert (
        await refusal(
            world.approvals.reconcile(
                approval.approval_id,
                "op-1",
                DispatchOutcome.RECONCILED_FAILED,
                reconciled_by="owner-1",
            )
        )
        is Refusal.OUTCOME_FINAL
    )
    view = await world.approvals.requester_view(approval.request_ref, "agent-1")
    assert view.approval_state is ApprovalState.CONSUMED
    assert view.dispatch_outcome is DispatchOutcome.COMPLETED


async def test_revoking_after_consumption_is_refused(world: World):
    approval = await approved(world)
    await world.approvals.admit(approval.approval_id, REQUEST, "op-1")
    assert await refusal(world.approvals.revoke(approval.approval_id, revoked_by="owner-1")) is (
        Refusal.CONSUMED
    )


# Concurrency


async def test_parallel_consumers_admit_exactly_one_dispatch(world: World):
    approval = await approved(world)
    results = await asyncio.gather(
        *(world.approvals.admit(approval.approval_id, REQUEST, f"op-{i}") for i in range(24)),
        return_exceptions=True,
    )
    admitted = [r for r in results if not isinstance(r, Exception)]
    refused = [r for r in results if isinstance(r, ApprovalRefused)]
    assert len(admitted) == 1 and admitted[0].first
    assert len(refused) == 23 and {r.reason for r in refused} == {Refusal.CONSUMED}


async def test_parallel_approvals_of_the_same_request_admit_one_dispatch(world: World):
    approvals = [await approved(world) for _ in range(6)]
    results = await asyncio.gather(
        *(
            world.approvals.admit(a.approval_id, REQUEST, f"op-{i}")
            for i, a in enumerate(approvals)
        ),
        return_exceptions=True,
    )
    admitted = [r for r in results if not isinstance(r, Exception)]
    refused = [r for r in results if isinstance(r, ApprovalRefused)]
    assert len(admitted) == 1
    assert {r.reason for r in refused} == {Refusal.UNRECONCILED_DISPATCH}


async def test_parallel_retries_of_one_operation_admit_it_once(world: World):
    approval = await approved(world)
    results = await asyncio.gather(
        *(world.approvals.admit(approval.approval_id, REQUEST, "op-1") for _ in range(12))
    )
    assert sum(r.first for r in results) == 1
    assert (await world.audit.kinds()).count("dispatch_admitted") == 1


async def test_parallel_decisions_record_exactly_one(world: World):
    _, approval = await mint(world)
    challenges = [await challenge(world, approval, d) for d in (Decision.APPROVE, Decision.REJECT)]
    results = await asyncio.gather(
        *(
            world.approvals.decide(
                approval.approval_id,
                d,
                Assurance.PASSKEY,
                sign(world.approver_key, APPROVER.subject, c),
                link_token=link_of(world, approval),
            )
            for d, c in zip((Decision.APPROVE, Decision.REJECT), challenges, strict=True)
        ),
        return_exceptions=True,
    )
    decided = [r for r in results if not isinstance(r, Exception)]
    refused = [r for r in results if isinstance(r, ApprovalRefused)]
    assert len(decided) == 1 and [r.reason for r in refused] == [Refusal.NOT_PENDING]
    assert (await world.audit.kinds()).count("approval_decided") == 1


async def test_an_admission_held_open_blocks_a_second_approval_of_the_same_request(world: World):
    first, second = await approved(world), await approved(world)
    async with world.store.db.transaction() as caller:
        await world.approvals.admit(first.approval_id, REQUEST, "op-1", tx=caller)
        competing = asyncio.create_task(world.approvals.admit(second.approval_id, REQUEST, "op-2"))
        await asyncio.sleep(0.3)
        assert not competing.done()
    assert await refusal(competing) is Refusal.UNRECONCILED_DISPATCH


# The caller's transaction


async def test_admission_in_a_rolled_back_caller_transaction_leaves_nothing(world: World):
    approval = await approved(world)
    before = await world.audit.kinds()
    with pytest.raises(RuntimeError):
        async with world.store.db.transaction() as caller:
            await world.approvals.admit(approval.approval_id, REQUEST, "op-1", tx=caller)
            raise RuntimeError("the caller's own write failed")
    assert (await world.approvals.get(approval.approval_id)).state is ApprovalState.APPROVED
    assert await world.audit.kinds() == before
    async with world.store.db.transaction() as caller:
        await world.approvals.admit(approval.approval_id, REQUEST, "op-1", tx=caller)
    assert (await world.approvals.get(approval.approval_id)).state is ApprovalState.CONSUMED
    assert (await world.audit.kinds())[-1] == "dispatch_admitted"


async def test_a_refused_admission_does_not_abort_the_caller_transaction(world: World):
    _, pending = await mint(world)
    approval = await approved(world, {**REQUEST, "source_version": 2})
    async with world.store.db.transaction() as caller:
        assert await refusal(
            world.approvals.admit(pending.approval_id, REQUEST, "op-0", tx=caller)
        ) is (Refusal.NOT_APPROVED)
        await world.approvals.admit(
            approval.approval_id, {**REQUEST, "source_version": 2}, "op-1", tx=caller
        )
    assert (await world.approvals.get(approval.approval_id)).state is ApprovalState.CONSUMED


# One-use links


async def test_the_link_is_used_once_by_the_decision(world: World):
    _, approval = await mint(world)
    token = link_of(world, approval)
    await decide(world, approval)
    assert await refusal(world.approvals.open_link(token)) is Refusal.LINK_UNAVAILABLE
    used = await world.store.db.fetch_value(
        "SELECT used_at FROM {{tables.approval_links}} WHERE approval_id = $1", approval.approval_id
    )
    assert used is not None


async def test_a_linked_approval_is_decided_only_through_its_own_link(world: World):
    _, approval = await mint(world)
    _, other = await mint(world)
    assert await refusal(decide(world, approval, link_token=None)) is Refusal.PRESENTATION_MISMATCH
    assert await refusal(decide(world, approval, link_token=link_of(world, other))) is (
        Refusal.LINK_UNAVAILABLE
    )
    assert (
        await refusal(
            world.approvals.challenge(approval.approval_id, Decision.APPROVE, Assurance.PASSKEY)
        )
        is Refusal.PRESENTATION_MISMATCH
    )


# Containment


async def test_revoke_many_revokes_only_the_live_approvals_it_names(world: World):
    pending = (await mint(world))[1]
    approved_one = await approved(world, {**REQUEST, "source_version": 2})
    consumed = await approved(world, {**REQUEST, "source_version": 3})
    await world.approvals.admit(consumed.approval_id, {**REQUEST, "source_version": 3}, "op-1")
    unnamed = (await mint(world, {**REQUEST, "source_version": 4}))[1]

    revoked = await world.approvals.revoke_many(
        [pending.approval_id, approved_one.approval_id, consumed.approval_id, "missing"],
        revoked_by="owner-1",
        reason="secret rotated",
    )

    assert {a.approval_id for a in revoked} == {pending.approval_id, approved_one.approval_id}
    states = {
        a.approval_id: (await world.approvals.get(a.approval_id)).state
        for a in (pending, approved_one, consumed, unnamed)
    }
    assert states == {
        pending.approval_id: ApprovalState.REVOKED,
        approved_one.approval_id: ApprovalState.REVOKED,
        consumed.approval_id: ApprovalState.CONSUMED,
        unnamed.approval_id: ApprovalState.PENDING,
    }
    assert await refusal(world.approvals.open_link(link_of(world, pending))) is (
        Refusal.LINK_UNAVAILABLE
    )
    assert (
        await refusal(
            world.approvals.admit(
                approved_one.approval_id, {**REQUEST, "source_version": 2}, "op-2"
            )
        )
        is Refusal.REVOKED
    )
    revocations = [row for row in await world.audit.rows() if row["kind"] == "approval_revoked"]
    assert len(revocations) == 2
    assert all(json.loads(row["details"])["reason"] == "secret rotated" for row in revocations)


async def test_revoke_many_in_a_rolled_back_caller_transaction_revokes_nothing(world: World):
    _, pending = await mint(world)
    with pytest.raises(RuntimeError):
        async with world.store.db.transaction() as caller:
            await world.approvals.revoke_many(
                [pending.approval_id], revoked_by="owner-1", tx=caller
            )
            raise RuntimeError("containment step failed")
    assert (await world.approvals.get(pending.approval_id)).state is ApprovalState.PENDING
    assert "approval_revoked" not in await world.audit.kinds()


# A retired approver


async def test_a_retired_approvers_pending_approval_cannot_be_decided(world: World):
    _, approval = await mint(world)
    issued = await challenge(world, approval)
    world.directory.approver = SUCCESSOR
    proof = sign(world.approver_key, APPROVER.subject, issued)
    assert (
        await refusal(
            world.approvals.decide(
                approval.approval_id,
                Decision.APPROVE,
                Assurance.PASSKEY,
                proof,
                link_token=link_of(world, approval),
            )
        )
        is Refusal.APPROVER_RETIRED
    )
    assert await refusal(challenge(world, approval)) is Refusal.APPROVER_RETIRED
    assert (await world.approvals.get(approval.approval_id)).state is ApprovalState.PENDING


async def test_a_retired_approvers_approval_is_not_admitted_and_keeps_its_history(world: World):
    approval = await approved(world)
    world.directory.approver = SUCCESSOR
    assert await refusal(world.approvals.admit(approval.approval_id, REQUEST, "op-1")) is (
        Refusal.APPROVER_RETIRED
    )
    record = await world.approvals.get(approval.approval_id)
    assert record.state is ApprovalState.APPROVED
    assert record.approver_subject == APPROVER.subject


async def test_retirement_stops_a_transport_retry_but_not_retrieval(world: World):
    other = {**REQUEST, "source_version": 2}
    unsent, sent = await approved(world), await approved(world, other)
    await world.approvals.admit(unsent.approval_id, REQUEST, "op-1")
    await world.approvals.record_outcome(unsent.approval_id, "op-1", DispatchOutcome.NOT_SENT)
    await world.approvals.admit(sent.approval_id, other, "op-2")
    world.directory.approver = SUCCESSOR
    assert await refusal(world.approvals.admit(unsent.approval_id, REQUEST, "op-1")) is (
        Refusal.APPROVER_RETIRED
    )
    retrieved = await world.approvals.admit(sent.approval_id, other, "op-2")
    assert not retrieved.first and not retrieved.may_send
    await world.approvals.record_outcome(
        sent.approval_id, "op-2", DispatchOutcome.COMPLETED, response_status="200"
    )


async def test_the_requester_view_is_only_for_the_requester(world: World):
    view, _ = await mint(world)
    assert (await world.approvals.requester_view(view.request_id, "agent-1")).request_id == (
        view.request_id
    )
    assert await refusal(world.approvals.requester_view(view.request_id, "agent-2")) is (
        Refusal.NOT_FOUND
    )


# Stopping a transport retry


async def not_sent(w: World):
    approval = await approved(w)
    await w.approvals.admit(approval.approval_id, REQUEST, "op-1")
    await w.approvals.record_outcome(approval.approval_id, "op-1", DispatchOutcome.NOT_SENT)
    return approval


async def test_a_not_sent_retry_is_refused_after_the_approval_expires(world: World):
    approval = await not_sent(world)
    world.clock.advance(timedelta(minutes=10))
    assert await refusal(world.approvals.admit(approval.approval_id, REQUEST, "op-1")) is (
        Refusal.EXPIRED
    )


async def test_revoking_a_not_sent_approval_stops_its_retry(world: World):
    approval = await not_sent(world)
    revoked = await world.approvals.revoke(approval.approval_id, revoked_by="owner-1")
    assert revoked.state is ApprovalState.CONSUMED and revoked.revoked_at is not None
    assert revoked.state_at(world.clock()) is ApprovalState.REVOKED
    assert await refusal(world.approvals.admit(approval.approval_id, REQUEST, "op-1")) is (
        Refusal.REVOKED
    )
    assert await refusal(world.approvals.revoke(approval.approval_id, revoked_by="owner-1")) is (
        Refusal.REVOKED
    )


async def test_revoke_many_stops_not_sent_retries_but_leaves_other_consumptions(world: World):
    stopped = await not_sent(world)
    other = {**REQUEST, "source_version": 2}
    dispatched = await approved(world, other)
    await world.approvals.admit(dispatched.approval_id, other, "op-2")
    revoked = await world.approvals.revoke_many(
        [stopped.approval_id, dispatched.approval_id], revoked_by="owner-1"
    )
    assert [a.approval_id for a in revoked] == [stopped.approval_id]
    assert await refusal(world.approvals.admit(stopped.approval_id, REQUEST, "op-1")) is (
        Refusal.REVOKED
    )
    assert (await world.approvals.get(dispatched.approval_id)).revoked_at is None


async def test_a_used_link_cannot_record_a_decision_even_through_the_store(world: World):
    _, approval = await mint(world)
    await decide(world, approval)
    link = await world.store.find_link(link_verifier(link_of(world, approval)))
    with pytest.raises(LinkAlreadyUsed):
        async with world.store.locked(approval.approval_id, None) as locked:
            await locked.set_decision(
                ApprovalState.REJECTED,
                Evidence(Assurance.PASSKEY, APPROVER.subject, "app_local", "e"),
                None,
                link.link_id,
                world.clock(),
            )
    assert (await world.approvals.get(approval.approval_id)).state is ApprovalState.APPROVED


# Task answers


async def task_approval(w: World):
    _, approval = await mint(w, presentation=PresentationKind.TASK, presentation_ref="task-1")
    return approval


async def test_a_task_decision_needs_its_task_answer_verified(world: World):
    approval = await task_approval(world)
    assert await refusal(decide(world, approval, task_answer_ref="unverified")) is (
        Refusal.TASK_ANSWER_UNVERIFIED
    )
    world.task_answers.record("answer-reject", approval, Decision.REJECT)
    assert await refusal(decide(world, approval, task_answer_ref="answer-reject")) is (
        Refusal.TASK_ANSWER_UNVERIFIED
    )
    _, other = await mint(
        world,
        {**REQUEST, "executor": "runner"},
        presentation=PresentationKind.TASK,
        presentation_ref="task-2",
    )
    world.task_answers.record("answer-other", other, Decision.APPROVE)
    assert await refusal(decide(world, approval, task_answer_ref="answer-other")) is (
        Refusal.TASK_ANSWER_UNVERIFIED
    )
    assert (await world.approvals.get(approval.approval_id)).state is ApprovalState.PENDING


async def test_an_authenticator_proof_is_bound_to_its_task_answer(world: World):
    approval = await task_approval(world)
    world.task_answers.record("answer-1", approval, Decision.APPROVE)
    world.task_answers.record("answer-2", approval, Decision.APPROVE)
    issued = await challenge(world, approval, task_answer_ref="answer-1")
    proof = sign(world.approver_key, APPROVER.subject, issued)
    assert (
        await refusal(
            world.approvals.decide(
                approval.approval_id,
                Decision.APPROVE,
                Assurance.PASSKEY,
                proof,
                task_answer_ref="answer-2",
            )
        )
        is Refusal.AUTHENTICATION_FAILED
    )
    assert (await world.approvals.get(approval.approval_id)).state is ApprovalState.PENDING


async def test_task_presentation_needs_an_app_that_verifies_task_answers(world: World):
    approvals = Approvals(
        store=world.store,
        policies=world.policies,
        approvers=world.directory,
        delivery=world.mailbox,
        authenticators=[world.passkey],
        audit=world.audit,
        clock=world.clock,
    )
    with pytest.raises(ApprovalRefused) as raised:
        await approvals.mint(
            request=REQUEST,
            policy_ref="send-charge",
            requested_by="agent-1",
            presentation=PresentationKind.TASK,
            presentation_ref="task-1",
        )
    assert raised.value.reason is Refusal.PRESENTATION_UNSUPPORTED


# Viewing the request behind a link


async def test_a_passkey_policy_shows_the_request_only_after_a_view_assertion(world: World):
    _, approval = await mint(world)
    token = link_of(world, approval)
    assert (await world.approvals.open_link(token)).request is None
    issued = await world.approvals.view_challenge(
        approval.approval_id, Assurance.PASSKEY, link_token=token
    )
    viewed = await world.approvals.view(
        approval.approval_id,
        Assurance.PASSKEY,
        sign(world.approver_key, APPROVER.subject, issued),
        link_token=token,
    )
    assert viewed.request == REQUEST
    assert viewed.approval.state is ApprovalState.PENDING
    assert (await decide(world, approval)).state is ApprovalState.APPROVED


async def test_a_view_assertion_cannot_decide(world: World):
    _, approval = await mint(world)
    token = link_of(world, approval)
    issued = await world.approvals.view_challenge(
        approval.approval_id, Assurance.PASSKEY, link_token=token
    )
    proof = sign(world.approver_key, APPROVER.subject, issued)
    assert (
        await refusal(
            world.approvals.decide(
                approval.approval_id, Decision.APPROVE, Assurance.PASSKEY, proof, link_token=token
            )
        )
        is Refusal.AUTHENTICATION_FAILED
    )


async def test_only_the_approver_can_view(world: World):
    _, approval = await mint(world)
    token = link_of(world, approval)
    intruder = world.passkey.register("someone-else")
    issued = await world.approvals.view_challenge(
        approval.approval_id, Assurance.PASSKEY, link_token=token
    )
    assert (
        await refusal(
            world.approvals.view(
                approval.approval_id,
                Assurance.PASSKEY,
                sign(intruder, "someone-else", issued),
                link_token=token,
            )
        )
        is Refusal.APPROVER_MISMATCH
    )


async def test_link_possession_reveals_the_request_when_the_policy_allows_it(world: World):
    _, internal = await mint(world, policy_ref="internal-edit")
    assert (await world.approvals.open_link(link_of(world, internal))).request == REQUEST
    world.policies.set(policy(policy_ref="open-passkey", link_reveals_request=True))
    _, revealed = await mint(world, policy_ref="open-passkey")
    assert (await world.approvals.open_link(link_of(world, revealed))).request == REQUEST
