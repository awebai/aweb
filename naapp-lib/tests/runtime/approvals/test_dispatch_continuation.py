"""The one safe repeat of an outcome_unknown approved dispatch, over real B2 and S3."""

from __future__ import annotations

import asyncio
import uuid
from datetime import timedelta
from uuid import UUID

import pytest
from pgdbm.core import TransactionManager

from aweb_naapp.dispatch import (
    Dispatch,
    Dispatches,
    InvalidTransition,
    RepeatClaimed,
    State,
    apply_dispatch_migrations,
)
from aweb_naapp.runtime.approvals import ApprovalRefused, DispatchOutcome, Refusal
from tests.runtime.approvals.test_approvals import REQUEST, decide, mint, refusal
from tests.runtime.approvals.test_dispatch_fence import admitted, authority, held_locks, rows

SUBJECT = "did:aw:agent-1"
ACTION = "credential-1:create-refund"


async def _no_transition(tx, transition) -> None:
    pass


@pytest.fixture
async def machine(world) -> Dispatches:
    await apply_dispatch_migrations(world.store.db)
    return Dispatches(
        on_transition=_no_transition,
        max_dispatch=timedelta(seconds=30),
        sweep_margin=timedelta(seconds=30),
    )


class ApprovalFence:
    """The app's S3 fence over one prepared B2 handle: check runs B2's final check."""

    def __init__(self, approvals, prepared) -> None:
        self.approvals = approvals
        self.prepared = prepared

    async def prepare(self, tx: TransactionManager) -> None:
        pass

    async def check(self, tx: TransactionManager, dispatch: Dispatch) -> None:
        await self.approvals.check_dispatch(tx, self.prepared)


class NoFence:
    async def prepare(self, tx: TransactionManager) -> None:
        pass

    async def check(self, tx: TransactionManager, dispatch: Dispatch) -> None:
        pass


async def unknown_original(world, machine: Dispatches, action: str = ACTION):
    """An approved, consumed dispatch whose outcome both B2 and S3 hold unknown."""
    _, pending = await mint(world)
    approval = await decide(world, pending)
    original = uuid.uuid4()
    async with world.store.db.transaction() as tx:
        await machine.create(tx, dispatch_id=original, subject=SUBJECT, action=action)
        assert (
            await world.approvals.admit(approval.approval_id, REQUEST, str(original), tx=tx)
        ).may_send
        await machine.admit(tx, original, fence=NoFence())
        await machine.begin_dispatch(tx, original, fence=NoFence())
    async with world.store.db.transaction() as tx:
        await world.approvals.record_outcome(
            approval.approval_id, str(original), DispatchOutcome.OUTCOME_UNKNOWN, tx=tx
        )
        await machine.outcome_unknown(tx, original, {"error": "reset"})
    return approval, original


async def publish_repeat(world, machine, approval, original: UUID, source) -> UUID:
    """Claim, admit and begin the repeat in one transaction, B2 before S3."""
    repeat = uuid.uuid4()
    async with world.store.db.transaction() as tx:
        prepared = await world.approvals.prepare_continuation(
            tx, approval.approval_id, REQUEST, str(original), authority=source
        )
        fence = ApprovalFence(world.approvals, prepared)
        await machine.continue_dispatch(tx, original, dispatch_id=repeat, fence=fence)
        await machine.admit(tx, repeat, fence=fence)
        await machine.begin_dispatch(tx, repeat, fence=fence)
    return repeat


class _OutcomeMoved(Exception):
    pass


async def resolve(world, machine, approval, original, repeat, state: State, result) -> bool:
    """The caller's resolution of a definite repeat: B2 rows and requests before S3.

    Returns False when the owner (or the sweep) settled first; the repeat's own
    result is then recorded alone and the winning settlement is kept.
    """
    async with world.store.db.transaction() as tx:
        await world.approvals.lock_many(tx, [approval.approval_id])
        try:
            async with tx.transaction() as attempt:
                await world.approvals.reconcile(
                    approval.approval_id,
                    str(original),
                    DispatchOutcome(state.value),
                    reconciled_by=approval.requested_by,
                    tx=attempt,
                )
                if not await machine.complete(attempt, repeat, result):
                    raise _OutcomeMoved
                if await machine.resolve_original(attempt, repeat, state, result) is None:
                    raise _OutcomeMoved
                return True
        except ApprovalRefused as exc:
            if exc.reason is not Refusal.OUTCOME_FINAL:
                raise
        except _OutcomeMoved:
            pass
        await machine.complete(tx, repeat, result)
        return False


async def owner_settles(world, machine, approval, original, state: State) -> None:
    async with world.store.db.transaction() as tx:
        await world.approvals.lock_many(tx, [approval.approval_id])
        await world.approvals.reconcile(
            approval.approval_id,
            str(original),
            DispatchOutcome(state.value),
            reconciled_by="owner",
            tx=tx,
        )
        await machine.reconcile(tx, original, state, {"by": "owner"})


async def _after(delay: float, awaitable):
    await asyncio.sleep(delay)
    return await awaitable


async def approval_outcome(world, approval) -> DispatchOutcome:
    current = await world.approvals.get(approval.approval_id)
    assert current is not None
    return current.dispatch_outcome


# B2: the continuation handle


async def test_continuation_check_passes_for_the_unknown_original_without_writing(world, machine):
    approval, original = await unknown_original(world, machine)
    source = await authority(world)
    async with world.store.db.transaction() as tx:
        before = await rows(world, tx)
        prepared = await world.approvals.prepare_continuation(
            tx, approval.approval_id, REQUEST, str(original), authority=source
        )
        assert prepared.expires_at == approval.expires_at
        locks = await held_locks(tx)
        for _ in range(2):
            await world.approvals.check_dispatch(tx, prepared)
        assert await held_locks(tx) == locks
        assert await rows(world, tx) == before
    assert await approval_outcome(world, approval) is DispatchOutcome.OUTCOME_UNKNOWN


@pytest.mark.parametrize(
    "outcome", [o for o in DispatchOutcome if o is not DispatchOutcome.OUTCOME_UNKNOWN]
)
async def test_continuation_takes_only_an_unknown_original(world, outcome):
    a = await admitted(world)
    source = await authority(world)
    if outcome in (DispatchOutcome.COMPLETED, DispatchOutcome.NOT_SENT):
        await world.approvals.record_outcome(
            a.approval_id,
            "op-1",
            outcome,
            response_status="200" if outcome is DispatchOutcome.COMPLETED else None,
        )
    elif outcome is not DispatchOutcome.DISPATCHING:
        await world.approvals.reconcile(a.approval_id, "op-1", outcome, reconciled_by="owner")
    async with world.store.db.transaction() as tx:
        assert (
            await refusal(
                world.approvals.prepare_continuation(
                    tx, a.approval_id, REQUEST, "op-1", authority=source
                )
            )
            is Refusal.OUTCOME_INVALID
        )


async def test_a_settlement_after_preparation_refuses_the_continuation(world, machine):
    approval, original = await unknown_original(world, machine)
    source = await authority(world)
    async with world.store.db.transaction() as tx:
        prepared = await world.approvals.prepare_continuation(
            tx, approval.approval_id, REQUEST, str(original), authority=source
        )
        await world.approvals.reconcile(
            approval.approval_id,
            str(original),
            DispatchOutcome.RECONCILED_UNKNOWN,
            reconciled_by="owner",
            tx=tx,
        )
        assert (
            await refusal(world.approvals.check_dispatch(tx, prepared)) is Refusal.OUTCOME_INVALID
        )


@pytest.mark.parametrize("change", ["expiry", "policy", "retire", "missing_policy"])
async def test_continuation_keeps_every_exact_original_check(world, machine, change):
    approval, original = await unknown_original(world, machine)
    source = await authority(world)
    expected = {
        "expiry": Refusal.EXPIRED,
        "policy": Refusal.POLICY_CHANGED,
        "retire": Refusal.APPROVER_RETIRED,
        "missing_policy": Refusal.POLICY_UNKNOWN,
    }[change]
    if change == "expiry":
        world.clock.advance(timedelta(minutes=11))
    else:
        async with world.store.db.transaction() as other:
            if change == "policy":
                await other.execute("UPDATE {{tables.dispatch_authority}} SET version=2")
            elif change == "retire":
                await other.execute(
                    "UPDATE {{tables.dispatch_authority}} SET current_decider=false"
                )
            else:
                await other.execute("DELETE FROM {{tables.dispatch_authority}}")
    async with world.store.db.transaction() as tx:
        prepared = await world.approvals.prepare_continuation(
            tx, approval.approval_id, REQUEST, str(original), authority=source
        )
        assert await refusal(world.approvals.check_dispatch(tx, prepared)) is expected


@pytest.mark.parametrize("wrong", ["request", "operation"])
async def test_continuation_binds_the_original_request_and_operation(world, machine, wrong):
    approval, original = await unknown_original(world, machine)
    source = await authority(world)
    async with world.store.db.transaction() as tx:
        assert await refusal(
            world.approvals.prepare_continuation(
                tx,
                approval.approval_id,
                {**REQUEST, "source_version": 2} if wrong == "request" else REQUEST,
                str(uuid.uuid4()) if wrong == "operation" else str(original),
                authority=source,
            )
        ) is (Refusal.REQUEST_MISMATCH if wrong == "request" else Refusal.OPERATION_MISMATCH)


# B2 and S3 composed by the caller


async def test_a_refused_b2_check_leaves_no_repeat_claim(world, machine):
    approval, original = await unknown_original(world, machine)
    source = await authority(world)
    world.clock.advance(timedelta(minutes=11))
    with pytest.raises(ApprovalRefused):
        await publish_repeat(world, machine, approval, original, source)
    assert not await world.store.db.fetch_value(
        "SELECT count(*) FROM {{tables.dispatches}} WHERE continues = $1", original
    )


@pytest.mark.parametrize("state", [State.RECONCILED_COMPLETED, State.RECONCILED_FAILED])
async def test_a_definite_repeat_settles_the_original_in_b2_and_s3(world, machine, state):
    approval, original = await unknown_original(world, machine)
    source = await authority(world)
    async with world.store.db.transaction() as tx:
        before = await rows(world, tx)
    repeat = await publish_repeat(world, machine, approval, original, source)
    async with world.store.db.transaction() as tx:
        # Publication writes nothing in B2: no admission, audit or rearm.
        assert await rows(world, tx) == before
    assert await resolve(world, machine, approval, original, repeat, state, {"status": 201})
    assert await approval_outcome(world, approval) is DispatchOutcome(state.value)
    async with world.store.db.transaction() as tx:
        assert (await machine.get(tx, original)).state is state
        assert (await machine.get(tx, repeat)).state is State.COMPLETED
    settled = (await world.audit.rows())[-1]
    assert (settled["kind"], settled["actor"]) == ("dispatch_outcome", approval.requested_by)


@pytest.mark.parametrize("owner_state", [State.RECONCILED_COMPLETED, State.RECONCILED_FAILED])
async def test_an_owner_settlement_that_won_is_kept(world, machine, owner_state):
    approval, original = await unknown_original(world, machine)
    source = await authority(world)
    repeat = await publish_repeat(world, machine, approval, original, source)
    await owner_settles(world, machine, approval, original, owner_state)
    # Same outcome: B2 is idempotent and S3 reports the owner won. Different
    # outcome: B2 refuses OUTCOME_FINAL before any S3 lock.
    assert not await resolve(
        world, machine, approval, original, repeat, State.RECONCILED_COMPLETED, {"status": 200}
    )
    assert await approval_outcome(world, approval) is DispatchOutcome(owner_state.value)
    async with world.store.db.transaction() as tx:
        settled = await machine.get(tx, original)
        assert (settled.state, settled.result) == (owner_state, {"by": "owner"})
        continued = await machine.get(tx, repeat)
        assert (continued.state, continued.result) == (State.COMPLETED, {"status": 200})


@pytest.mark.parametrize("claimed", [False, True])
async def test_a_repeat_cannot_publish_after_the_owner_settled(world, machine, claimed):
    approval, original = await unknown_original(world, machine)
    source = await authority(world)
    repeat = uuid.uuid4()
    if claimed:
        # A claim left received by a crash, before the owner settles.
        async with world.store.db.transaction() as tx:
            await machine.continue_dispatch(tx, original, dispatch_id=repeat, fence=NoFence())
    await owner_settles(world, machine, approval, original, State.RECONCILED_UNKNOWN)
    async with world.store.db.transaction() as tx:
        assert (
            await refusal(
                world.approvals.prepare_continuation(
                    tx, approval.approval_id, REQUEST, str(original), authority=source
                )
            )
            is Refusal.OUTCOME_INVALID
        )
    if claimed:
        with pytest.raises(InvalidTransition):
            async with world.store.db.transaction() as tx:
                await machine.admit(tx, repeat, fence=NoFence())
    else:
        with pytest.raises(InvalidTransition):
            async with world.store.db.transaction() as tx:
                await machine.continue_dispatch(tx, original, dispatch_id=repeat, fence=NoFence())


async def test_resolution_owner_settlement_and_claims_never_deadlock(world, machine):
    source = await authority(world)
    for round_number in range(5):
        approval, original = await unknown_original(world, machine, f"{ACTION}:{round_number}")
        repeat = await publish_repeat(world, machine, approval, original, source)

        results = await asyncio.gather(
            resolve(world, machine, approval, original, repeat, State.RECONCILED_COMPLETED, {}),
            _after(
                0.01, owner_settles(world, machine, approval, original, State.RECONCILED_FAILED)
            ),
            _after(0.005, publish_repeat(world, machine, approval, original, source)),
            return_exceptions=True,
        )
        assert isinstance(results[0], bool), results
        assert results[1] is None or (
            isinstance(results[1], ApprovalRefused) and results[1].reason is Refusal.OUTCOME_FINAL
        ), results
        assert isinstance(results[2], RepeatClaimed | ApprovalRefused), results
        assert (await approval_outcome(world, approval)) in (
            DispatchOutcome.RECONCILED_COMPLETED,
            DispatchOutcome.RECONCILED_FAILED,
        )
