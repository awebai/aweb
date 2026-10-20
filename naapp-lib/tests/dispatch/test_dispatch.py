"""The shared dispatch state machine on real PostgreSQL."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from datetime import timedelta
from uuid import UUID

import pytest
from pgdbm import AsyncDatabaseManager
from pgdbm.core import TransactionManager

from aweb_naapp.dispatch import (
    Dispatch,
    Dispatches,
    InvalidTransition,
    ReconciliationPending,
    State,
    Transition,
    apply_dispatch_migrations,
)

SUBJECT = "did:aw:member"
ACTION = "credential-1:create-refund"


class Recorder:
    """Records every transition, and fails the one named in ``fail_on``."""

    def __init__(self) -> None:
        self.transitions: list[Transition] = []
        self.fail_on: State | None = None

    async def __call__(self, tx: TransactionManager, transition: Transition) -> None:
        if transition.to_state is self.fail_on:
            raise EnqueueFailed(transition.to_state)
        await tx.execute("SELECT 1")
        self.transitions.append(transition)

    def states(self, dispatch_id: UUID) -> list[State]:
        return [t.to_state for t in self.transitions if t.dispatch_id == dispatch_id]


class EnqueueFailed(Exception):
    pass


class FenceRefused(Exception):
    pass


@pytest.fixture
async def db(test_db_factory) -> AsyncIterator[AsyncDatabaseManager]:
    database = await test_db_factory.create_db(suffix="naapp_dispatch")
    await apply_dispatch_migrations(database)
    yield database


@pytest.fixture
def recorder() -> Recorder:
    return Recorder()


@pytest.fixture
def machine(recorder: Recorder) -> Dispatches:
    return Dispatches(
        on_transition=recorder,
        max_dispatch=timedelta(seconds=30),
        sweep_margin=timedelta(seconds=30),
    )


async def no_fence(tx: TransactionManager, dispatch: Dispatch) -> None:
    return None


async def _admitted(
    db: AsyncDatabaseManager,
    machine: Dispatches,
    *,
    subject: str = SUBJECT,
    action: str = ACTION,
    retry_exempt: bool = False,
) -> UUID:
    dispatch_id = uuid.uuid4()
    async with db.transaction() as tx:
        await machine.create(
            tx, dispatch_id=dispatch_id, subject=subject, action=action, retry_exempt=retry_exempt
        )
        await machine.admit(tx, dispatch_id)
    return dispatch_id


async def _dispatching(db: AsyncDatabaseManager, machine: Dispatches, **kwargs) -> UUID:
    dispatch_id = await _admitted(db, machine, **kwargs)
    async with db.transaction() as tx:
        await machine.begin_dispatch(tx, dispatch_id, fence=no_fence)
    return dispatch_id


async def _state(db: AsyncDatabaseManager, machine: Dispatches, dispatch_id: UUID) -> Dispatch:
    async with db.transaction() as tx:
        return await machine.get(tx, dispatch_id)


async def test_a_dispatch_runs_from_received_to_completed(
    db: AsyncDatabaseManager, machine: Dispatches, recorder: Recorder
) -> None:
    dispatch_id = await _dispatching(db, machine)
    async with db.transaction() as tx:
        assert await machine.complete(tx, dispatch_id, {"status": 201}) is True
    dispatch = await _state(db, machine, dispatch_id)
    assert (dispatch.state, dispatch.result) == (State.COMPLETED, {"status": 201})
    assert recorder.states(dispatch_id) == [
        State.RECEIVED,
        State.ADMITTED,
        State.DISPATCHING,
        State.COMPLETED,
    ]
    assert [t.from_state for t in recorder.transitions] == [
        None,
        State.RECEIVED,
        State.ADMITTED,
        State.DISPATCHING,
    ]


async def test_approval_states(db: AsyncDatabaseManager, machine: Dispatches) -> None:
    for closing in (State.APPROVAL_DENIED, State.APPROVAL_EXPIRED, State.CANCELLED):
        dispatch_id = uuid.uuid4()
        async with db.transaction() as tx:
            await machine.create(tx, dispatch_id=dispatch_id, subject=SUBJECT, action=ACTION)
            await machine.await_approval(tx, dispatch_id)
            await machine.close(tx, dispatch_id, closing)
        assert (await _state(db, machine, dispatch_id)).state is closing
    approved = uuid.uuid4()
    async with db.transaction() as tx:
        await machine.create(tx, dispatch_id=approved, subject=SUBJECT, action=ACTION)
        await machine.await_approval(tx, approved)
        await machine.admit(tx, approved)
    assert (await _state(db, machine, approved)).state is State.ADMITTED


async def test_a_crash_after_dispatching_is_swept_to_outcome_unknown(
    db: AsyncDatabaseManager, recorder: Recorder
) -> None:
    machine = Dispatches(
        on_transition=recorder,
        max_dispatch=timedelta(milliseconds=200),
        sweep_margin=timedelta(milliseconds=100),
    )
    dispatch_id = await _dispatching(db, machine)
    await asyncio.sleep(0.5)
    assert await machine.sweep(db) == 1
    assert (await _state(db, machine, dispatch_id)).state is State.OUTCOME_UNKNOWN
    assert recorder.states(dispatch_id)[-1] is State.OUTCOME_UNKNOWN
    assert await machine.sweep(db) == 0


async def test_a_dispatch_within_its_time_bound_is_never_swept(
    db: AsyncDatabaseManager, machine: Dispatches
) -> None:
    dispatch_id = await _dispatching(db, machine)
    assert await machine.sweep(db) == 0
    assert (await _state(db, machine, dispatch_id)).state is State.DISPATCHING


async def test_the_sweep_threshold_covers_the_dispatch_time_plus_the_margin(
    db: AsyncDatabaseManager, recorder: Recorder
) -> None:
    machine = Dispatches(
        on_transition=recorder,
        max_dispatch=timedelta(milliseconds=300),
        sweep_margin=timedelta(milliseconds=300),
    )
    dispatch_id = await _dispatching(db, machine)
    await asyncio.sleep(0.4)
    assert await machine.sweep(db) == 0
    assert (await _state(db, machine, dispatch_id)).state is State.DISPATCHING


@pytest.mark.parametrize("late", ["complete", "not_sent"])
async def test_a_late_result_after_the_sweep_is_kept_as_evidence(
    db: AsyncDatabaseManager, recorder: Recorder, late: str
) -> None:
    machine = Dispatches(
        on_transition=recorder,
        max_dispatch=timedelta(milliseconds=100),
        sweep_margin=timedelta(milliseconds=100),
    )
    dispatch_id = await _dispatching(db, machine)
    await asyncio.sleep(0.3)
    await machine.sweep(db)
    async with db.transaction() as tx:
        assert await getattr(machine, late)(tx, dispatch_id, {"status": 200}) is False
    dispatch = await _state(db, machine, dispatch_id)
    assert dispatch.state is State.OUTCOME_UNKNOWN
    assert dispatch.result is None
    assert dispatch.late_results == [{"status": 200}]
    assert recorder.states(dispatch_id)[-1] is State.OUTCOME_UNKNOWN


async def test_a_not_sent_retry_keeps_the_dispatch_id(
    db: AsyncDatabaseManager, machine: Dispatches, recorder: Recorder
) -> None:
    dispatch_id = await _dispatching(db, machine)
    async with db.transaction() as tx:
        assert await machine.not_sent(tx, dispatch_id, {"error": "connect"}) is True
    async with db.transaction() as tx:
        await machine.begin_dispatch(tx, dispatch_id, fence=no_fence)
        await machine.complete(tx, dispatch_id, {"status": 200})
    dispatch = await _state(db, machine, dispatch_id)
    assert (dispatch.state, dispatch.attempts) == (State.COMPLETED, 2)
    assert recorder.states(dispatch_id)[2:] == [
        State.DISPATCHING,
        State.NOT_SENT,
        State.DISPATCHING,
        State.COMPLETED,
    ]


@pytest.mark.parametrize(
    "failing", [State.RECEIVED, State.ADMITTED, State.DISPATCHING, State.COMPLETED]
)
async def test_a_failing_enqueue_leaves_the_previous_state(
    db: AsyncDatabaseManager, machine: Dispatches, recorder: Recorder, failing: State
) -> None:
    dispatch_id = uuid.uuid4()
    steps = [
        lambda tx: machine.create(tx, dispatch_id=dispatch_id, subject=SUBJECT, action=ACTION),
        lambda tx: machine.admit(tx, dispatch_id),
        lambda tx: machine.begin_dispatch(tx, dispatch_id, fence=no_fence),
        lambda tx: machine.complete(tx, dispatch_id, {"status": 200}),
    ]
    order = [State.RECEIVED, State.ADMITTED, State.DISPATCHING, State.COMPLETED]
    recorder.fail_on = failing
    for state, step in zip(order, steps, strict=True):
        if state is failing:
            with pytest.raises(EnqueueFailed):
                async with db.transaction() as tx:
                    await step(tx)
            break
        async with db.transaction() as tx:
            await step(tx)
    previous = order.index(failing) - 1
    async with db.transaction() as tx:
        if previous < 0:
            assert await machine.find(tx, dispatch_id) is None
        else:
            assert (await machine.get(tx, dispatch_id)).state is order[previous]


async def test_a_failing_fence_refuses_before_dispatching(
    db: AsyncDatabaseManager, machine: Dispatches, recorder: Recorder
) -> None:
    dispatch_id = await _admitted(db, machine)

    async def fence(tx: TransactionManager, dispatch: Dispatch) -> None:
        assert dispatch.state is State.ADMITTED
        raise FenceRefused

    with pytest.raises(FenceRefused):
        async with db.transaction() as tx:
            await machine.begin_dispatch(tx, dispatch_id, fence=fence)
    assert (await _state(db, machine, dispatch_id)).state is State.ADMITTED
    assert State.DISPATCHING not in recorder.states(dispatch_id)
    async with db.transaction() as tx:
        await machine.refuse(tx, dispatch_id)
    assert (await _state(db, machine, dispatch_id)).state is State.REFUSED


async def test_the_fence_holds_the_row_lock_until_dispatching_commits(
    db: AsyncDatabaseManager, machine: Dispatches
) -> None:
    dispatch_id = await _admitted(db, machine)
    fence_entered = asyncio.Event()

    async def slow_fence(tx: TransactionManager, dispatch: Dispatch) -> None:
        fence_entered.set()
        await asyncio.sleep(0.3)

    async def dispatcher() -> None:
        async with db.transaction() as tx:
            await machine.begin_dispatch(tx, dispatch_id, fence=slow_fence)

    async def canceller() -> None:
        await fence_entered.wait()
        async with db.transaction() as tx:
            await machine.close(tx, dispatch_id, State.CANCELLED)

    results = await asyncio.gather(dispatcher(), canceller(), return_exceptions=True)
    assert results[0] is None
    assert isinstance(results[1], InvalidTransition)
    assert (await _state(db, machine, dispatch_id)).state is State.DISPATCHING


async def test_a_cancel_committed_before_the_fence_stops_the_dispatch(
    db: AsyncDatabaseManager, machine: Dispatches
) -> None:
    dispatch_id = await _admitted(db, machine)
    async with db.transaction() as tx:
        await machine.close(tx, dispatch_id, State.CANCELLED)
    with pytest.raises(InvalidTransition):
        async with db.transaction() as tx:
            await machine.begin_dispatch(tx, dispatch_id, fence=no_fence)
    assert (await _state(db, machine, dispatch_id)).state is State.CANCELLED


async def _unknown(db: AsyncDatabaseManager, recorder: Recorder, **kwargs) -> UUID:
    quick = Dispatches(
        on_transition=recorder,
        max_dispatch=timedelta(milliseconds=50),
        sweep_margin=timedelta(milliseconds=50),
    )
    dispatch_id = await _dispatching(db, quick, **kwargs)
    await asyncio.sleep(0.2)
    await quick.sweep(db)
    return dispatch_id


async def test_an_unreconciled_outcome_blocks_the_same_subject_and_action(
    db: AsyncDatabaseManager, machine: Dispatches, recorder: Recorder
) -> None:
    unknown = await _unknown(db, recorder)
    blocked = uuid.uuid4()
    async with db.transaction() as tx:
        await machine.create(tx, dispatch_id=blocked, subject=SUBJECT, action=ACTION)
    with pytest.raises(ReconciliationPending) as pending:
        async with db.transaction() as tx:
            await machine.admit(tx, blocked)
    assert pending.value.code == "reconciliation_pending"
    await _admitted(db, machine, subject="did:aw:other")
    await _admitted(db, machine, action="credential-1:list-charges")

    async with db.transaction() as tx:
        await machine.reconcile(tx, unknown, State.RECONCILED_FAILED, {"by": "owner"})
        await machine.admit(tx, blocked)
    assert (await _state(db, machine, blocked)).state is State.ADMITTED
    assert (await _state(db, machine, unknown)).result == {"by": "owner"}


async def test_a_declared_exemption_does_not_block(
    db: AsyncDatabaseManager, machine: Dispatches, recorder: Recorder
) -> None:
    await _unknown(db, recorder, retry_exempt=True)
    await _admitted(db, machine, retry_exempt=True)


@pytest.mark.parametrize(
    "step",
    [
        lambda m, tx, i: m.complete(tx, i, {}),
        lambda m, tx, i: m.not_sent(tx, i, {}),
        lambda m, tx, i: m.reconcile(tx, i, State.RECONCILED_COMPLETED, {}),
        lambda m, tx, i: m.await_approval(tx, i),
        lambda m, tx, i: m.close(tx, i, State.APPROVAL_DENIED),
    ],
)
async def test_transitions_outside_the_graph_are_refused(
    db: AsyncDatabaseManager, machine: Dispatches, step
) -> None:
    dispatch_id = await _admitted(db, machine)
    with pytest.raises(InvalidTransition):
        async with db.transaction() as tx:
            await step(machine, tx, dispatch_id)
    assert (await _state(db, machine, dispatch_id)).state is State.ADMITTED


async def test_close_and_reconcile_take_only_their_own_states(
    db: AsyncDatabaseManager, machine: Dispatches
) -> None:
    dispatch_id = await _admitted(db, machine)
    with pytest.raises(ValueError):
        async with db.transaction() as tx:
            await machine.close(tx, dispatch_id, State.COMPLETED)
    with pytest.raises(ValueError):
        async with db.transaction() as tx:
            await machine.reconcile(tx, dispatch_id, State.COMPLETED, {})


def test_the_sweep_threshold_must_be_positive(recorder: Recorder) -> None:
    for max_dispatch, margin in ((timedelta(0), timedelta(1)), (timedelta(1), timedelta(0))):
        with pytest.raises(ValueError):
            Dispatches(on_transition=recorder, max_dispatch=max_dispatch, sweep_margin=margin)
