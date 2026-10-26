"""The shared dispatch state machine on real PostgreSQL."""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import timedelta
from uuid import UUID

import pytest
from pgdbm import AsyncDatabaseManager
from pgdbm.core import TransactionManager

from aweb_naapp.dispatch import (
    RECONCILED_STATES,
    Dispatch,
    Dispatches,
    DispatchInFlight,
    FenceTookLock,
    InvalidTransition,
    ReconciliationPending,
    RepeatClaimed,
    State,
    Transition,
    apply_dispatch_migrations,
)

SUBJECT = "did:aw:member"
ACTION = "credential-1:create-refund"


class Recorder:
    """Records every transition, and fails the one named in ``fail_on`` or
    any transition of a dispatch in ``fail_ids``."""

    def __init__(self) -> None:
        self.transitions: list[Transition] = []
        self.fail_on: State | None = None
        self.fail_ids: set[UUID] = set()

    async def __call__(self, tx: TransactionManager, transition: Transition) -> None:
        if transition.to_state is self.fail_on or transition.dispatch_id in self.fail_ids:
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


class CallFence:
    """A fence whose phases are the given coroutines; with neither, it locks
    and checks nothing."""

    def __init__(
        self,
        check: Callable[[TransactionManager, Dispatch], Awaitable[None]] | None = None,
        prepare: Callable[[TransactionManager], Awaitable[None]] | None = None,
    ) -> None:
        self._check = check
        self._prepare = prepare

    async def prepare(self, tx: TransactionManager) -> None:
        if self._prepare is not None:
            await self._prepare(tx)

    async def check(self, tx: TransactionManager, dispatch: Dispatch) -> None:
        if self._check is not None:
            await self._check(tx, dispatch)


NO_FENCE = CallFence()


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
        await machine.admit(tx, dispatch_id, fence=NO_FENCE)
    return dispatch_id


async def _dispatching(db: AsyncDatabaseManager, machine: Dispatches, **kwargs) -> UUID:
    dispatch_id = await _admitted(db, machine, **kwargs)
    async with db.transaction() as tx:
        await machine.begin_dispatch(tx, dispatch_id, fence=NO_FENCE)
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


async def test_immediate_unknown_is_a_durable_cas_and_keeps_late_evidence(db, machine, recorder):
    dispatch_id = await _dispatching(db, machine)
    async with db.transaction() as tx:
        assert await machine.outcome_unknown(tx, dispatch_id, {"error": "transport_reset"}) is True
    async with db.transaction() as tx:
        assert await machine.outcome_unknown(tx, dispatch_id, {"error": "late_reset"}) is False
        assert await machine.complete(tx, dispatch_id, {"status": 200}) is False
    current = await _state(db, machine, dispatch_id)
    assert current.state is State.OUTCOME_UNKNOWN
    assert current.result == {"error": "transport_reset"}
    assert current.late_results == [{"error": "late_reset"}, {"status": 200}]
    assert recorder.states(dispatch_id).count(State.OUTCOME_UNKNOWN) == 1
    async with db.transaction() as tx:
        await machine.reconcile(tx, dispatch_id, State.RECONCILED_FAILED, {"by": "owner"})
        assert await machine.outcome_unknown(tx, dispatch_id, {"error": "after_reconcile"}) is False
    current = await _state(db, machine, dispatch_id)
    assert current.state is State.RECONCILED_FAILED
    assert current.result == {"by": "owner"}
    assert current.late_results[-1] == {"error": "after_reconcile"}


async def test_immediate_unknown_rolls_back_when_transition_enqueue_fails(db, machine, recorder):
    dispatch_id = await _dispatching(db, machine)
    recorder.fail_on = State.OUTCOME_UNKNOWN
    with pytest.raises(EnqueueFailed):
        async with db.transaction() as tx:
            await machine.outcome_unknown(tx, dispatch_id, {"error": "timeout"})
    current = await _state(db, machine, dispatch_id)
    assert current.state is State.DISPATCHING
    assert current.result is None
    assert current.late_results == []


async def test_immediate_unknown_racing_completion_never_overwrites_the_winner(db, machine):
    dispatch_id = await _dispatching(db, machine)

    async def settle(method, result):
        try:
            async with db.transaction() as tx:
                return await getattr(machine, method)(tx, dispatch_id, result)
        except InvalidTransition:
            return "terminal"

    results = await asyncio.gather(
        settle("outcome_unknown", {"error": "timeout"}), settle("complete", {"status": 200})
    )
    assert results.count(True) == 1
    current = await _state(db, machine, dispatch_id)
    assert current.state in {State.OUTCOME_UNKNOWN, State.COMPLETED}
    if current.state is State.OUTCOME_UNKNOWN:
        assert current.result == {"error": "timeout"}
        assert current.late_results == [{"status": 200}]
    else:
        assert current.result == {"status": 200}
        assert current.late_results == []


@pytest.mark.parametrize("state", ["received", "admitted", "completed"])
async def test_immediate_unknown_refuses_an_unstarted_or_terminal_dispatch(db, machine, state):
    if state == "received":
        dispatch_id = uuid.uuid4()
        async with db.transaction() as tx:
            await machine.create(tx, dispatch_id=dispatch_id, subject=SUBJECT, action=ACTION)
    elif state == "admitted":
        dispatch_id = await _admitted(db, machine)
    else:
        dispatch_id = await _dispatching(db, machine)
        async with db.transaction() as tx:
            await machine.complete(tx, dispatch_id, {"status": 200})
    with pytest.raises(InvalidTransition):
        async with db.transaction() as tx:
            await machine.outcome_unknown(tx, dispatch_id, {"error": "timeout"})
    assert (await _state(db, machine, dispatch_id)).state.value == state


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
        await machine.admit(tx, approved, fence=NO_FENCE)
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
        await machine.begin_dispatch(tx, dispatch_id, fence=NO_FENCE)
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
        lambda tx: machine.admit(tx, dispatch_id, fence=NO_FENCE),
        lambda tx: machine.begin_dispatch(tx, dispatch_id, fence=NO_FENCE),
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
            await machine.begin_dispatch(tx, dispatch_id, fence=CallFence(check=fence))
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
            await machine.begin_dispatch(tx, dispatch_id, fence=CallFence(check=slow_fence))

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
            await machine.begin_dispatch(tx, dispatch_id, fence=NO_FENCE)
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
            await machine.admit(tx, blocked, fence=NO_FENCE)
    assert pending.value.code == "reconciliation_pending"
    await _admitted(db, machine, subject="did:aw:other")
    await _admitted(db, machine, action="credential-1:list-charges")

    async with db.transaction() as tx:
        await machine.reconcile(tx, unknown, State.RECONCILED_FAILED, {"by": "owner"})
        await machine.admit(tx, blocked, fence=NO_FENCE)
    assert (await _state(db, machine, blocked)).state is State.ADMITTED
    assert (await _state(db, machine, unknown)).result == {"by": "owner"}


async def test_the_exemption_is_the_new_dispatchs_own(
    db: AsyncDatabaseManager, machine: Dispatches, recorder: Recorder
) -> None:
    await _unknown(db, recorder, retry_exempt=True)
    await _admitted(db, machine, retry_exempt=True)
    with pytest.raises(ReconciliationPending):
        await _admitted(db, machine)


async def test_an_exempt_dispatch_is_not_blocked_by_an_unknown_one(
    db: AsyncDatabaseManager, machine: Dispatches, recorder: Recorder
) -> None:
    await _unknown(db, recorder)
    await _admitted(db, machine, retry_exempt=True)


async def _sweep_soon(recorder: Recorder) -> Dispatches:
    return Dispatches(
        on_transition=recorder,
        max_dispatch=timedelta(milliseconds=50),
        sweep_margin=timedelta(milliseconds=50),
    )


async def test_a_not_sent_retry_is_blocked_by_an_unknown_outcome_of_its_pair(
    db: AsyncDatabaseManager, machine: Dispatches, recorder: Recorder
) -> None:
    quick = await _sweep_soon(recorder)
    retrying = await _dispatching(db, machine)
    async with db.transaction() as tx:
        await machine.not_sent(tx, retrying, {"error": "connect"})
    unknown = await _dispatching(db, quick)
    await asyncio.sleep(0.2)
    await quick.sweep(db)
    with pytest.raises(ReconciliationPending):
        async with db.transaction() as tx:
            await machine.begin_dispatch(tx, retrying, fence=NO_FENCE)
    async with db.transaction() as tx:
        await machine.reconcile(tx, unknown, State.RECONCILED_FAILED, {})
        await machine.begin_dispatch(tx, retrying, fence=NO_FENCE)


async def test_a_dispatch_admitted_before_the_sweep_is_blocked_at_dispatch(
    db: AsyncDatabaseManager, recorder: Recorder
) -> None:
    quick = await _sweep_soon(recorder)
    admitted = await _admitted(db, quick)
    exempt = await _admitted(db, quick, retry_exempt=True)
    running = uuid.uuid4()
    async with db.transaction() as tx:
        await quick.create(tx, dispatch_id=running, subject=SUBJECT, action=ACTION)
        await quick.admit(tx, running, fence=NO_FENCE)
        await quick.begin_dispatch(tx, running, fence=NO_FENCE)
    await asyncio.sleep(0.2)
    await quick.sweep(db)
    with pytest.raises(ReconciliationPending):
        async with db.transaction() as tx:
            await quick.begin_dispatch(tx, admitted, fence=NO_FENCE)
    async with db.transaction() as tx:
        await quick.begin_dispatch(tx, exempt, fence=NO_FENCE)


async def test_a_pair_has_at_most_one_dispatch_in_flight(
    db: AsyncDatabaseManager, machine: Dispatches
) -> None:
    first = await _admitted(db, machine)
    second = await _admitted(db, machine)
    async with db.transaction() as tx:
        await machine.begin_dispatch(tx, first, fence=NO_FENCE)
    with pytest.raises(DispatchInFlight) as in_flight:
        async with db.transaction() as tx:
            await machine.begin_dispatch(tx, second, fence=NO_FENCE)
    assert in_flight.value.code == "dispatch_in_flight"
    with pytest.raises(DispatchInFlight):
        await _admitted(db, machine)
    await _admitted(db, machine, subject="did:aw:other")
    async with db.transaction() as tx:
        await machine.complete(tx, first, {"status": 200})
        await machine.begin_dispatch(tx, second, fence=NO_FENCE)


async def test_concurrent_dispatches_of_one_pair_yield_one(
    db: AsyncDatabaseManager, machine: Dispatches
) -> None:
    first = await _admitted(db, machine)
    second = await _admitted(db, machine)

    async def slow_fence(tx: TransactionManager, dispatch: Dispatch) -> None:
        await asyncio.sleep(0.2)

    async def begin(dispatch_id: UUID) -> None:
        async with db.transaction() as tx:
            await machine.begin_dispatch(tx, dispatch_id, fence=CallFence(check=slow_fence))

    results = await asyncio.gather(begin(first), begin(second), return_exceptions=True)
    assert sorted(type(r).__name__ for r in results) == ["DispatchInFlight", "NoneType"]
    states = {(await _state(db, machine, d)).state for d in (first, second)}
    assert states == {State.DISPATCHING, State.ADMITTED}


async def test_admission_racing_the_sweep_is_refused(
    db: AsyncDatabaseManager, recorder: Recorder
) -> None:
    quick = await _sweep_soon(recorder)
    await _dispatching(db, quick)
    await asyncio.sleep(0.2)
    newcomer = uuid.uuid4()
    async with db.transaction() as tx:
        await quick.create(tx, dispatch_id=newcomer, subject=SUBJECT, action=ACTION)

    async def admit() -> None:
        async with db.transaction() as tx:
            await quick.admit(tx, newcomer, fence=NO_FENCE)

    results = await asyncio.gather(quick.sweep(db), admit(), return_exceptions=True)
    assert results[0] == 1
    assert isinstance(results[1], ReconciliationPending | DispatchInFlight)
    assert (await _state(db, quick, newcomer)).state is State.RECEIVED


async def test_a_slow_fence_does_not_eat_the_sweep_margin(
    db: AsyncDatabaseManager, recorder: Recorder
) -> None:
    machine = Dispatches(
        on_transition=recorder,
        max_dispatch=timedelta(milliseconds=300),
        sweep_margin=timedelta(milliseconds=300),
    )
    dispatch_id = await _admitted(db, machine)

    async def slow_fence(tx: TransactionManager, dispatch: Dispatch) -> None:
        await asyncio.sleep(0.7)

    async with db.transaction() as tx:
        await machine.begin_dispatch(tx, dispatch_id, fence=CallFence(check=slow_fence))
    assert await machine.sweep(db) == 0
    assert (await _state(db, machine, dispatch_id)).state is State.DISPATCHING


async def test_one_failing_row_does_not_stop_the_sweep(
    db: AsyncDatabaseManager, recorder: Recorder, caplog: pytest.LogCaptureFixture
) -> None:
    quick = await _sweep_soon(recorder)
    bad = await _dispatching(db, quick, subject="did:aw:bad")
    good = await _dispatching(db, quick, subject="did:aw:good")
    await asyncio.sleep(0.2)
    recorder.fail_ids = {bad}
    with caplog.at_level(logging.ERROR, logger="aweb_naapp.dispatch"):
        # Bounded, so a sweep that keeps retrying the bad row fails instead of hanging.
        assert await asyncio.wait_for(quick.sweep(db), timeout=5) == 1
    assert (await _state(db, quick, good)).state is State.OUTCOME_UNKNOWN
    assert (await _state(db, quick, bad)).state is State.DISPATCHING
    assert [r.levelno for r in caplog.records] == [logging.ERROR]
    assert str(bad) in caplog.records[0].getMessage()


async def test_the_sweep_skips_a_row_being_completed(
    db: AsyncDatabaseManager, recorder: Recorder
) -> None:
    quick = await _sweep_soon(recorder)
    dispatch_id = await _dispatching(db, quick)
    await asyncio.sleep(0.2)
    completing = asyncio.Event()

    async def complete() -> None:
        async with db.transaction() as tx:
            await quick.complete(tx, dispatch_id, {"status": 200})
            completing.set()
            await asyncio.sleep(0.3)

    async def sweep() -> int:
        await completing.wait()
        return await quick.sweep(db)

    results = await asyncio.gather(complete(), sweep())
    assert results[1] == 0
    assert (await _state(db, quick, dispatch_id)).state is State.COMPLETED


async def test_a_late_result_after_reconciliation_is_kept(
    db: AsyncDatabaseManager, recorder: Recorder
) -> None:
    quick = await _sweep_soon(recorder)
    dispatch_id = await _dispatching(db, quick)
    await asyncio.sleep(0.2)
    await quick.sweep(db)
    async with db.transaction() as tx:
        await quick.reconcile(tx, dispatch_id, State.RECONCILED_COMPLETED, {"by": "lookup"})
    async with db.transaction() as tx:
        assert await quick.complete(tx, dispatch_id, {"status": 200}) is False
        assert await quick.not_sent(tx, dispatch_id, {"error": "reset"}) is False
    dispatch = await _state(db, quick, dispatch_id)
    assert dispatch.state is State.RECONCILED_COMPLETED
    assert dispatch.result == {"by": "lookup"}
    assert dispatch.late_results == [{"status": 200}, {"error": "reset"}]


@pytest.mark.parametrize("ending", ["refuse", "cancel"])
async def test_a_not_sent_dispatch_can_be_ended(
    db: AsyncDatabaseManager, machine: Dispatches, ending: str
) -> None:
    dispatch_id = await _dispatching(db, machine)
    async with db.transaction() as tx:
        await machine.not_sent(tx, dispatch_id, {"error": "connect"})
        if ending == "refuse":
            await machine.refuse(tx, dispatch_id)
        else:
            await machine.close(tx, dispatch_id, State.CANCELLED)
    expected = State.REFUSED if ending == "refuse" else State.CANCELLED
    assert (await _state(db, machine, dispatch_id)).state is expected


async def test_a_dispatching_row_always_has_a_sweep_time(
    db: AsyncDatabaseManager, machine: Dispatches
) -> None:
    dispatch_id = await _admitted(db, machine)
    with pytest.raises(Exception, match="check"):
        await db.execute(
            "UPDATE {{tables.dispatches}} SET state = 'dispatching' WHERE dispatch_id = $1",
            dispatch_id,
        )


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


# The fence comes first: its prepare runs before S3 takes any lock, and its
# check runs under S3's locks without taking any of its own.


async def _held(tx: TransactionManager) -> dict[str, int]:
    """The locks this transaction holds that S3 takes: its row lock on
    dispatches and the pair's advisory lock."""
    row = await tx.fetch_one(
        """
        SELECT count(*) FILTER (WHERE locktype = 'advisory') AS advisory,
               count(*) FILTER (WHERE locktype = 'relation' AND mode = 'RowShareLock'
                                AND relation = '{{tables.dispatches}}'::regclass) AS dispatch_rows
        FROM pg_locks WHERE pid = pg_backend_pid() AND granted
        """
    )
    assert row is not None
    return {"advisory": row["advisory"], "dispatch_rows": row["dispatch_rows"]}


@pytest.mark.parametrize("step", ["admit", "begin_dispatch"])
async def test_the_fence_prepares_before_s3_locks_and_checks_under_them(
    db: AsyncDatabaseManager, machine: Dispatches, step: str
) -> None:
    seen: dict[str, dict[str, int]] = {}

    async def prepare(tx: TransactionManager) -> None:
        seen["prepare"] = await _held(tx)

    async def check(tx: TransactionManager, dispatch: Dispatch) -> None:
        seen["check"] = await _held(tx)

    fence = CallFence(check=check, prepare=prepare)
    dispatch_id = uuid.uuid4()
    async with db.transaction() as tx:
        await machine.create(tx, dispatch_id=dispatch_id, subject=SUBJECT, action=ACTION)
    async with db.transaction() as tx:
        await machine.admit(tx, dispatch_id, fence=fence if step == "admit" else NO_FENCE)
    if step == "begin_dispatch":
        async with db.transaction() as tx:
            await machine.begin_dispatch(tx, dispatch_id, fence=fence)
    assert seen["prepare"] == {"advisory": 0, "dispatch_rows": 0}
    assert seen["check"] == {"advisory": 1, "dispatch_rows": 1}


@pytest.mark.parametrize("step", ["admit", "begin_dispatch"])
async def test_a_fence_refusing_in_prepare_leaves_no_s3_lock_and_the_dispatch_as_it_was(
    db: AsyncDatabaseManager, machine: Dispatches, step: str
) -> None:
    async def refuse(tx: TransactionManager) -> None:
        raise FenceRefused

    dispatch_id = uuid.uuid4()
    async with db.transaction() as tx:
        await machine.create(tx, dispatch_id=dispatch_id, subject=SUBJECT, action=ACTION)
    if step == "begin_dispatch":
        async with db.transaction() as tx:
            await machine.admit(tx, dispatch_id, fence=NO_FENCE)
    before = (await _state(db, machine, dispatch_id)).state
    async with db.transaction() as tx:
        with pytest.raises(FenceRefused):
            await getattr(machine, step)(tx, dispatch_id, fence=CallFence(prepare=refuse))
        assert await _held(tx) == {"advisory": 0, "dispatch_rows": 0}
    assert (await _state(db, machine, dispatch_id)).state is before


async def test_a_fence_refusing_admission_leaves_the_dispatch_received(
    db: AsyncDatabaseManager, machine: Dispatches
) -> None:
    async def refuse(tx: TransactionManager, dispatch: Dispatch) -> None:
        raise FenceRefused

    dispatch_id = uuid.uuid4()
    async with db.transaction() as tx:
        await machine.create(tx, dispatch_id=dispatch_id, subject=SUBJECT, action=ACTION)
    with pytest.raises(FenceRefused):
        async with db.transaction() as tx:
            await machine.admit(tx, dispatch_id, fence=CallFence(check=refuse))
    assert (await _state(db, machine, dispatch_id)).state is State.RECEIVED


@pytest.fixture
async def installations(db: AsyncDatabaseManager) -> AsyncDatabaseManager:
    """An app's installation rows, which its fences lock."""
    await db.execute(
        "CREATE TABLE {{tables.installations}} (team_id TEXT PRIMARY KEY, generation INT NOT NULL)"
    )
    await db.execute("INSERT INTO {{tables.installations}} VALUES ('team-1', 1)")
    return db


@pytest.mark.parametrize(
    "late_lock",
    [
        "SELECT generation FROM {{tables.installations}} WHERE team_id = 'team-1' FOR SHARE",
        "UPDATE {{tables.installations}} SET generation = generation WHERE team_id = 'team-1'",
        "SELECT pg_advisory_xact_lock(42)",
    ],
)
async def test_a_check_that_takes_a_lock_is_refused(
    installations: AsyncDatabaseManager, machine: Dispatches, late_lock: str
) -> None:
    async def check(tx: TransactionManager, dispatch: Dispatch) -> None:
        await tx.execute(late_lock)

    dispatch_id = await _admitted(installations, machine)
    with pytest.raises(FenceTookLock):
        async with installations.transaction() as tx:
            await machine.begin_dispatch(tx, dispatch_id, fence=CallFence(check=check))
    assert (await _state(installations, machine, dispatch_id)).state is State.ADMITTED


async def test_a_check_that_only_reads_what_prepare_locked_is_accepted(
    installations: AsyncDatabaseManager, machine: Dispatches
) -> None:
    async def prepare(tx: TransactionManager) -> None:
        await tx.execute(
            "SELECT 1 FROM {{tables.installations}} WHERE team_id = 'team-1' FOR SHARE"
        )

    async def check(tx: TransactionManager, dispatch: Dispatch) -> None:
        await tx.fetch_value(
            "SELECT generation FROM {{tables.installations}} WHERE team_id = 'team-1'"
        )

    dispatch_id = await _admitted(installations, machine)
    async with installations.transaction() as tx:
        await machine.begin_dispatch(tx, dispatch_id, fence=CallFence(check=check, prepare=prepare))
    assert (await _state(installations, machine, dispatch_id)).state is State.DISPATCHING


def _installation_fence(*, mode: str, hold: float = 0.0) -> CallFence:
    """An installation fence: prepare locks the team's row (FOR UPDATE when
    admitting, FOR SHARE when dispatching), check reads it under S3's locks."""

    async def prepare(tx: TransactionManager) -> None:
        await tx.execute(
            f"SELECT 1 FROM {{{{tables.installations}}}} WHERE team_id = 'team-1' FOR {mode}"
        )
        await asyncio.sleep(hold)

    async def check(tx: TransactionManager, dispatch: Dispatch) -> None:
        await tx.fetch_value(
            "SELECT generation FROM {{tables.installations}} WHERE team_id = 'team-1'"
        )

    return CallFence(check=check, prepare=prepare)


async def test_admission_and_dispatch_of_one_pair_never_deadlock(
    installations: AsyncDatabaseManager, machine: Dispatches
) -> None:
    db = installations
    for round_number in range(10):
        action = f"{ACTION}:{round_number}"
        dispatching = await _admitted(db, machine, action=action)
        newcomer = uuid.uuid4()
        async with db.transaction() as tx:
            await machine.create(tx, dispatch_id=newcomer, subject=SUBJECT, action=action)

        async def admit(dispatch_id: UUID) -> None:
            async with db.transaction() as tx:
                await machine.admit(
                    tx, dispatch_id, fence=_installation_fence(mode="UPDATE", hold=0.1)
                )

        async def dispatch(dispatch_id: UUID) -> None:
            await asyncio.sleep(0.02)
            async with db.transaction() as tx:
                await machine.begin_dispatch(
                    tx, dispatch_id, fence=_installation_fence(mode="SHARE")
                )

        # Whichever commits first decides whether the other is refused as in
        # flight; neither may fail any other way.
        results = await asyncio.gather(
            admit(newcomer), dispatch(dispatching), return_exceptions=True
        )
        for result in results:
            assert result is None or isinstance(result, DispatchInFlight), results


# The one safe repeat of an outcome_unknown dispatch


async def _unknown(db: AsyncDatabaseManager, machine: Dispatches, **kwargs) -> UUID:
    dispatch_id = await _dispatching(db, machine, **kwargs)
    async with db.transaction() as tx:
        assert await machine.outcome_unknown(tx, dispatch_id, {"error": "reset"}) is True
    return dispatch_id


async def _claim(
    tx: TransactionManager, machine: Dispatches, original: UUID, fence: CallFence = NO_FENCE
) -> UUID:
    repeat = uuid.uuid4()
    await machine.continue_dispatch(tx, original, dispatch_id=repeat, fence=fence)
    return repeat


async def _published(db: AsyncDatabaseManager, machine: Dispatches, original: UUID) -> UUID:
    """Claim, admit and begin the repeat in one transaction, as its caller does."""
    async with db.transaction() as tx:
        repeat = await _claim(tx, machine, original)
        await machine.admit(tx, repeat, fence=NO_FENCE)
        await machine.begin_dispatch(tx, repeat, fence=NO_FENCE)
    return repeat


@pytest.mark.parametrize("settles", [State.RECONCILED_COMPLETED, State.RECONCILED_FAILED])
async def test_a_definite_repeat_settles_its_unknown_original(
    db: AsyncDatabaseManager, machine: Dispatches, recorder: Recorder, settles: State
) -> None:
    original = await _unknown(db, machine, retry_exempt=True)
    repeat = await _published(db, machine, original)
    async with db.transaction() as tx:
        assert await machine.complete(tx, repeat, {"status": 409}) is True
        settled = await machine.resolve_original(tx, repeat, settles, {"repeat": str(repeat)})
    assert settled is not None and settled.state is settles
    continued = await _state(db, machine, repeat)
    assert (continued.continues, continued.state, continued.attempts) == (
        original,
        State.COMPLETED,
        1,
    )
    assert (continued.subject, continued.action, continued.retry_exempt) == (
        SUBJECT,
        ACTION,
        True,
    )
    assert (await _state(db, machine, original)).result == {"repeat": str(repeat)}
    assert recorder.states(repeat) == [
        State.RECEIVED,
        State.ADMITTED,
        State.DISPATCHING,
        State.COMPLETED,
    ]
    assert recorder.states(original)[-2:] == [State.OUTCOME_UNKNOWN, settles]


async def test_an_original_is_repeated_at_most_once(
    db: AsyncDatabaseManager, machine: Dispatches
) -> None:
    original = await _unknown(db, machine)
    repeat = await _published(db, machine, original)
    async with db.transaction() as tx:
        assert await machine.not_sent(tx, repeat, {"error": "connect"}) is True
        await machine.refuse(tx, repeat)
    with pytest.raises(RepeatClaimed):
        async with db.transaction() as tx:
            await _claim(tx, machine, original)
    assert (await _state(db, machine, original)).state is State.OUTCOME_UNKNOWN


async def test_concurrent_repeat_claims_yield_one(
    db: AsyncDatabaseManager, machine: Dispatches
) -> None:
    original = await _unknown(db, machine)

    async def slow(tx: TransactionManager, dispatch: Dispatch) -> None:
        await asyncio.sleep(0.2)

    async def claim() -> UUID:
        async with db.transaction() as tx:
            return await _claim(tx, machine, original, CallFence(check=slow))

    results = await asyncio.gather(claim(), claim(), return_exceptions=True)
    assert sorted(type(r).__name__ for r in results) == ["RepeatClaimed", "UUID"]
    claimed = await db.fetch_value(
        "SELECT count(*) FROM {{tables.dispatches}} WHERE continues = $1", original
    )
    assert claimed == 1


@pytest.mark.parametrize(
    "state",
    [State.DISPATCHING, State.COMPLETED, State.NOT_SENT, State.RECONCILED_UNKNOWN, "repeat"],
)
async def test_only_an_unknown_original_can_be_repeated(
    db: AsyncDatabaseManager, machine: Dispatches, state: State | str
) -> None:
    dispatch_id = await _dispatching(db, machine)
    async with db.transaction() as tx:
        if state is State.COMPLETED:
            await machine.complete(tx, dispatch_id, {"status": 200})
        elif state is State.NOT_SENT:
            await machine.not_sent(tx, dispatch_id, {"error": "connect"})
        elif state is not State.DISPATCHING:
            await machine.outcome_unknown(tx, dispatch_id, {"error": "reset"})
            if state is State.RECONCILED_UNKNOWN:
                await machine.reconcile(tx, dispatch_id, state, {"by": "owner"})
    if state == "repeat":
        # A repeat that is itself of unknown outcome is never repeated.
        dispatch_id = await _published(db, machine, dispatch_id)
        async with db.transaction() as tx:
            await machine.outcome_unknown(tx, dispatch_id, {"error": "reset"})
    with pytest.raises(InvalidTransition):
        async with db.transaction() as tx:
            await _claim(tx, machine, dispatch_id)


@pytest.mark.parametrize("phase", ["prepare", "check"])
async def test_a_refused_repeat_leaves_no_claim(
    db: AsyncDatabaseManager, machine: Dispatches, recorder: Recorder, phase: str
) -> None:
    original = await _unknown(db, machine)

    async def refuse(*args) -> None:
        raise FenceRefused

    fence = CallFence(prepare=refuse) if phase == "prepare" else CallFence(check=refuse)
    async with db.transaction() as tx:
        # The caller survives the refusal and commits its transaction.
        with pytest.raises(FenceRefused):
            await _claim(tx, machine, original, fence)
    assert not await db.fetch_value(
        "SELECT count(*) FROM {{tables.dispatches}} WHERE continues = $1", original
    )
    assert len(recorder.transitions) == 4
    await _published(db, machine, original)


async def test_a_repeat_is_not_blocked_by_its_own_original_but_by_others(
    db: AsyncDatabaseManager, machine: Dispatches
) -> None:
    original = await _unknown(db, machine)
    # An exempt dispatch of the pair may be in flight beside the unknown original.
    exempt = await _dispatching(db, machine, retry_exempt=True)
    with pytest.raises(DispatchInFlight):
        await _published(db, machine, original)
    async with db.transaction() as tx:
        await machine.complete(tx, exempt, {"status": 200})
    await _published(db, machine, original)


async def test_a_fresh_request_stays_blocked_until_the_owner_settles_the_original(
    db: AsyncDatabaseManager, machine: Dispatches
) -> None:
    original = await _unknown(db, machine)
    repeat = await _published(db, machine, original)
    fresh = uuid.uuid4()
    async with db.transaction() as tx:
        await machine.create(tx, dispatch_id=fresh, subject=SUBJECT, action=ACTION)
    with pytest.raises(ReconciliationPending):
        async with db.transaction() as tx:
            await machine.admit(tx, fresh, fence=NO_FENCE)
    async with db.transaction() as tx:
        await machine.outcome_unknown(tx, repeat, {"error": "reset"})
    with pytest.raises(ReconciliationPending):
        async with db.transaction() as tx:
            await machine.admit(tx, fresh, fence=NO_FENCE)
    async with db.transaction() as tx:
        await machine.reconcile(tx, original, State.RECONCILED_UNKNOWN, {"by": "owner"})
    # The repeat's own unknown outcome is evidence for its settled original.
    async with db.transaction() as tx:
        await machine.admit(tx, fresh, fence=NO_FENCE)
        await machine.begin_dispatch(tx, fresh, fence=NO_FENCE)


async def test_a_repeat_is_sent_once(db: AsyncDatabaseManager, machine: Dispatches) -> None:
    original = await _unknown(db, machine)
    repeat = await _published(db, machine, original)
    async with db.transaction() as tx:
        await machine.not_sent(tx, repeat, {"error": "connect"})
    with pytest.raises(InvalidTransition):
        async with db.transaction() as tx:
            await machine.begin_dispatch(tx, repeat, fence=NO_FENCE)
    assert (await _state(db, machine, repeat)).state is State.NOT_SENT


@pytest.mark.parametrize("left", [State.RECEIVED, State.ADMITTED])
async def test_a_persisted_repeat_never_publishes_after_its_original_was_settled(
    db: AsyncDatabaseManager, machine: Dispatches, left: State
) -> None:
    original = await _unknown(db, machine)
    async with db.transaction() as tx:
        repeat = await _claim(tx, machine, original)
        if left is State.ADMITTED:
            await machine.admit(tx, repeat, fence=NO_FENCE)
    async with db.transaction() as tx:
        await machine.reconcile(tx, original, State.RECONCILED_FAILED, {"by": "owner"})
    with pytest.raises(InvalidTransition):
        async with db.transaction() as tx:
            if left is State.RECEIVED:
                await machine.admit(tx, repeat, fence=NO_FENCE)
            await machine.begin_dispatch(tx, repeat, fence=NO_FENCE)
    assert (await _state(db, machine, repeat)).state is left
    async with db.transaction() as tx:
        await machine.refuse(tx, repeat)


async def test_owner_settlement_waits_for_the_repeat_publication_to_commit(
    db: AsyncDatabaseManager, machine: Dispatches
) -> None:
    original = await _unknown(db, machine)
    fenced = asyncio.Event()
    release = asyncio.Event()

    async def held(tx: TransactionManager, dispatch: Dispatch) -> None:
        fenced.set()
        await release.wait()

    async def publish() -> UUID:
        async with db.transaction() as tx:
            repeat = await _claim(tx, machine, original)
            await machine.admit(tx, repeat, fence=NO_FENCE)
            await machine.begin_dispatch(tx, repeat, fence=CallFence(check=held))
        return repeat

    async def settle() -> None:
        await fenced.wait()
        async with db.transaction() as tx:
            await machine.reconcile(tx, original, State.RECONCILED_UNKNOWN, {"by": "owner"})

    publishing = asyncio.create_task(publish())
    settling = asyncio.create_task(settle())
    await asyncio.wait_for(fenced.wait(), 5)
    await asyncio.sleep(0.2)
    assert not settling.done()
    release.set()
    repeat = await asyncio.wait_for(publishing, 5)
    await asyncio.wait_for(settling, 5)
    assert (await _state(db, machine, repeat)).state is State.DISPATCHING
    # The owner's settlement is the one settlement; the repeat's result is evidence.
    async with db.transaction() as tx:
        assert await machine.complete(tx, repeat, {"status": 200}) is True
        assert await machine.resolve_original(tx, repeat, State.RECONCILED_COMPLETED, {}) is None
    settled = await _state(db, machine, original)
    assert (settled.state, settled.result) == (State.RECONCILED_UNKNOWN, {"by": "owner"})
    assert (await _state(db, machine, repeat)).result == {"status": 200}


async def test_resolve_original_takes_only_a_completed_repeat_and_a_definite_state(
    db: AsyncDatabaseManager, machine: Dispatches
) -> None:
    original = await _unknown(db, machine)
    repeat = await _published(db, machine, original)
    with pytest.raises(InvalidTransition):
        async with db.transaction() as tx:
            await machine.resolve_original(tx, repeat, State.RECONCILED_COMPLETED, {})
    with pytest.raises(InvalidTransition):
        async with db.transaction() as tx:
            await machine.resolve_original(tx, original, State.RECONCILED_COMPLETED, {})
    async with db.transaction() as tx:
        await machine.complete(tx, repeat, {"status": 200})
    for state in (State.RECONCILED_UNKNOWN, State.COMPLETED):
        with pytest.raises(ValueError):
            async with db.transaction() as tx:
                await machine.resolve_original(tx, repeat, state, {})
    assert (await _state(db, machine, original)).state is State.OUTCOME_UNKNOWN


async def _after(delay: float, awaitable: Awaitable[object]) -> object:
    await asyncio.sleep(delay)
    return await awaitable


async def _resolve_slowly(db: AsyncDatabaseManager, machine: Dispatches, repeat: UUID) -> None:
    async with db.transaction() as tx:
        await machine.complete(tx, repeat, {"status": 200})
        await asyncio.sleep(0.05)
        await machine.resolve_original(tx, repeat, State.RECONCILED_COMPLETED, {})


async def _owner_settles(db: AsyncDatabaseManager, machine: Dispatches, original: UUID) -> None:
    async with db.transaction() as tx:
        await machine.reconcile(tx, original, State.RECONCILED_FAILED, {"by": "owner"})


async def _claim_alone(db: AsyncDatabaseManager, machine: Dispatches, original: UUID) -> UUID:
    async with db.transaction() as tx:
        return await _claim(tx, machine, original)


async def test_repeat_resolution_owner_settlement_and_claims_never_deadlock(
    db: AsyncDatabaseManager, machine: Dispatches
) -> None:
    for round_number in range(10):
        original = await _unknown(db, machine, action=f"{ACTION}:{round_number}")
        repeat = await _published(db, machine, original)
        results = await asyncio.gather(
            _resolve_slowly(db, machine, repeat),
            _after(0.02, _owner_settles(db, machine, original)),
            _after(0.01, _claim_alone(db, machine, original)),
            return_exceptions=True,
        )
        # One settlement wins; a second claim is refused; nothing else fails.
        assert results[0] is None, results
        assert results[1] is None or isinstance(results[1], InvalidTransition), results
        assert isinstance(results[2], RepeatClaimed | InvalidTransition), results
        assert (await _state(db, machine, original)).state in RECONCILED_STATES
