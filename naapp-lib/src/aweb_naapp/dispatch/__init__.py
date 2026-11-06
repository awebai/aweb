"""The shared state machine for requests that cause an external effect.

A dispatch is one intent: it is received, may wait for an approval, is
admitted, and is then dispatched. ``dispatching`` is committed before the
first byte leaves, after a :class:`Fence` has re-read whatever may stop it
under a lock on the dispatch row. The outcome is ``completed`` (a definite
response), ``not_sent`` (nothing reached the upstream; it may be dispatched
again under the same id), or ``outcome_unknown``, which the sweeper writes
when a dispatch outlives its time bound. ``completed`` and ``not_sent`` are
compare-and-set from ``dispatching`` only, so a result that arrives after the
sweep, or after reconciliation, is kept as evidence and never overwrites it.

A subject has at most one dispatch of an action in flight or of unknown
outcome. Admitting or dispatching another is refused, with
:class:`DispatchInFlight` while one is dispatching and with
:class:`ReconciliationPending` while one awaits reconciliation, unless the
dispatch being admitted or dispatched was declared exempt. The check runs under
a transaction-scoped advisory lock on the (subject, action) pair, so two
dispatches of one pair cannot both begin.

An ``outcome_unknown`` dispatch may be repeated once, by a continuation: a
new dispatch of the same subject and action that names the original.
:meth:`Dispatches.continue_dispatch` claims the repeat, and a second claim is
refused with :class:`RepeatClaimed`. A continuation is sent at most once, and
only while its original is still ``outcome_unknown``: admitting or dispatching
it locks the original after the continuation and refuses if the original was
settled. Its own original does not block it. A continuation of unknown outcome
blocks nothing, because its original still blocks until it is settled. A
definite repeat settles the original with :meth:`Dispatches.resolve_original`,
unless the owner settled it first. A continuation's row is locked before its
original's, and owner settlement locks only the original.

A dispatch left ``admitted`` by a crash stays there until its caller closes it;
the caller (secrets' S13 wiring) owns that cleanup.

Every transition runs in the caller's transaction and calls ``on_transition``
in that same transaction, so a failed enqueue rolls the transition back.

Admitting and dispatching both take a fence, and the fence's locks always come
before S3's: :meth:`Fence.prepare` runs before S3 locks the dispatch row or the
pair, and :meth:`Fence.check` runs under those locks and may take none of its
own. Every caller then acquires locks in one order, so admission and dispatch
for one pair cannot deadlock.

Imports only the standard library and pgdbm, so it needs no naapp runtime.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID

from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.core import TransactionManager

MIGRATIONS_PATH = Path(__file__).resolve().parent / "migrations"
MIGRATIONS_MODULE = "aweb_naapp_dispatch"

logger = logging.getLogger(__name__)


class State(StrEnum):
    RECEIVED = "received"
    REFUSED = "refused"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVAL_DENIED = "approval_denied"
    APPROVAL_EXPIRED = "approval_expired"
    CANCELLED = "cancelled"
    ADMITTED = "admitted"
    DISPATCHING = "dispatching"
    COMPLETED = "completed"
    NOT_SENT = "not_sent"
    OUTCOME_UNKNOWN = "outcome_unknown"
    RECONCILED_COMPLETED = "reconciled_completed"
    RECONCILED_FAILED = "reconciled_failed"
    RECONCILED_UNKNOWN = "reconciled_unknown"


CLOSING_STATES = frozenset({State.APPROVAL_DENIED, State.APPROVAL_EXPIRED, State.CANCELLED})
RECONCILED_STATES = frozenset(
    {State.RECONCILED_COMPLETED, State.RECONCILED_FAILED, State.RECONCILED_UNKNOWN}
)

TRANSITIONS: Mapping[State, frozenset[State]] = {
    State.RECEIVED: frozenset({State.REFUSED, State.AWAITING_APPROVAL, State.ADMITTED}),
    State.AWAITING_APPROVAL: CLOSING_STATES | {State.ADMITTED},
    State.ADMITTED: frozenset({State.DISPATCHING, State.REFUSED, State.CANCELLED}),
    State.DISPATCHING: frozenset({State.COMPLETED, State.NOT_SENT, State.OUTCOME_UNKNOWN}),
    State.NOT_SENT: frozenset({State.DISPATCHING, State.REFUSED, State.CANCELLED}),
    State.OUTCOME_UNKNOWN: RECONCILED_STATES,
}


class InvalidTransition(Exception):
    """The dispatch is not in a state this transition starts from."""


class ReconciliationPending(Exception):
    """The subject has an unreconciled outcome for this action."""

    code = "reconciliation_pending"


class DispatchInFlight(Exception):
    """The subject already has a dispatch of this action in flight."""

    code = "dispatch_in_flight"


class RepeatClaimed(Exception):
    """The outcome_unknown dispatch already has its one repeat."""

    code = "repeat_claimed"


@dataclass(frozen=True)
class Dispatch:
    dispatch_id: UUID
    subject: str
    action: str
    retry_exempt: bool
    state: State
    attempts: int
    result: Any
    late_results: list[Any] = field(default_factory=list)
    continues: UUID | None = None


@dataclass(frozen=True)
class Transition:
    """One committed-together state change, handed to ``on_transition``.

    ``from_state`` is None when the dispatch is created. ``occurred_at`` is the
    database time of the change.
    """

    dispatch_id: UUID
    subject: str
    action: str
    from_state: State | None
    to_state: State
    occurred_at: datetime


OnTransition = Callable[[TransactionManager, Transition], Awaitable[None]]


class Fence(Protocol):
    """Whatever may stop a dispatch, re-read inside the transaction that admits
    or begins it.

    ``prepare`` must take the transaction's first lock. A caller that also
    holds other rows (roles, approvals) takes them only after S3 returns, or
    calls ``prepare`` itself before taking them; S3 then calls it again, so it
    must be safe to repeat in one transaction, as a repeated SELECT ... FOR
    UPDATE is.
    """

    async def prepare(self, tx: TransactionManager) -> None:
        """Runs before S3 takes any lock; takes every lock the fence needs,
        held to the end of the transaction."""

    async def check(self, tx: TransactionManager, dispatch: Dispatch) -> None:
        """Runs under S3's row and pair locks; raises to refuse, and takes no
        lock of its own."""


class FenceTookLock(RuntimeError):
    """A fence's check took a lock, which it must take in prepare instead."""


async def apply_dispatch_migrations(db: AsyncDatabaseManager) -> None:
    await AsyncMigrationManager(
        db, migrations_path=str(MIGRATIONS_PATH), module_name=MIGRATIONS_MODULE
    ).apply_pending_migrations()


class Dispatches:
    """The state machine, with the caller's enqueue hook and time bounds.

    The sweeper declares a dispatch's outcome unknown only after
    ``max_dispatch`` (the longest a dispatch may take) plus ``sweep_margin``,
    so a dispatch that is still running is never swept.
    """

    def __init__(
        self, *, on_transition: OnTransition, max_dispatch: timedelta, sweep_margin: timedelta
    ) -> None:
        if max_dispatch <= timedelta(0) or sweep_margin <= timedelta(0):
            raise ValueError("the dispatch bound and the sweep margin must be positive")
        self._on_transition = on_transition
        self._sweep_after = max_dispatch + sweep_margin

    async def create(
        self,
        tx: TransactionManager,
        *,
        dispatch_id: UUID,
        subject: str,
        action: str,
        retry_exempt: bool = False,
    ) -> Dispatch:
        row = await tx.fetch_one(
            """
            INSERT INTO {{tables.dispatches}} (dispatch_id, subject, action, retry_exempt, state)
            VALUES ($1, $2, $3, $4, 'received')
            RETURNING *, clock_timestamp() AS occurred_at
            """,
            dispatch_id,
            subject,
            action,
            retry_exempt,
        )
        if row is None:
            raise LookupError("the dispatch row was not returned")
        dispatch = _dispatch(row)
        await self._notify(tx, dispatch, None, row["occurred_at"])
        return dispatch

    async def continue_dispatch(
        self, tx: TransactionManager, original_id: UUID, *, dispatch_id: UUID, fence: Fence
    ) -> Dispatch:
        """Claim the one repeat of an outcome_unknown dispatch, as a received
        dispatch of the same subject and action.

        A fence that raises leaves no claim, so the repeat may be claimed again.
        """
        await fence.prepare(tx)
        original = await self._lock(tx, original_id)
        if original.state is not State.OUTCOME_UNKNOWN or original.continues is not None:
            raise InvalidTransition(f"{original_id} is {original.state} and cannot be repeated")
        # Every claim holds the original's lock, so this read is authoritative.
        # Inserting over an existing continuation would wait on its row while
        # holding the original, against the continuation-first lock order.
        if await tx.fetch_value(
            "SELECT 1 FROM {{tables.dispatches}} WHERE continues = $1", original_id
        ):
            raise RepeatClaimed(f"{original_id} has already been repeated")
        async with tx.transaction() as claim_tx:
            row = await claim_tx.fetch_one(
                """
                INSERT INTO {{tables.dispatches}}
                    (dispatch_id, subject, action, retry_exempt, state, continues)
                VALUES ($1, $2, $3, $4, 'received', $5)
                RETURNING *, clock_timestamp() AS occurred_at
                """,
                dispatch_id,
                original.subject,
                original.action,
                original.retry_exempt,
                original_id,
            )
            if row is None:
                raise LookupError("the dispatch row was not returned")
            continuation = _dispatch(row)
            # The fence checks the caller's transaction; the savepoint shares it.
            await _checked(fence, tx, continuation)
        await self._notify(tx, continuation, None, row["occurred_at"])
        return continuation

    async def find(self, tx: TransactionManager, dispatch_id: UUID) -> Dispatch | None:
        row = await tx.fetch_one(
            "SELECT * FROM {{tables.dispatches}} WHERE dispatch_id = $1", dispatch_id
        )
        return None if row is None else _dispatch(row)

    async def get(self, tx: TransactionManager, dispatch_id: UUID) -> Dispatch:
        dispatch = await self.find(tx, dispatch_id)
        if dispatch is None:
            raise LookupError(f"no dispatch {dispatch_id}")
        return dispatch

    async def refuse(self, tx: TransactionManager, dispatch_id: UUID) -> Dispatch:
        return await self._move(tx, dispatch_id, State.REFUSED)

    async def await_approval(self, tx: TransactionManager, dispatch_id: UUID) -> Dispatch:
        return await self._move(tx, dispatch_id, State.AWAITING_APPROVAL)

    async def close(self, tx: TransactionManager, dispatch_id: UUID, state: State) -> Dispatch:
        """End a dispatch that was never sent: denied, expired or cancelled."""
        if state not in CLOSING_STATES:
            raise ValueError(f"{state} does not close a dispatch")
        return await self._move(tx, dispatch_id, state)

    async def admit(self, tx: TransactionManager, dispatch_id: UUID, *, fence: Fence) -> Dispatch:
        """Admit the intent, unless its subject and action await reconciliation
        or ``fence`` refuses. A fence that raises leaves the dispatch where it was."""
        await fence.prepare(tx)
        current = await self._lock(tx, dispatch_id)
        await self._lock_unsettled_original(tx, current)
        _check(current, State.ADMITTED)
        await self._check_pair(tx, current)
        await _checked(fence, tx, current)
        return await self._write(tx, current, State.ADMITTED)

    async def begin_dispatch(
        self, tx: TransactionManager, dispatch_id: UUID, *, fence: Fence
    ) -> Dispatch:
        """Prepare ``fence``, check it under the row lock, then write ``dispatching``.

        Commit before sending the first byte. A fence that raises leaves the
        dispatch where it was. A continuation is sent once: one that was not
        sent is closed, never sent again.
        """
        await fence.prepare(tx)
        current = await self._lock(tx, dispatch_id)
        await self._lock_unsettled_original(tx, current)
        if current.continues is not None and current.attempts > 0:
            raise InvalidTransition(f"{dispatch_id} repeats {current.continues} and was sent")
        _check(current, State.DISPATCHING)
        await self._check_pair(tx, current)
        await _checked(fence, tx, current)
        return await self._write(
            tx,
            current,
            State.DISPATCHING,
            "attempts = attempts + 1, sweep_after = clock_timestamp() + $3",
            self._sweep_after,
        )

    async def complete(self, tx: TransactionManager, dispatch_id: UUID, result: Any) -> bool:
        """Record a definite response; False if the sweep got there first."""
        return await self._settle(tx, dispatch_id, State.COMPLETED, result)

    async def not_sent(self, tx: TransactionManager, dispatch_id: UUID, result: Any) -> bool:
        """Record that nothing reached the upstream; False if the sweep got there first."""
        return await self._settle(tx, dispatch_id, State.NOT_SENT, result)

    async def outcome_unknown(self, tx: TransactionManager, dispatch_id: UUID, result: Any) -> bool:
        """Record an ambiguous transport outcome now; sweep remains crash recovery.

        As with complete/not_sent, an already unknown or reconciled dispatch
        retains this report as late evidence and returns False.
        """
        return await self._settle(tx, dispatch_id, State.OUTCOME_UNKNOWN, result)

    async def reconcile(
        self, tx: TransactionManager, dispatch_id: UUID, state: State, result: Any
    ) -> Dispatch:
        if state not in RECONCILED_STATES:
            raise ValueError(f"{state} does not reconcile a dispatch")
        current = await self._lock(tx, dispatch_id)
        return await self._write(tx, current, state, "result = $3::jsonb", json.dumps(result))

    async def resolve_original(
        self, tx: TransactionManager, continuation_id: UUID, state: State, result: Any
    ) -> Dispatch | None:
        """Settle the original of a completed continuation as ``state``.

        The caller maps the continuation's response to a definite state. None,
        with nothing written, if the original was already settled.
        """
        if state not in (State.RECONCILED_COMPLETED, State.RECONCILED_FAILED):
            raise ValueError(f"{state} does not settle a repeated dispatch")
        continuation = await self._lock(tx, continuation_id)
        if continuation.continues is None or continuation.state is not State.COMPLETED:
            raise InvalidTransition(f"{continuation_id} is not a completed continuation")
        original = await self._lock(tx, continuation.continues)
        if original.state in RECONCILED_STATES:
            return None
        return await self._write(tx, original, state, "result = $3::jsonb", json.dumps(result))

    async def sweep(self, db: AsyncDatabaseManager) -> int:
        """Declare every dispatch past its bound ``outcome_unknown``, one per transaction.

        A row whose transition fails is logged and left for the next sweep;
        the others are still swept.
        """
        swept = 0
        tried: list[UUID] = []
        while True:
            dispatch_id: UUID | None = None
            try:
                async with db.transaction() as tx:
                    row = await tx.fetch_one(
                        """
                        SELECT * FROM {{tables.dispatches}}
                        WHERE state = 'dispatching' AND sweep_after <= clock_timestamp()
                          AND NOT dispatch_id = ANY($1::uuid[])
                        ORDER BY sweep_after
                        LIMIT 1
                        FOR UPDATE SKIP LOCKED
                        """,
                        tried,
                    )
                    if row is None:
                        return swept
                    dispatch_id = row["dispatch_id"]
                    await self._write(tx, _dispatch(row), State.OUTCOME_UNKNOWN)
                swept += 1
            except Exception:
                if dispatch_id is None:
                    raise
                logger.exception(
                    "sweeping dispatch %s failed; it is left for the next sweep", dispatch_id
                )
                tried.append(dispatch_id)

    async def _settle(
        self, tx: TransactionManager, dispatch_id: UUID, state: State, result: Any
    ) -> bool:
        current = await self._lock(tx, dispatch_id)
        if current.state is State.DISPATCHING:
            await self._write(tx, current, state, "result = $3::jsonb", json.dumps(result))
            return True
        if current.state is State.OUTCOME_UNKNOWN or current.state in RECONCILED_STATES:
            await tx.execute(
                """
                UPDATE {{tables.dispatches}}
                SET late_results = late_results || jsonb_build_array($2::jsonb),
                    updated_at = clock_timestamp()
                WHERE dispatch_id = $1
                """,
                dispatch_id,
                json.dumps(result),
            )
            return False
        raise InvalidTransition(f"{dispatch_id} is {current.state}, not dispatching")

    async def _lock_unsettled_original(self, tx: TransactionManager, current: Dispatch) -> None:
        """Lock a continuation's original, refusing if it is no longer outcome_unknown."""
        if current.continues is None:
            return
        original = await self._lock(tx, current.continues)
        if original.state is not State.OUTCOME_UNKNOWN:
            raise InvalidTransition(
                f"{current.dispatch_id} repeats {original.dispatch_id}, which is {original.state}"
            )

    async def _check_pair(self, tx: TransactionManager, current: Dispatch) -> None:
        """Refuse a non-exempt dispatch whose pair is in flight or of unknown outcome.

        A continuation is not blocked by its own original, and a continuation
        of unknown outcome blocks nothing.
        """
        if current.retry_exempt:
            return
        await tx.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            json.dumps([current.subject, current.action]),
        )
        blocking = await tx.fetch_value(
            """
            SELECT state FROM {{tables.dispatches}}
            WHERE subject = $1 AND action = $2 AND dispatch_id <> $3
              AND dispatch_id IS DISTINCT FROM $4
              AND state IN ('dispatching', 'outcome_unknown')
              AND NOT (continues IS NOT NULL AND state = 'outcome_unknown')
            ORDER BY state = 'outcome_unknown' DESC
            LIMIT 1
            """,
            current.subject,
            current.action,
            current.dispatch_id,
            current.continues,
        )
        if blocking == State.OUTCOME_UNKNOWN:
            raise ReconciliationPending(
                f"{current.subject} has an unreconciled outcome for {current.action}"
            )
        if blocking == State.DISPATCHING:
            raise DispatchInFlight(f"{current.subject} has {current.action} in flight")

    async def _move(self, tx: TransactionManager, dispatch_id: UUID, state: State) -> Dispatch:
        return await self._write(tx, await self._lock(tx, dispatch_id), state)

    async def _lock(self, tx: TransactionManager, dispatch_id: UUID) -> Dispatch:
        row = await tx.fetch_one(
            "SELECT * FROM {{tables.dispatches}} WHERE dispatch_id = $1 FOR UPDATE", dispatch_id
        )
        if row is None:
            raise LookupError(f"no dispatch {dispatch_id}")
        return _dispatch(row)

    async def _write(
        self, tx: TransactionManager, current: Dispatch, state: State, changes: str = "", *args: Any
    ) -> Dispatch:
        _check(current, state)
        assignments = ", ".join(
            filter(None, ["state = $2", "updated_at = clock_timestamp()", changes])
        )
        row = await tx.fetch_one(
            f"""
            UPDATE {{{{tables.dispatches}}}} SET {assignments}
            WHERE dispatch_id = $1
            RETURNING *, clock_timestamp() AS occurred_at
            """,
            current.dispatch_id,
            state.value,
            *args,
        )
        if row is None:
            raise LookupError("the dispatch row was not returned")
        dispatch = _dispatch(row)
        await self._notify(tx, dispatch, current.state, row["occurred_at"])
        return dispatch

    async def _notify(
        self,
        tx: TransactionManager,
        dispatch: Dispatch,
        from_state: State | None,
        occurred_at: datetime,
    ) -> None:
        await self._on_transition(
            tx,
            Transition(
                dispatch_id=dispatch.dispatch_id,
                subject=dispatch.subject,
                action=dispatch.action,
                from_state=from_state,
                to_state=dispatch.state,
                occurred_at=occurred_at,
            ),
        )


async def _checked(fence: Fence, tx: TransactionManager, current: Dispatch) -> None:
    """Run the fence's check, refusing it if it took a lock."""
    before = await _held_locks(tx)
    await fence.check(tx, current)
    taken = await _held_locks(tx) - before
    if taken:
        raise FenceTookLock(f"a fence check took locks it must take in prepare: {sorted(taken)}")


async def _held_locks(tx: TransactionManager) -> frozenset[tuple[str, str, str]]:
    """The locks this transaction holds that can block another writer: table
    and advisory locks, but not plain reads or its own transaction ids."""
    rows = await tx.fetch_all(
        """
        SELECT locktype, mode,
               concat_ws(':', relation::regclass::text, classid, objid, objsubid) AS target
        FROM pg_locks
        WHERE pid = pg_backend_pid() AND granted
          AND locktype NOT IN ('virtualxid', 'transactionid')
          AND mode <> 'AccessShareLock'
        """
    )
    return frozenset((row["locktype"], row["mode"], row["target"]) for row in rows)


def _check(current: Dispatch, state: State) -> None:
    if state not in TRANSITIONS.get(current.state, frozenset()):
        raise InvalidTransition(f"{current.dispatch_id} cannot go from {current.state} to {state}")


def _dispatch(row: Mapping[str, Any]) -> Dispatch:
    result = row["result"]
    late = row["late_results"]
    return Dispatch(
        dispatch_id=row["dispatch_id"],
        subject=row["subject"],
        action=row["action"],
        retry_exempt=row["retry_exempt"],
        state=State(row["state"]),
        attempts=row["attempts"],
        result=json.loads(result) if isinstance(result, str) else result,
        late_results=json.loads(late) if isinstance(late, str) else list(late),
        continues=row["continues"],
    )
