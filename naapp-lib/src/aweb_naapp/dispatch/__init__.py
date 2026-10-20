"""The shared state machine for requests that cause an external effect.

A dispatch is one intent: it is received, may wait for an approval, is
admitted, and is then dispatched. ``dispatching`` is committed before the
first byte leaves, after a fence callback has re-read whatever may stop it
under a lock on the dispatch row. The outcome is ``completed`` (a definite
response), ``not_sent`` (nothing reached the upstream; it may be dispatched
again under the same id), or ``outcome_unknown``, which the sweeper writes
when a dispatch outlives its time bound. ``completed`` and ``not_sent`` are
compare-and-set from ``dispatching`` only, so a result that arrives after the
sweep is kept as evidence and never overwrites it.

While a subject has an unreconciled ``outcome_unknown`` for an action, a new
dispatch of that action for that subject is refused until it is reconciled,
unless the caller declared the action exempt.

Every transition runs in the caller's transaction and calls ``on_transition``
in that same transaction, so a failed enqueue rolls the transition back.

Imports only the standard library and pgdbm, so it needs no naapp runtime.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import UUID

from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.core import TransactionManager

MIGRATIONS_PATH = Path(__file__).resolve().parent / "migrations"
MIGRATIONS_MODULE = "aweb_naapp_dispatch"


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
    State.NOT_SENT: frozenset({State.DISPATCHING}),
    State.OUTCOME_UNKNOWN: RECONCILED_STATES,
}


class InvalidTransition(Exception):
    """The dispatch is not in a state this transition starts from."""


class ReconciliationPending(Exception):
    """The subject has an unreconciled outcome for this action."""

    code = "reconciliation_pending"


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
Fence = Callable[[TransactionManager, Dispatch], Awaitable[None]]


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
            RETURNING *, NOW() AS occurred_at
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

    async def admit(self, tx: TransactionManager, dispatch_id: UUID) -> Dispatch:
        """Admit the intent, unless its subject and action await reconciliation."""
        current = await self._lock(tx, dispatch_id)
        _check(current, State.ADMITTED)
        blocked = await tx.fetch_value(
            """
            SELECT EXISTS (
                SELECT 1 FROM {{tables.dispatches}}
                WHERE subject = $1 AND action = $2 AND state = 'outcome_unknown'
                  AND NOT retry_exempt AND dispatch_id <> $3
            )
            """,
            current.subject,
            current.action,
            dispatch_id,
        )
        if blocked:
            raise ReconciliationPending(
                f"{current.subject} has an unreconciled outcome for {current.action}"
            )
        return await self._write(tx, current, State.ADMITTED)

    async def begin_dispatch(
        self, tx: TransactionManager, dispatch_id: UUID, *, fence: Fence
    ) -> Dispatch:
        """Run ``fence`` under the row lock, then write ``dispatching``.

        Commit before sending the first byte. A fence that raises leaves the
        dispatch where it was.
        """
        current = await self._lock(tx, dispatch_id)
        _check(current, State.DISPATCHING)
        await fence(tx, current)
        return await self._write(
            tx,
            current,
            State.DISPATCHING,
            "attempts = attempts + 1, sweep_after = NOW() + $3",
            self._sweep_after,
        )

    async def complete(self, tx: TransactionManager, dispatch_id: UUID, result: Any) -> bool:
        """Record a definite response; False if the sweep got there first."""
        return await self._settle(tx, dispatch_id, State.COMPLETED, result)

    async def not_sent(self, tx: TransactionManager, dispatch_id: UUID, result: Any) -> bool:
        """Record that nothing reached the upstream; False if the sweep got there first."""
        return await self._settle(tx, dispatch_id, State.NOT_SENT, result)

    async def reconcile(
        self, tx: TransactionManager, dispatch_id: UUID, state: State, result: Any
    ) -> Dispatch:
        if state not in RECONCILED_STATES:
            raise ValueError(f"{state} does not reconcile a dispatch")
        current = await self._lock(tx, dispatch_id)
        return await self._write(tx, current, state, "result = $3::jsonb", json.dumps(result))

    async def sweep(self, db: AsyncDatabaseManager) -> int:
        """Declare every dispatch past its bound ``outcome_unknown``, one per transaction."""
        swept = 0
        while True:
            async with db.transaction() as tx:
                row = await tx.fetch_one(
                    """
                    SELECT * FROM {{tables.dispatches}}
                    WHERE state = 'dispatching' AND sweep_after <= NOW()
                    ORDER BY sweep_after
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED
                    """
                )
                if row is None:
                    return swept
                await self._write(tx, _dispatch(row), State.OUTCOME_UNKNOWN)
                swept += 1

    async def _settle(
        self, tx: TransactionManager, dispatch_id: UUID, state: State, result: Any
    ) -> bool:
        current = await self._lock(tx, dispatch_id)
        if current.state is State.DISPATCHING:
            await self._write(tx, current, state, "result = $3::jsonb", json.dumps(result))
            return True
        if current.state is State.OUTCOME_UNKNOWN:
            await tx.execute(
                """
                UPDATE {{tables.dispatches}}
                SET late_results = late_results || jsonb_build_array($2::jsonb),
                    updated_at = NOW()
                WHERE dispatch_id = $1
                """,
                dispatch_id,
                json.dumps(result),
            )
            return False
        raise InvalidTransition(f"{dispatch_id} is {current.state}, not dispatching")

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
        assignments = ", ".join(filter(None, ["state = $2", "updated_at = NOW()", changes]))
        row = await tx.fetch_one(
            f"""
            UPDATE {{{{tables.dispatches}}}} SET {assignments}
            WHERE dispatch_id = $1
            RETURNING *, NOW() AS occurred_at
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
    )
