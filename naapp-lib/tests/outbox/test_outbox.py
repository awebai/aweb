"""The shared durable outbox on real PostgreSQL."""

from __future__ import annotations

import hashlib
import subprocess
import sys
from collections.abc import AsyncIterator, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from pgdbm import AsyncDatabaseManager

from aweb_naapp.outbox import (
    Acked,
    Cancelled,
    Conflict,
    OutboxConflict,
    OutboxEvent,
    Permanent,
    Retryable,
    RetryPolicy,
    StoredEvent,
    Target,
    acknowledge_dead_letters,
    apply_outbox_migrations,
    cancel,
    drain,
    enqueue,
    latest_receipt,
    mint_event_id,
    next_sequence,
    outbox_status,
    redrive,
)

_CHILD = Path(__file__).with_name("drain_child.py")
_POLICY = RetryPolicy(stalled_after=timedelta(hours=1))
_TEAM = "backend:example.com"


@pytest.fixture
async def db(test_db_factory) -> AsyncIterator[AsyncDatabaseManager]:
    database = await test_db_factory.create_db(suffix="naapp_outbox")
    await apply_outbox_migrations(database)
    yield database


def _event(payload: bytes = b'{"n":1}', *, critical: bool = False, **changes) -> OutboxEvent:
    values = dict(
        event_id=mint_event_id(),
        team_id=_TEAM,
        kind="example/thing.changed",
        occurred_at=datetime.now(UTC),
        payload=payload,
        signature="sig",
        critical=critical,
        producer={"seq": 1},
    )
    values.update(changes)
    return OutboxEvent(**values)


class Targets:
    """A resolver returning fixed targets, recording each call."""

    def __init__(self, targets: Sequence[Target] | None) -> None:
        self.targets = targets
        self.calls: list[UUID] = []

    async def __call__(self, event: StoredEvent) -> Sequence[Target] | None:
        self.calls.append(event.event_id)
        return self.targets


class Scripted:
    """A transport answering each target with a fixed outcome, recording what it sent."""

    def __init__(self, outcomes: dict[str, object]) -> None:
        self.outcomes = outcomes
        self.sent: list[tuple[UUID, str, bytes, dict]] = []

    async def deliver(self, event: StoredEvent, target: Target):
        self.sent.append((event.event_id, target.id, event.payload, dict(target.meta)))
        outcome = self.outcomes[target.id]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


async def _states(db: AsyncDatabaseManager) -> dict[str, str]:
    rows = await db.fetch_all("SELECT target_id, state FROM {{tables.outbox_deliveries}}")
    return {row["target_id"]: row["state"] for row in rows}


async def _make_due(db: AsyncDatabaseManager) -> None:
    await db.execute("UPDATE {{tables.outbox_deliveries}} SET next_attempt_at = NOW()")


async def test_enqueue_commits_and_rolls_back_with_the_callers_transaction(db) -> None:
    kept, dropped = _event(), _event()
    async with db.transaction() as tx:
        await enqueue(tx, kept)
    with pytest.raises(RuntimeError):
        async with db.transaction() as tx:
            await enqueue(tx, dropped)
            raise RuntimeError("the effect failed")
    ids = [
        row["event_id"]
        for row in await db.fetch_all("SELECT event_id FROM {{tables.outbox_events}}")
    ]
    assert ids == [kept.event_id]


async def test_enqueueing_the_same_event_again_is_a_no_op_and_different_bytes_conflict(db) -> None:
    event = _event()
    for _ in range(2):
        async with db.transaction() as tx:
            await enqueue(tx, event)
    assert await db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 1
    for changed in (
        OutboxEvent(**{**event.__dict__, "payload": b'{"n":2}'}),
        OutboxEvent(**{**event.__dict__, "signature": "other"}),
        OutboxEvent(**{**event.__dict__, "team_id": "other:example.com"}),
    ):
        with pytest.raises(OutboxConflict):
            async with db.transaction() as tx:
                await enqueue(tx, changed)


async def test_event_ids_are_random_and_minted_once() -> None:
    ids = {mint_event_id() for _ in range(100)}
    assert len(ids) == 100
    assert all(event_id.version == 4 for event_id in ids)


async def test_sequences_count_per_scope_and_team_in_the_callers_transaction(db) -> None:
    async with db.transaction() as tx:
        first = [await next_sequence(tx, scope="secrets:hook", team_id=_TEAM) for _ in range(3)]
        other = await next_sequence(tx, scope="secrets:hook", team_id="other:example.com")
    with pytest.raises(RuntimeError):
        async with db.transaction() as tx:
            await next_sequence(tx, scope="secrets:hook", team_id=_TEAM)
            raise RuntimeError("rolled back")
    async with db.transaction() as tx:
        after = await next_sequence(tx, scope="secrets:hook", team_id=_TEAM)
    assert (first, other, after) == ([1, 2, 3], 1, 4)


async def test_drain_delivers_each_target_the_exact_bytes_with_its_metadata(db) -> None:
    event = _event(b'{"exact":"bytes"}')
    async with db.transaction() as tx:
        await enqueue(tx, event)
    targets = Targets([Target("a", {"origin": "https://a.example"}), Target("b")])
    transport = Scripted({"a": Acked("delivered", b"receipt-a"), "b": Acked("duplicate", None)})

    result = await drain(
        db, channel="default", resolver=targets, transport=transport, policy=_POLICY
    )

    assert sorted(transport.sent, key=lambda sent: sent[1]) == [
        (event.event_id, "a", b'{"exact":"bytes"}', {"origin": "https://a.example"}),
        (event.event_id, "b", b'{"exact":"bytes"}', {}),
    ]
    assert result.delivered == 2
    assert await _states(db) == {"a": "delivered", "b": "duplicate"}
    assert await latest_receipt(db, "a") == b"receipt-a"


async def test_a_drained_event_keeps_a_tombstone_and_its_receipts(db) -> None:
    event = _event(b"payload")
    async with db.transaction() as tx:
        await enqueue(tx, event)
    await drain(
        db,
        channel="default",
        resolver=Targets([Target("a")]),
        transport=Scripted({"a": Acked("delivered", b"r")}),
        policy=_POLICY,
    )
    row = await db.fetch_one(
        "SELECT payload, payload_sha256, drained_at FROM {{tables.outbox_events}}"
    )
    assert row["payload"] is None
    assert row["payload_sha256"] == hashlib.sha256(b"payload").hexdigest()
    assert row["drained_at"] is not None
    assert await latest_receipt(db, "a") == b"r"
    async with db.transaction() as tx:
        await enqueue(tx, event)
    with pytest.raises(OutboxConflict):
        async with db.transaction() as tx:
            await enqueue(tx, OutboxEvent(**{**event.__dict__, "payload": b"other"}))


async def test_latest_receipt_follows_arrival_order_not_enqueue_order(db) -> None:
    early, late, replayed = _event(b"early"), _event(b"late"), _event(b"replayed")
    async with db.transaction() as tx:
        for event in (early, late, replayed):
            await enqueue(tx, event)
    outcomes = {
        b"early": [Retryable("ConnectError"), Acked("delivered", b"receipt-early")],
        b"late": [Acked("delivered", b"receipt-late")],
        b"replayed": [Retryable("ConnectError"), Acked("duplicate", b"receipt-old")],
    }

    class InTurn(Scripted):
        async def deliver(self, event: StoredEvent, target: Target):
            return outcomes[event.payload].pop(0)

    resolver, transport = Targets([Target("a")]), InTurn({})
    await drain(db, channel="default", resolver=resolver, transport=transport, policy=_POLICY)
    assert await latest_receipt(db, "a") == b"receipt-late"
    await _make_due(db)
    await drain(db, channel="default", resolver=resolver, transport=transport, policy=_POLICY)
    # early arrived last, so its receipt commits to the longest prefix; a duplicate
    # ack carries an older receipt and never replaces it.
    assert await latest_receipt(db, "a") == b"receipt-early"
    assert await latest_receipt(db, "unknown") is None


async def test_latest_receipt_falls_back_to_duplicates_when_nothing_was_appended(db) -> None:
    async with db.transaction() as tx:
        await enqueue(tx, _event())
    await drain(
        db,
        channel="default",
        resolver=Targets([Target("a")]),
        transport=Scripted({"a": Acked("duplicate", b"dup")}),
        policy=_POLICY,
    )
    assert await latest_receipt(db, "a") == b"dup"


async def test_retryable_failures_back_off_per_target_and_are_never_dropped(db) -> None:
    async with db.transaction() as tx:
        await enqueue(tx, _event())
    transport = Scripted({"a": Retryable("ConnectError"), "b": Acked("delivered", None)})
    resolver = Targets([Target("a"), Target("b")])

    await drain(db, channel="default", resolver=resolver, transport=transport, policy=_POLICY)
    row = await db.fetch_one(
        "SELECT state, attempts, last_error_class, next_attempt_at > NOW() AS later"
        " FROM {{tables.outbox_deliveries}} WHERE target_id = 'a'"
    )
    assert dict(row) == {
        "state": "pending",
        "attempts": 1,
        "last_error_class": "ConnectError",
        "later": True,
    }
    assert (await _states(db))["b"] == "delivered"

    sent_before = len(transport.sent)
    await drain(db, channel="default", resolver=resolver, transport=transport, policy=_POLICY)
    assert len(transport.sent) == sent_before, "a backed-off delivery is not retried early"

    first_delay = await db.fetch_value(
        "SELECT next_attempt_at - updated_at FROM {{tables.outbox_deliveries}} WHERE target_id = 'a'"
    )
    await _make_due(db)
    await drain(db, channel="default", resolver=resolver, transport=transport, policy=_POLICY)
    second_delay = await db.fetch_value(
        "SELECT next_attempt_at - updated_at FROM {{tables.outbox_deliveries}} WHERE target_id = 'a'"
    )
    assert second_delay > first_delay
    assert (await _states(db))["a"] == "pending"


async def test_the_backoff_is_capped(db) -> None:
    policy = RetryPolicy(stalled_after=timedelta(hours=1), base_seconds=5, max_seconds=30)
    async with db.transaction() as tx:
        await enqueue(tx, _event())
    transport = Scripted({"a": Retryable("Timeout")})
    for attempt in range(6):
        if attempt:
            await _make_due(db)
        await drain(
            db,
            channel="default",
            resolver=Targets([Target("a")]),
            transport=transport,
            policy=policy,
        )
    delay = await db.fetch_value(
        "SELECT EXTRACT(EPOCH FROM next_attempt_at - updated_at) FROM {{tables.outbox_deliveries}}"
    )
    assert float(delay) == pytest.approx(30, abs=1)


async def test_a_transport_exception_is_retried_like_a_retryable_failure(db) -> None:
    async with db.transaction() as tx:
        await enqueue(tx, _event())
    await drain(
        db,
        channel="default",
        resolver=Targets([Target("a")]),
        transport=Scripted({"a": ConnectionResetError()}),
        policy=_POLICY,
    )
    row = await db.fetch_one(
        "SELECT state, attempts, last_error_class FROM {{tables.outbox_deliveries}}"
    )
    assert dict(row) == {
        "state": "pending",
        "attempts": 1,
        "last_error_class": "ConnectionResetError",
    }


async def test_permanent_failures_are_rejected_only_after_the_bounded_attempts(db) -> None:
    policy = RetryPolicy(stalled_after=timedelta(hours=1), rejected_after_attempts=3)
    assert RetryPolicy(stalled_after=timedelta(hours=1)).rejected_after_attempts == 8
    async with db.transaction() as tx:
        await enqueue(tx, _event())
    transport = Scripted({"a": Permanent("schema_rejected")})
    states = []
    for _ in range(3):
        await drain(
            db,
            channel="default",
            resolver=Targets([Target("a")]),
            transport=transport,
            policy=policy,
        )
        states.append((await _states(db))["a"])
        await _make_due(db)
    assert states == ["pending", "pending", "rejected"]


async def test_a_conflict_is_terminal_at_once(db) -> None:
    async with db.transaction() as tx:
        await enqueue(tx, _event())
    transport = Scripted({"a": Conflict()})
    await drain(
        db, channel="default", resolver=Targets([Target("a")]), transport=transport, policy=_POLICY
    )
    await _make_due(db)
    await drain(
        db, channel="default", resolver=Targets([Target("a")]), transport=transport, policy=_POLICY
    )
    assert (await _states(db))["a"] == "conflict"
    assert len(transport.sent) == 1


async def test_a_target_revoked_before_send_ends_cancelled_not_rejected(db) -> None:
    async with db.transaction() as tx:
        await enqueue(tx, _event(critical=False))
    await drain(
        db,
        channel="default",
        resolver=Targets([Target("a")]),
        transport=Scripted({"a": Cancelled("binding_revoked")}),
        policy=_POLICY,
    )
    row = await db.fetch_one("SELECT state, cancel_reason FROM {{tables.outbox_deliveries}}")
    assert dict(row) == {"state": "cancelled", "cancel_reason": "binding_revoked"}
    status = await outbox_status(db)
    assert status.targets["a"].dead_letter == 0
    assert status.targets["a"].cancelled == 1


async def test_past_the_horizon_a_retrying_delivery_is_stalled_and_still_retried(db) -> None:
    policy = RetryPolicy(stalled_after=timedelta(seconds=0))
    async with db.transaction() as tx:
        await enqueue(tx, _event())
    transport = Scripted({"a": Retryable("ConnectError")})
    await drain(
        db, channel="default", resolver=Targets([Target("a")]), transport=transport, policy=policy
    )
    assert (await _states(db))["a"] == "stalled"
    await _make_due(db)
    transport.outcomes["a"] = Acked("delivered", None)
    await drain(
        db, channel="default", resolver=Targets([Target("a")]), transport=transport, policy=policy
    )
    assert (await _states(db))["a"] == "delivered"


async def test_an_unresolvable_event_stays_pending_and_counts_as_undelivered(db) -> None:
    async with db.transaction() as tx:
        await enqueue(tx, _event())
    resolver = Targets(None)
    for _ in range(2):
        await drain(
            db, channel="default", resolver=resolver, transport=Scripted({}), policy=_POLICY
        )
    assert len(resolver.calls) == 2
    assert await db.fetch_value("SELECT count(*) FROM {{tables.outbox_deliveries}}") == 0
    status = await outbox_status(db)
    assert status.unmaterialized[_TEAM].count == 1
    assert status.unmaterialized[_TEAM].oldest_age_seconds >= 0
    assert status.targets == {}


async def test_a_resolver_exception_leaves_the_event_unmaterialized(db) -> None:
    async with db.transaction() as tx:
        await enqueue(tx, _event())

    async def broken(event: StoredEvent):
        raise ConnectionError("registry down")

    await drain(db, channel="default", resolver=broken, transport=Scripted({}), policy=_POLICY)
    assert (await outbox_status(db)).unmaterialized[_TEAM].count == 1


async def test_cancel_cancels_a_targets_backlog_except_the_given_events(db) -> None:
    revocation, backlog = _event(b"revocation"), _event(b"backlog")
    async with db.transaction() as tx:
        await enqueue(tx, revocation)
        await enqueue(tx, backlog)
    transport = Scripted({"a": Retryable("ConnectError"), "b": Retryable("ConnectError")})
    await drain(
        db,
        channel="default",
        resolver=Targets([Target("a"), Target("b")]),
        transport=transport,
        policy=_POLICY,
    )

    cancelled = await cancel(db, "a", except_event_ids=[revocation.event_id])

    assert cancelled == [backlog.event_id]
    rows = await db.fetch_all(
        "SELECT event_id, target_id, state FROM {{tables.outbox_deliveries}} ORDER BY target_id"
    )
    states = {(row["event_id"], row["target_id"]): row["state"] for row in rows}
    assert states[(backlog.event_id, "a")] == "cancelled"
    assert states[(revocation.event_id, "a")] == "pending"
    assert states[(backlog.event_id, "b")] == "pending"


async def test_status_reports_per_target_backlog_and_its_oldest_age(db) -> None:
    async with db.transaction() as tx:
        for _ in range(2):
            await enqueue(tx, _event())
    transport = Scripted({"a": Retryable("ConnectError"), "b": Acked("delivered", None)})
    await drain(
        db,
        channel="default",
        resolver=Targets([Target("a"), Target("b")]),
        transport=transport,
        policy=_POLICY,
    )
    status = await outbox_status(db)
    assert (status.targets["a"].pending, status.targets["a"].dead_letter) == (2, 0)
    assert status.targets["a"].oldest_undelivered_age_seconds >= 0
    assert status.targets["b"].pending == 0
    assert status.targets["b"].oldest_undelivered_age_seconds is None
    assert status.unmaterialized == {}


async def test_a_critical_event_with_no_surviving_delivery_is_a_fault(db) -> None:
    cancelled_out, rejected, no_targets, delivered, ordinary = (
        _event(b"1", critical=True),
        _event(b"2", critical=True),
        _event(b"3", critical=True),
        _event(b"4", critical=True),
        _event(b"5", critical=False),
    )
    policy = RetryPolicy(stalled_after=timedelta(hours=1), rejected_after_attempts=1)
    by_payload = {
        b"1": Cancelled("binding_revoked"),
        b"2": Permanent("schema_rejected"),
        b"4": Acked("delivered", None),
        b"5": Cancelled("binding_revoked"),
    }

    class ByPayload(Scripted):
        async def deliver(self, event: StoredEvent, target: Target):
            return by_payload[event.payload]

    async def resolver(event: StoredEvent):
        return [] if event.payload == b"3" else [Target("a")]

    async with db.transaction() as tx:
        for event in (cancelled_out, rejected, no_targets, delivered, ordinary):
            await enqueue(tx, event)
    await drain(db, channel="default", resolver=resolver, transport=ByPayload({}), policy=policy)

    status = await outbox_status(db)
    assert sorted(status.faults) == sorted(
        [cancelled_out.event_id, rejected.event_id, no_targets.event_id]
    )
    assert status.targets["a"].dead_letter == 1


async def test_nothing_is_lost_or_duplicated_when_a_drain_is_killed_mid_send(
    db, tmp_path: Path
) -> None:
    event = _event(b"survives")
    async with db.transaction() as tx:
        await enqueue(tx, event)
    sending = tmp_path / "sending"
    child = subprocess.Popen(
        [sys.executable, str(_CHILD), db.config.get_dsn(), str(sending)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        for _ in range(300):
            if sending.exists() or child.poll() is not None:
                break
            await _sleep(0.05)
    finally:
        child.kill()
        _, stderr = child.communicate(timeout=10)
    assert sending.exists(), stderr.decode()
    assert child.returncode == -9

    # The materialization committed before the send: it survives and is not redone.
    rows = await db.fetch_all("SELECT target_id, state, attempts FROM {{tables.outbox_deliveries}}")
    assert [dict(row) for row in rows] == [{"target_id": "a", "state": "pending", "attempts": 0}]

    resolver = Targets([Target("a"), Target("extra")])
    transport = Scripted({"a": Acked("delivered", b"after-restart")})
    await _make_due(db)
    await drain(db, channel="default", resolver=resolver, transport=transport, policy=_POLICY)
    assert resolver.calls == []
    assert transport.sent == [(event.event_id, "a", b"survives", {})]
    assert await _states(db) == {"a": "delivered"}


async def _sleep(seconds: float) -> None:
    import asyncio

    await asyncio.sleep(seconds)


async def _payload(db, event: OutboxEvent) -> bytes | None:
    value = await db.fetch_value(
        "SELECT payload FROM {{tables.outbox_events}} WHERE event_id = $1", event.event_id
    )
    return bytes(value) if value is not None else None


async def test_a_rejected_delivery_keeps_its_bytes_until_redriven_and_delivered(db) -> None:
    event = _event(b"keep me", critical=True)
    async with db.transaction() as tx:
        await enqueue(tx, event)
    policy = RetryPolicy(stalled_after=timedelta(hours=1), rejected_after_attempts=1)
    transport = Scripted({"a": Permanent("schema_rejected")})
    await drain(
        db, channel="default", resolver=Targets([Target("a")]), transport=transport, policy=policy
    )
    await drain(
        db, channel="default", resolver=Targets([Target("a")]), transport=transport, policy=policy
    )
    assert (await _states(db))["a"] == "rejected"
    assert await _payload(db, event) == b"keep me"

    assert await redrive(db, "a", [event.event_id]) == [event.event_id]
    transport.outcomes["a"] = Acked("delivered", None)
    await drain(
        db, channel="default", resolver=Targets([Target("a")]), transport=transport, policy=policy
    )
    assert (await _states(db))["a"] == "delivered"
    assert await _payload(db, event) is None
    assert transport.sent[-1][2] == b"keep me"


async def test_a_conflict_keeps_its_bytes_until_the_loss_is_acknowledged(db) -> None:
    event = _event(b"conflicting")
    async with db.transaction() as tx:
        await enqueue(tx, event)
    await drain(
        db,
        channel="default",
        resolver=Targets([Target("a")]),
        transport=Scripted({"a": Conflict()}),
        policy=_POLICY,
    )
    await drain(
        db,
        channel="default",
        resolver=Targets([Target("a")]),
        transport=Scripted({}),
        policy=_POLICY,
    )
    assert await _payload(db, event) == b"conflicting"
    assert (await outbox_status(db)).targets["a"].dead_letter == 1

    assert await redrive(db, "a", [event.event_id]) == []
    assert await acknowledge_dead_letters(db, "a", [event.event_id]) == [event.event_id]
    await drain(
        db,
        channel="default",
        resolver=Targets([Target("a")]),
        transport=Scripted({}),
        policy=_POLICY,
    )
    assert await _payload(db, event) is None
    assert (await _states(db))["a"] == "conflict"
    assert (await outbox_status(db)).targets["a"].dead_letter == 0


async def test_redrive_and_acknowledge_touch_only_the_named_dead_letters(db) -> None:
    named, other = _event(b"named"), _event(b"other")
    async with db.transaction() as tx:
        await enqueue(tx, named)
        await enqueue(tx, other)
    policy = RetryPolicy(stalled_after=timedelta(hours=1), rejected_after_attempts=1)
    await drain(
        db,
        channel="default",
        resolver=Targets([Target("a")]),
        transport=Scripted({"a": Permanent("x")}),
        policy=policy,
    )
    assert await redrive(db, "a", [named.event_id]) == [named.event_id]
    assert await redrive(db, "b", [other.event_id]) == []
    rows = await db.fetch_all("SELECT event_id, state FROM {{tables.outbox_deliveries}}")
    assert {row["event_id"]: row["state"] for row in rows} == {
        named.event_id: "pending",
        other.event_id: "rejected",
    }


def test_the_call_timeout_is_bounded() -> None:
    assert RetryPolicy(stalled_after=timedelta(hours=1)).call_timeout_seconds == 30
    for bad in (0, -1, 30.5):
        with pytest.raises(ValueError):
            RetryPolicy(stalled_after=timedelta(hours=1), call_timeout_seconds=bad)


async def test_a_hung_transport_times_out_as_a_retryable_failure(db) -> None:
    async with db.transaction() as tx:
        await enqueue(tx, _event())

    class Hung:
        async def deliver(self, event: StoredEvent, target: Target):
            await _sleep(60)

    policy = RetryPolicy(stalled_after=timedelta(hours=1), call_timeout_seconds=0.2)
    await drain(
        db, channel="default", resolver=Targets([Target("a")]), transport=Hung(), policy=policy
    )
    row = await db.fetch_one(
        "SELECT state, attempts, last_error_class FROM {{tables.outbox_deliveries}}"
    )
    assert dict(row) == {"state": "pending", "attempts": 1, "last_error_class": "timeout"}


async def test_a_hung_resolver_times_out_and_leaves_the_event_unmaterialized(db) -> None:
    async with db.transaction() as tx:
        await enqueue(tx, _event())

    async def hung(event: StoredEvent):
        await _sleep(60)

    policy = RetryPolicy(stalled_after=timedelta(hours=1), call_timeout_seconds=0.2)
    await drain(db, channel="default", resolver=hung, transport=Scripted({}), policy=policy)
    assert (await outbox_status(db)).unmaterialized[_TEAM].count == 1


async def test_a_drain_claims_only_its_own_channel(db) -> None:
    wake, hook = _event(b"wake", channel="app-events"), _event(b"hook", channel="hooks")
    async with db.transaction() as tx:
        await enqueue(tx, wake)
        await enqueue(tx, hook)
    resolver = Targets([Target("app-events")])
    transport = Scripted({"app-events": Acked("delivered", None)})

    await drain(db, channel="app-events", resolver=resolver, transport=transport, policy=_POLICY)

    assert resolver.calls == [wake.event_id]
    assert [sent[0] for sent in transport.sent] == [wake.event_id]
    hooks = await outbox_status(db, channel="hooks")
    assert hooks.unmaterialized[_TEAM].count == 1
    assert hooks.targets == {}


async def test_status_per_channel_keeps_one_channels_stall_out_of_the_other(db) -> None:
    async with db.transaction() as tx:
        await enqueue(tx, _event(b"wake", channel="app-events"))
        await enqueue(tx, _event(b"hook", channel="hooks"))
    await drain(
        db,
        channel="app-events",
        resolver=Targets([Target("app-events")]),
        transport=Scripted({"app-events": Retryable("ConnectError")}),
        policy=_POLICY,
    )
    await drain(
        db,
        channel="hooks",
        resolver=Targets([Target("binding-1")]),
        transport=Scripted({"binding-1": Acked("delivered", None)}),
        policy=_POLICY,
    )
    wakes, hooks, everything = (
        await outbox_status(db, channel="app-events"),
        await outbox_status(db, channel="hooks"),
        await outbox_status(db),
    )
    assert wakes.targets["app-events"].oldest_undelivered_age_seconds is not None
    assert set(wakes.targets) == {"app-events"}
    assert set(hooks.targets) == {"binding-1"}
    assert hooks.targets["binding-1"].oldest_undelivered_age_seconds is None
    assert set(everything.targets) == {"app-events", "binding-1"}


async def test_the_same_event_id_on_another_channel_is_a_conflict(db) -> None:
    event = _event(channel="hooks")
    async with db.transaction() as tx:
        await enqueue(tx, event)
    with pytest.raises(OutboxConflict):
        async with db.transaction() as tx:
            await enqueue(tx, OutboxEvent(**{**event.__dict__, "channel": "app-events"}))


async def test_a_target_id_used_on_another_channel_is_refused_and_the_event_waits(db) -> None:
    first, second = _event(b"1", channel="hooks"), _event(b"2", channel="app-events")
    async with db.transaction() as tx:
        await enqueue(tx, first)
        await enqueue(tx, second)
    shared = Targets([Target("same-id")])
    transport = Scripted({"same-id": Acked("delivered", None)})
    await drain(db, channel="hooks", resolver=shared, transport=transport, policy=_POLICY)
    await drain(db, channel="app-events", resolver=shared, transport=transport, policy=_POLICY)

    rows = await db.fetch_all("SELECT event_id FROM {{tables.outbox_deliveries}}")
    assert [row["event_id"] for row in rows] == [first.event_id]
    assert (await outbox_status(db, channel="app-events")).unmaterialized[_TEAM].count == 1


def test_events_default_to_the_default_channel() -> None:
    assert _event().channel == "default"
