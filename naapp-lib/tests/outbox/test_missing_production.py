"""Typed signer-loss accounting stays local and shares the real sequence lock."""

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import asyncpg
import pytest
from nacl.signing import SigningKey
from pgdbm.errors import QueryError

from aweb_naapp.hooks.envelope import verify
from aweb_naapp.hooks.producer import HookProducer, Registration, RegistrationView, ServerProducer
from aweb_naapp.outbox import (
    OutboxConflict,
    OutboxEvent,
    RetryPolicy,
    acknowledge_dead_letters,
    cancel,
    drain,
    enqueue,
    latest_receipt,
    outbox_status,
    redrive,
    reserve_missing_production,
)
from tests.outbox.test_outbox import db as db

TEAM = "backend:example.com"
HOOK = "post-mutation-hook"
ORIGIN = "https://core.example"
SCOPE = "core:" + HOOK
BINDING = str(uuid4())
SYSTEM = {"authority_mode": "system", "attestations": []}


async def reserve(tx, **changes):
    fields = dict(
        team_id=TEAM,
        scope=SCOPE,
        origin=ORIGIN,
        kind=HOOK,
        channel="hooks",
        occurred_at=datetime.now(UTC),
        reason="key_out_of_window",
        binding_ids=[BINDING],
    )
    fields.update(changes)
    return await reserve_missing_production(tx, **fields)


def producer():
    return HookProducer(
        ServerProducer.core(origin=ORIGIN, kid="core", seed=bytes(SigningKey.generate()))
    )


async def signed(tx, signer):
    return await signer.enqueue(
        tx,
        hook=HOOK,
        team_id=TEAM,
        actor=SYSTEM,
        occurred_at=datetime.now(UTC),
        result_status="success",
        payload={
            "mutation_type": "app_key.revoked",
            "target_ref": "app:fixture",
            "app_id": "fixture",
            "kid": "old",
            "purposes": ["hook-event"],
        },
    )


async def test_reservation_and_effect_commit_or_rollback_together(db):
    await db.execute("CREATE TABLE effects (n INTEGER)")
    async with db.transaction() as tx:
        await tx.execute("INSERT INTO effects VALUES (1)")
        kept = await reserve(tx)
    with pytest.raises(RuntimeError):
        async with db.transaction() as tx:
            await tx.execute("INSERT INTO effects VALUES (2)")
            await reserve(tx)
            raise RuntimeError("abort effect")
    async with db.transaction() as tx:
        after = await reserve(tx)
    assert (kept.sequence, after.sequence) == (1, 2)
    assert await db.fetch_value("SELECT count(*) FROM effects") == 1
    rows = await db.fetch_all("SELECT * FROM {{tables.outbox_events}} ORDER BY position")
    assert len(rows) == 2
    for row in rows:
        assert row["record_type"] == "missing_production"
        assert row["payload"] is row["payload_sha256"] is row["signature"] is None
        assert row["reservation_scope"] == SCOPE
        assert row["producer_origin"] == ORIGIN
        assert row["owed_binding_ids"] == [BINDING]


async def test_signed_events_and_reservations_serialize_one_counter_without_recovery(db):
    signer = producer()

    async def firing(index):
        async with db.transaction() as tx:
            if index % 2:
                await reserve(tx)
            else:
                await signed(tx, signer)

    await asyncio.gather(*(firing(index) for index in range(8)))
    async with db.transaction() as tx:
        last = await signed(tx, signer)
    rows = await db.fetch_all("SELECT * FROM {{tables.outbox_events}} ORDER BY position")
    seqs = []
    for row in rows:
        if row["record_type"] == "event":
            seqs.append(
                verify(bytes(row["payload"]), row["signature"], team_id=TEAM).fields["producer"][
                    "seq"
                ]
            )
        else:
            seqs.append(row["reservation_seq"])
    assert sorted(seqs) == list(range(1, 10))
    last_row = next(row for row in rows if row["event_id"] == last)
    assert (
        verify(bytes(last_row["payload"]), last_row["signature"], team_id=TEAM).fields["producer"][
            "seq"
        ]
        == 9
    )
    assert sum(row["record_type"] == "missing_production" for row in rows) == 4


async def test_reservation_is_never_an_event_delivery_backlog_receipt_or_fault(db):
    async with db.transaction() as tx:
        record = await reserve(tx)

    async def no_resolver(event):
        pytest.fail("a local reservation reached materialization")

    class NoTransport:
        async def deliver(self, event, target):
            pytest.fail("a local reservation reached transport")

    result = await drain(
        db,
        channel="hooks",
        resolver=no_resolver,
        transport=NoTransport(),
        policy=RetryPolicy(stalled_after=timedelta(seconds=1)),
    )
    assert (result.materialized, result.delivered, result.failed, result.finished) == (0, 0, 0, 0)
    for channel in (None, "hooks"):
        status = await outbox_status(db, channel)
        assert not status.targets and not status.unmaterialized and not status.faults
    assert await cancel(db, BINDING) == []
    assert await redrive(db, BINDING, [record.record_id]) == []
    assert await acknowledge_dead_letters(db, BINDING, [record.record_id]) == []
    assert await latest_receipt(db, BINDING) is None
    with pytest.raises(QueryError) as rejected:
        await db.execute(
            "INSERT INTO {{tables.outbox_deliveries}} (event_id,target_id) VALUES ($1,$2)",
            record.record_id,
            BINDING,
        )
    assert isinstance(rejected.value.__cause__, asyncpg.ForeignKeyViolationError)
    with pytest.raises(OutboxConflict):
        async with db.transaction() as tx:
            await enqueue(
                tx, OutboxEvent(record.record_id, TEAM, HOOK, datetime.now(UTC), b"fabricated")
            )
    row = await db.fetch_one(
        "SELECT * FROM {{tables.outbox_events}} WHERE event_id=$1", record.record_id
    )
    assert row["materialized_at"] is row["drained_at"] is None
    assert row["missing_reason"] == "key_out_of_window"


async def test_old_reservation_is_excluded_from_shared_admission_scanner(db):
    now = datetime.now(UTC)
    async with db.transaction() as tx:
        await reserve(tx, occurred_at=now - timedelta(hours=2))
    await db.execute("UPDATE {{tables.outbox_events}} SET created_at=NOW()-INTERVAL '2 hours'")
    view = RegistrationView(
        TEAM,
        HOOK,
        now,
        timedelta(seconds=60),
        (
            Registration(
                BINDING, "https://logs.example", "POST", "/ingest", now - timedelta(days=1)
            ),
        ),
    )
    async with db.transaction() as tx:
        await producer().require_admission(
            tx,
            team_id=TEAM,
            hook=HOOK,
            occurred_at=now,
            view=view,
            max_backlog_age=timedelta(seconds=1),
        )


@pytest.mark.parametrize("changes", [{"reason": "arbitrary"}, {"binding_ids": []}, {"scope": ""}])
async def test_invalid_local_record_never_spends_a_sequence(db, changes):
    with pytest.raises(ValueError):
        async with db.transaction() as tx:
            await reserve(tx, **changes)
    assert await db.fetch_value("SELECT count(*) FROM {{tables.outbox_sequences}}") == 0


async def test_one_firing_shares_one_record_across_all_owed_bindings(db):
    other = str(uuid4())
    async with db.transaction() as tx:
        record = await reserve(tx, binding_ids=[BINDING, other, BINDING])
    row = await db.fetch_one("SELECT * FROM {{tables.outbox_events}}")
    assert row["event_id"] == record.record_id
    assert row["reservation_seq"] == 1
    assert row["owed_binding_ids"] == sorted([BINDING, other])
    assert await db.fetch_value("SELECT last_seq FROM {{tables.outbox_sequences}}") == 1
    with pytest.raises(QueryError) as rejected:
        await db.execute(
            "UPDATE {{tables.outbox_events}} SET signature='fabricated' WHERE event_id=$1",
            record.record_id,
        )
    assert isinstance(rejected.value.__cause__, asyncpg.CheckViolationError)
