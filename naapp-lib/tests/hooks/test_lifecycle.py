"""Non-authorizing lifecycle recording on real PostgreSQL and real signatures."""

from dataclasses import replace
from datetime import timedelta

import asyncpg
import pytest

from aweb_naapp.hooks.envelope import verify
from aweb_naapp.hooks.producer import HookProducer, ServerProducer
from aweb_naapp.hooks.strictjson import Refused
from tests.hooks.test_admission import backlog, require
from tests.hooks.test_producer import (
    NOW,
    TEAM,
    app_producer,
    events,
    payload,
    registration,
    view,
)
from tests.hooks.test_producer import db as db

HOOK = "post-secret-use-hook"
LIFECYCLES = (
    "approval_denied",
    "approval_expired",
    "cancelled",
    "completed",
    "not_sent",
    "outcome_unknown",
    "reconciled_completed",
    "reconciled_failed",
    "reconciled_unknown",
)
AUTHORIZING = ("awaiting_approval", "approval_approved", "admitted", "dispatching")
TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"
REQUESTER = {
    "authority_mode": "team_cert",
    "attestations": [],
    "did_key": app_producer().producer.did_key,
    "certificate_id": "original-request-certificate",
    "alias": "requesting-member",
}


def body(transition):
    return payload("secret_use_lifecycle_" + transition)


def options(transition):
    return dict(
        team_id=TEAM,
        payload=body(transition),
        actor=REQUESTER,
        occurred_at=NOW,
        result_status="success",
        signed_trace_id=TRACE,
    )


@pytest.mark.parametrize("transition", LIFECYCLES)
async def test_lifecycle_records_original_payload_actor_trace_and_valid_signature(db, transition):
    producer = app_producer()
    async with db.transaction() as tx:
        event_id = await producer.enqueue_lifecycle(tx, **options(transition))
    (row,) = await events(db)
    event = verify(bytes(row["payload"]), row["signature"], team_id=TEAM)
    assert event.event_id == str(event_id)
    assert event.fields["payload"] == body(transition)
    assert event.fields["actor"] == REQUESTER
    assert event.fields["trace"] == {"id": TRACE, "origin": "signed_request"}
    assert row["critical"] is False
    assert event.fields["producer"]["seq"] == 1


@pytest.mark.parametrize("transition", LIFECYCLES)
@pytest.mark.parametrize(
    "current",
    [None, view(), view(as_of=NOW - timedelta(seconds=61), registrations=(registration(),))],
    ids=["missing", "empty", "stale"],
)
async def test_ordinary_enqueue_obeys_catalog_without_gating_recorded_consequences(
    db, transition, current
):
    async with db.transaction() as tx:
        await app_producer().enqueue(tx, hook=HOOK, view=current, **options(transition))
    (row,) = await events(db)
    assert row["critical"] is False


@pytest.mark.parametrize("transition", AUTHORIZING)
async def test_lifecycle_rejects_authorizing_steps_before_any_sequence_write(db, transition):
    async with db.transaction() as tx:
        with pytest.raises(Refused, match="non-authorizing"):
            await app_producer().enqueue_lifecycle(tx, **options(transition))
        assert await tx.fetch_value("SELECT count(*) FROM {{tables.outbox_sequences}}") == 0
    assert await events(db) == []


@pytest.mark.parametrize("transition", AUTHORIZING)
async def test_authorizing_steps_still_require_an_active_target(db, transition):
    producer = app_producer()
    async with db.transaction() as tx:
        with pytest.raises(Refused) as refused:
            await producer.enqueue(tx, hook=HOOK, **options(transition))
        assert refused.value.code == "audit_target_unavailable"
    async with db.transaction() as tx:
        await producer.enqueue(
            tx, hook=HOOK, view=view(registrations=(registration(),)), **options(transition)
        )
    (row,) = await events(db)
    assert row["critical"] is True


async def test_lifecycle_keeps_refusals_on_the_existing_exclusive_path(db):
    values = {**options("cancelled"), "payload": payload("secret_use_refused")}
    async with db.transaction() as tx:
        with pytest.raises(Refused, match="non-authorizing"):
            await app_producer().enqueue_lifecycle(tx, **values)
    assert await events(db) == []


@pytest.mark.parametrize(
    "changes",
    [
        {"payload": {**body("cancelled"), "approval_decision": "unknown"}},
        {"payload": {**body("cancelled"), "extra": "not allowed"}},
        {"payload": {"action": "approval_decided", "op_kind": "broker"}},
        {"actor": {"authority_mode": "team_cert", "attestations": []}},
        {"result_status": "unknown"},
        {"occurred_at": NOW + timedelta(seconds=6)},
    ],
)
async def test_lifecycle_keeps_catalog_envelope_and_clock_checks_before_seq(db, changes):
    async with db.transaction() as tx:
        with pytest.raises(ValueError):
            await app_producer().enqueue_lifecycle(tx, **{**options("cancelled"), **changes})
        assert await tx.fetch_value("SELECT count(*) FROM {{tables.outbox_sequences}}") == 0
    assert await events(db) == []


async def test_lifecycle_keeps_producer_kind_and_key_checks(db):
    invalid = [
        ServerProducer.core(origin="https://aweb.example.com", kid="test-key", seed=bytes(32)),
        replace(app_producer().producer, seed=b""),
    ]
    for identity in invalid:
        async with db.transaction() as tx:
            with pytest.raises(ValueError):
                await HookProducer(identity, clock=lambda: NOW).enqueue_lifecycle(
                    tx, **options("cancelled")
                )
            assert await tx.fetch_value("SELECT count(*) FROM {{tables.outbox_sequences}}") == 0
    assert await events(db) == []


async def test_lifecycle_stores_when_admission_is_blocked_by_stalled_backlog(db):
    await backlog(db)
    with pytest.raises(Refused) as refused:
        await require(db)
    assert refused.value.code == "audit_delivery_stalled"
    async with db.transaction() as tx:
        await app_producer().enqueue_lifecycle(tx, **options("completed"))
    assert len(await events(db)) == 2
    # Recording did not clear the backlog or grant another admission.
    with pytest.raises(Refused) as refused:
        await require(db)
    assert refused.value.code == "audit_delivery_stalled"


async def test_lifecycle_local_storage_failure_rolls_back_its_effect_and_seq(db):
    await db.execute("CREATE TABLE {{tables.effect}} (id integer PRIMARY KEY)")
    await db.execute(
        "ALTER TABLE {{tables.outbox_events}} ADD CONSTRAINT reject_hook "
        "CHECK (kind <> 'post-secret-use-hook')"
    )
    with pytest.raises(asyncpg.CheckViolationError):
        async with db.transaction() as tx:
            await tx.execute("INSERT INTO {{tables.effect}} VALUES (1)")
            await app_producer().enqueue_lifecycle(tx, **options("cancelled"))
    assert await db.fetch_value("SELECT count(*) FROM {{tables.effect}}") == 0
    assert await db.fetch_value("SELECT count(*) FROM {{tables.outbox_sequences}}") == 0
    assert await events(db) == []
