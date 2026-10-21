"""Decision 94: durable refusals and admission from the real shared outbox."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest

from aweb_naapp.hooks.envelope import verify
from aweb_naapp.hooks.producer import HOOKS_CHANNEL, ServerProducer, hook_targets
from aweb_naapp.hooks.strictjson import Refused
from aweb_naapp.outbox import Acked, OutboxEvent, Retryable, RetryPolicy, drain
from aweb_naapp.outbox import enqueue as enqueue_event
from tests.hooks.test_producer import (
    BINDING,
    NOW,
    SYSTEM,
    TEAM,
    app_producer,
    events,
    registration,
    view,
)
from tests.hooks.test_producer import db as db

HOOK = "post-secret-use-hook"
BOUND = timedelta(hours=1)
PRIMARY = registration(active_from=NOW - timedelta(days=1))
SECONDARY = replace(PRIMARY, binding_id="5cae94d6-2a83-4e76-9116-d2f7f3d8d73f")
REFUSAL = {"action": "refused", "op_kind": "broker", "refusal_code": "audit_target_unavailable"}


async def record_refusal(db, producer=None, **options):
    async with db.transaction() as tx:
        return await (producer or app_producer()).enqueue_refusal(
            tx,
            team_id=TEAM,
            payload=options.pop("payload", REFUSAL),
            actor=options.pop("actor", SYSTEM),
            occurred_at=options.pop("occurred_at", NOW),
            **options,
        )


async def require(db, registrations=(PRIMARY,), **options):
    async with db.transaction() as tx:
        await app_producer().require_admission(
            tx,
            team_id=TEAM,
            hook=HOOK,
            occurred_at=NOW,
            view=options.pop("view", view(registrations=registrations)),
            max_backlog_age=options.pop("max_backlog_age", BOUND),
            **options,
        )


async def backlog(
    db,
    *,
    age=timedelta(hours=2),
    states=None,
    team_id=TEAM,
    hook=HOOK,
    channel=HOOKS_CHANNEL,
    occurred_at=None,
):
    """Explicit local enqueue time; payload content is irrelevant to this query."""
    event_id = uuid4()
    async with db.transaction() as tx:
        await enqueue_event(
            tx,
            OutboxEvent(
                event_id=event_id,
                team_id=team_id,
                kind=hook,
                occurred_at=occurred_at or NOW - age,
                payload=b"fixture event",
                signature="fixture",
                channel=channel,
            ),
        )
        await tx.execute(
            "UPDATE {{tables.outbox_events}} SET created_at=$2 WHERE event_id=$1",
            event_id,
            NOW - age,
        )
        if states is not None:
            await tx.execute(
                "UPDATE {{tables.outbox_events}} SET materialized_at=$2 WHERE event_id=$1",
                event_id,
                NOW,
            )
            for target_id, state in states.items():
                await tx.execute(
                    "INSERT INTO {{tables.outbox_deliveries}} (event_id,target_id,state)"
                    " VALUES ($1,$2,$3)",
                    event_id,
                    target_id,
                    state,
                )
    return event_id


async def test_no_target_refuses_without_writing(db):
    with pytest.raises(Refused) as refused:
        await require(db, registrations=())
    assert refused.value.code == "audit_target_unavailable"
    assert await events(db) == []


async def test_one_healthy_target_admits(db):
    await require(db)
    await backlog(db, age=timedelta(minutes=59), states={BINDING: "pending"})
    await require(db)


async def test_a_stalled_primary_refuses(db):
    await backlog(db, states={BINDING: "stalled"})
    with pytest.raises(Refused) as refused:
        await require(db)
    assert refused.value.code == "audit_delivery_stalled"


async def test_a_stalled_secondary_does_not_block_a_healthy_primary(db):
    await backlog(db, states={BINDING: "delivered", SECONDARY.binding_id: "stalled"})
    await require(db, registrations=(PRIMARY, SECONDARY))


async def test_unmaterialized_backlog_counts_for_every_owed_target(db):
    await backlog(db)
    with pytest.raises(Refused) as refused:
        await require(db, registrations=(PRIMARY, SECONDARY))
    assert refused.value.code == "audit_delivery_stalled"


async def test_backlog_exactly_at_the_bound_is_current(db):
    await backlog(db, age=BOUND, states={BINDING: "pending"})
    await require(db)


async def test_a_new_target_is_not_owed_events_from_before_its_activation(db):
    await backlog(db)
    await require(db, registrations=(registration(),))


@pytest.mark.parametrize("state", ["delivered", "duplicate"])
async def test_acknowledged_delivery_is_current(db, state):
    await backlog(db, states={BINDING: state})
    await require(db)


@pytest.mark.parametrize("state", ["rejected", "conflict", "cancelled"])
async def test_a_terminal_failure_is_not_treated_as_delivered(db, state):
    await backlog(db, states={BINDING: state})
    with pytest.raises(Refused) as refused:
        await require(db)
    assert refused.value.code == "audit_delivery_stalled"


@pytest.mark.parametrize(
    "scope",
    [{"team_id": "other:example.com"}, {"hook": "post-governance-hook"}, {"channel": "default"}],
)
async def test_backlog_is_isolated_to_this_team_hook_and_channel(db, scope):
    await backlog(db, **scope)
    await require(db)


@pytest.mark.parametrize(
    "bad_view",
    [
        None,
        view(as_of=NOW - timedelta(seconds=61), registrations=(PRIMARY,)),
        view(registrations=(replace(PRIMARY, active_from=NOW + timedelta(seconds=1)),)),
        replace(view(registrations=(PRIMARY,)), team_id="other:example.com"),
        view("post-governance-hook", registrations=(PRIMARY,)),
    ],
)
async def test_backlog_does_not_bypass_freshness_scope_or_activation(db, bad_view):
    with pytest.raises(Refused) as refused:
        await require(db, view=bad_view)
    assert refused.value.code == "audit_target_unavailable"


@pytest.mark.parametrize("bound", [timedelta(0), timedelta(seconds=-1)])
async def test_backlog_age_must_be_positive_configuration(db, bound):
    with pytest.raises(ValueError, match="max_backlog_age must be positive"):
        await require(db, max_backlog_age=bound)


async def test_gate_failure_can_be_recorded_without_an_intent_or_target(db):
    with pytest.raises(Refused):
        await require(db, registrations=())
    event_id = await record_refusal(db)
    (row,) = await events(db)
    assert row["event_id"] == event_id
    assert row["critical"] is True
    event = verify(bytes(row["payload"]), row["signature"], team_id=TEAM)
    assert event.fields["payload"] == REFUSAL
    assert event.fields["result_status"] == "denied"
    assert event.fields["producer"]["seq"] == 1


async def test_backlog_gate_failure_does_not_block_its_refusal_record(db):
    await backlog(db, states={BINDING: "stalled"})
    with pytest.raises(Refused) as refused:
        await require(db)
    await record_refusal(db, payload={**REFUSAL, "refusal_code": refused.value.code})
    row = (await events(db))[-1]
    assert (
        verify(bytes(row["payload"]), row["signature"], team_id=TEAM).fields["payload"][
            "refusal_code"
        ]
        == "audit_delivery_stalled"
    )


@pytest.mark.parametrize("action", ["admitted", "dispatching", "completed", "not_sent"])
async def test_refusal_path_cannot_record_an_effect_action(db, action):
    with pytest.raises(Refused) as refused:
        await record_refusal(db, payload={**REFUSAL, "action": action})
    assert refused.value.code == "rule_violation"
    assert await events(db) == []


@pytest.mark.parametrize("fault", ["payload", "actor", "time", "key", "core_producer"])
async def test_refusal_exemption_preserves_validation_and_key_checks(db, fault):
    producer = app_producer()
    options = {
        "payload": {"payload": {**REFUSAL, "body": "forbidden"}},
        "actor": {"actor": {"authority_mode": "team_cert", "attestations": []}},
        "time": {"occurred_at": NOW + timedelta(seconds=6)},
        "key": {},
        "core_producer": {},
    }[fault]
    if fault == "key":
        producer.producer = replace(producer.producer, seed=b"invalid seed")
    if fault == "core_producer":
        producer.producer = ServerProducer.core(
            origin=producer.producer.origin,
            kid=producer.producer.kid,
            seed=producer.producer.seed,
        )
    with pytest.raises(ValueError):
        await record_refusal(db, producer, **options)
    assert await events(db) == []
    await record_refusal(db)
    (row,) = await events(db)
    assert (
        verify(bytes(row["payload"]), row["signature"], team_id=TEAM).fields["producer"]["seq"] == 1
    )


async def test_refusal_record_and_sequence_roll_back_with_caller_transaction(db):
    with pytest.raises(RuntimeError):
        async with db.transaction() as tx:
            await app_producer().enqueue_refusal(
                tx,
                team_id=TEAM,
                payload=REFUSAL,
                actor=SYSTEM,
                occurred_at=NOW,
            )
            raise RuntimeError("local refusal record did not commit")
    assert await events(db) == []
    await record_refusal(db)
    (row,) = await events(db)
    assert (
        verify(bytes(row["payload"]), row["signature"], team_id=TEAM).fields["producer"]["seq"] == 1
    )


class Source:
    async def view(self, team_id, hook):
        return view(hook, registrations=(PRIMARY,))


class Transport:
    def __init__(self, *, retry=False):
        self.retry = retry
        self.received = []

    async def deliver(self, event, target):
        self.received.append((event.event_id, bytes(event.payload)))
        return Retryable("offline") if self.retry else Acked("delivered")


async def test_refusal_retries_to_an_existing_target_after_recovery(db):
    event_id = await record_refusal(db)
    source = Source()
    transport = Transport(retry=True)
    options = dict(
        channel=HOOKS_CHANNEL,
        resolver=hook_targets(source, clock=lambda: NOW),
        transport=transport,
        policy=RetryPolicy(stalled_after=BOUND),
    )
    await drain(db, **options)
    assert len(transport.received) == 1
    transport.retry = False
    await db.execute("UPDATE {{tables.outbox_deliveries}} SET next_attempt_at=NOW()")
    await drain(db, **options)
    assert transport.received[0] == transport.received[1]
    assert transport.received[0][0] == event_id


@pytest.mark.parametrize("materialize_before_activation", [False, True])
async def test_no_target_refusal_is_never_delivered_to_a_later_target(
    db,
    materialize_before_activation,
):
    await record_refusal(db)
    current = view()

    class ChangingSource:
        async def view(self, team_id, hook):
            return current

    transport = Transport()
    options = dict(
        channel=HOOKS_CHANNEL,
        resolver=hook_targets(ChangingSource(), clock=lambda: NOW),
        transport=transport,
        policy=RetryPolicy(stalled_after=BOUND),
    )
    if materialize_before_activation:
        await drain(db, **options)
    current = view(registrations=(replace(PRIMARY, active_from=NOW + timedelta(seconds=1)),))
    await drain(db, **options)
    assert transport.received == []
    assert await db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 1
    assert await db.fetch_value("SELECT count(*) FROM {{tables.outbox_deliveries}}") == 0
