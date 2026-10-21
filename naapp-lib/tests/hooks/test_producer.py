"""Producing hook events on real PostgreSQL: the enqueue in the effect's
transaction, the audit-critical gate, and the drain's resolver.

Signatures are real: every enqueued event verifies under the producer's key.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from pgdbm import AsyncDatabaseManager

from aweb_naapp.hooks.envelope import verify
from aweb_naapp.hooks.producer import (
    HOOKS_CHANNEL,
    HookProducer,
    Registration,
    RegistrationView,
    ServerProducer,
    hook_targets,
)
from aweb_naapp.hooks.strictjson import Refused
from aweb_naapp.outbox import StoredEvent, apply_outbox_migrations

AWEB_ROOT = Path(__file__).resolve().parents[3]
CASES = {
    case["name"]: case
    for case in json.loads((AWEB_ROOT / "docs" / "vectors" / "hook-catalog-v1.json").read_bytes())[
        "positive_cases"
    ]
}
TEAM = "backend:example.com"
SEED = bytes(range(32))
SYSTEM = {"authority_mode": "system", "attestations": []}
NOW = datetime(2026, 10, 21, 12, 0, 0, tzinfo=UTC)
BINDING = "6f9619ff-8b86-4011-b42d-00c04fc964ff"


def payload(name: str) -> dict:
    return CASES[name]["payload"]


def registration(active_from: datetime = NOW - timedelta(minutes=5)) -> Registration:
    return Registration(
        binding_id=BINDING,
        origin="https://logs.example.com",
        method="POST",
        path="/hooks/ingest",
        active_from=active_from,
    )


def view(
    hook: str = "post-secret-use-hook",
    *,
    as_of: datetime = NOW,
    registrations: tuple[Registration, ...] = (),
) -> RegistrationView:
    return RegistrationView(
        team_id=TEAM,
        hook=hook,
        as_of=as_of,
        max_age=timedelta(seconds=60),
        registrations=registrations,
    )


def app_producer(clock=lambda: NOW) -> HookProducer:
    return HookProducer(
        ServerProducer.app(
            origin="https://secrets.example.com",
            app_id="secrets",
            installation_id="1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b",
            generation=2,
            kid="hook-2026-10",
            seed=SEED,
        ),
        clock=clock,
    )


@pytest.fixture
async def db(test_db_factory) -> AsyncIterator[AsyncDatabaseManager]:
    database = await test_db_factory.create_db(suffix="naapp_hook_producer")
    await apply_outbox_migrations(database)
    yield database


async def events(db: AsyncDatabaseManager) -> list[dict]:
    return await db.fetch_all(
        "SELECT event_id, kind, payload, signature, critical, producer, channel"
        " FROM {{tables.outbox_events}} ORDER BY position"
    )


async def enqueue(db, producer: HookProducer, hook: str, name: str, **options) -> UUID:
    async with db.transaction() as tx:
        return await producer.enqueue(
            tx,
            hook=hook,
            team_id=TEAM,
            payload=payload(name),
            actor=SYSTEM,
            occurred_at=options.pop("occurred_at", NOW),
            result_status="success",
            **options,
        )


async def test_an_enqueued_event_is_signed_by_the_producer_and_stored_on_the_hooks_channel(
    db,
) -> None:
    producer = app_producer()
    event_id = await enqueue(
        db, producer, "post-manifest-command-hook", "manifest_command_mutation"
    )
    (row,) = await events(db)
    assert row["event_id"] == event_id
    assert row["kind"] == "post-manifest-command-hook"
    assert row["channel"] == HOOKS_CHANNEL
    envelope = verify(bytes(row["payload"]), row["signature"], team_id=TEAM)
    assert envelope.event_id == str(event_id)
    assert envelope.producer == "app:secrets"
    assert envelope.producer_did_key == producer.producer.did_key
    assert envelope.fields["payload"] == payload("manifest_command_mutation")
    assert envelope.fields["occurred_at"] == "2026-10-21T12:00:00.000Z"


async def test_seq_counts_per_producer_team_and_hook(db) -> None:
    producer = app_producer()
    for _ in range(2):
        await enqueue(db, producer, "post-manifest-command-hook", "manifest_command_mutation")
    await enqueue(
        db,
        producer,
        "post-secret-use-hook",
        "secret_use_refused",
        view=view(registrations=(registration(),)),
    )
    seqs = [
        (row["kind"], json.loads(bytes(row["payload"]).split(b"\n", 1)[1])["producer"]["seq"])
        for row in await events(db)
    ]
    assert seqs == [
        ("post-manifest-command-hook", 1),
        ("post-manifest-command-hook", 2),
        ("post-secret-use-hook", 1),
    ]


async def test_an_enqueue_rolls_back_with_its_effect_and_spends_no_seq(db) -> None:
    producer = app_producer()
    with pytest.raises(RuntimeError):
        async with db.transaction() as tx:
            await producer.enqueue(
                tx,
                hook="post-manifest-command-hook",
                team_id=TEAM,
                payload=payload("manifest_command_mutation"),
                actor=SYSTEM,
                occurred_at=NOW,
                result_status="success",
            )
            raise RuntimeError("the effect failed")
    assert await events(db) == []
    await enqueue(db, producer, "post-manifest-command-hook", "manifest_command_mutation")
    (row,) = await events(db)
    assert json.loads(bytes(row["payload"]).split(b"\n", 1)[1])["producer"]["seq"] == 1


async def test_a_refused_enqueue_spends_no_seq_even_when_the_caller_commits(db) -> None:
    producer = app_producer()
    async with db.transaction() as tx:
        with pytest.raises(Refused):
            await producer.enqueue(
                tx,
                hook="post-manifest-command-hook",
                team_id=TEAM,
                payload=payload("manifest_command_mutation"),
                actor={"authority_mode": "team_cert", "attestations": []},
                occurred_at=NOW,
                result_status="success",
            )
    await enqueue(db, producer, "post-manifest-command-hook", "manifest_command_mutation")
    (row,) = await events(db)
    assert json.loads(bytes(row["payload"]).split(b"\n", 1)[1])["producer"]["seq"] == 1


async def test_a_payload_outside_the_catalog_is_refused(db) -> None:
    with pytest.raises(ValueError) as refused:
        async with db.transaction() as tx:
            await app_producer().enqueue(
                tx,
                hook="post-manifest-command-hook",
                team_id=TEAM,
                payload={**payload("manifest_command_mutation"), "note": "free text"},
                actor=SYSTEM,
                occurred_at=NOW,
                result_status="success",
            )
    assert getattr(refused.value, "code", None) == "unknown_field"
    assert await events(db) == []


# --- the audit-critical gate ---


async def test_a_critical_event_with_a_fresh_active_registration_is_enqueued(db) -> None:
    await enqueue(
        db,
        app_producer(),
        "post-secret-use-hook",
        "secret_use_refused",
        view=view(registrations=(registration(),)),
    )
    (row,) = await events(db)
    assert row["critical"] is True


@pytest.mark.parametrize(
    "case",
    [
        "no_view",
        "stale_view",
        "view_from_the_future",
        "no_registration",
        "inside_the_active_from_pad",
        "other_hook",
        "other_team",
    ],
)
async def test_a_critical_event_without_a_target_owed_is_refused(db, case) -> None:
    gate = {
        "no_view": None,
        "stale_view": view(as_of=NOW - timedelta(seconds=61), registrations=(registration(),)),
        "no_registration": view(),
        "inside_the_active_from_pad": view(
            registrations=(registration(active_from=NOW + timedelta(milliseconds=1)),)
        ),
        "other_hook": view("post-governance-hook", registrations=(registration(),)),
        "view_from_the_future": view(
            as_of=NOW + timedelta(seconds=1), registrations=(registration(),)
        ),
        "other_team": RegistrationView(
            team_id="other:example.com",
            hook="post-secret-use-hook",
            as_of=NOW,
            max_age=timedelta(seconds=60),
            registrations=(registration(),),
        ),
    }[case]
    with pytest.raises(Refused) as refused:
        await enqueue(db, app_producer(), "post-secret-use-hook", "secret_use_refused", view=gate)
    assert refused.value.code == "audit_target_unavailable"
    assert await events(db) == []


async def test_a_view_exactly_sixty_seconds_old_still_counts(db) -> None:
    await enqueue(
        db,
        app_producer(),
        "post-secret-use-hook",
        "secret_use_refused",
        view=view(as_of=NOW - timedelta(seconds=60), registrations=(registration(),)),
    )
    assert len(await events(db)) == 1


async def test_a_registration_active_from_the_moment_of_the_effect_counts(db) -> None:
    await enqueue(
        db,
        app_producer(),
        "post-secret-use-hook",
        "secret_use_refused",
        view=view(registrations=(registration(active_from=NOW),)),
    )
    assert len(await events(db)) == 1


async def test_an_event_dated_in_the_future_is_refused(db) -> None:
    # A future occurred_at could let a registration still inside its
    # active_from pad count as owed.
    with pytest.raises(Refused) as refused:
        await enqueue(
            db,
            app_producer(),
            "post-secret-use-hook",
            "secret_use_refused",
            occurred_at=NOW + timedelta(seconds=6),
            view=view(registrations=(registration(active_from=NOW + timedelta(seconds=6)),)),
        )
    assert refused.value.code == "invalid_value"
    assert await events(db) == []


async def test_an_event_within_the_clock_allowance_is_accepted(db) -> None:
    await enqueue(
        db,
        app_producer(),
        "post-manifest-command-hook",
        "manifest_command_mutation",
        occurred_at=NOW + timedelta(seconds=5),
    )
    assert len(await events(db)) == 1


async def test_a_widening_governance_act_is_gated(db) -> None:
    with pytest.raises(Refused) as refused:
        await enqueue(db, app_producer(), "post-governance-hook", "governance_widening_owner_act")
    assert refused.value.code == "audit_target_unavailable"


async def test_a_narrowing_governance_act_is_never_refused(db) -> None:
    await enqueue(db, app_producer(), "post-governance-hook", "governance_narrowing_team_cert")
    (row,) = await events(db)
    assert row["critical"] is False


async def test_a_hook_that_is_not_audit_critical_needs_no_target(db) -> None:
    await enqueue(db, app_producer(), "post-manifest-command-hook", "manifest_command_mutation")
    (row,) = await events(db)
    assert row["critical"] is False


# --- trace ---


async def test_a_signed_trace_id_is_kept_and_an_absent_one_is_minted(db) -> None:
    producer = app_producer()
    signed = "4bf92f3577b34da6a3ce929d0e0e4736"
    await enqueue(
        db,
        producer,
        "post-manifest-command-hook",
        "manifest_command_mutation",
        signed_trace_id=signed,
    )
    await enqueue(db, producer, "post-manifest-command-hook", "manifest_command_mutation")
    await enqueue(
        db,
        producer,
        "post-manifest-command-hook",
        "manifest_command_mutation",
        signed_trace_id="0" * 32,
    )
    traces = [
        json.loads(bytes(row["payload"]).split(b"\n", 1)[1])["trace"] for row in await events(db)
    ]
    assert traces[0] == {"id": signed, "origin": "signed_request"}
    for minted in traces[1:]:
        assert minted["origin"] == "producer"
        assert len(minted["id"]) == 32 and minted["id"] != "0" * 32


# --- the drain's resolver ---


def stored(occurred_at: datetime = NOW, hook: str = "post-secret-use-hook") -> StoredEvent:
    return StoredEvent(
        event_id=UUID(int=1),
        team_id=TEAM,
        kind=hook,
        occurred_at=occurred_at,
        payload=b"",
        signature="",
        critical=True,
        producer={},
        channel=HOOKS_CHANNEL,
    )


class Views:
    def __init__(self, current: RegistrationView | None) -> None:
        self.current = current

    async def view(self, team_id: str, hook: str) -> RegistrationView | None:
        return self.current


async def test_the_resolver_names_one_delivery_per_eligible_registration() -> None:
    late = Registration(
        binding_id="0192f0c4-6f1e-7c3a-9a51-3d2b8e0f4c11",
        origin="https://other.example.com",
        method="POST",
        path="/in",
        active_from=NOW + timedelta(seconds=1),
    )
    resolve = hook_targets(Views(view(registrations=(registration(), late))), clock=lambda: NOW)
    targets = await resolve(stored())
    assert targets is not None
    assert [t.id for t in targets] == [BINDING]
    assert targets[0].meta == {
        "binding_id": BINDING,
        "origin": "https://logs.example.com",
        "method": "POST",
        "path": "/hooks/ingest",
    }


@pytest.mark.parametrize("current", [None, view(as_of=NOW - timedelta(seconds=61))])
async def test_the_resolver_leaves_the_event_pending_without_a_fresh_view(current) -> None:
    resolve = hook_targets(Views(current), clock=lambda: NOW)
    assert await resolve(stored()) is None


async def test_core_signs_its_mutations_and_an_app_may_not(db) -> None:
    core = HookProducer(
        ServerProducer.core(origin="https://aweb.example.com", kid="hook-2026-10", seed=SEED),
        clock=lambda: NOW,
    )
    await enqueue(db, core, "post-mutation-hook", "mutation_task_updated")
    (row,) = await events(db)
    assert verify(bytes(row["payload"]), row["signature"], team_id=TEAM).producer == "core"
    with pytest.raises(Refused) as refused:
        await enqueue(db, app_producer(), "post-mutation-hook", "mutation_task_updated")
    assert refused.value.code == "producer_not_allowed"
    assert len(await events(db)) == 1


def test_a_server_producer_names_itself_by_kind() -> None:
    core = ServerProducer.core(origin="https://aweb.example.com", kid="hook-2026-10", seed=SEED)
    assert core.name == "core"
    assert core.did_key == app_producer().producer.did_key
    assert core.did_key.startswith("did:key:z")
