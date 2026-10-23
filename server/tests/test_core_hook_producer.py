"""Core wiring uses the shared producer and commits with the reported effect."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from nacl.signing import SigningKey

from aweb.hook_producer import CoreHooks, MutationHookContext, enqueue_mutation_hook, CoreRegistrations
from aweb.hook_bindings import HookBindingDeclaration, write_pending_bindings
from aweb_naapp.hooks.envelope import verify
from aweb_naapp.hooks.producer import HookProducer, ServerProducer
from tests.test_verified_installations import TEAM, db, origin, fetched
from aweb.installations import install_verified_manifest_on
from tests.installation_fixtures import seed_pending_installation

pytestmark = pytest.mark.asyncio
SYSTEM = {"authority_mode": "system", "attestations": []}


def context():
    key = SigningKey.generate()
    return MutationHookContext(CoreHooks(HookProducer(ServerProducer.core(
        origin="https://core.example", kid="core-test", seed=bytes(key),
    ))), SYSTEM)


async def registration(db, *, state="active", pad=False, hook="post-mutation-hook", team=TEAM, app="logs", target_origin="https://logs.example"):
    await seed_pending_installation(
        db, team_id=team, app_id=app, origin=target_origin, app_version="1.0.0",
        manifest_version=2, digest="sha256:" + "a" * 64, granted_scopes=[],
    )
    async with db.transaction() as tx:
        bindings = await write_pending_bindings(
            tx, team_id=team, app_id=app, origin=target_origin,
            digest="sha256:" + "a" * 64, installation_id=str(uuid4()), generation=1,
            declarations=[HookBindingDeclaration(
                kind="registration", catalog_id="aweb.hooks", catalog_version=1,
                hook=hook, tool="ingest", method="POST", path="/hooks/ingest", scopes=(),
            )],
        )
        if state == "active":
            activation = datetime.now(UTC).replace(microsecond=0) - (timedelta(0) if pad else timedelta(minutes=2))
            await tx.execute(
                "UPDATE {{tables.app_hook_bindings}} SET state='active',activated_at=$2::timestamptz,active_from=$2::timestamptz+INTERVAL '60 seconds',activation_act_sha256=$3 WHERE binding_id=$1",
                bindings[0].binding_id, activation, "a" * 64,
            )
        elif state != "pending":
            await tx.execute(
                "UPDATE {{tables.app_hook_bindings}} SET state=$2,ended_by=$3,revoked_at=NOW() WHERE binding_id=$1",
                bindings[0].binding_id, state, "uninstall" if state == "revoked" else "generation",
            )
    return str(bindings[0].binding_id)


async def events(db):
    rows = await db.fetch_all("SELECT payload,signature FROM {{tables.outbox_events}} WHERE record_type='event' ORDER BY position")
    return [verify(bytes(r["payload"]), r["signature"], team_id=TEAM).fields for r in rows]


async def test_no_registration_enqueues_nothing(db):
    async with db.transaction() as tx:
        assert await enqueue_mutation_hook(tx, team_id=TEAM, payload={}) is None
    assert await db.fetch_value("SELECT COUNT(*) FROM {{tables.outbox_events}}") == 0


@pytest.mark.parametrize("state,pad", [("pending", False), ("revoked", False), ("superseded", False), ("active", True)])
async def test_no_eligible_registration_needs_no_key_or_event(db, state, pad):
    await registration(db, state=state, pad=pad)
    async with db.transaction() as tx:
        assert await enqueue_mutation_hook(tx, team_id=TEAM, payload={"unused": "not validated"}) is None
        await tx.execute("UPDATE {{tables.teams}} SET team_name=team_name WHERE team_id=$1", TEAM)
    assert await db.fetch_value("SELECT COUNT(*) FROM {{tables.outbox_events}}") == 0


@pytest.mark.parametrize("rollback", [False, True])
async def test_event_sequence_and_install_commit_or_rollback_together(db, origin, rollback):
    await registration(db)
    ctx = context()
    evidence = await fetched(origin)
    try:
        async with db.transaction() as tx:
            await install_verified_manifest_on(tx, team_id=TEAM, fetched=evidence, granted_scopes=[], hook_context=ctx)
            assert await tx.fetch_value("SELECT COUNT(*) FROM {{tables.outbox_events}}") == 1
            if rollback:
                raise RuntimeError("abort caller")
    except RuntimeError:
        assert rollback
    assert await db.fetch_value("SELECT COUNT(*) FROM {{tables.team_app_installs}} WHERE app_id='fixture'") == int(not rollback)
    assert await db.fetch_value("SELECT COUNT(*) FROM {{tables.outbox_sequences}}") == int(not rollback)
    recorded = await events(db)
    assert len(recorded) == int(not rollback)
    if recorded:
        assert recorded[0]["payload"]["mutation_type"] == "app.installed"
        assert recorded[0]["producer"]["kind"] == "core"
        assert recorded[0]["actor"] == SYSTEM


async def test_update_records_the_previous_digest_and_signed_trace(db, origin):
    await registration(db)
    ctx = context()
    first_evidence = await fetched(origin)
    async with db.transaction() as tx:
        first = await install_verified_manifest_on(tx, team_id=TEAM, fetched=first_evidence, granted_scopes=[], hook_context=ctx)
    trace = uuid4().hex
    ctx = MutationHookContext(ctx.hooks, SYSTEM, trace)
    updated_evidence = await fetched(origin, "2.0.0")
    async with db.transaction() as tx:
        await install_verified_manifest_on(tx, team_id=TEAM, fetched=updated_evidence, granted_scopes=[], expected_generation=1, hook_context=ctx)
    installed, updated = await events(db)
    assert installed["trace"]["origin"] == "producer"
    assert updated["trace"] == {"id": trace, "origin": "signed_request"}
    assert updated["payload"]["previous_digest"] == first["digest"]
    assert [e["producer"]["seq"] for e in (installed, updated)] == [1, 2]


async def test_missing_key_commits_effect_with_local_reservation_and_no_wire_event(db, origin):
    binding = await registration(db)
    evidence = await fetched(origin)
    async with db.transaction() as tx:
        await install_verified_manifest_on(
            tx, team_id=TEAM, fetched=evidence, granted_scopes=[],
            hook_context=MutationHookContext(None, SYSTEM, origin="https://core.example"),
        )
    assert await db.fetch_value("SELECT COUNT(*) FROM {{tables.team_app_installs}} WHERE app_id='fixture'") == 1
    row = await db.fetch_one("SELECT * FROM {{tables.outbox_events}}")
    assert row["record_type"] == "missing_production"
    assert row["producer_origin"] == "https://core.example"
    assert row["owed_binding_ids"] == [binding]
    assert row["reservation_seq"] == 1 and row["missing_reason"] == "key_unconfigured"
    assert row["payload"] is row["signature"] is None
    assert await events(db) == []


async def test_core_resolver_reads_current_state_without_cached_revocation(db):
    binding_id = await registration(db)
    resolver = CoreRegistrations(db)
    view = await resolver.view(TEAM, "post-mutation-hook")
    assert [r.binding_id for r in view.registrations] == [binding_id]
    assert view.is_fresh(datetime.now(UTC))
    await db.execute("UPDATE {{tables.app_hook_bindings}} SET state='revoked',ended_by='uninstall',revoked_at=NOW()")
    assert (await resolver.view(TEAM, "post-mutation-hook")).registrations == ()


@pytest.mark.parametrize("trace", [None, "0" * 32, "bad-trace"])
async def test_unsigned_or_malformed_trace_is_minted_by_the_shared_producer(db, trace):
    await registration(db)
    ctx = context()
    ctx = MutationHookContext(ctx.hooks, SYSTEM, trace)
    async with db.transaction() as tx:
        await enqueue_mutation_hook(tx, team_id=TEAM, hook_context=ctx, payload={
            "mutation_type": "app_key.revoked", "target_ref": "app:fixture", "app_id": "fixture", "kid": "old", "purposes": ["hook-event"],
        })
    recorded, = await events(db)
    assert recorded["trace"]["origin"] == "producer"
    assert len(recorded["trace"]["id"]) == 32 and int(recorded["trace"]["id"], 16) > 0


@pytest.mark.parametrize("rollback", [False, True])
async def test_missing_production_sequence_and_effect_are_atomic(db, origin, rollback):
    await registration(db)
    evidence = await fetched(origin)
    missing = MutationHookContext(None, SYSTEM, origin="https://core.example")
    try:
        async with db.transaction() as tx:
            await install_verified_manifest_on(tx, team_id=TEAM, fetched=evidence, granted_scopes=[], hook_context=missing)
            if rollback:
                raise RuntimeError("abort caller")
    except RuntimeError:
        assert rollback
    assert await db.fetch_value("SELECT COUNT(*) FROM {{tables.team_app_installs}} WHERE app_id='fixture'") == int(not rollback)
    assert await db.fetch_value("SELECT COUNT(*) FROM {{tables.outbox_sequences}}") == int(not rollback)
    assert await db.fetch_value("SELECT COUNT(*) FROM {{tables.outbox_events}} WHERE record_type='missing_production'") == int(not rollback)


async def test_restored_signer_does_not_backfill_the_missing_firing(db):
    await registration(db)
    payload = {"mutation_type": "app_key.revoked", "target_ref": "app:fixture", "app_id": "fixture", "kid": "old", "purposes": ["hook-event"]}
    async with db.transaction() as tx:
        await enqueue_mutation_hook(tx, team_id=TEAM, payload=payload, hook_context=MutationHookContext(None, SYSTEM, origin="https://core.example"))
    async with db.transaction() as tx:
        await enqueue_mutation_hook(tx, team_id=TEAM, payload=payload, hook_context=context())
    recorded, = await events(db)
    assert recorded["producer"]["seq"] == 2
    assert await db.fetch_value("SELECT COUNT(*) FROM {{tables.outbox_events}} WHERE record_type='missing_production' AND reservation_seq=1 AND payload IS NULL") == 1


async def test_missing_production_local_write_failure_rolls_back_effect_and_sequence(db, origin):
    import asyncpg

    await registration(db)
    evidence = await fetched(origin)
    await db.execute("ALTER TABLE {{tables.outbox_events}} ADD CONSTRAINT refuse_local_loss CHECK (record_type <> 'missing_production') NOT VALID")
    with pytest.raises(asyncpg.CheckViolationError):
        async with db.transaction() as tx:
            await install_verified_manifest_on(tx, team_id=TEAM, fetched=evidence, granted_scopes=[], hook_context=MutationHookContext(None, SYSTEM, origin="https://core.example"))
    assert await db.fetch_value("SELECT COUNT(*) FROM {{tables.team_app_installs}} WHERE app_id='fixture'") == 0
    assert await db.fetch_value("SELECT COUNT(*) FROM {{tables.outbox_sequences}}") == 0
    assert await db.fetch_value("SELECT COUNT(*) FROM {{tables.outbox_events}}") == 0
