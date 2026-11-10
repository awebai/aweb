"""logs' own owner acts (audit-substrate.md §B6): the owner sets retention,
erases and holds, each by a real owner act consumed in the transaction that
applies it and recorded in logs' own chain. A legal hold is recorded even when
no hook target would admit a widening act (ruling ed36580d); every other
widening act still needs one. Real PostgreSQL, a real AWID registry."""

from __future__ import annotations

import asyncio
import copy
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from aweb_naapp.hooks import envelope as hook_envelope
from aweb_naapp.hooks.owner_act import Refused, VerifiedOwnerAct
from aweb_naapp_testing.owner_acts import APP_ID, INSTALLATION_ID, TEAM_ID

from aweb_logs.governance import GovernanceRefused
from aweb_logs.ledger import append, open_next_epoch, verify_epoch
from aweb_logs.retention import apply_retention

from .fixtures import _APP_EVENT, SECRETS_SEED
from .reader_world import (
    LOGS,
    World,
    count,
    designation,
    outbox,
    slot,
    world_fixture,  # noqa: F401
)
from .test_read_store import AGENT, secret_use

NOW = datetime.now(UTC)
OTHER_AGENT = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"


def subject(**fields) -> dict:
    return {"app_id": APP_ID, "installation_id": INSTALLATION_ID, **fields}


async def appended(world: World, signed: tuple[bytes, str], *, age: timedelta) -> None:
    signing, signature = signed
    event = hook_envelope.verify(signing, signature, team_id=TEAM_ID)
    await append(
        world.db,
        world.signer,
        event=event,
        signing_bytes=signing,
        signature=signature,
        key_evidence={"did_key": event.producer_did_key, "kid": event.producer_kid},
        received_at=NOW - age,
    )


async def purged(world: World) -> dict[int, str | None]:
    rows = await world.db.fetch_all(
        "SELECT team_seq, purge_act FROM {{tables.chain_events}}"
        " WHERE team_id = $1 AND hook = 'post-secret-use-hook' ORDER BY team_seq",
        TEAM_ID,
    )
    return {row["team_seq"]: row["purge_act"] for row in rows}


async def governance(world: World) -> list[dict]:
    """The payloads of logs' own governance entries, which no erasure purges."""
    rows = await world.db.fetch_all(
        "SELECT signing_bytes, signature FROM {{tables.chain_events}}"
        " WHERE team_id = $1 AND hook = 'post-governance-hook' ORDER BY team_seq",
        TEAM_ID,
    )
    return [
        hook_envelope.verify(bytes(row["signing_bytes"]), row["signature"], team_id=TEAM_ID).fields[
            "payload"
        ]
        for row in rows
    ]


async def set_retention(world: World, event_class: str, days: int | None) -> str:
    fields: dict[str, str | int] = {
        "event_class": event_class,
        "retention": "keep" if days is None else "days",
    }
    if days is not None:
        fields["retention_days"] = days
    signing, signature = world.owner.sign("logs.retention.set", subject(**fields))
    return await world.governance.set_retention(
        TEAM_ID, signing=signing, signature=signature, **fields
    )


async def hold(world: World, hold_id: str, *, actor_ref: str | None = None) -> str:
    fields = {"hold_id": hold_id, "hold_scope": "all" if actor_ref is None else "actor",
              "reason_code": "litigation"}  # fmt: skip
    if actor_ref is not None:
        fields["actor_ref"] = actor_ref
    signing, signature = world.owner.sign("logs.legal-hold.set", subject(**fields))
    return await world.governance.set_hold(TEAM_ID, signing=signing, signature=signature, **fields)


async def release(world: World, hold_id: str) -> str:
    signing, signature = world.owner.sign("logs.legal-hold.release", subject(hold_id=hold_id))
    return await world.governance.release_hold(
        TEAM_ID, signing=signing, signature=signature, hold_id=hold_id
    )


async def erase(world: World, **fields) -> int:
    fields = {"reason_code": "data_subject_request", **fields}
    signing, signature = world.owner.sign("logs.erase", subject(**fields))
    return await world.governance.erase(TEAM_ID, signing=signing, signature=signature, **fields)


async def test_a_shortened_retention_is_recorded_and_its_purges_name_that_record(world: World):
    await appended(world, secret_use(seq=1), age=timedelta(days=45))
    await appended(world, secret_use(seq=2), age=timedelta(days=1))
    event_id = await set_retention(world, "all", 30)
    [entry] = await governance(world)
    assert entry["act"] == "logs.retention.shortened"
    assert (entry["event_class"], entry["retention"], entry["retention_days"]) == (
        "all",
        "days",
        30,
    )
    assert entry["authority"] == "owner_act"
    assert await apply_retention(world.db, now=NOW, logs_origin=LOGS) == 1
    assert await purged(world) == {1: f"logs.retention.set:{event_id}", 2: None}


async def test_keeping_events_longer_is_a_widening_act_that_needs_a_target(world: World):
    await set_retention(world, "all", 30)
    world.registered[0] = False
    with pytest.raises(Refused) as refused:
        await set_retention(world, "all", None)
    assert refused.value.code == "audit_target_unavailable"
    assert [entry["act"] for entry in await governance(world)] == ["logs.retention.shortened"]
    world.registered[0] = True
    await set_retention(world, "all", None)
    assert [entry["act"] for entry in await governance(world)] == [
        "logs.retention.shortened",
        "logs.retention.lengthened",
    ]


async def test_an_erased_range_is_purged_and_counted_in_its_record(world: World):
    for seq in (1, 2, 3):
        await appended(world, secret_use(seq=seq), age=timedelta(days=1))
    assert (
        await erase(world, erase_scope="range", chain_epoch=1, team_seq_first=1, team_seq_last=2)
        == 2
    )
    entry = (await governance(world))[-1]
    assert entry["act"] == "logs.erased"
    assert (entry["erased_count"], entry["team_seq_first"], entry["team_seq_last"]) == (2, 1, 2)
    erased = await world.db.fetch_value(
        "SELECT event_id FROM {{tables.chain_events}} WHERE team_id = $1"
        " AND hook = 'post-governance-hook' ORDER BY team_seq DESC LIMIT 1",
        TEAM_ID,
    )
    assert await purged(world) == {1: f"logs.erase:{erased}", 2: f"logs.erase:{erased}", 3: None}


async def test_an_actors_erasure_purges_only_that_actors_events(world: World):
    await appended(world, secret_use(seq=1), age=timedelta(days=1))
    await appended(world, secret_use(seq=2, actor=OTHER_AGENT), age=timedelta(days=1))
    await appended(world, secret_use(seq=3), age=timedelta(days=1))
    assert await erase(world, erase_scope="actor", actor_ref=AGENT) == 2
    after = await purged(world)
    assert after[2] is None and after[1] is not None and after[3] is not None
    entry = (await governance(world))[-1]
    assert (entry["actor_ref"], entry["erased_count"]) == (AGENT, 2)
    assert "team_seq_first" not in entry


async def test_an_erasure_names_its_actor_by_a_did_only(world: World):
    await appended(world, secret_use(seq=1), age=timedelta(days=1))
    with pytest.raises(GovernanceRefused):
        await erase(world, erase_scope="actor", actor_ref="bond")
    assert await purged(world) == {1: None}
    assert await count(world, "owner_act_nonces") == 0


async def test_a_hold_on_everything_stops_retention_and_erasure_until_released(world: World):
    await appended(world, secret_use(seq=1), age=timedelta(days=45))
    await hold(world, "hold-1")
    await set_retention(world, "all", 30)
    assert await apply_retention(world.db, now=NOW, logs_origin=LOGS) == 0
    with pytest.raises(GovernanceRefused):
        await erase(world, erase_scope="range", chain_epoch=1, team_seq_first=1, team_seq_last=1)
    await release(world, "hold-1")
    assert await apply_retention(world.db, now=NOW, logs_origin=LOGS) == 1
    assert [entry["act"] for entry in await governance(world)] == [
        "logs.legal_hold.set",
        "logs.retention.shortened",
        "logs.legal_hold.released",
    ]


async def test_a_hold_on_an_actor_keeps_only_that_actors_events(world: World):
    await appended(world, secret_use(seq=1), age=timedelta(days=45))
    await appended(world, secret_use(seq=2, actor=OTHER_AGENT), age=timedelta(days=45))
    await hold(world, "hold-1", actor_ref=AGENT)
    await set_retention(world, "all", 30)
    assert await apply_retention(world.db, now=NOW, logs_origin=LOGS) == 1
    after = await purged(world)
    assert after[1] is None and after[2] is not None


async def test_a_hold_is_recorded_and_owed_with_no_target_while_a_designation_is_refused(
    world: World,
):
    world.registered[0] = False
    await hold(world, "hold-1")
    assert [entry["act"] for entry in await governance(world)] == ["logs.legal_hold.set"]
    assert len(await outbox(world)) == 1
    scope = await slot(world)
    signing, signature = world.owner.sign("app-role.designate", designation(scope))
    with pytest.raises(Refused) as refused:
        await world.designations.designate(
            signing=signing, signature=signature, scope=scope, contact="reader@example.com"
        )
    assert refused.value.code == "audit_target_unavailable"
    assert [entry["act"] for entry in await governance(world)] == ["logs.legal_hold.set"]


async def test_a_hold_is_recorded_while_logs_own_delivery_is_stalled(world: World):
    await hold(world, "hold-1")
    await world.db.execute(
        "UPDATE {{tables.outbox_events}} SET created_at = created_at - interval '1 day'"
    )
    await hold(world, "hold-2")
    assert [entry["hold_id"] for entry in await governance(world)] == ["hold-1", "hold-2"]
    assert len(await outbox(world)) == 2
    scope = await slot(world)
    signing, signature = world.owner.sign("app-role.designate", designation(scope))
    with pytest.raises(Refused) as refused:
        await world.designations.designate(
            signing=signing, signature=signature, scope=scope, contact="reader@example.com"
        )
    assert refused.value.code == "audit_delivery_stalled"


async def test_a_hold_id_is_set_once(world: World):
    await hold(world, "hold-1")
    with pytest.raises(GovernanceRefused):
        await hold(world, "hold-1")
    with pytest.raises(GovernanceRefused):
        await release(world, "hold-2")


def another_apps_governance(**payload) -> tuple[bytes, str]:
    """A post-governance-hook event another app produced and logs received."""
    event = copy.deepcopy(_APP_EVENT)
    event["event_id"] = str(uuid.uuid4())
    event["hook"] = "post-governance-hook"
    event["payload"] = payload or {"act": "role.revoked", "direction": "narrowing"}
    return hook_envelope.sign(SECRETS_SEED, event)


async def test_retention_never_purges_logs_own_governance_records(world: World):
    await hold(world, "hold-1")
    await release(world, "hold-1")
    await appended(world, another_apps_governance(), age=timedelta(days=2))
    await appended(world, secret_use(seq=1), age=timedelta(days=2))
    await set_retention(world, "all", 1)
    later = datetime.now(UTC) + timedelta(days=3)
    assert await apply_retention(world.db, now=later, logs_origin=LOGS) == 2
    rows = await world.db.fetch_all(
        "SELECT producer_origin = $2 AS own, purge_act IS NOT NULL AS purged"
        " FROM {{tables.chain_events}} WHERE team_id = $1 ORDER BY team_seq",
        TEAM_ID,
        LOGS,
    )
    assert {(row["own"], row["purged"]) for row in rows} == {(True, False), (False, True)}


async def test_an_owner_act_records_only_the_event_acts_it_permits(world: World):
    erase = VerifiedOwnerAct(
        fields={}, act="logs.erase", team_id=TEAM_ID, audience=LOGS, subject={},
        nonce="n", issued_at=NOW, expires_at=NOW, transaction_id=None,
    )  # fmt: skip
    async with world.db.transaction() as tx:
        with pytest.raises(GovernanceRefused):
            await world.governance._record(tx, erase, {"act": "logs.legal_hold.set"})


async def test_lengthening_a_hooks_inherited_retention_needs_a_target(world: World):
    await set_retention(world, "all", 30)
    world.registered[0] = False
    with pytest.raises(Refused) as refused:
        await set_retention(world, "post-secret-use-hook", 90)
    assert refused.value.code == "audit_target_unavailable"
    world.registered[0] = True
    await set_retention(world, "post-secret-use-hook", 90)
    assert [entry["act"] for entry in await governance(world)] == [
        "logs.retention.shortened",
        "logs.retention.lengthened",
    ]


async def test_an_erasure_counts_what_it_purged_while_retention_runs(world: World):
    for seq in (1, 2):
        await appended(world, secret_use(seq=seq), age=timedelta(days=45))
    await set_retention(world, "all", 30)
    recording = asyncio.Event()
    proceed = asyncio.Event()

    async def held_while_recording() -> None:
        recording.set()
        await proceed.wait()

    world.before_append = held_while_recording
    range_ = {"erase_scope": "range", "chain_epoch": 1, "team_seq_first": 1, "team_seq_last": 2}
    erasing = asyncio.create_task(erase(world, **range_))
    await recording.wait()
    retained = await apply_retention(world.db, now=NOW, logs_origin=LOGS)
    proceed.set()
    erased = await erasing
    assert (erased, retained) == (2, 0)
    record = await world.db.fetch_value(
        "SELECT event_id FROM {{tables.chain_events}} WHERE team_id = $1"
        " AND hook = 'post-governance-hook' ORDER BY team_seq DESC LIMIT 1",
        TEAM_ID,
    )
    named = await world.db.fetch_value(
        "SELECT count(*) FROM {{tables.chain_events}} WHERE team_id = $1 AND purge_act = $2",
        TEAM_ID,
        f"logs.erase:{record}",
    )
    assert ((await governance(world))[-1]["erased_count"], named) == (2, 2)


@pytest.mark.parametrize("actor_ref", ["did:aw:", "did:key:not-a-key", "did:aw:0OIl"])
async def test_an_actor_is_a_whole_valid_did(world: World, actor_ref: str):
    await appended(world, secret_use(seq=1), age=timedelta(days=1))
    with pytest.raises(GovernanceRefused):
        await erase(world, erase_scope="actor", actor_ref=actor_ref)
    with pytest.raises(GovernanceRefused):
        await hold(world, "hold-1", actor_ref=actor_ref)
    assert await count(world, "owner_act_nonces") == 0
    assert await governance(world) == []


async def test_an_erasure_and_an_append_overlapping_on_unprojected_history_both_complete(
    world: World,
):
    await appended(world, secret_use(seq=1), age=timedelta(days=1))
    await world.db.execute("DELETE FROM {{tables.read_events}} WHERE team_id = $1", TEAM_ID)
    recording = asyncio.Event()
    proceed = asyncio.Event()

    async def held_while_recording() -> None:
        recording.set()
        await proceed.wait()

    world.before_append = held_while_recording
    range_ = {"erase_scope": "range", "chain_epoch": 1, "team_seq_first": 1, "team_seq_last": 1}
    erasing = asyncio.create_task(erase(world, **range_))
    await recording.wait()
    appending = asyncio.create_task(appended(world, secret_use(seq=2), age=timedelta(seconds=1)))
    await asyncio.sleep(0.5)
    proceed.set()
    assert await erasing == 1
    await appending
    first, second = (await purged(world)).values()
    assert first is not None and second is None


async def verified(world: World, chain_epoch: int = 1) -> dict:
    keys = frozenset({world.signer.did_key})
    return await verify_epoch(
        world.db, TEAM_ID, chain_epoch, receipt_keys=keys, checkpoint_keys=keys
    )


async def governance_positions(world: World) -> list[dict]:
    """Where each of logs' own governance entries sits in the team's chain."""
    rows = await world.db.fetch_all(
        "SELECT chain_epoch, team_seq FROM {{tables.chain_events}} WHERE team_id = $1"
        " AND hook = 'post-governance-hook' AND producer_origin = $2"
        " ORDER BY chain_epoch, team_seq",
        TEAM_ID,
        LOGS,
    )
    return [{"chain_epoch": row["chain_epoch"], "team_seq": row["team_seq"]} for row in rows]


async def test_verify_discloses_each_hold_from_its_chain_entries(world: World):
    await appended(world, secret_use(seq=1), age=timedelta(days=1))
    await hold(world, "hold-1")
    await hold(world, "hold-2", actor_ref=AGENT)
    await release(world, "hold-1")
    set_1, set_2, released_1 = await governance_positions(world)
    report = await verified(world)
    assert report["intact"]
    assert report["holds"] == [
        {"hold_id": "hold-1", "hold_scope": "all", "set": set_1, "released": released_1},
        {"hold_id": "hold-2", "hold_scope": "actor", "actor_ref": AGENT, "set": set_2,
         "released": None},
    ]  # fmt: skip


async def test_verify_never_counts_another_producers_hold_acts(world: World):
    await hold(world, "hold-1")
    forged = {"direction": "widening", "hold_scope": "all", "reason_code": "litigation"}
    await appended(
        world,
        another_apps_governance(act="logs.legal_hold.set", hold_id="forged", **forged),
        age=timedelta(seconds=1),
    )
    await appended(
        world,
        another_apps_governance(act="logs.legal_hold.released", direction="narrowing",
                                hold_id="hold-1"),
        age=timedelta(seconds=1),
    )  # fmt: skip
    [set_1] = await governance_positions(world)
    report = await verified(world)
    assert report["intact"]
    assert report["holds"] == [
        {"hold_id": "hold-1", "hold_scope": "all", "set": set_1, "released": None}
    ]


async def test_verify_carries_each_hold_still_active_into_the_next_epoch(world: World):
    await hold(world, "hold-1")
    await hold(world, "hold-2")
    await release(world, "hold-2")
    await open_next_epoch(world.db, world.signer, TEAM_ID, at=datetime.now(UTC))
    await hold(world, "hold-3", actor_ref=AGENT)
    await release(world, "hold-1")
    set_1, _, _, set_3, released_1 = await governance_positions(world)
    assert (set_1["chain_epoch"], set_3["chain_epoch"], released_1["chain_epoch"]) == (1, 2, 2)
    report = await verified(world, chain_epoch=2)
    assert report["intact"]
    assert report["holds"] == [
        {"hold_id": "hold-1", "hold_scope": "all", "set": set_1, "released": released_1},
        {"hold_id": "hold-3", "hold_scope": "actor", "actor_ref": AGENT, "set": set_3,
         "released": None},
    ]  # fmt: skip
