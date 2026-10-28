"""Appending to a team's chain, checkpointing it and starting a new epoch, on real PostgreSQL."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from aweb_naapp.hooks import envelope as hook_envelope
from nacl.signing import SigningKey
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager

from aweb_logs import MIGRATIONS_MODULE, MIGRATIONS_PATH
from aweb_logs.chain import Genesis, artefact_sha256, format_time, open_checkpoint, open_receipt
from aweb_logs.ledger import (
    Appended,
    Conflicted,
    LogsSigner,
    OriginMismatch,
    append,
    append_on,
    checkpoint_moved_heads,
    issue_checkpoint,
    load_epoch,
    open_next_epoch,
    verify_epoch,
)
from aweb_logs.verify import verify_chain

from .fixtures import LOGS_KID, LOGS_ORIGIN, LOGS_SEED, TEAM_ID, did_key, signed_event

SIGNER = LogsSigner(logs_origin=LOGS_ORIGIN, kid=LOGS_KID, signing_key=SigningKey(LOGS_SEED))
LOGS_KEYS = frozenset({did_key(LOGS_SEED)})
OTHER_TEAM = "other:example.com"
START = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)


@pytest.fixture
async def db(test_db_factory) -> AsyncIterator[AsyncDatabaseManager]:
    database = await test_db_factory.create_db(suffix="logs_ledger")
    await AsyncMigrationManager(
        database, migrations_path=str(MIGRATIONS_PATH), module_name=MIGRATIONS_MODULE
    ).apply_pending_migrations()
    yield database


def _evidence(signing: bytes) -> dict[str, object]:
    event = hook_envelope.open_envelope(signing)
    return {"did_key": event.producer_did_key, "kid": event.producer_kid}


async def _append(
    db: AsyncDatabaseManager,
    kind: str = "core",
    *,
    event_id: str | None = None,
    team_id: str = TEAM_ID,
    seq: int = 1,
    at: datetime = START,
) -> Appended | Conflicted:
    signing, signature = signed_event(
        kind, event_id=event_id or str(uuid.uuid4()), seq=seq, team_id=team_id
    )
    event = hook_envelope.verify(signing, signature, team_id=team_id)
    return await append(
        db,
        SIGNER,
        event=event,
        signing_bytes=signing,
        signature=signature,
        key_evidence=_evidence(signing),
        received_at=at,
    )


async def _verify(db: AsyncDatabaseManager, team_id: str = TEAM_ID, epoch: int = 1, **artefacts):
    genesis, events = await load_epoch(db, team_id, epoch)
    return verify_chain(
        genesis, events, receipt_keys=LOGS_KEYS, checkpoint_keys=LOGS_KEYS, **artefacts
    )


async def test_appended_events_chain_and_each_gets_a_receipt(db: AsyncDatabaseManager) -> None:
    results = [
        await _append(db, kind, seq=i + 1) for i, kind in enumerate(("core", "app", "client"))
    ]
    assert all(isinstance(result, Appended) and not result.duplicate for result in results)
    receipts = [open_receipt(*result.receipt) for result in results]  # type: ignore[union-attr]
    assert [receipt.team_seq for receipt in receipts] == [1, 2, 3]
    assert {receipt.did_key for receipt in receipts} == LOGS_KEYS
    report = await _verify(db, receipts=[result.receipt for result in results])  # type: ignore[union-attr]
    assert report.to_json() == {"intact": True, "missing": [], "purged": [], "contradicted": []}


async def test_a_redelivery_returns_the_original_receipt(db: AsyncDatabaseManager) -> None:
    event_id = str(uuid.uuid4())
    first = await _append(db, event_id=event_id)
    again = await _append(db, event_id=event_id, at=START + timedelta(minutes=5))
    assert isinstance(first, Appended) and isinstance(again, Appended)
    assert again.duplicate and again.receipt == first.receipt
    _, events = await load_epoch(db, TEAM_ID, 1)
    assert len(events) == 1


async def test_other_bytes_under_a_known_event_id_conflict_and_are_kept_as_a_fault(
    db: AsyncDatabaseManager,
) -> None:
    event_id = str(uuid.uuid4())
    await _append(db, event_id=event_id, seq=1)
    conflicted = await _append(db, event_id=event_id, seq=2)
    assert conflicted == Conflicted(event_id=uuid.UUID(event_id))
    faults = await db.fetch_all(
        "SELECT event_id, kind FROM {{tables.chain_faults}} WHERE team_id = $1", TEAM_ID
    )
    assert [(row["event_id"], row["kind"]) for row in faults] == [
        (uuid.UUID(event_id), "event_conflict")
    ]
    _, events = await load_epoch(db, TEAM_ID, 1)
    assert len(events) == 1


async def test_concurrent_appends_get_gap_free_sequence_numbers(db: AsyncDatabaseManager) -> None:
    results = await asyncio.gather(*(_append(db, seq=i + 1) for i in range(12)))
    seqs = sorted(open_receipt(*result.receipt).team_seq for result in results)  # type: ignore[union-attr]
    assert seqs == list(range(1, 13))
    assert (await _verify(db)).intact


async def test_each_team_has_its_own_chain(db: AsyncDatabaseManager) -> None:
    await _append(db, team_id=TEAM_ID)
    await _append(db, team_id=TEAM_ID, seq=2)
    other = await _append(db, team_id=OTHER_TEAM)
    assert isinstance(other, Appended)
    assert open_receipt(*other.receipt).team_seq == 1
    assert (await _verify(db, OTHER_TEAM)).intact


async def test_checkpoints_witness_the_head_and_link_to_each_other(
    db: AsyncDatabaseManager,
) -> None:
    await _append(db)
    first = await issue_checkpoint(db, SIGNER, TEAM_ID, issued_at=START + timedelta(minutes=1))
    await _append(db, seq=2)
    second = await issue_checkpoint(db, SIGNER, TEAM_ID, issued_at=START + timedelta(minutes=2))
    opened = [open_checkpoint(*first), open_checkpoint(*second)]
    assert [checkpoint.team_seq for checkpoint in opened] == [1, 2]
    assert opened[0].previous_checkpoint_sha256 is None
    assert opened[1].previous_checkpoint_sha256 == artefact_sha256(first[0])
    assert (await _verify(db, checkpoints=[first, second])).intact


async def test_a_team_with_no_chain_has_nothing_to_checkpoint(db: AsyncDatabaseManager) -> None:
    with pytest.raises(LookupError):
        await issue_checkpoint(db, SIGNER, TEAM_ID, issued_at=START)


async def test_a_new_epoch_records_the_previous_ones_final_checkpoint(
    db: AsyncDatabaseManager,
) -> None:
    await _append(db)
    final = await open_next_epoch(db, SIGNER, TEAM_ID, at=START + timedelta(minutes=1))
    appended = await _append(db, seq=2, at=START + timedelta(minutes=2))
    assert isinstance(appended, Appended)
    receipt = open_receipt(*appended.receipt)
    assert (receipt.chain_epoch, receipt.team_seq) == (2, 1)

    genesis, _ = await load_epoch(db, TEAM_ID, 2)
    assert genesis.previous_checkpoint_sha256 == artefact_sha256(final[0])
    assert open_checkpoint(*final).team_seq == 1
    assert (await _verify(db, epoch=1, checkpoints=[final])).intact
    assert (await _verify(db, epoch=2, receipts=[appended.receipt])).intact


async def test_a_redelivery_of_a_purged_event_returns_its_receipt(
    db: AsyncDatabaseManager,
) -> None:
    event_id = str(uuid.uuid4())
    first = await _append(db, event_id=event_id)
    await db.execute(
        "UPDATE {{tables.chain_events}} SET salt = NULL, signing_bytes = NULL, signature = NULL,"
        " purge_act = 'logs.erase:test' WHERE event_id = $1",
        uuid.UUID(event_id),
    )
    again = await _append(db, event_id=event_id)
    assert isinstance(first, Appended) and isinstance(again, Appended)
    assert again.duplicate and again.receipt == first.receipt


MOVED = LogsSigner(
    logs_origin="https://logs.moved.example", kid=LOGS_KID, signing_key=SigningKey(LOGS_SEED)
)


async def test_an_epoch_signs_only_under_its_own_origin(db: AsyncDatabaseManager) -> None:
    await _append(db)
    signing, signature = signed_event("core", event_id=str(uuid.uuid4()), seq=2)
    with pytest.raises(OriginMismatch):
        await append(
            db,
            MOVED,
            event=hook_envelope.verify(signing, signature, team_id=TEAM_ID),
            signing_bytes=signing,
            signature=signature,
            key_evidence=_evidence(signing),
            received_at=START,
        )
    with pytest.raises(OriginMismatch):
        await issue_checkpoint(db, MOVED, TEAM_ID, issued_at=START)
    with pytest.raises(OriginMismatch):
        await open_next_epoch(db, MOVED, TEAM_ID, at=START)
    _, events = await load_epoch(db, TEAM_ID, 1)
    assert len(events) == 1


async def test_a_new_epoch_can_move_to_another_origin(db: AsyncDatabaseManager) -> None:
    await _append(db)
    final = await open_next_epoch(
        db, SIGNER, TEAM_ID, at=START + timedelta(minutes=1), logs_origin=MOVED.logs_origin
    )
    signing, signature = signed_event("core", event_id=str(uuid.uuid4()), seq=2)
    moved = await append(
        db,
        MOVED,
        event=hook_envelope.verify(signing, signature, team_id=TEAM_ID),
        signing_bytes=signing,
        signature=signature,
        key_evidence=_evidence(signing),
        received_at=START + timedelta(minutes=2),
    )
    assert isinstance(moved, Appended)
    assert open_checkpoint(*final).logs_origin == LOGS_ORIGIN
    assert open_receipt(*moved.receipt).logs_origin == MOVED.logs_origin
    assert (await _verify(db, epoch=1, checkpoints=[final])).intact
    assert (await _verify(db, epoch=2, receipts=[moved.receipt])).intact


async def test_a_purged_event_still_conflicts_on_what_its_skeleton_keeps(
    db: AsyncDatabaseManager,
) -> None:
    event_id = str(uuid.uuid4())
    await _append(db, "core", event_id=event_id)
    await db.execute(
        "UPDATE {{tables.chain_events}} SET salt = NULL, signing_bytes = NULL, signature = NULL,"
        " purge_act = 'logs.erase:test' WHERE event_id = $1",
        uuid.UUID(event_id),
    )
    other_producer = await _append(db, "app", event_id=event_id)
    assert other_producer == Conflicted(event_id=uuid.UUID(event_id))


async def test_a_checkpoint_waiting_on_an_epoch_move_witnesses_the_new_epoch(
    db: AsyncDatabaseManager,
) -> None:
    await _append(db)
    moved_genesis_at = START + timedelta(minutes=1)
    async with db.transaction() as tx:
        await tx.fetch_one(
            "SELECT team_id FROM {{tables.chain_heads}} WHERE team_id = $1 FOR UPDATE", TEAM_ID
        )
        waiting = asyncio.create_task(
            issue_checkpoint(db, SIGNER, TEAM_ID, issued_at=START + timedelta(minutes=2))
        )
        await asyncio.sleep(0.3)
        assert not waiting.done()
        genesis = Genesis(
            team_id=TEAM_ID,
            chain_epoch=2,
            logs_origin=LOGS_ORIGIN,
            created_at=format_time(moved_genesis_at),
            previous_checkpoint_sha256="00" * 32,
        )
        await tx.execute(
            "INSERT INTO {{tables.chain_epochs}} (team_id, chain_epoch, logs_origin, created_at,"
            " previous_checkpoint_sha256, genesis_hash) VALUES ($1, 2, $2, $3, $4, $5)",
            TEAM_ID,
            LOGS_ORIGIN,
            genesis.created_at,
            genesis.previous_checkpoint_sha256,
            genesis.hash(),
        )
        await tx.execute(
            "UPDATE {{tables.chain_heads}} SET chain_epoch = 2, team_seq = 0, event_hash = $2"
            " WHERE team_id = $1",
            TEAM_ID,
            genesis.hash(),
        )
    checkpoint = open_checkpoint(*await waiting)
    assert (checkpoint.chain_epoch, checkpoint.team_seq) == (2, 0)


async def _checkpoint_seqs(db: AsyncDatabaseManager, team_id: str = TEAM_ID) -> list[tuple[int, int]]:
    rows = await db.fetch_all(
        "SELECT chain_epoch, team_seq FROM {{tables.chain_checkpoints}}"
        " WHERE team_id = $1 ORDER BY position",
        team_id,
    )
    return [(row["chain_epoch"], row["team_seq"]) for row in rows]


async def test_a_pass_checkpoints_each_head_that_moved_and_nothing_else(
    db: AsyncDatabaseManager,
) -> None:
    await _append(db, team_id=TEAM_ID)
    await _append(db, team_id=TEAM_ID, seq=2)
    await _append(db, team_id=OTHER_TEAM)
    assert sorted(await checkpoint_moved_heads(db, SIGNER, issued_at=START)) == sorted(
        [TEAM_ID, OTHER_TEAM]
    )
    assert await _checkpoint_seqs(db) == [(1, 2)]
    assert await checkpoint_moved_heads(db, SIGNER, issued_at=START) == []

    await _append(db, team_id=TEAM_ID, seq=3)
    assert await checkpoint_moved_heads(db, SIGNER, issued_at=START) == [TEAM_ID]
    assert await _checkpoint_seqs(db) == [(1, 2), (1, 3)]
    checkpoints = await db.fetch_all(
        "SELECT signing_bytes, signature FROM {{tables.chain_checkpoints}}"
        " WHERE team_id = $1 ORDER BY position",
        TEAM_ID,
    )
    report = await _verify(
        db, checkpoints=[(bytes(row["signing_bytes"]), row["signature"]) for row in checkpoints]
    )
    assert report.intact


async def test_a_pass_skips_an_epoch_with_no_events_yet(db: AsyncDatabaseManager) -> None:
    await _append(db)
    await open_next_epoch(db, SIGNER, TEAM_ID, at=START)
    assert await checkpoint_moved_heads(db, SIGNER, issued_at=START) == []
    assert await _checkpoint_seqs(db) == [(1, 1)]


async def test_a_pass_leaves_an_epoch_of_another_origin_to_it(db: AsyncDatabaseManager) -> None:
    await _append(db)
    await open_next_epoch(db, SIGNER, TEAM_ID, at=START, logs_origin=MOVED.logs_origin)
    signing, signature = signed_event("core", event_id=str(uuid.uuid4()), seq=2)
    await append(
        db,
        MOVED,
        event=hook_envelope.verify(signing, signature, team_id=TEAM_ID),
        signing_bytes=signing,
        signature=signature,
        key_evidence=_evidence(signing),
        received_at=START,
    )
    assert await checkpoint_moved_heads(db, SIGNER, issued_at=START) == []
    assert await checkpoint_moved_heads(db, MOVED, issued_at=START) == [TEAM_ID]
    assert await _checkpoint_seqs(db) == [(1, 1), (2, 1)]


async def test_concurrent_passes_sign_each_moved_head_once(db: AsyncDatabaseManager) -> None:
    for seq in range(1, 4):
        await _append(db, seq=seq)
    passes = await asyncio.gather(
        *(checkpoint_moved_heads(db, SIGNER, issued_at=START) for _ in range(6))
    )
    assert sorted(team for result in passes for team in result) == [TEAM_ID]
    assert await _checkpoint_seqs(db) == [(1, 3)]


async def test_caller_transaction_rolls_back_its_effect_and_chain_append(
    db: AsyncDatabaseManager,
) -> None:
    await db.execute("CREATE TABLE {{tables.caller_effects}} (effect_id INTEGER PRIMARY KEY)")
    signing, signature = signed_event("app", event_id=str(uuid.uuid4()))
    event = hook_envelope.verify(signing, signature, team_id=TEAM_ID)
    with pytest.raises(RuntimeError, match="forced caller rollback"):
        async with db.transaction() as tx:
            await tx.execute("INSERT INTO {{tables.caller_effects}} VALUES (1)")
            result = await append_on(
                tx, SIGNER, event=event, signing_bytes=signing, signature=signature,
                key_evidence=_evidence(signing), received_at=START,
            )
            assert isinstance(result, Appended) and not result.duplicate
            assert await tx.fetch_value("SELECT count(*) FROM {{tables.chain_events}}") == 1
            raise RuntimeError("forced caller rollback")
    for table in ("caller_effects", "chain_events", "chain_epochs", "chain_heads"):
        assert await db.fetch_value("SELECT count(*) FROM {{tables." + table + "}}") == 0


async def test_caller_transaction_commits_the_original_receipt_for_later_redelivery(
    db: AsyncDatabaseManager,
) -> None:
    await db.execute("CREATE TABLE {{tables.caller_effects}} (effect_id INTEGER PRIMARY KEY)")
    event_id = str(uuid.uuid4())
    signing, signature = signed_event("app", event_id=event_id)
    event = hook_envelope.verify(signing, signature, team_id=TEAM_ID)
    async with db.transaction() as tx:
        await tx.execute("INSERT INTO {{tables.caller_effects}} VALUES (1)")
        first = await append_on(
            tx, SIGNER, event=event, signing_bytes=signing, signature=signature,
            key_evidence=_evidence(signing), received_at=START,
        )
    delivered = await append(
        db, SIGNER, event=event, signing_bytes=signing, signature=signature,
        key_evidence=_evidence(signing), received_at=START + timedelta(seconds=1),
    )
    assert isinstance(first, Appended) and isinstance(delivered, Appended)
    assert not first.duplicate and delivered.duplicate and delivered.receipt == first.receipt
    assert await db.fetch_value("SELECT count(*) FROM {{tables.caller_effects}}") == 1
    assert await db.fetch_value("SELECT team_seq FROM {{tables.chain_heads}}") == 1
    assert (await _verify(db, receipts=[first.receipt])).intact


async def test_verify_reports_conflicts_in_this_team_epoch_without_returning_refused_content(db):
    event_id = str(uuid.uuid4())
    await _append(db, event_id=event_id, seq=40)
    await _append(db, event_id=event_id, seq=41)
    await _append(db, team_id=OTHER_TEAM)
    report = await verify_epoch(db, TEAM_ID, 1, receipt_keys=LOGS_KEYS, checkpoint_keys=LOGS_KEYS)
    assert report["intact"] is True
    conflict, = report["conflicts"]
    assert conflict["event_id"] == event_id
    assert conflict["team_seq"] == 1
    assert conflict["kind"] == "event_conflict"
    assert set(conflict) == {"fault_id", "event_id", "team_seq", "kind", "refused_sha256", "recorded_at"}
    assert (await verify_epoch(db, OTHER_TEAM, 1, receipt_keys=LOGS_KEYS, checkpoint_keys=LOGS_KEYS))["conflicts"] == []
    await open_next_epoch(db, SIGNER, TEAM_ID, at=START + timedelta(hours=1))
    assert (await verify_epoch(db, TEAM_ID, 2, receipt_keys=LOGS_KEYS, checkpoint_keys=LOGS_KEYS))["conflicts"] == []


async def test_duplicate_keeps_each_admitted_binding_context_but_the_original_receipt(db):
    signing, signature = signed_event("app", event_id=str(uuid.uuid4()))
    event = hook_envelope.verify(signing, signature, team_id=TEAM_ID)
    receipts = []
    for binding_id in ("first", "second", "second"):
        evidence = {**_evidence(signing), "admissions": [{"registration": {"binding_id": binding_id}}]}
        result = await append(db, SIGNER, event=event, signing_bytes=signing, signature=signature,
                              key_evidence=evidence, received_at=START)
        assert isinstance(result, Appended)
        receipts.append(result.receipt)
    assert receipts[0] == receipts[1] == receipts[2]
    _, events = await load_epoch(db, TEAM_ID, 1)
    stored, = events
    assert [a["registration"]["binding_id"] for a in stored.key_evidence["admissions"]] == ["first", "second"]
