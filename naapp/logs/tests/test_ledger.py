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
from aweb_logs.chain import artefact_sha256, open_checkpoint, open_receipt
from aweb_logs.ledger import (
    Appended,
    Conflicted,
    LogsSigner,
    append,
    issue_checkpoint,
    load_epoch,
    open_next_epoch,
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
