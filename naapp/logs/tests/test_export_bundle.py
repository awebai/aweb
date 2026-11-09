"""Exporting a team's stored log as an ``aweb.logs-export/1`` bundle
(docs/logs-chain.md), read from real PostgreSQL and checked by the bundle
verifier with no server."""

from __future__ import annotations

import asyncio
import io
import json
from collections.abc import AsyncIterator
from datetime import timedelta

import pytest
from aweb_naapp.hooks import envelope as hook_envelope
from aweb_naapp.hooks.envelope import MAX_ENVELOPE_BYTES
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager

from aweb_logs import MIGRATIONS_MODULE, MIGRATIONS_PATH
from aweb_logs.export import EXPORT_PAGE, export_bundle, header_line, verify_bundle
from aweb_logs.ledger import Appended, append, issue_checkpoint, open_next_epoch
from aweb_logs.retention import purge

from .fixtures import TEAM_ID
from .test_read_store import OTHER_TEAM, SIGNER, START, secret_use

KEYS = frozenset({SIGNER.did_key})


@pytest.fixture
async def db(test_db_factory) -> AsyncIterator[AsyncDatabaseManager]:
    database = await test_db_factory.create_db(suffix="logs_export_bundle")
    await AsyncMigrationManager(
        database, migrations_path=str(MIGRATIONS_PATH), module_name=MIGRATIONS_MODULE
    ).apply_pending_migrations()
    yield database


async def appended(db: AsyncDatabaseManager, seq: int, *, team_id: str = TEAM_ID) -> Appended:
    signing, signature = secret_use(seq=seq, team_id=team_id)
    event = hook_envelope.verify(signing, signature, team_id=team_id)
    result = await append(
        db,
        SIGNER,
        event=event,
        signing_bytes=signing,
        signature=signature,
        key_evidence={
            "did_key": event.producer_did_key,
            "kid": event.producer_kid,
            "purposes": ["hook-event"],
        },
        received_at=START + timedelta(minutes=seq),
    )
    assert isinstance(result, Appended)
    return result


async def exported(db: AsyncDatabaseManager, team_id: str = TEAM_ID, **options) -> list[bytes]:
    return [line async for line in export_bundle(db, team_id, **options)]


def verified(lines: list[bytes], **witnesses) -> dict:
    return verify_bundle(
        io.BytesIO(b"".join(lines)), receipt_keys=KEYS, checkpoint_keys=KEYS, **witnesses
    ).to_json()


def kinds(lines: list[bytes]) -> list[str]:
    return [next(iter(json.loads(line))) for line in lines[1:]]


async def test_a_teams_whole_log_exports_as_a_bundle_that_verifies(db) -> None:
    receipts = [(await appended(db, seq)).receipt for seq in (1, 2, 3)]
    first = await issue_checkpoint(db, SIGNER, TEAM_ID, issued_at=START + timedelta(hours=1))
    final = await open_next_epoch(db, SIGNER, TEAM_ID, at=START + timedelta(hours=2))
    receipts.append((await appended(db, 4)).receipt)
    second = await issue_checkpoint(db, SIGNER, TEAM_ID, issued_at=START + timedelta(hours=3))

    lines = await exported(db, page=2)

    assert lines[0] == header_line(TEAM_ID)
    assert all(line.endswith(b"\n") for line in lines)
    assert kinds(lines) == [
        "genesis",
        *["event", "receipt"] * 3, "checkpoint", "checkpoint",
        "genesis", "event", "receipt", "checkpoint",
    ]
    report = verified(
        lines, witness_receipts=receipts, witness_checkpoints=[first, final, second]
    )
    assert report["intact"] is True
    assert [(e["chain_epoch"], e["linked"], e.get("anchored_to")) for e in report["epochs"]] == [
        (1, True, 3),
        (2, True, 1),
    ]
    assert report["witnesses"] == {"contradicted": []}


async def test_a_purged_event_is_exported_by_its_skeleton_and_purge_act(db) -> None:
    for seq in (1, 2):
        await appended(db, seq)
    async with db.transaction() as tx:
        await purge(tx, TEAM_ID, [(1, 1)], act="logs.erase:7d0e3f1a")

    lines = await exported(db)

    events = [json.loads(line)["event"] for line in lines if line.startswith(b'{"event"')]
    assert [("content" in e, e.get("purge_act")) for e in events] == [
        (False, "logs.erase:7d0e3f1a"),
        (True, None),
    ]
    assert verified(lines)["intact"] is True


async def test_a_team_with_no_log_exports_its_header_alone(db) -> None:
    await appended(db, 1, team_id=OTHER_TEAM)

    assert await exported(db) == [header_line(TEAM_ID)]


async def test_another_teams_events_are_never_exported(db) -> None:
    await appended(db, 1)
    await appended(db, 1, team_id=OTHER_TEAM)

    lines = await exported(db)

    assert kinds(lines) == ["genesis", "event", "receipt"]
    assert all(
        json.loads(line)["event"]["link"]["team_id"] == TEAM_ID
        for line in lines
        if line.startswith(b'{"event"')
    )


async def test_an_export_ends_at_the_head_it_started_from(db) -> None:
    for seq in (1, 2):
        await appended(db, seq)
    export = export_bundle(db, TEAM_ID, page=1)
    lines = [await anext(export)]

    await appended(db, 3)
    lines += [line async for line in export]

    assert kinds(lines) == ["genesis", *["event", "receipt"] * 2]
    assert verified(lines)["intact"] is True


async def test_an_append_goes_ahead_while_an_export_waits_on_its_reader(db) -> None:
    for seq in (1, 2):
        await appended(db, seq)
    export = export_bundle(db, TEAM_ID, page=1)
    await anext(export)
    await anext(export)

    await asyncio.wait_for(appended(db, 3), timeout=5)

    await export.aclose()


async def test_an_event_purged_mid_export_is_exported_purged_and_still_verifies(db) -> None:
    for seq in (1, 2, 3):
        await appended(db, seq)
    export = export_bundle(db, TEAM_ID, page=1)
    lines = [await anext(export), await anext(export), await anext(export)]

    async with db.transaction() as tx:
        await purge(tx, TEAM_ID, [(1, 3)], act="logs.retention.set:5b1c9e0d")
    lines += [line async for line in export]

    events = [json.loads(line)["event"] for line in lines if line.startswith(b'{"event"')]
    assert [e.get("purge_act") for e in events] == [None, None, "logs.retention.set:5b1c9e0d"]
    assert verified(lines)["intact"] is True


def test_a_page_of_the_largest_envelopes_holds_at_most_16_mib() -> None:
    assert EXPORT_PAGE >= 1
    assert EXPORT_PAGE * MAX_ENVELOPE_BYTES <= 16 << 20
