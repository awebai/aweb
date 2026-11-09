"""Retention: a team's owner-set retention purges the content of events older
than it, keeps their skeleton, and the chain still verifies (audit-substrate
§B6). Real PostgreSQL, real signed envelopes."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta

import asyncpg
import pytest
from aweb_naapp.hooks import envelope as hook_envelope
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager

from aweb_logs import MIGRATIONS_MODULE, MIGRATIONS_PATH, read_store
from aweb_logs.ledger import append, verify_epoch
from aweb_logs.retention import apply_retention, purge, set_retention

from .fixtures import TEAM_ID
from .test_read_store import SIGNER, START, certificate_observed, secret_use

NOW = START + timedelta(days=60)
KEYS = frozenset({SIGNER.did_key})


@pytest.fixture
async def db(test_db_factory) -> AsyncIterator[AsyncDatabaseManager]:
    database = await test_db_factory.create_db(suffix="logs_retention")
    await AsyncMigrationManager(
        database, migrations_path=str(MIGRATIONS_PATH), module_name=MIGRATIONS_MODULE
    ).apply_pending_migrations()
    yield database


async def appended(db: AsyncDatabaseManager, signed: tuple[bytes, str], *, age: timedelta) -> str:
    signing, signature = signed
    event = hook_envelope.verify(signing, signature, team_id=TEAM_ID)
    await append(
        db,
        SIGNER,
        event=event,
        signing_bytes=signing,
        signature=signature,
        key_evidence={"did_key": event.producer_did_key, "kid": event.producer_kid},
        received_at=NOW - age,
    )
    return event.event_id


async def contents(db: AsyncDatabaseManager) -> list[tuple[int, bool, str | None]]:
    rows = await db.fetch_all(
        "SELECT team_seq, signing_bytes IS NOT NULL AS kept, purge_act"
        " FROM {{tables.chain_events}} WHERE team_id = $1 ORDER BY team_seq",
        TEAM_ID,
    )
    return [(row["team_seq"], row["kept"], row["purge_act"]) for row in rows]


async def report(db: AsyncDatabaseManager) -> dict:
    return await verify_epoch(db, TEAM_ID, 1, receipt_keys=KEYS, checkpoint_keys=KEYS)


async def test_a_team_without_a_retention_keeps_every_event(db) -> None:
    await appended(db, secret_use(seq=1), age=timedelta(days=3650))
    assert await apply_retention(db, now=NOW) == 0
    assert await contents(db) == [(1, True, None)]


async def test_events_older_than_the_retention_lose_their_content_and_keep_the_chain(db) -> None:
    await appended(db, secret_use(seq=1), age=timedelta(days=45))
    await appended(db, secret_use(seq=2), age=timedelta(days=31))
    await appended(db, secret_use(seq=3), age=timedelta(days=29))
    setting = await set_retention(db, TEAM_ID, "all", days=30)

    assert await apply_retention(db, now=NOW) == 2
    act = f"logs.retention.set:{setting}"
    assert await contents(db) == [(1, False, act), (2, False, act), (3, True, None)]
    verified = await report(db)
    assert verified["intact"] is True
    assert verified["purged"] == [{"from": 1, "to": 2, "act": act}]
    assert await apply_retention(db, now=NOW) == 0


async def test_a_hooks_own_retention_comes_before_the_teams(db) -> None:
    await appended(db, secret_use(seq=1), age=timedelta(days=10))
    await appended(db, certificate_observed(seq=2), age=timedelta(days=10))
    await set_retention(db, TEAM_ID, "all", days=None)
    setting = await set_retention(db, TEAM_ID, "post-secret-use-hook", days=7)

    assert await apply_retention(db, now=NOW) == 1
    assert await contents(db) == [(1, False, f"logs.retention.set:{setting}"), (2, True, None)]


async def test_setting_a_class_again_replaces_its_retention(db) -> None:
    await appended(db, secret_use(seq=1), age=timedelta(days=10))
    await set_retention(db, TEAM_ID, "all", days=7)
    await set_retention(db, TEAM_ID, "all", days=None)
    assert await apply_retention(db, now=NOW) == 0
    assert await contents(db) == [(1, True, None)]


async def test_a_purge_removes_every_projection_of_the_event(db) -> None:
    await appended(db, secret_use(seq=1, job_id="job-7"), age=timedelta(days=1))
    async with db.transaction() as tx:
        assert await purge(tx, TEAM_ID, [(1, 1)], act="logs.erase:7d0e3f1a") == 1
    row = await db.fetch_one(
        "SELECT * FROM {{tables.read_events}} WHERE team_id = $1 AND team_seq = 1", TEAM_ID
    )
    assert row["purged"] is True
    kept = {"team_id", "chain_epoch", "team_seq", "purged", "hook"}
    assert {name: value for name, value in dict(row).items() if name not in kept} == {
        name: None for name in dict(row) if name not in kept
    }
    page = await read_store.query(db, TEAM_ID, read_store.EventFilter.from_query({}))
    assert [(event["team_seq"], event["purged"]) for event in page.events] == [(1, True)]
    assert "payload" not in page.events[0]


async def test_purging_an_event_again_changes_nothing(db) -> None:
    await appended(db, secret_use(seq=1), age=timedelta(days=1))
    async with db.transaction() as tx:
        assert await purge(tx, TEAM_ID, [(1, 1)], act="logs.erase:first") == 1
    async with db.transaction() as tx:
        assert await purge(tx, TEAM_ID, [(1, 1)], act="logs.erase:second") == 0
    assert await contents(db) == [(1, False, "logs.erase:first")]


async def test_a_purge_waits_for_a_projection_reading_the_same_events(db) -> None:
    await appended(db, secret_use(seq=1), age=timedelta(days=1))
    await db.execute("DELETE FROM {{tables.read_events}} WHERE team_id = $1", TEAM_ID)
    async with db.transaction() as projecting:
        await projecting.fetch_all(read_store._UNPROJECTED, TEAM_ID, read_store._PROJECTION_BATCH)
        with pytest.raises(asyncpg.exceptions.LockNotAvailableError):
            async with db.transaction() as purging:
                await purging.execute("SET LOCAL lock_timeout = '100ms'")
                await purge(purging, TEAM_ID, [(1, 1)], act="logs.erase:7d0e3f1a")
