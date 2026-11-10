"""The per-session number of chat messages and read receipts.

A trigger takes each number from chat_sessions.last_seq under the session's row
lock, for every writer; migration 048 numbers the rows that existed before it.
"""

from __future__ import annotations

import asyncio
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager

import aweb

MIGRATIONS = Path(aweb.__file__).parent / "migrations" / "aweb"
SEQ_MIGRATION = "048_chat_session_seq.sql"
LOCK_WAIT_BOUND_SECONDS = 5


async def _session(db, *dids: str) -> UUID:
    session_id = uuid4()
    await db.execute("INSERT INTO {{tables.chat_sessions}} (session_id, created_by) VALUES ($1, 'alice')", session_id)
    for did in dids:
        await db.execute(
            "INSERT INTO {{tables.chat_participants}} (session_id, did, alias) VALUES ($1, $2, $2)", session_id, did,
        )
    return session_id


async def _insert_message(db, session_id: UUID, body: str = "hello", **columns) -> UUID:
    names = ["session_id", "from_did", "from_alias", "body", *columns]
    values = [session_id, "did:aw:alice", "alice", body, *columns.values()]
    placeholders = ", ".join(f"${n}" for n in range(1, len(values) + 1))
    return await db.fetch_value(
        f"INSERT INTO {{{{tables.chat_messages}}}} ({', '.join(names)}) VALUES ({placeholders}) RETURNING message_id",
        *values,
    )


async def _seq(db, message_id: UUID) -> int:
    return await db.fetch_value("SELECT seq FROM {{tables.chat_messages}} WHERE message_id = $1", message_id)


async def _last_seq(db, session_id: UUID) -> int:
    return await db.fetch_value("SELECT last_seq FROM {{tables.chat_sessions}} WHERE session_id = $1", session_id)


@pytest.mark.asyncio
async def test_a_supplied_seq_is_replaced_by_the_sessions_next_number(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    session_id = await _session(db)
    first = await _insert_message(db, session_id)
    supplied = await _insert_message(db, session_id, seq=1)
    far = await _insert_message(db, session_id, seq=4000)
    assert [await _seq(db, message_id) for message_id in (first, supplied, far)] == [1, 2, 3]
    assert await _last_seq(db, session_id) == 3


@pytest.mark.asyncio
async def test_concurrent_inserts_in_a_session_are_numbered_in_commit_order(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    session_id = await _session(db)
    async with db.transaction() as first_writer:
        first = await _insert_message(first_writer, session_id, "first")

        async def second_writer() -> UUID:
            async with db.transaction() as tx:
                return await _insert_message(tx, session_id, "second")

        waiting = asyncio.create_task(second_writer())
        # The second writer needs the session row the first one holds.
        done, _ = await asyncio.wait({waiting}, timeout=0.5)
        assert not done
    async with asyncio.timeout(LOCK_WAIT_BOUND_SECONDS):
        second = await waiting
    assert [await _seq(db, first), await _seq(db, second)] == [1, 2]
    assert await _last_seq(db, session_id) == 2


@pytest.mark.asyncio
async def test_a_rolled_back_insert_returns_its_number(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    session_id = await _session(db)
    with pytest.raises(RuntimeError, match="abandoned"):
        async with db.transaction() as tx:
            await _insert_message(tx, session_id)
            raise RuntimeError("abandoned")
    assert await _seq(db, await _insert_message(db, session_id)) == 1


@pytest.mark.asyncio
async def test_an_open_insert_in_one_session_does_not_block_another_session(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    held_session, free_session = await _session(db), await _session(db)
    async with db.transaction() as tx:
        await _insert_message(tx, held_session)
        async with asyncio.timeout(LOCK_WAIT_BOUND_SECONDS):
            free = await _insert_message(db, free_session)
    assert await _seq(db, free) == 1


@pytest.mark.asyncio
async def test_a_message_for_a_missing_session_is_a_foreign_key_violation(aweb_cloud_db):
    import asyncpg

    db = aweb_cloud_db.aweb_db
    with pytest.raises(Exception) as refused:
        await _insert_message(db, uuid4())
    cause = refused.value.__cause__ or refused.value
    assert isinstance(cause, asyncpg.exceptions.ForeignKeyViolationError), cause


@pytest.mark.asyncio
async def test_a_read_receipt_takes_a_number_when_it_is_written_or_changes(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    session_id = await _session(db, "did:aw:bob")
    first, second = await _insert_message(db, session_id), await _insert_message(db, session_id)
    read_at = datetime(2026, 7, 1, tzinfo=timezone.utc)

    async def receipt_seq() -> int:
        return await db.fetch_value(
            "SELECT seq FROM {{tables.chat_read_receipts}} WHERE session_id = $1 AND did = 'did:aw:bob'", session_id,
        )

    async def upsert(message_id: UUID, at: datetime) -> int:
        await db.execute(
            """
            INSERT INTO {{tables.chat_read_receipts}} (session_id, did, last_read_message_id, last_read_at)
            VALUES ($1, 'did:aw:bob', $2, $3)
            ON CONFLICT (session_id, did) DO UPDATE
            SET last_read_message_id = EXCLUDED.last_read_message_id, last_read_at = EXCLUDED.last_read_at
            """,
            session_id, message_id, at,
        )
        return await receipt_seq()

    inserted = await upsert(first, read_at)
    assert inserted == 3
    advanced = await upsert(second, read_at)
    assert advanced > inserted
    # last_read_at moving backwards is still a receipt to deliver.
    earlier = await upsert(second, read_at - timedelta(hours=1))
    assert earlier > advanced
    assert earlier == await _last_seq(db, session_id)

    await db.execute(
        "UPDATE {{tables.chat_read_receipts}} SET agent_id = NULL WHERE session_id = $1", session_id,
    )
    assert await receipt_seq() == earlier
    await db.execute("UPDATE {{tables.chat_read_receipts}} SET seq = 1 WHERE session_id = $1", session_id)
    assert await receipt_seq() == await _last_seq(db, session_id) > earlier


@pytest.mark.asyncio
async def test_migration_numbers_existing_rows_and_later_writes_continue(shared_test_pool, tmp_path):
    await AsyncDatabaseManager(pool=shared_test_pool, schema=None).execute("CREATE SCHEMA aweb")
    db = AsyncDatabaseManager(pool=shared_test_pool, schema="aweb")
    staged = tmp_path / "migrations"
    staged.mkdir()
    for migration in sorted(MIGRATIONS.glob("*.sql")):
        if migration.name < SEQ_MIGRATION:
            shutil.copy(migration, staged / migration.name)
    manager = AsyncMigrationManager(
        db, migrations_path=str(staged), module_name="chat-seq-upgrade-test", migrations_table="schema_migrations",
    )
    await manager.apply_pending_migrations()

    noon = datetime(2026, 7, 26, 12, 0, tzinfo=timezone.utc)
    busy = await _session(db, "did:aw:alice", "did:aw:bob", "did:aw:carol")
    # Two messages share a timestamp; message_id breaks the tie.
    tied = sorted([uuid4(), uuid4()])
    earliest, latest = uuid4(), uuid4()
    await _insert_message(db, busy, message_id=latest, created_at=noon + timedelta(minutes=2))
    await _insert_message(db, busy, message_id=tied[1], created_at=noon + timedelta(minutes=1))
    await _insert_message(db, busy, message_id=tied[0], created_at=noon + timedelta(minutes=1))
    await _insert_message(db, busy, message_id=earliest, created_at=noon)
    await db.execute(
        """
        INSERT INTO {{tables.chat_read_receipts}} (session_id, did, last_read_message_id, last_read_at)
        VALUES ($1, 'did:aw:carol', $2, $3), ($1, 'did:aw:bob', $2, $4), ($1, 'did:aw:alice', NULL, NULL)
        """,
        busy, earliest, noon + timedelta(minutes=5), noon + timedelta(minutes=3),
    )
    receipts_only = await _session(db, "did:aw:bob", "did:aw:alice")
    await db.execute(
        """
        INSERT INTO {{tables.chat_read_receipts}} (session_id, did, last_read_at)
        VALUES ($1, 'did:aw:bob', $2), ($1, 'did:aw:alice', $2)
        """,
        receipts_only, noon,
    )
    empty = await _session(db)

    shutil.copy(MIGRATIONS / SEQ_MIGRATION, staged / SEQ_MIGRATION)
    await manager.apply_pending_migrations()

    async def receipt_numbers(session_id: UUID) -> dict[str, int]:
        rows = await db.fetch_all(
            "SELECT did, seq FROM {{tables.chat_read_receipts}} WHERE session_id = $1", session_id,
        )
        return {row["did"]: row["seq"] for row in rows}

    assert [await _seq(db, message_id) for message_id in (earliest, *tied, latest)] == [1, 2, 3, 4]
    assert await receipt_numbers(busy) == {"did:aw:alice": 5, "did:aw:bob": 6, "did:aw:carol": 7}
    assert await receipt_numbers(receipts_only) == {"did:aw:alice": 1, "did:aw:bob": 2}
    assert [await _last_seq(db, session_id) for session_id in (busy, receipts_only, empty)] == [7, 2, 0]

    assert await _seq(db, await _insert_message(db, busy)) == 8
    assert await _seq(db, await _insert_message(db, empty)) == 1
    with pytest.raises(Exception, match="chat_messages_session_seq_unique"):
        await db.execute("UPDATE {{tables.chat_messages}} SET seq = 1 WHERE message_id = $1", latest)
