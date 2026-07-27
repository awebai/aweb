from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
from uuid import uuid4

import pytest
from nacl.signing import SigningKey
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager

from awid.did import did_from_public_key
import aweb.messaging.chat as chat_service
from aweb.messaging.chat import (
    ensure_session,
    get_message_history,
    mark_messages_read,
    send_in_session,
)
from aweb.service_errors import ValidationError


class _DbShim:
    def __init__(self, aweb_db):
        self._db = aweb_db

    def get_manager(self, name="aweb"):
        return self._db


async def _setup_team_and_agents(aweb_db):
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:read-race.example', 'read-race.example', 'backend', 'did:key:z6Mkteam')
        """
    )

    agents = []
    for alias in ("alice", "bob"):
        signing_key = SigningKey.generate()
        did_key = did_from_public_key(bytes(signing_key.verify_key))
        row = await aweb_db.fetch_one(
            """
            INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, alias, identity_scope)
            VALUES ('backend:read-race.example', $1, $2, $3, 'global')
            RETURNING agent_id
            """,
            did_key,
            f"did:aw:{alias}",
            alias,
        )
        agents.append(
            {
                "agent_id": row["agent_id"],
                "team_id": "backend:read-race.example",
                "alias": alias,
                "did_key": did_key,
                "did_aw": f"did:aw:{alias}",
            }
        )
    return agents


class _FrozenDateTime(datetime):
    instant = datetime(2026, 7, 26, 20, 0, tzinfo=timezone.utc)

    @classmethod
    def now(cls, tz=None):
        if tz is None:
            return cls.instant.replace(tzinfo=None)
        return cls.instant.astimezone(tz)


@pytest.mark.asyncio
async def test_message_inserted_during_presented_snapshot_remains_unread(
    aweb_cloud_db, monkeypatch
):
    db = _DbShim(aweb_cloud_db.aweb_db)
    alice, bob = await _setup_team_and_agents(aweb_cloud_db.aweb_db)
    session_id = await ensure_session(
        db,
        team_id="backend:read-race.example",
        participant_rows=[alice, bob],
        created_by="alice",
    )
    monkeypatch.setattr(chat_service, "datetime", _FrozenDateTime)

    presented = await send_in_session(
        db,
        session_id=session_id,
        sender_did=alice["did_aw"],
        sender_agent_id=str(alice["agent_id"]),
        body="presented before provider run",
    )
    assert presented is not None

    async with aweb_cloud_db.aweb_db.transaction() as writer_tx:
        concurrent = await send_in_session(
            _DbShim(writer_tx),
            session_id=session_id,
            sender_did=alice["did_aw"],
            sender_agent_id=str(alice["agent_id"]),
            body="committed after recipient acknowledgement",
        )
        assert concurrent is not None
        assert presented["created_at"] == concurrent["created_at"] == _FrozenDateTime.instant

        snapshot = await get_message_history(
            db,
            session_id=session_id,
            participant_did=bob["did_aw"],
            unread_only=True,
        )
        presented_ids = [row["message_id"] for row in snapshot]
        assert presented_ids == [str(presented["message_id"])]
        assert str(concurrent["message_id"]) not in presented_ids

        invisible = await get_message_history(
            db,
            session_id=session_id,
            participant_did=bob["did_aw"],
            message_id=str(concurrent["message_id"]),
        )
        assert invisible == [], "uncommitted message entered the recipient snapshot"

        await mark_messages_read(
            db,
            session_id=session_id,
            participant_did=bob["did_aw"],
            participant_agent_id=str(bob["agent_id"]),
            message_ids=presented_ids,
        )
        receipt = await aweb_cloud_db.aweb_db.fetch_one(
            """
            SELECT last_read_message_id
            FROM {{tables.chat_read_receipts}}
            WHERE session_id = $1 AND did = $2
            """,
            session_id,
            bob["did_aw"],
        )
        assert str(receipt["last_read_message_id"]) == presented_ids[-1]

    retrievable = await get_message_history(
        db,
        session_id=session_id,
        participant_did=bob["did_aw"],
        message_id=str(concurrent["message_id"]),
    )
    assert [row["message_id"] for row in retrievable] == [str(concurrent["message_id"])]

    unread = await get_message_history(
        db,
        session_id=session_id,
        participant_did=bob["did_aw"],
        unread_only=True,
    )
    assert [row["message_id"] for row in unread] == [str(concurrent["message_id"])]


@pytest.mark.asyncio
async def test_mark_read_records_only_the_presented_message_ids(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    alice, bob = await _setup_team_and_agents(aweb_cloud_db.aweb_db)
    session_id = await ensure_session(
        db,
        team_id="backend:read-race.example",
        participant_rows=[alice, bob],
        created_by="alice",
    )

    messages = []
    for body in ("first", "not presented", "third"):
        message = await send_in_session(
            db,
            session_id=session_id,
            sender_did=alice["did_aw"],
            sender_agent_id=str(alice["agent_id"]),
            body=body,
        )
        assert message is not None
        messages.append(message)

    presented_ids = [str(messages[0]["message_id"]), str(messages[2]["message_id"])]
    result = await mark_messages_read(
        db,
        session_id=session_id,
        participant_did=bob["did_aw"],
        participant_agent_id=str(bob["agent_id"]),
        message_ids=presented_ids,
    )
    assert result["messages_marked"] == 2

    unread = await get_message_history(
        db,
        session_id=session_id,
        participant_did=bob["did_aw"],
        unread_only=True,
    )
    assert [row["message_id"] for row in unread] == [str(messages[1]["message_id"])]

    rows = await aweb_cloud_db.aweb_db.fetch_all(
        """
        SELECT message_id::text AS message_id
        FROM {{tables.chat_message_reads}}
        WHERE session_id = $1 AND did = $2
        ORDER BY message_id
        """,
        session_id,
        bob["did_aw"],
    )
    assert sorted(row["message_id"] for row in rows) == sorted(presented_ids)

    retry = await mark_messages_read(
        db,
        session_id=session_id,
        participant_did=bob["did_aw"],
        participant_agent_id=str(bob["agent_id"]),
        message_ids=presented_ids,
    )
    assert retry["messages_marked"] == 0


@pytest.mark.asyncio
async def test_watermark_and_exact_ids_produce_equivalent_read_state(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    alice, bob = await _setup_team_and_agents(aweb_cloud_db.aweb_db)
    session_id = await ensure_session(
        db,
        team_id="backend:read-race.example",
        participant_rows=[alice, bob],
        created_by="alice",
    )

    messages = []
    for body in ("first", "second", "third"):
        message = await send_in_session(
            db,
            session_id=session_id,
            sender_did=alice["did_aw"],
            sender_agent_id=str(alice["agent_id"]),
            body=body,
        )
        assert message is not None
        messages.append(message)

    message_ids = [str(message["message_id"]) for message in messages]
    legacy_result = await chat_service.mark_messages_read_up_to(
        db,
        session_id=session_id,
        participant_did=bob["did_aw"],
        participant_agent_id=str(bob["agent_id"]),
        up_to_message_id=message_ids[-1],
    )
    legacy_rows = await aweb_cloud_db.aweb_db.fetch_all(
        """
        SELECT message_id::text AS message_id
        FROM {{tables.chat_message_reads}}
        WHERE session_id = $1 AND did = $2
        ORDER BY message_id
        """,
        session_id,
        bob["did_aw"],
    )
    legacy_unread = await get_message_history(
        db,
        session_id=session_id,
        participant_did=bob["did_aw"],
        unread_only=True,
    )

    await aweb_cloud_db.aweb_db.execute(
        "DELETE FROM {{tables.chat_message_reads}} WHERE session_id = $1 AND did = $2",
        session_id,
        bob["did_aw"],
    )
    await aweb_cloud_db.aweb_db.execute(
        "DELETE FROM {{tables.chat_read_receipts}} WHERE session_id = $1 AND did = $2",
        session_id,
        bob["did_aw"],
    )

    exact_result = await mark_messages_read(
        db,
        session_id=session_id,
        participant_did=bob["did_aw"],
        participant_agent_id=str(bob["agent_id"]),
        message_ids=message_ids,
    )
    exact_rows = await aweb_cloud_db.aweb_db.fetch_all(
        """
        SELECT message_id::text AS message_id
        FROM {{tables.chat_message_reads}}
        WHERE session_id = $1 AND did = $2
        ORDER BY message_id
        """,
        session_id,
        bob["did_aw"],
    )
    exact_unread = await get_message_history(
        db,
        session_id=session_id,
        participant_did=bob["did_aw"],
        unread_only=True,
    )

    assert legacy_result["messages_marked"] == exact_result["messages_marked"] == 3
    assert [row["message_id"] for row in legacy_rows] == [row["message_id"] for row in exact_rows]
    assert legacy_unread == exact_unread == []


@pytest.mark.asyncio
async def test_mark_read_batch_limit_accepts_1000_and_rejects_1001(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    alice, bob = await _setup_team_and_agents(aweb_cloud_db.aweb_db)
    session_id = await ensure_session(
        db,
        team_id="backend:read-race.example",
        participant_rows=[alice, bob],
        created_by="alice",
    )
    rows = await aweb_cloud_db.aweb_db.fetch_all(
        """
        INSERT INTO {{tables.chat_messages}}
            (session_id, from_did, from_alias, body)
        SELECT $1, $2, 'alice', 'batch boundary'
        FROM generate_series(1, 1000)
        RETURNING message_id
        """,
        session_id,
        alice["did_aw"],
    )
    message_ids = [str(row["message_id"]) for row in rows]
    assert len(message_ids) == 1000

    accepted = await mark_messages_read(
        db,
        session_id=session_id,
        participant_did=bob["did_aw"],
        participant_agent_id=str(bob["agent_id"]),
        message_ids=message_ids,
    )
    assert accepted["messages_marked"] == 1000

    with pytest.raises(ValidationError, match="message_ids cannot exceed 1000 items"):
        await mark_messages_read(
            db,
            session_id=session_id,
            participant_did=bob["did_aw"],
            participant_agent_id=str(bob["agent_id"]),
            message_ids=[*message_ids, message_ids[0]],
        )


@pytest.mark.asyncio
async def test_exact_read_migration_backfills_existing_watermarks(
    shared_test_pool, tmp_path
):
    schema_manager = AsyncDatabaseManager(pool=shared_test_pool, schema=None)
    await schema_manager.execute("CREATE SCHEMA aweb")
    upgrade_db = AsyncDatabaseManager(pool=shared_test_pool, schema="aweb")

    migrations = Path(chat_service.__file__).parents[1] / "migrations" / "aweb"
    staged_migrations = tmp_path / "migrations"
    staged_migrations.mkdir()
    for migration in sorted(migrations.glob("*.sql")):
        if migration.name < "011_chat_message_reads.sql":
            shutil.copy(migration, staged_migrations / migration.name)

    migration_manager = AsyncMigrationManager(
        upgrade_db,
        migrations_path=str(staged_migrations),
        module_name="chat-read-upgrade-test",
        migrations_table="schema_migrations",
    )
    await migration_manager.apply_pending_migrations()

    session_id = uuid4()
    alice_did = "did:aw:upgrade-alice"
    bob_did = "did:aw:upgrade-bob"
    message_ids = [uuid4(), uuid4(), uuid4()]
    base_time = datetime(2026, 7, 26, 12, 0, tzinfo=timezone.utc)
    await upgrade_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, created_by)
        VALUES ($1, 'alice')
        """,
        session_id,
    )
    await upgrade_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, alias)
        VALUES ($1, $2, 'alice'), ($1, $3, 'bob')
        """,
        session_id,
        alice_did,
        bob_did,
    )
    for index, message_id in enumerate(message_ids):
        await upgrade_db.execute(
            """
            INSERT INTO {{tables.chat_messages}}
                (message_id, session_id, from_did, from_alias, body, created_at)
            VALUES ($1, $2, $3, 'alice', $4, $5)
            """,
            message_id,
            session_id,
            alice_did,
            f"message {index}",
            base_time + timedelta(seconds=index),
        )
    await upgrade_db.execute(
        """
        INSERT INTO {{tables.chat_read_receipts}}
            (session_id, did, last_read_message_id, last_read_at)
        VALUES ($1, $2, $3, $4)
        """,
        session_id,
        bob_did,
        message_ids[1],
        base_time + timedelta(minutes=1),
    )

    shutil.copy(
        migrations / "011_chat_message_reads.sql",
        staged_migrations / "011_chat_message_reads.sql",
    )
    await migration_manager.apply_pending_migrations()

    backfilled = await upgrade_db.fetch_all(
        """
        SELECT message_id
        FROM {{tables.chat_message_reads}}
        WHERE session_id = $1 AND did = $2
        ORDER BY read_at, message_id
        """,
        session_id,
        bob_did,
    )
    assert {row["message_id"] for row in backfilled} == set(message_ids[:2])
