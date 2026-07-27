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
@pytest.mark.parametrize("published_011_already_applied", [False, True])
async def test_exact_read_migration_skips_orphaned_receipts_on_both_upgrade_paths(
    shared_test_pool, tmp_path, published_011_already_applied
):
    schema_manager = AsyncDatabaseManager(pool=shared_test_pool, schema=None)
    await schema_manager.execute("CREATE SCHEMA aweb")
    upgrade_db = AsyncDatabaseManager(pool=shared_test_pool, schema="aweb")

    migrations = Path(chat_service.__file__).parents[1] / "migrations" / "aweb"
    staged_migrations = tmp_path / "migrations"
    staged_migrations.mkdir()
    for migration in sorted(migrations.glob("*.sql")):
        if migration.name <= "010_session_admission_leases.sql":
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
    orphan_did = "did:aw:hard-deleted-participant"
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

    if published_011_already_applied:
        shutil.copy(
            migrations / "011_chat_message_reads.sql",
            staged_migrations / "011_chat_message_reads.sql",
        )
        await migration_manager.apply_pending_migrations()

    await upgrade_db.execute(
        """
        INSERT INTO {{tables.chat_read_receipts}}
            (session_id, did, last_read_message_id, last_read_at)
        VALUES
            ($1, $2, $4, $5),
            ($1, $3, $6, $5)
        """,
        session_id,
        bob_did,
        orphan_did,
        message_ids[1],
        base_time + timedelta(minutes=1),
        message_ids[2],
    )

    pre_012_filenames = (
        ("010a_chat_message_reads_orphan_guard.sql",)
        if published_011_already_applied
        else (
            "010a_chat_message_reads_orphan_guard.sql",
            "011_chat_message_reads.sql",
        )
    )
    for filename in pre_012_filenames:
        shutil.copy(migrations / filename, staged_migrations / filename)
    pre_012_error = None
    try:
        await migration_manager.apply_pending_migrations()
    except Exception as exc:  # asserted so a published-011 FK failure is named
        pre_012_error = exc
    pre_012_error_detail = (
        f"{pre_012_error!r}; cause={pre_012_error.__cause__!r}"
        if pre_012_error is not None
        else ""
    )
    assert pre_012_error is None, (
        f"published 011 must complete with the orphan guard: {pre_012_error_detail}"
    )

    intermediate_constraints = await upgrade_db.fetch_all(
        """
        SELECT pg_get_constraintdef(oid) AS definition
        FROM pg_constraint
        WHERE conrelid = 'aweb.chat_message_reads'::regclass
        """
    )
    intermediate_definitions = {
        row["definition"] for row in intermediate_constraints
    }
    assert any(
        "FOREIGN KEY (session_id, did) REFERENCES aweb.chat_participants(session_id, did)"
        in definition
        for definition in intermediate_definitions
    )
    assert any(
        "FOREIGN KEY (session_id, message_id) REFERENCES aweb.chat_messages(session_id, message_id)"
        in definition
        for definition in intermediate_definitions
    )

    if not published_011_already_applied:
        rows_after_published_011 = await upgrade_db.fetch_all(
            """
            SELECT did, message_id
            FROM {{tables.chat_message_reads}}
            WHERE session_id = $1
            """,
            session_id,
        )
        assert {
            row["message_id"]
            for row in rows_after_published_011
            if row["did"] == bob_did
        } == set(message_ids[:2])
        assert [
            row for row in rows_after_published_011 if row["did"] == orphan_did
        ] == []

    shutil.copy(
        migrations / "012_chat_message_reads_orphan_backfill.sql",
        staged_migrations / "012_chat_message_reads_orphan_backfill.sql",
    )
    migration_error = None
    migration_result = None
    try:
        migration_result = await migration_manager.apply_pending_migrations()
    except Exception as exc:  # asserted below so an FK failure is named clearly
        migration_error = exc
    error_detail = (
        f"{migration_error!r}; cause={migration_error.__cause__!r}"
        if migration_error is not None
        else ""
    )
    assert migration_error is None, f"orphan-safe backfill must complete: {error_detail}"
    assert migration_result is not None

    backfilled = await upgrade_db.fetch_all(
        """
        SELECT did, message_id
        FROM {{tables.chat_message_reads}}
        WHERE session_id = $1
        ORDER BY did, message_id
        """,
        session_id,
    )
    assert {
        row["message_id"] for row in backfilled if row["did"] == bob_did
    } == set(message_ids[:2])
    assert [row for row in backfilled if row["did"] == orphan_did] == []

    receipt_count = await upgrade_db.fetch_val(
        """
        SELECT COUNT(*)
        FROM {{tables.chat_read_receipts}}
        WHERE session_id = $1
        """,
        session_id,
    )
    assert receipt_count == 2

    constraints = await upgrade_db.fetch_all(
        """
        SELECT conname, pg_get_constraintdef(oid) AS definition
        FROM pg_constraint
        WHERE conrelid = 'aweb.chat_message_reads'::regclass
        ORDER BY conname
        """
    )
    definitions = {row["definition"] for row in constraints}
    assert any(
        "FOREIGN KEY (session_id, did) REFERENCES aweb.chat_participants(session_id, did)"
        in definition
        for definition in definitions
    )
    assert any(
        "FOREIGN KEY (session_id, message_id) REFERENCES aweb.chat_messages(session_id, message_id)"
        in definition
        for definition in definitions
    )
    message_constraints = await upgrade_db.fetch_all(
        """
        SELECT conname
        FROM pg_constraint
        WHERE conrelid = 'aweb.chat_messages'::regclass
        """
    )
    message_constraint_names = {row["conname"] for row in message_constraints}
    assert "chat_messages_session_message_unique" in message_constraint_names
    assert "aapc_chat_messages_session_message_unique" not in message_constraint_names

    trigger_count = await upgrade_db.fetch_val(
        """
        SELECT COUNT(*)
        FROM pg_trigger
        WHERE tgrelid = 'aweb.chat_message_reads'::regclass
          AND NOT tgisinternal
        """
    )
    assert trigger_count == 0
    shim_function = await upgrade_db.fetch_val(
        "SELECT to_regprocedure('aweb.aapc_skip_orphan_chat_message_read()')"
    )
    assert shim_function is None
