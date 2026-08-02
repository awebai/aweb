from __future__ import annotations

from pathlib import Path
import shutil
from uuid import uuid4

import aweb
import pytest
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.errors import QueryError


async def _database_at_migration_014(shared_test_pool, tmp_path):
    schema_manager = AsyncDatabaseManager(pool=shared_test_pool, schema=None)
    await schema_manager.execute("CREATE SCHEMA aweb")
    database = AsyncDatabaseManager(pool=shared_test_pool, schema="aweb")
    source = Path(aweb.__file__).parent / "migrations" / "aweb"
    staged = tmp_path / "migrations"
    staged.mkdir()
    for migration in sorted(source.glob("*.sql")):
        if migration.name <= "014_federation_authority_work.sql":
            shutil.copy(migration, staged / migration.name)
    manager = AsyncMigrationManager(
        database,
        migrations_path=str(staged),
        module_name="federation-delivery-upgrade-test",
        migrations_table="schema_migrations",
    )
    await manager.apply_pending_migrations()
    return database, manager, source, staged


@pytest.mark.asyncio
async def test_migration_015_backfills_historical_mail_and_chat_as_unreplayable(
    shared_test_pool,
    tmp_path,
) -> None:
    database, migrations, source, staged = await _database_at_migration_014(
        shared_test_pool, tmp_path
    )
    mail_id = uuid4()
    chat_id = uuid4()
    session_id = uuid4()
    await database.execute(
        """
        INSERT INTO {{tables.messages}} (message_id, from_did, to_did, body)
        VALUES ($1, 'did:key:sender', 'did:key:recipient', 'historical mail')
        """,
        mail_id,
    )
    await database.execute(
        "INSERT INTO {{tables.chat_sessions}} (session_id, created_by) VALUES ($1, 'did:key:sender')",
        session_id,
    )
    await database.execute(
        """
        INSERT INTO {{tables.chat_messages}} (
            message_id, session_id, from_did, from_alias, body
        ) VALUES ($1, $2, 'did:key:sender', 'sender', 'historical chat')
        """,
        chat_id,
        session_id,
    )
    shutil.copy(
        source / "015_federation_delivery_policy.sql",
        staged / "015_federation_delivery_policy.sql",
    )

    await migrations.apply_pending_migrations()

    rows = await database.fetch_all(
        """
        SELECT message_id, storage_kind, legacy_unreplayable,
               envelope_hash, established_result
        FROM {{tables.message_ingress_receipts}}
        ORDER BY storage_kind
        """
    )
    assert [dict(row) for row in rows] == [
        {
            "message_id": chat_id,
            "storage_kind": "chat",
            "legacy_unreplayable": True,
            "envelope_hash": None,
            "established_result": None,
        },
        {
            "message_id": mail_id,
            "storage_kind": "mail",
            "legacy_unreplayable": True,
            "envelope_hash": None,
            "established_result": None,
        },
    ]


@pytest.mark.asyncio
async def test_migration_015_collision_aborts_without_partial_effects(
    shared_test_pool,
    tmp_path,
) -> None:
    database, migrations, source, staged = await _database_at_migration_014(
        shared_test_pool, tmp_path
    )
    message_id = uuid4()
    session_id = uuid4()
    await database.execute(
        """
        INSERT INTO {{tables.messages}} (message_id, from_did, to_did, body)
        VALUES ($1, 'did:key:sender', 'did:key:recipient', 'historical mail')
        """,
        message_id,
    )
    await database.execute(
        "INSERT INTO {{tables.chat_sessions}} (session_id, created_by) VALUES ($1, 'did:key:sender')",
        session_id,
    )
    await database.execute(
        """
        INSERT INTO {{tables.chat_messages}} (
            message_id, session_id, from_did, from_alias, body
        ) VALUES ($1, $2, 'did:key:sender', 'sender', 'historical chat')
        """,
        message_id,
        session_id,
    )
    shutil.copy(
        source / "015_federation_delivery_policy.sql",
        staged / "015_federation_delivery_policy.sql",
    )

    with pytest.raises(Exception) as error:
        await migrations.apply_pending_migrations()

    detail = f"{error.value!r}; cause={error.value.__cause__!r}"
    assert "mail/chat message_id collision" in detail
    assert await database.fetch_value(
        "SELECT to_regclass('aweb.message_ingress_receipts')"
    ) is None
    assert await database.fetch_value(
        """
        SELECT COUNT(*) FROM information_schema.columns
        WHERE table_schema = 'aweb' AND table_name = 'contacts'
          AND column_name IN (
              'contact_did_aw', 'binding_controller_did', 'binding_accepted_at'
          )
        """
    ) == 0
    assert await database.fetch_value(
        "SELECT COUNT(*) FROM {{tables.schema_migrations}} WHERE filename = '015_federation_delivery_policy.sql'"
    ) == 0


@pytest.mark.asyncio
async def test_message_ingress_receipt_is_receiver_wide_and_transactional(aweb_cloud_db) -> None:
    db = aweb_cloud_db.aweb_db
    message_id = uuid4()
    session_id = uuid4()
    await db.execute(
        """
        INSERT INTO {{tables.messages}} (message_id, from_did, to_did, body)
        VALUES ($1, 'did:key:sender', 'did:key:recipient', 'mail')
        """,
        message_id,
    )
    await db.execute(
        "INSERT INTO {{tables.chat_sessions}} (session_id, created_by) VALUES ($1, 'did:key:sender')",
        session_id,
    )

    with pytest.raises(QueryError, match="message_id already belongs to mail storage"):
        await db.execute(
            """
            INSERT INTO {{tables.chat_messages}} (
                message_id, session_id, from_did, from_alias, body
            ) VALUES ($1, $2, 'did:key:sender', 'sender', 'chat')
            """,
            message_id,
            session_id,
        )

    receipt = await db.fetch_one(
        """
        SELECT message_id, storage_kind, legacy_unreplayable
        FROM {{tables.message_ingress_receipts}}
        WHERE message_id = $1
        """,
        message_id,
    )
    assert dict(receipt) == {
        "message_id": message_id,
        "storage_kind": "mail",
        "legacy_unreplayable": True,
    }

    await db.execute("DELETE FROM {{tables.messages}} WHERE message_id = $1", message_id)
    assert await db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.message_ingress_receipts}} WHERE message_id = $1",
        message_id,
    ) == 1
    with pytest.raises(QueryError, match="message_id already claimed by mail storage"):
        await db.execute(
            """
            INSERT INTO {{tables.messages}} (message_id, from_did, to_did, body)
            VALUES ($1, 'did:key:other', 'did:key:recipient', 'replacement')
            """,
            message_id,
        )


@pytest.mark.asyncio
async def test_message_and_receipt_roll_back_together(aweb_cloud_db) -> None:
    db = aweb_cloud_db.aweb_db
    message_id = uuid4()

    with pytest.raises(RuntimeError, match="forced rollback"):
        async with db.transaction() as tx:
            await tx.execute(
                """
                INSERT INTO {{tables.messages}} (message_id, from_did, to_did, body)
                VALUES ($1, 'did:key:sender', 'did:key:recipient', 'mail')
                """,
                message_id,
            )
            raise RuntimeError("forced rollback")

    assert await db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.message_ingress_receipts}} WHERE message_id = $1",
        message_id,
    ) == 0


@pytest.mark.asyncio
async def test_contact_identity_binding_is_nullable_but_required_for_authority(aweb_cloud_db) -> None:
    columns = await aweb_cloud_db.aweb_db.fetch_all(
        """
        SELECT column_name, is_nullable
        FROM information_schema.columns
        WHERE table_schema = 'aweb' AND table_name = 'contacts'
          AND column_name = 'contact_did_aw'
        """
    )
    assert [dict(row) for row in columns] == [
        {"column_name": "contact_did_aw", "is_nullable": "YES"}
    ]

    with pytest.raises(QueryError, match="contacts_identity_binding_shape_valid"):
        await aweb_cloud_db.aweb_db.execute(
            """
            INSERT INTO {{tables.contacts}} (
                owner_did, contact_address, contact_did_aw,
                binding_controller_did, binding_accepted_at, label
            ) VALUES (
                'did:aw:owner', 'alpha.example/alice', NULL,
                'did:key:z6Mkcontroller', clock_timestamp(), 'partial'
            )
            """
        )


@pytest.mark.asyncio
async def test_message_ingress_receipt_primary_key_is_only_message_id(aweb_cloud_db) -> None:
    rows = await aweb_cloud_db.aweb_db.fetch_all(
        """
        SELECT a.attname
        FROM pg_index i
        JOIN pg_class c ON c.oid = i.indrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY(i.indkey)
        WHERE n.nspname = 'aweb' AND c.relname = 'message_ingress_receipts'
          AND i.indisprimary
        ORDER BY array_position(i.indkey, a.attnum)
        """
    )
    assert [row["attname"] for row in rows] == ["message_id"]
