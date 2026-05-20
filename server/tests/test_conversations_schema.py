from __future__ import annotations

from uuid import UUID

import asyncpg
import pytest
from pgdbm.errors import QueryError


async def _insert_team(aweb_db, team_id: str = "backend:acme.com"):
    team_name, namespace = team_id.split(":", 1)
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, 'did:key:z6Mkteam')
        """,
        team_id,
        namespace,
        team_name,
    )


async def _insert_agent(aweb_db, *, team_id: str, alias: str, did_aw: str, address: str):
    row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, lifetime, role, inbound_mode)
        VALUES ($1, $2, $3, $4, $5, 'persistent', 'developer', 'open')
        RETURNING agent_id
        """,
        team_id,
        f"did:key:z6Mk{alias}",
        did_aw,
        address,
        alias,
    )
    return row["agent_id"]


@pytest.mark.asyncio
async def test_conversation_schema_tables_columns_and_indexes_exist(aweb_cloud_db):
    rows = await aweb_cloud_db.aweb_db.fetch_all(
        """
        SELECT table_name, column_name, is_nullable
        FROM information_schema.columns
        WHERE table_schema = 'aweb'
          AND table_name IN ('conversations', 'conversation_participants', 'messages')
        """
    )
    columns = {(row["table_name"], row["column_name"]): row["is_nullable"] for row in rows}

    assert columns[("conversations", "conversation_id")] == "NO"
    assert columns[("conversations", "conversation_type")] == "NO"
    assert columns[("conversations", "status")] == "NO"
    assert columns[("conversations", "team_id")] == "YES"
    assert columns[("conversations", "created_by_did")] == "NO"
    assert columns[("conversations", "expires_at")] == "YES"
    assert columns[("conversation_participants", "conversation_id")] == "NO"
    assert columns[("conversation_participants", "did")] == "NO"
    assert columns[("conversation_participants", "agent_id")] == "YES"
    assert columns[("conversation_participants", "transport_hint")] == "YES"
    assert columns[("conversation_participants", "role")] == "NO"
    assert columns[("messages", "conversation_id")] == "YES"

    default_rows = await aweb_cloud_db.aweb_db.fetch_all(
        """
        SELECT table_name, column_name, column_default
        FROM information_schema.columns
        WHERE table_schema = 'aweb'
          AND (
            (table_name = 'conversations' AND column_name = 'created_by_did')
            OR (table_name = 'conversation_participants' AND column_name = 'alias')
          )
        """
    )
    defaults = {(row["table_name"], row["column_name"]): row["column_default"] for row in default_rows}
    assert defaults[("conversations", "created_by_did")] is None
    assert defaults[("conversation_participants", "alias")] is None

    index_rows = await aweb_cloud_db.aweb_db.fetch_all(
        """
        SELECT indexname
        FROM pg_indexes
        WHERE schemaname = 'aweb'
        """
    )
    index_names = {row["indexname"] for row in index_rows}

    assert "idx_conversations_type_status" in index_names
    assert "idx_conversations_expires_at" in index_names
    assert "idx_conversation_participants_did" in index_names
    assert "idx_conversation_participants_agent" in index_names
    assert "idx_messages_conversation" in index_names

    constraint_rows = await aweb_cloud_db.aweb_db.fetch_all(
        """
        SELECT conname
        FROM pg_constraint
        WHERE connamespace = 'aweb'::regnamespace
        """
    )
    constraint_names = {row["conname"] for row in constraint_rows}
    assert "conversations_created_by_did_not_blank" in constraint_names
    assert "conversation_participants_alias_not_blank" in constraint_names
    assert "conversation_participants_reachable" in constraint_names

    trigger = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT tgname
        FROM pg_trigger
        WHERE tgrelid = 'aweb.conversations'::regclass
          AND tgname = 'trg_conversations_updated_at'
          AND NOT tgisinternal
        """
    )
    assert trigger is not None


@pytest.mark.asyncio
async def test_conversation_schema_supports_participants_and_message_links(aweb_cloud_db):
    await _insert_team(aweb_cloud_db.aweb_db)
    alice_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_aw="did:aw:alice",
        address="acme.com/alice",
    )
    bob_agent_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="bob",
        did_aw="did:aw:bob",
        address="acme.com/bob",
    )

    conversation = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.conversations}} (
            conversation_type, team_id, created_by_did, expires_at
        )
        VALUES ('mail', 'backend:acme.com', 'did:aw:alice', NOW() + INTERVAL '30 days')
        RETURNING conversation_id, status
        """
    )
    conversation_id = conversation["conversation_id"]

    assert isinstance(conversation_id, UUID)
    assert conversation["status"] == "active"

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversation_participants}} (
            conversation_id, did, agent_id, alias, address, transport_hint, role
        )
        VALUES
            ($1, 'did:aw:alice', $2, 'alice', 'acme.com/alice', 'mail', 'initiator'),
            ($1, 'did:aw:bob', $3, 'bob', 'acme.com/bob', 'mail', 'participant')
        """,
        conversation_id,
        alice_agent_id,
        bob_agent_id,
    )
    message = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.messages}} (
            from_did, to_did, from_alias, to_alias, subject, body, priority, conversation_id
        )
        VALUES (
            'did:aw:alice',
            'did:aw:bob',
            'alice',
            'bob',
            'hello',
            'Hi Bob',
            'normal',
            $1
        )
        RETURNING message_id
        """,
        conversation_id,
    )

    participant_count = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT COUNT(*) AS count
        FROM {{tables.conversation_participants}}
        WHERE conversation_id = $1
        """,
        conversation_id,
    )
    linked_message = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT conversation_id
        FROM {{tables.messages}}
        WHERE message_id = $1
        """,
        message["message_id"],
    )

    assert participant_count["count"] == 2
    assert linked_message["conversation_id"] == conversation_id

    await aweb_cloud_db.aweb_db.execute(
        "DELETE FROM {{tables.conversations}} WHERE conversation_id = $1",
        conversation_id,
    )
    participant_count_after_delete = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT COUNT(*) AS count
        FROM {{tables.conversation_participants}}
        WHERE conversation_id = $1
        """,
        conversation_id,
    )
    message_after_delete = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT conversation_id
        FROM {{tables.messages}}
        WHERE message_id = $1
        """,
        message["message_id"],
    )

    assert participant_count_after_delete["count"] == 0
    assert message_after_delete["conversation_id"] is None


@pytest.mark.asyncio
async def test_conversation_schema_enforces_lifecycle_and_participant_invariants(aweb_cloud_db):
    await _insert_team(aweb_cloud_db.aweb_db)

    with pytest.raises(QueryError) as check_error:
        await aweb_cloud_db.aweb_db.execute(
            """
            INSERT INTO {{tables.conversations}} (conversation_type, team_id, created_by_did)
            VALUES ('thread', 'backend:acme.com', 'did:aw:alice')
            """
        )
    assert isinstance(check_error.value.__cause__, asyncpg.CheckViolationError)

    with pytest.raises(QueryError) as fk_error:
        await aweb_cloud_db.aweb_db.execute(
            """
            INSERT INTO {{tables.conversation_participants}} (conversation_id, did, alias, transport_hint)
            VALUES ('11111111-1111-1111-1111-111111111111', 'did:aw:alice', 'alice', 'mail')
            """
        )
    assert isinstance(fk_error.value.__cause__, asyncpg.ForeignKeyViolationError)

    conversation = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.conversations}} (conversation_type, team_id, created_by_did)
        VALUES ('mail', 'backend:acme.com', 'did:aw:alice')
        RETURNING conversation_id
        """
    )

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversation_participants}} (conversation_id, did, alias, transport_hint)
        VALUES ($1, 'did:aw:alice', 'alice', 'mail')
        """,
        conversation["conversation_id"],
    )
    with pytest.raises(QueryError) as unique_error:
        await aweb_cloud_db.aweb_db.execute(
            """
            INSERT INTO {{tables.conversation_participants}} (conversation_id, did, alias, transport_hint)
            VALUES ($1, 'did:aw:alice', 'alice-alt', 'mail')
            """,
            conversation["conversation_id"],
        )
    assert isinstance(unique_error.value.__cause__, asyncpg.UniqueViolationError)


@pytest.mark.asyncio
async def test_conversation_schema_enforces_identity_defaults_and_reachability(aweb_cloud_db):
    await _insert_team(aweb_cloud_db.aweb_db)

    with pytest.raises(QueryError) as missing_creator:
        await aweb_cloud_db.aweb_db.execute(
            """
            INSERT INTO {{tables.conversations}} (conversation_type, team_id)
            VALUES ('mail', 'backend:acme.com')
            """
        )
    assert isinstance(missing_creator.value.__cause__, asyncpg.NotNullViolationError)

    with pytest.raises(QueryError) as blank_creator:
        await aweb_cloud_db.aweb_db.execute(
            """
            INSERT INTO {{tables.conversations}} (conversation_type, team_id, created_by_did)
            VALUES ('mail', 'backend:acme.com', '')
            """
        )
    assert isinstance(blank_creator.value.__cause__, asyncpg.CheckViolationError)
    with pytest.raises(QueryError) as whitespace_creator:
        await aweb_cloud_db.aweb_db.execute(
            """
            INSERT INTO {{tables.conversations}} (conversation_type, team_id, created_by_did)
            VALUES ('mail', 'backend:acme.com', '   ')
            """
        )
    assert isinstance(whitespace_creator.value.__cause__, asyncpg.CheckViolationError)

    conversation = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.conversations}} (conversation_type, team_id, created_by_did)
        VALUES ('mail', 'backend:acme.com', 'did:aw:alice')
        RETURNING conversation_id
        """
    )

    with pytest.raises(QueryError) as missing_alias:
        await aweb_cloud_db.aweb_db.execute(
            """
            INSERT INTO {{tables.conversation_participants}} (conversation_id, did, transport_hint)
            VALUES ($1, 'did:aw:alice', 'mail')
            """,
            conversation["conversation_id"],
        )
    assert isinstance(missing_alias.value.__cause__, asyncpg.NotNullViolationError)

    with pytest.raises(QueryError) as whitespace_alias:
        await aweb_cloud_db.aweb_db.execute(
            """
            INSERT INTO {{tables.conversation_participants}} (
                conversation_id, did, alias, transport_hint
            )
            VALUES ($1, 'did:aw:alice', '   ', 'mail')
            """,
            conversation["conversation_id"],
        )
    assert isinstance(whitespace_alias.value.__cause__, asyncpg.CheckViolationError)

    with pytest.raises(QueryError) as unreachable:
        await aweb_cloud_db.aweb_db.execute(
            """
            INSERT INTO {{tables.conversation_participants}} (conversation_id, did, alias)
            VALUES ($1, 'did:aw:alice', 'alice')
            """,
            conversation["conversation_id"],
        )
    assert isinstance(unreachable.value.__cause__, asyncpg.CheckViolationError)


@pytest.mark.asyncio
async def test_conversation_updated_at_trigger_runs_when_update_omits_updated_at(aweb_cloud_db):
    await _insert_team(aweb_cloud_db.aweb_db)
    conversation = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.conversations}} (
            conversation_type, team_id, created_by_did, updated_at
        )
        VALUES (
            'mail',
            'backend:acme.com',
            'did:aw:alice',
            NOW() - INTERVAL '1 day'
        )
        RETURNING conversation_id, updated_at
        """
    )

    updated = await aweb_cloud_db.aweb_db.fetch_one(
        """
        UPDATE {{tables.conversations}}
        SET status = 'closed'
        WHERE conversation_id = $1
        RETURNING updated_at
        """,
        conversation["conversation_id"],
    )

    assert updated["updated_at"] > conversation["updated_at"]


@pytest.mark.asyncio
async def test_conversation_updated_at_trigger_preserves_explicit_updated_at(aweb_cloud_db):
    await _insert_team(aweb_cloud_db.aweb_db)
    conversation = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.conversations}} (
            conversation_type, team_id, created_by_did, updated_at
        )
        VALUES (
            'mail',
            'backend:acme.com',
            'did:aw:alice',
            NOW() - INTERVAL '1 day'
        )
        RETURNING conversation_id
        """
    )

    updated = await aweb_cloud_db.aweb_db.fetch_one(
        """
        UPDATE {{tables.conversations}}
        SET status = 'closed',
            updated_at = NOW() - INTERVAL '2 days'
        WHERE conversation_id = $1
        RETURNING updated_at, updated_at <= NOW() - INTERVAL '1 day' AS preserved
        """,
        conversation["conversation_id"],
    )

    assert updated["preserved"] is True
