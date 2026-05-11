from __future__ import annotations

import json
from uuid import uuid4

import pytest

from aweb.mcp.auth import AuthContext
from aweb.mcp.server import register_tools
from aweb.mcp.tools import chat as chat_tools
from aweb.mcp.tools import contacts as contacts_tools
from aweb.mcp.tools import mail as mail_tools


class DBInfra:
    def __init__(self, aweb_db):
        self._aweb_db = aweb_db

    def get_manager(self, name: str):
        if name != "aweb":
            raise KeyError(name)
        return self._aweb_db


class ToolCollector:
    def __init__(self) -> None:
        self.names: list[str] = []

    def tool(self, *, name: str, description: str):
        self.names.append(name)

        def decorator(func):
            return func

        return decorator


def _auth(agent_id: str | None = None) -> AuthContext:
    return AuthContext(
        team_id="ops:acme.com",
        agent_id=agent_id,
        alias="alice",
        did_key="did:key:alice",
        did_aw="did:aw:alice",
        address="acme.com/alice",
    )


def _patch_auth(monkeypatch, auth: AuthContext) -> None:
    monkeypatch.setattr(contacts_tools, "get_auth", lambda: auth)
    monkeypatch.setattr(mail_tools, "get_auth", lambda: auth)
    monkeypatch.setattr(chat_tools, "get_auth", lambda: auth)


async def _seed_team(aweb_db) -> tuple[str, str]:
    alice_agent_id = str(uuid4())
    bob_agent_id = str(uuid4())
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('ops:acme.com', 'acme.com', 'ops', 'did:key:team')
        """
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            agent_id, team_id, did_key, did_aw, address, alias, lifetime, role, status, messaging_policy
        )
        VALUES
            ($1, 'ops:acme.com', 'did:key:alice', 'did:aw:alice',
             'acme.com/alice', 'alice', 'persistent', 'developer', 'active', 'everyone'),
            ($2, 'ops:acme.com', 'did:key:bob', 'did:aw:bob',
             'acme.com/bob', 'bob', 'persistent', 'developer', 'active', 'everyone')
        """,
        alice_agent_id,
        bob_agent_id,
    )
    return alice_agent_id, bob_agent_id


def test_consumer_contact_mcp_tool_names_are_registered():
    collector = ToolCollector()

    register_tools(
        collector,  # type: ignore[arg-type]
        db_infra=object(),  # type: ignore[arg-type]
        redis=None,
        registry_client=object(),  # type: ignore[arg-type]
    )

    for name in {
        "list_contacts",
        "send_message_to_contact",
        "read_messages_from_contact",
        "add_contact_by_email",
        "add_contact_by_handle",
        "contacts_list",
        "contacts_add",
        "contacts_remove",
    }:
        assert name in collector.names


@pytest.mark.asyncio
async def test_consumer_mcp_add_contact_by_email_rejects_multiple_at_signs(aweb_cloud_db, monkeypatch):
    _patch_auth(monkeypatch, _auth())

    result = json.loads(
        await contacts_tools.add_contact_by_email(
            DBInfra(aweb_cloud_db.aweb_db),
            email="a@@example.com",
            label="Broken",
        )
    )

    assert result == {"error": "Invalid email format"}


@pytest.mark.asyncio
async def test_consumer_mcp_add_contact_by_email_valid_email_returns_unavailable(aweb_cloud_db, monkeypatch):
    _patch_auth(monkeypatch, _auth())

    result = json.loads(
        await contacts_tools.add_contact_by_email(
            DBInfra(aweb_cloud_db.aweb_db),
            email="alice@example.com",
            label="Alice",
        )
    )

    assert result == {"error": "Email contact requests are not available on this server"}


@pytest.mark.asyncio
async def test_consumer_mcp_add_contact_by_handle_is_pending_even_when_target_already_knows_sender(
    aweb_cloud_db,
    monkeypatch,
):
    _patch_auth(monkeypatch, _auth())
    await _seed_team(aweb_cloud_db.aweb_db)
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.contacts}} (owner_did, contact_address, label)
        VALUES ('did:aw:bob', 'acme.com/alice', 'Alice')
        """
    )

    result = json.loads(
        await contacts_tools.add_contact_by_handle(
            DBInfra(aweb_cloud_db.aweb_db),
            handle="@acme.com/bob",
            label="Bob",
        )
    )

    assert result["reference_type"] == "handle"
    assert result["status"] == "pending"
    assert result["handle_namespace"] == "acme.com"
    assert result["target_agent_name"] == "bob"


@pytest.mark.asyncio
async def test_consumer_mcp_send_message_to_identity_contact_reuses_existing_mail_conversation(
    aweb_cloud_db,
    monkeypatch,
):
    alice_agent_id, bob_agent_id = await _seed_team(aweb_cloud_db.aweb_db)
    _patch_auth(monkeypatch, _auth(agent_id=alice_agent_id))
    contact = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.contacts}} (owner_did, contact_address, label)
        VALUES ('did:aw:alice', 'acme.com/bob', 'Bob')
        RETURNING contact_id
        """
    )
    existing_conversation_id = str(uuid4())
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversations}} (
            conversation_id, conversation_type, team_id, created_by_did, created_at, updated_at
        )
        VALUES ($1, 'mail', 'ops:acme.com', 'did:aw:alice', NOW() - INTERVAL '1 minute', NOW() - INTERVAL '1 minute')
        """,
        existing_conversation_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversation_participants}} (
            conversation_id, did, agent_id, alias, address, transport_hint, role
        )
        VALUES
            ($1, 'did:aw:alice', $2, 'alice', 'acme.com/alice', 'sender', 'initiator'),
            ($1, 'did:aw:bob', $3, 'bob', 'acme.com/bob', 'to_address', 'participant')
        """,
        existing_conversation_id,
        alice_agent_id,
        bob_agent_id,
    )

    class NoRegistry:
        async def resolve_address(self, *_args, **_kwargs):
            raise AssertionError("existing conversation continuation must not rediscover")

    result = json.loads(
        await contacts_tools.send_message_to_contact(
            DBInfra(aweb_cloud_db.aweb_db),
            registry_client=NoRegistry(),
            contact_id=str(contact["contact_id"]),
            message="hello again",
            subject="Re",
            channel="mail",
        )
    )

    assert result["status"] == "delivered"
    assert result["conversation_id"] == existing_conversation_id
    assert await aweb_cloud_db.aweb_db.fetch_val("SELECT COUNT(*) FROM {{tables.conversations}}") == 1
    row = await aweb_cloud_db.aweb_db.fetch_one("SELECT conversation_id, body FROM {{tables.messages}}")
    assert str(row["conversation_id"]) == existing_conversation_id
    assert row["body"] == "hello again"


@pytest.mark.asyncio
async def test_consumer_mcp_send_message_to_handle_contact_uses_recent_active_agent(
    aweb_cloud_db,
    monkeypatch,
):
    alice_agent_id, _ = await _seed_team(aweb_cloud_db.aweb_db)
    _patch_auth(monkeypatch, _auth(agent_id=alice_agent_id))
    older_id = str(uuid4())
    recent_id = str(uuid4())
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (
            agent_id, team_id, did_key, did_aw, address, alias, lifetime, role, status, created_at
        )
        VALUES
            ($1, 'ops:acme.com', 'did:key:older', 'did:aw:older',
             'acme.com/older', 'older', 'persistent', 'developer', 'active', '2026-01-01T00:00:00Z'),
            ($2, 'ops:acme.com', 'did:key:recent', 'did:aw:recent',
             'acme.com/recent', 'recent', 'persistent', 'developer', 'active', '2026-01-02T00:00:00Z')
        """,
        older_id,
        recent_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}} (team_id, agent_id, alias, last_seen_at)
        VALUES
            ('ops:acme.com', $1, 'older', '2026-05-01T00:00:00Z'),
            ('ops:acme.com', $2, 'recent', '2026-05-02T00:00:00Z')
        """,
        older_id,
        recent_id,
    )
    contact = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.contacts}} (
            owner_did, contact_address, label, reference_type, status, handle_namespace
        )
        VALUES ('did:aw:alice', NULL, 'Acme', 'handle', 'pending', 'acme.com')
        RETURNING contact_id
        """
    )

    result = json.loads(
        await contacts_tools.send_message_to_contact(
            DBInfra(aweb_cloud_db.aweb_db),
            registry_client=None,
            contact_id=str(contact["contact_id"]),
            message="hello handle",
            channel="mail",
        )
    )

    assert result["status"] == "delivered"
    row = await aweb_cloud_db.aweb_db.fetch_one("SELECT to_did, to_alias FROM {{tables.messages}}")
    assert row["to_did"] == "did:aw:recent"
    assert row["to_alias"] == "recent"


@pytest.mark.asyncio
async def test_consumer_mcp_send_message_to_identity_pending_contact_is_sendable(
    aweb_cloud_db,
    monkeypatch,
):
    alice_agent_id, bob_agent_id = await _seed_team(aweb_cloud_db.aweb_db)
    _patch_auth(monkeypatch, _auth(agent_id=alice_agent_id))
    contact = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.contacts}} (owner_did, contact_address, label, status)
        VALUES ('did:aw:alice', 'acme.com/bob', 'Bob', 'pending')
        RETURNING contact_id
        """
    )

    result = json.loads(
        await contacts_tools.send_message_to_contact(
            DBInfra(aweb_cloud_db.aweb_db),
            registry_client=None,
            contact_id=str(contact["contact_id"]),
            message="hello pending identity",
            channel="mail",
        )
    )

    assert result["status"] == "delivered"
    row = await aweb_cloud_db.aweb_db.fetch_one("SELECT to_agent_id, to_did, body FROM {{tables.messages}}")
    assert str(row["to_agent_id"]) == bob_agent_id
    assert row["to_did"] == "did:aw:bob"
    assert row["body"] == "hello pending identity"


@pytest.mark.asyncio
async def test_consumer_mcp_send_message_to_contact_reuses_existing_chat_session_without_rediscovery(
    aweb_cloud_db,
    monkeypatch,
):
    alice_agent_id, bob_agent_id = await _seed_team(aweb_cloud_db.aweb_db)
    _patch_auth(monkeypatch, _auth(agent_id=alice_agent_id))
    contact = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.contacts}} (owner_did, contact_address, label)
        VALUES ('did:aw:alice', 'acme.com/bob', 'Bob')
        RETURNING contact_id
        """
    )
    session_id = str(uuid4())
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by)
        VALUES ($1, 'ops:acme.com', 'alice')
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, agent_id, alias, address)
        VALUES
            ($1, 'did:aw:alice', $2, 'alice', 'acme.com/alice'),
            ($1, 'did:aw:bob', $3, 'bob', 'acme.com/bob')
        """,
        session_id,
        alice_agent_id,
        bob_agent_id,
    )

    class NoRegistry:
        async def resolve_address(self, *_args, **_kwargs):
            raise AssertionError("existing chat continuation must not rediscover")

    result = json.loads(
        await contacts_tools.send_message_to_contact(
            DBInfra(aweb_cloud_db.aweb_db),
            registry_client=NoRegistry(),
            contact_id=str(contact["contact_id"]),
            message="hello chat",
            channel="chat",
        )
    )

    assert result["delivered"] is True
    assert result["conversation_id"] == session_id
    assert await aweb_cloud_db.aweb_db.fetch_val("SELECT COUNT(*) FROM {{tables.chat_sessions}}") == 1
    row = await aweb_cloud_db.aweb_db.fetch_one("SELECT session_id, body FROM {{tables.chat_messages}}")
    assert str(row["session_id"]) == session_id
    assert row["body"] == "hello chat"


@pytest.mark.asyncio
async def test_consumer_mcp_read_messages_from_contact_filters_on_server_side(aweb_cloud_db, monkeypatch):
    alice_agent_id, bob_agent_id = await _seed_team(aweb_cloud_db.aweb_db)
    _patch_auth(monkeypatch, _auth(agent_id=alice_agent_id))
    contact = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.contacts}} (owner_did, contact_address, label)
        VALUES ('did:aw:alice', 'acme.com/bob', 'Bob')
        RETURNING contact_id
        """
    )
    bob_conversation_id = str(uuid4())
    other_conversation_id = str(uuid4())
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversations}} (
            conversation_id, conversation_type, team_id, created_by_did, created_at, updated_at
        )
        VALUES
            ($1, 'mail', 'ops:acme.com', 'did:aw:alice', NOW(), NOW()),
            ($2, 'mail', 'ops:acme.com', 'did:aw:alice', NOW(), NOW())
        """,
        bob_conversation_id,
        other_conversation_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversation_participants}} (
            conversation_id, did, agent_id, alias, address, transport_hint, role
        )
        VALUES
            ($1, 'did:aw:alice', $3, 'alice', 'acme.com/alice', 'sender', 'initiator'),
            ($1, 'did:aw:bob', $4, 'bob', 'acme.com/bob', 'to_address', 'participant'),
            ($2, 'did:aw:alice', $3, 'alice', 'acme.com/alice', 'sender', 'initiator'),
            ($2, 'did:aw:carol', NULL, 'carol', 'acme.com/carol', 'to_address', 'participant')
        """,
        bob_conversation_id,
        other_conversation_id,
        alice_agent_id,
        bob_agent_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.messages}} (
            conversation_id, from_did, to_did, from_alias, from_address, to_alias, subject, body
        )
        VALUES
            ($1, 'did:aw:bob', 'did:aw:alice', 'bob', 'acme.com/bob', 'alice', 'wanted', 'from bob'),
            ($2, 'did:aw:carol', 'did:aw:alice', 'carol', 'acme.com/carol', 'alice', 'other', 'from carol')
        """,
        bob_conversation_id,
        other_conversation_id,
    )

    result = json.loads(
        await contacts_tools.read_messages_from_contact(
            DBInfra(aweb_cloud_db.aweb_db),
            registry_client=None,
            contact_id=str(contact["contact_id"]),
            channel="mail",
        )
    )

    assert [message["body"] for message in result["messages"]] == ["from bob"]
