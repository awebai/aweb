from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from unittest.mock import AsyncMock
from types import SimpleNamespace

import pytest

from aweb.mcp.auth import AuthContext
from aweb.mcp.server import register_tools
from aweb.mcp.tools import chat as chat_tools
from aweb.mcp.tools import contacts as contacts_tools
from aweb.mcp.tools import mail as mail_tools
from test_mcp_chat_send_parity import chat_server
from test_messages_http import _signed_team_headers

__all__ = ["chat_server"]


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
        self.funcs: dict[str, object] = {}
        self.descriptions: dict[str, str] = {}

    def tool(self, *, name: str, description: str):
        self.names.append(name)
        self.descriptions[name] = description

        def decorator(func):
            self.funcs[name] = func
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
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_key, did_aw, address, alias, identity_scope, role, status, inbound_mode)
        VALUES
            ($1, 'ops:acme.com', 'did:key:alice', 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'developer', 'active', 'open'),
            ($2, 'ops:acme.com', 'did:key:bob', 'did:aw:bob', 'acme.com/bob', 'bob', 'global', 'developer', 'active', 'open')
        """,
        alice_agent_id,
        bob_agent_id,
    )
    await aweb_db.execute(
        "UPDATE {{tables.agents}} SET did_aw_verified_key=did_key WHERE agent_id=ANY($1::uuid[])",
        [alice_agent_id, bob_agent_id],
    )
    return alice_agent_id, bob_agent_id


async def _seed_hosted_target(aweb_db) -> str:
    c3po_agent_id = str(uuid4())
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('default:jane.aweb.ai', 'jane.aweb.ai', 'default', 'did:key:jane-team')
        """
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_key, did_aw, address, alias, identity_scope, role, status, inbound_mode)
        VALUES ($1, 'default:jane.aweb.ai', 'did:key:c3po', 'did:aw:c3po', 'jane.aweb.ai/c3po', 'c3po', 'global', 'developer', 'active', 'open')
        """,
        c3po_agent_id,
    )
    await aweb_db.execute(
        "UPDATE {{tables.agents}} SET did_aw_verified_key=did_key WHERE agent_id=$1",
        c3po_agent_id,
    )
    return c3po_agent_id


def test_mcp_tool_names_include_canonical_and_legacy_compatibility_aliases():
    collector = ToolCollector()

    register_tools(
        collector,  # type: ignore[arg-type]
        db_infra=object(),  # type: ignore[arg-type]
        redis=None,
        registry_client=object(),  # type: ignore[arg-type]
    )

    expected = {
        "send_mail",
        "check_mail",
        "list_threads",
        "send_chat",
        "check_chats",
        "read_chat",
        "mark_chat_read",
        "list_contacts",
        "add_contact",
        "add_contact_by_handle",
        "remove_contact",
        "read_contact_messages",
    }
    for name in expected:
        assert name in collector.names


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool_name", "session_parameter"),
    (("mark_chat_read", "conversation_id"),),
)
async def test_mcp_read_tools_accept_old_new_and_expand_contract_shapes(
    aweb_cloud_db,
    monkeypatch,
    tool_name,
    session_parameter,
):
    alice_agent_id, _ = await _seed_team(aweb_cloud_db.aweb_db)
    _patch_auth(monkeypatch, _auth(alice_agent_id))

    session_id = uuid4()
    first_message_id = uuid4()
    exact_message_id = uuid4()
    watermark_message_id = uuid4()
    created_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, created_by, created_at)
        VALUES ($1, 'alice', $2)
        """,
        session_id,
        created_at,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, alias)
        VALUES ($1, 'did:aw:alice', 'alice'), ($1, 'did:aw:bob', 'bob')
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_messages}}
            (message_id, session_id, from_did, from_alias, body, created_at)
        VALUES
            ($2, $1, 'did:aw:bob', 'bob', 'first', $5),
            ($3, $1, 'did:aw:bob', 'bob', 'exact only', $6),
            ($4, $1, 'did:aw:bob', 'bob', 'watermark only', $7)
        """,
        session_id,
        first_message_id,
        exact_message_id,
        watermark_message_id,
        created_at + timedelta(minutes=1),
        created_at + timedelta(minutes=2),
        created_at + timedelta(minutes=3),
    )

    collector = ToolCollector()
    register_tools(
        collector,  # type: ignore[arg-type]
        db_infra=DBInfra(aweb_cloud_db.aweb_db),
        redis=None,
        registry_client=object(),  # type: ignore[arg-type]
    )
    read_tool = collector.funcs[tool_name]
    session_arg = {session_parameter: str(session_id)}

    old_shape = json.loads(
        await read_tool(  # type: ignore[operator]
            **session_arg,
            up_to_message_id=str(first_message_id),
        )
    )
    new_shape = json.loads(
        await read_tool(  # type: ignore[operator]
            **session_arg,
            message_ids=[str(exact_message_id)],
        )
    )
    disagreeing_both = json.loads(
        await read_tool(  # type: ignore[operator]
            **session_arg,
            up_to_message_id=str(watermark_message_id),
            message_ids=[str(first_message_id)],
        )
    )
    neither_shape = json.loads(await read_tool(**session_arg))  # type: ignore[operator]

    read_rows = await aweb_cloud_db.aweb_db.fetch_all(
        """
        SELECT message_id::text AS message_id
        FROM {{tables.chat_message_reads}}
        WHERE session_id = $1
        ORDER BY message_id
        """,
        session_id,
    )

    assert old_shape["messages_marked"] == 1
    assert new_shape["messages_marked"] == 1
    assert disagreeing_both["messages_marked"] == 0
    assert {row["message_id"] for row in read_rows} == {
        str(first_message_id),
        str(exact_message_id),
    }
    assert neither_shape == {"error": "up_to_message_id or message_ids is required"}
    description = collector.descriptions[tool_name]
    assert "up_to_message_id" in description
    assert "message_ids" in description
    assert "takes precedence" in description


async def _public_mcp_tool(server, alias, name, **arguments):
    actor = server.actors[alias]
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    ).encode()
    response = await server.client.post(
        "/mcp/",
        content=body,
        headers={
            **_signed_team_headers(
                actor.signing_key, actor.did_key, actor.team_id, actor.certificate, body
            ),
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
    )
    assert response.status_code == 200, response.text
    envelope = response.json()
    assert "error" not in envelope, envelope
    result = envelope["result"]
    assert not result.get("isError"), result
    return json.loads(result["content"][0]["text"])


@pytest.mark.asyncio
async def test_check_mail_marks_only_the_returned_page_read(chat_server):
    server = chat_server
    sent_ids = set()
    for number in range(4):
        sent = await _public_mcp_tool(
            server,
            "bob",
            "send_mail",
            to="pilot",
            subject=f"subject-{number}",
            body=f"mail-{number}",
            plaintext=True,
        )
        assert "error" not in sent, sent
        sent_ids.add(sent["message_id"])

    inbox = await _public_mcp_tool(server, "pilot", "check_mail", limit=3)
    messages = inbox["messages"]
    assert len(messages) == 3
    assert {message["body"] for message in messages} <= {f"mail-{n}" for n in range(4)}
    read = await server.db.fetch_all(
        "SELECT message_id FROM {{tables.messages}} WHERE read_at IS NOT NULL"
    )
    assert {str(row["message_id"]) for row in read} == {
        m["message_id"] for m in messages
    }
    remaining = await _public_mcp_tool(server, "pilot", "check_mail", limit=3)
    assert len(remaining["messages"]) == 1
    assert {m["message_id"] for m in messages + remaining["messages"]} == sent_ids
    assert (await _public_mcp_tool(server, "pilot", "check_mail"))["messages"] == []


@pytest.mark.asyncio
async def test_send_chat_public_tool_maps_to_unified_recipient_args(chat_server):
    server = chat_server
    sent = []
    for recipient, body in (
        ("acme.com/bob", "by-address"),
        (server.dids["bob"], "by-did"),
        ("bob", "by-alias"),
    ):
        result = await _public_mcp_tool(
            server, "pilot", "send_chat", to=recipient, message=body
        )
        assert result["delivered"] is True
        sent.append(result)
    continued = await _public_mcp_tool(
        server,
        "pilot",
        "send_chat",
        conversation_id=sent[0]["session_id"],
        message="continuation",
    )
    assert continued["delivered"] is True
    sent.append(continued)
    assert {result["session_id"] for result in sent} == {sent[0]["session_id"]}
    assert len({result["message_id"] for result in sent}) == 4
    rows = await server.db.fetch_all(
        "SELECT message_id, body FROM {{tables.chat_messages}} ORDER BY seq"
    )
    assert [row["body"] for row in rows] == [
        "by-address",
        "by-did",
        "by-alias",
        "continuation",
    ]
    assert {str(row["message_id"]) for row in rows} == {r["message_id"] for r in sent}

    conflicting = await _public_mcp_tool(
        server,
        "pilot",
        "send_chat",
        to="bob",
        conversation_id=sent[0]["session_id"],
        message="blocked",
    )
    assert conflicting == {"error": "Provide session_id or a recipient, not both"}
    absent = await _public_mcp_tool(server, "pilot", "send_chat", message="blocked")
    assert absent == {"error": "Provide exactly one of to_alias, to_did, or to_address"}
    assert (
        await server.db.fetch_all(
            "SELECT message_id, body FROM {{tables.chat_messages}} ORDER BY seq"
        )
        == rows
    )


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
async def test_consumer_mcp_add_contact_by_hosted_handle_normalizes_namespace(
    aweb_cloud_db,
    monkeypatch,
):
    _patch_auth(monkeypatch, _auth())

    result = json.loads(
        await contacts_tools.add_contact_by_handle(
            DBInfra(aweb_cloud_db.aweb_db),
            handle="@jane/c3po",
            label="C-3PO",
        )
    )

    assert result["reference_type"] == "handle"
    assert result["status"] == "pending"
    assert result["handle_namespace"] == "jane.aweb.ai"
    assert result["target_agent_name"] == "c3po"


@pytest.mark.asyncio
async def test_consumer_mcp_add_contact_by_hosted_handle_rejects_empty_agent(
    aweb_cloud_db,
    monkeypatch,
):
    _patch_auth(monkeypatch, _auth())

    result = json.loads(
        await contacts_tools.add_contact_by_handle(
            DBInfra(aweb_cloud_db.aweb_db),
            handle="@jane/",
            label="Broken",
        )
    )

    assert result == {"error": "Invalid handle format"}


@pytest.mark.asyncio
async def test_consumer_mcp_add_contact_by_hosted_handle_rejects_bad_namespace(
    aweb_cloud_db,
    monkeypatch,
):
    _patch_auth(monkeypatch, _auth())

    result = json.loads(
        await contacts_tools.add_contact_by_handle(
            DBInfra(aweb_cloud_db.aweb_db),
            handle="@jane..aweb.ai/c3po",
            label="Broken",
        )
    )

    assert result == {"error": "Invalid handle format"}


@pytest.mark.asyncio
async def test_consumer_mcp_contacts_add_normalizes_hosted_handle_address(
    aweb_cloud_db,
    monkeypatch,
):
    _patch_auth(monkeypatch, _auth())

    authority = SimpleNamespace(
        resolve_contact=AsyncMock(
            return_value=SimpleNamespace(
                canonical_address="jane.aweb.ai/c3po",
                did_aw="did:aw:c3po",
                controller_did="did:key:z6Mkcontroller",
            )
        )
    )
    result = json.loads(
        await contacts_tools.contacts_add(
            DBInfra(aweb_cloud_db.aweb_db),
            contact_address="@jane/c3po",
            label="C-3PO",
            federation_authority=authority,
        )
    )

    assert result["contact_address"] == "jane.aweb.ai/c3po"
    assert result["contact_did_aw"] == "did:aw:c3po"
    assert result["binding_controller_did"] == "did:key:z6Mkcontroller"
    assert result["binding_accepted_at"] is not None
    authority.resolve_contact.assert_awaited_once_with(
        "jane.aweb.ai/c3po", source_ip="mcp:did:key:alice"
    )


@pytest.mark.asyncio
async def test_mcp_mail_send_to_hosted_handle_uses_canonical_address(
    aweb_cloud_db, monkeypatch
):
    alice_agent_id, _ = await _seed_team(aweb_cloud_db.aweb_db)
    await _seed_hosted_target(aweb_cloud_db.aweb_db)
    _patch_auth(monkeypatch, _auth(agent_id=alice_agent_id))

    result = json.loads(
        await mail_tools.send_mail(
            DBInfra(aweb_cloud_db.aweb_db),
            registry_client=None,
            to="@jane/c3po",
            subject="hosted handle",
            body="hello",
        )
    )

    assert result["status"] == "delivered"
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT to_did, to_alias, to_agent_id
        FROM {{tables.messages}}
        WHERE subject = 'hosted handle'
        """
    )
    assert row["to_did"] == "did:aw:c3po"
    assert row["to_alias"] == "c3po"
    # An explicit address selects the identity, not a team membership.
    assert row["to_agent_id"] is None


@pytest.mark.asyncio
async def test_mcp_chat_send_to_hosted_handle_uses_canonical_address(
    aweb_cloud_db, monkeypatch
):
    alice_agent_id, _ = await _seed_team(aweb_cloud_db.aweb_db)
    await _seed_hosted_target(aweb_cloud_db.aweb_db)
    _patch_auth(monkeypatch, _auth(agent_id=alice_agent_id))

    result = json.loads(
        await chat_tools.chat_send(
            DBInfra(aweb_cloud_db.aweb_db),
            redis=None,
            registry_client=None,
            to_alias="@jane/c3po",
            message="hello",
        )
    )

    assert result["delivered"] is True
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT did, alias, address
        FROM {{tables.chat_participants}}
        WHERE did = 'did:aw:c3po'
        """
    )
    assert row["alias"] == "c3po"
    assert row["address"] == "jane.aweb.ai/c3po"


@pytest.mark.asyncio
async def test_consumer_mcp_read_messages_from_contact_filters_on_server_side(
    aweb_cloud_db, monkeypatch
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


@pytest.mark.asyncio
@pytest.mark.parametrize("channel", ["mail", "chat"])
async def test_read_messages_from_contact_does_not_read_an_earlier_holder_of_the_address(
    aweb_cloud_db,
    monkeypatch,
    channel,
):
    """An address can pass to another identity. Reading is by the reader's
    identity: whoever holds the address now is no party to what its earlier
    holder exchanged."""
    alice_agent_id, bob_agent_id = await _seed_team(aweb_cloud_db.aweb_db)
    _patch_auth(monkeypatch, _auth(agent_id=alice_agent_id))
    contact = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.contacts}} (owner_did, contact_address, label)
        VALUES ('did:aw:alice', 'acme.com/bob', 'Bob')
        RETURNING contact_id
        """
    )
    earlier_id = str(uuid4())
    if channel == "mail":
        await aweb_cloud_db.aweb_db.execute(
            """
            INSERT INTO {{tables.conversations}} (
                conversation_id, conversation_type, team_id, created_by_did, created_at, updated_at
            )
            VALUES ($1, 'mail', 'ops:acme.com', 'did:aw:earlier-alice', NOW(), NOW())
            """,
            earlier_id,
        )
        await aweb_cloud_db.aweb_db.execute(
            """
            INSERT INTO {{tables.conversation_participants}} (
                conversation_id, did, agent_id, alias, address, transport_hint, role
            )
            VALUES
                ($1, 'did:aw:earlier-alice', NULL, 'alice', 'acme.com/alice', 'sender', 'initiator'),
                ($1, 'did:aw:bob', $2, 'bob', 'acme.com/bob', 'to_address', 'participant')
            """,
            earlier_id,
            bob_agent_id,
        )
        await aweb_cloud_db.aweb_db.execute(
            """
            INSERT INTO {{tables.messages}} (
                conversation_id, from_did, to_did, from_alias, from_address, to_alias, subject, body
            )
            VALUES ($1, 'did:aw:bob', 'did:aw:earlier-alice', 'bob', 'acme.com/bob', 'alice', 'private', 'to the earlier holder')
            """,
            earlier_id,
        )
    else:
        await aweb_cloud_db.aweb_db.execute(
            """
            INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by)
            VALUES ($1, 'ops:acme.com', 'alice')
            """,
            earlier_id,
        )
        await aweb_cloud_db.aweb_db.execute(
            """
            INSERT INTO {{tables.chat_participants}} (session_id, did, agent_id, alias, address)
            VALUES
                ($1, 'did:aw:earlier-alice', NULL, 'alice', 'acme.com/alice'),
                ($1, 'did:aw:bob', $2, 'bob', 'acme.com/bob')
            """,
            earlier_id,
            bob_agent_id,
        )
        await aweb_cloud_db.aweb_db.execute(
            """
            INSERT INTO {{tables.chat_messages}} (message_id, session_id, from_did, from_alias, body)
            VALUES ($2, $1, 'did:aw:bob', 'bob', 'to the earlier holder')
            """,
            earlier_id,
            str(uuid4()),
        )

    result = json.loads(
        await contacts_tools.read_messages_from_contact(
            DBInfra(aweb_cloud_db.aweb_db),
            registry_client=None,
            contact_id=str(contact["contact_id"]),
            channel=channel,
        )
    )

    assert result["messages"] == []


@pytest.mark.asyncio
async def test_consumer_mcp_read_messages_from_contact_returns_encrypted_mail_metadata_only(
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
    conversation_id = str(uuid4())
    message_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversations}} (
            conversation_id, conversation_type, team_id, created_by_did, created_at, updated_at
        )
        VALUES ($1, 'mail', 'ops:acme.com', 'did:aw:alice', NOW(), NOW())
        """,
        conversation_id,
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
        conversation_id,
        alice_agent_id,
        bob_agent_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.messages}} (
            message_id, conversation_id, from_did, to_did, from_alias, from_address,
            to_alias, subject, body, priority, content_mode, message_version,
            encrypted_envelope, encrypted_ciphertext, encrypted_key_wraps,
            encrypted_ciphertext_hash, encrypted_ciphertext_size, encrypted_key_wraps_hash,
            encrypted_inner_header_hash, encrypted_suite, encrypted_signing_key_id,
            signed_envelope_hash
        )
        VALUES (
            $1, $2, 'did:aw:bob', 'did:aw:alice', 'bob', 'acme.com/bob',
            'alice', '', '', 'normal', 'encrypted_v2', 2,
            '{}'::jsonb, 'ciphertext-bytes', '[]'::jsonb,
            'sha256:ciphertext', 16, 'sha256:wraps',
            'sha256:inner', 'E2EEv2-X25519-HPKE-AES256GCM-Ed25519', 'did:key:z6MkBob',
            'sha256:envelope'
        )
        """,
        message_id,
        conversation_id,
    )

    result = json.loads(
        await contacts_tools.read_messages_from_contact(
            DBInfra(aweb_cloud_db.aweb_db),
            registry_client=None,
            contact_id=str(contact["contact_id"]),
            channel="mail",
        )
    )

    assert len(result["messages"]) == 1
    message = result["messages"][0]
    assert message["message_id"] == str(message_id)
    assert message["encrypted"] is True
    assert message["content_mode"] == "encrypted_v2"
    assert message["subject"] == ""
    assert message["body"] == ""
    assert "content_notice" in message
    assert "ciphertext-bytes" not in json.dumps(message)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    ["missing", "recipient_identity_not_found", "sender_registry_unavailable"],
)
async def test_contact_creation_refuses_without_authority_evidence(
    aweb_cloud_db, monkeypatch, failure
):
    from awid.federation_errors import FederationAuthorityError

    _patch_auth(monkeypatch, _auth())
    collector = ToolCollector()
    authority = (
        None
        if failure == "missing"
        else SimpleNamespace(
            resolve_contact=AsyncMock(side_effect=FederationAuthorityError(failure))
        )
    )
    register_tools(
        collector,
        db_infra=DBInfra(aweb_cloud_db.aweb_db),
        redis=None,
        registry_client=None,
        federation_authority=authority,
    )
    result = json.loads(
        await collector.funcs["add_contact"](address="example.test/alice")
    )
    expected = (
        "federation_authority_coordination_unavailable"
        if failure == "missing"
        else failure
    )
    assert result == {"error": expected}
    assert (
        await aweb_cloud_db.aweb_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.contacts}}"
        )
        == 0
    )
