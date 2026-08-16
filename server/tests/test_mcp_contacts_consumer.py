from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from aweb.mcp.auth import AuthContext
from aweb.mcp import server as mcp_server
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
    legacy = {
        "check_inbox",
        "chat_send",
        "chat_pending",
        "chat_history",
        "chat_read",
        "contacts_list",
        "contacts_add",
        "contacts_remove",
        "add_contact_by_email",
        "send_message_to_contact",
        "read_messages_from_contact",
    }
    for name in expected | legacy:
        assert name in collector.names


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool_name", "session_parameter"),
    (("mark_chat_read", "conversation_id"), ("chat_read", "session_id")),
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
        VALUES ($1, 'did:key:alice', 'alice'), ($1, 'did:aw:bob', 'bob')
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


@pytest.mark.asyncio
async def test_legacy_mcp_tool_aliases_delegate_to_existing_implementations(monkeypatch):
    collector = ToolCollector()
    calls: list[tuple[str, dict]] = []

    async def fake_check_inbox(*args, **kwargs):
        calls.append(("check_inbox", kwargs))
        return json.dumps({"ok": True})

    async def fake_chat_send(*args, **kwargs):
        calls.append(("chat_send", kwargs))
        return json.dumps({"ok": True})

    async def fake_chat_pending(*args, **kwargs):
        calls.append(("chat_pending", kwargs))
        return json.dumps({"ok": True})

    async def fake_send_message_to_contact(*args, **kwargs):
        calls.append(("send_message_to_contact", kwargs))
        return json.dumps({"ok": True})

    monkeypatch.setattr(mcp_server, "_check_inbox_impl", fake_check_inbox)
    monkeypatch.setattr(mcp_server, "_chat_send_impl", fake_chat_send)
    monkeypatch.setattr(mcp_server, "_chat_pending_impl", fake_chat_pending)
    monkeypatch.setattr(
        mcp_server, "_send_message_to_contact_impl", fake_send_message_to_contact
    )
    register_tools(
        collector,  # type: ignore[arg-type]
        db_infra=object(),  # type: ignore[arg-type]
        redis=None,
        registry_client=object(),  # type: ignore[arg-type]
    )

    await collector.funcs["check_inbox"](limit=3)  # type: ignore[operator]
    await collector.funcs["chat_pending"]()  # type: ignore[operator]
    await collector.funcs["chat_send"](  # type: ignore[operator]
        message="hi", to_address="aweb.ai/aida"
    )
    await collector.funcs["send_message_to_contact"](  # type: ignore[operator]
        contact_id="contact-1",
        message="hello",
        channel="chat",
        wait=True,
    )

    assert calls[0] == (
        "check_inbox",
        {"hosted_decryptor": None, "unread_only": True, "limit": 3, "include_bodies": True},
    )
    assert calls[1] == ("chat_pending", {"hosted_decryptor": None})
    assert calls[2][0] == "chat_send"
    assert calls[2][1]["to_address"] == "aweb.ai/aida"
    assert calls[2][1]["message"] == "hi"
    assert calls[3][0] == "send_message_to_contact"
    assert calls[3][1]["contact_id"] == "contact-1"
    assert calls[3][1]["channel"] == "chat"
    assert calls[3][1]["wait"] is True


@pytest.mark.asyncio
async def test_send_chat_public_tool_maps_to_unified_recipient_args(monkeypatch):
    collector = ToolCollector()
    calls: list[dict] = []

    async def fake_chat_send_impl(*args, **kwargs):
        calls.append(kwargs)
        return json.dumps({"ok": True})

    monkeypatch.setattr(mcp_server, "_chat_send_impl", fake_chat_send_impl)
    register_tools(
        collector,  # type: ignore[arg-type]
        db_infra=object(),  # type: ignore[arg-type]
        redis=None,
        registry_client=object(),  # type: ignore[arg-type]
    )

    send_chat = collector.funcs["send_chat"]
    await send_chat(message="hello", to="aweb.ai/aida")  # type: ignore[operator]
    await send_chat(message="hello", to="did:aw:target")  # type: ignore[operator]
    await send_chat(message="hello", to="bob")  # type: ignore[operator]
    await send_chat(message="hello", conversation_id="conv-1")  # type: ignore[operator]

    assert calls[0]["to_address"] == "aweb.ai/aida"
    assert calls[0]["to_alias"] == ""
    assert calls[0]["to_did"] == ""
    assert calls[0]["session_id"] == ""
    assert calls[1]["to_did"] == "did:aw:target"
    assert calls[2]["to_alias"] == "bob"
    assert calls[3]["session_id"] == "conv-1"
    assert calls[3]["to_address"] == ""
    assert calls[3]["to_alias"] == ""
    assert calls[3]["to_did"] == ""


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

    result = json.loads(
        await contacts_tools.contacts_add(
            DBInfra(aweb_cloud_db.aweb_db),
            contact_address="@jane/c3po",
            label="C-3PO",
        )
    )

    assert result["contact_address"] == "jane.aweb.ai/c3po"


@pytest.mark.asyncio
async def test_mcp_mail_send_to_hosted_handle_uses_canonical_address(aweb_cloud_db, monkeypatch):
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
    assert row["to_agent_id"] is not None


@pytest.mark.asyncio
async def test_mcp_chat_send_to_hosted_handle_uses_canonical_address(aweb_cloud_db, monkeypatch):
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
async def test_consumer_mcp_send_message_to_identity_contact_reuses_existing_mail_conversation(
    aweb_cloud_db,
    monkeypatch,
):
    alice_agent_id, bob_agent_id = await _seed_team(aweb_cloud_db.aweb_db)
    _patch_auth(monkeypatch, _auth(agent_id=alice_agent_id))
    contact = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.contacts}} (
            owner_did, contact_address, contact_did_aw,
            binding_controller_did, binding_accepted_at, label
        ) VALUES (
            'did:aw:alice', 'acme.com/bob', 'did:aw:bob',
            'did:key:z6MkNamespaceController', clock_timestamp(), 'Bob'
        ) RETURNING contact_id
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
            agent_id, team_id, did_key, did_aw, address, alias, identity_scope, role, status, inbound_mode, created_at
        )
        VALUES
            ($1, 'ops:acme.com', 'did:key:older', 'did:aw:older',
             'acme.com/older', 'older', 'global', 'developer', 'active', 'open', '2026-01-01T00:00:00Z'),
            ($2, 'ops:acme.com', 'did:key:recent', 'did:aw:recent',
             'acme.com/recent', 'recent', 'global', 'developer', 'active', 'open', '2026-01-02T00:00:00Z')
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

    assert result == {"error": "contact_identity_binding_required"}
    assert await aweb_cloud_db.aweb_db.fetch_val(
        "SELECT COUNT(*) FROM {{tables.messages}}"
    ) == 0


@pytest.mark.asyncio
async def test_consumer_mcp_identity_contact_rejects_local_address_reassignment(
    aweb_cloud_db,
    monkeypatch,
):
    alice_agent_id, _ = await _seed_team(aweb_cloud_db.aweb_db)
    _patch_auth(monkeypatch, _auth(agent_id=alice_agent_id))
    contact = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.contacts}} (
            owner_did, contact_address, contact_did_aw,
            binding_controller_did, binding_accepted_at, label
        ) VALUES (
            'did:aw:alice', 'acme.com/bob', 'did:aw:previous-bob',
            'did:key:z6MkNamespaceController', clock_timestamp(), 'Previous Bob'
        ) RETURNING contact_id
        """
    )

    result = json.loads(
        await contacts_tools.send_message_to_contact(
            DBInfra(aweb_cloud_db.aweb_db),
            registry_client=None,
            contact_id=str(contact["contact_id"]),
            message="must not transfer",
            channel="mail",
        )
    )

    assert result == {"error": "contact_identity_binding_required"}
    assert await aweb_cloud_db.aweb_db.fetch_val(
        "SELECT COUNT(*) FROM {{tables.messages}}"
    ) == 0


@pytest.mark.asyncio
async def test_consumer_mcp_identity_contact_rejects_reassigned_existing_mail_conversation(
    aweb_cloud_db,
    monkeypatch,
):
    alice_agent_id, bob_agent_id = await _seed_team(aweb_cloud_db.aweb_db)
    _patch_auth(monkeypatch, _auth(agent_id=alice_agent_id))
    contact = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.contacts}} (
            owner_did, contact_address, contact_did_aw,
            binding_controller_did, binding_accepted_at, label
        ) VALUES (
            'did:aw:alice', 'acme.com/bob', 'did:aw:previous-bob',
            'did:key:z6MkNamespaceController', clock_timestamp(), 'Previous Bob'
        ) RETURNING contact_id
        """
    )
    conversation_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversations}} (
            conversation_id, conversation_type, team_id, created_by_did
        ) VALUES ($1, 'mail', 'ops:acme.com', 'did:aw:alice')
        """,
        conversation_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.conversation_participants}} (
            conversation_id, did, agent_id, alias, address, role
        ) VALUES
            ($1, 'did:aw:alice', $2, 'alice', 'acme.com/alice', 'initiator'),
            ($1, 'did:aw:bob', $3, 'bob', 'acme.com/bob', 'participant')
        """,
        conversation_id,
        alice_agent_id,
        bob_agent_id,
    )

    result = json.loads(
        await contacts_tools.send_message_to_contact(
            DBInfra(aweb_cloud_db.aweb_db),
            registry_client=None,
            contact_id=str(contact["contact_id"]),
            message="must not transfer through mail conversation",
            channel="mail",
        )
    )

    assert result == {"error": "contact_identity_binding_required"}
    assert await aweb_cloud_db.aweb_db.fetch_val(
        "SELECT COUNT(*) FROM {{tables.messages}}"
    ) == 0


@pytest.mark.asyncio
async def test_consumer_mcp_identity_contact_rejects_reassigned_existing_chat_session(
    aweb_cloud_db,
    monkeypatch,
):
    alice_agent_id, bob_agent_id = await _seed_team(aweb_cloud_db.aweb_db)
    _patch_auth(monkeypatch, _auth(agent_id=alice_agent_id))
    contact = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.contacts}} (
            owner_did, contact_address, contact_did_aw,
            binding_controller_did, binding_accepted_at, label
        ) VALUES (
            'did:aw:alice', 'acme.com/bob', 'did:aw:previous-bob',
            'did:key:z6MkNamespaceController', clock_timestamp(), 'Previous Bob'
        ) RETURNING contact_id
        """
    )
    session_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by)
        VALUES ($1, 'ops:acme.com', 'alice')
        """,
        session_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (
            session_id, did, agent_id, alias, address
        ) VALUES
            ($1, 'did:aw:alice', $2, 'alice', 'acme.com/alice'),
            ($1, 'did:aw:bob', $3, 'bob', 'acme.com/bob')
        """,
        session_id,
        alice_agent_id,
        bob_agent_id,
    )

    result = json.loads(
        await contacts_tools.send_message_to_contact(
            DBInfra(aweb_cloud_db.aweb_db),
            registry_client=None,
            contact_id=str(contact["contact_id"]),
            message="must not transfer through chat session",
            channel="chat",
        )
    )

    assert result == {"error": "contact_identity_binding_required"}
    assert await aweb_cloud_db.aweb_db.fetch_val(
        "SELECT COUNT(*) FROM {{tables.chat_messages}}"
    ) == 0


@pytest.mark.asyncio
async def test_consumer_mcp_send_message_to_contact_reuses_existing_chat_session_without_rediscovery(
    aweb_cloud_db,
    monkeypatch,
):
    alice_agent_id, bob_agent_id = await _seed_team(aweb_cloud_db.aweb_db)
    _patch_auth(monkeypatch, _auth(agent_id=alice_agent_id))
    contact = await aweb_cloud_db.aweb_db.fetch_one(
        """
        INSERT INTO {{tables.contacts}} (
            owner_did, contact_address, contact_did_aw,
            binding_controller_did, binding_accepted_at, label
        ) VALUES (
            'did:aw:alice', 'acme.com/bob', 'did:aw:bob',
            'did:key:z6MkNamespaceController', clock_timestamp(), 'Bob'
        ) RETURNING contact_id
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
