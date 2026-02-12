"""Tests for the aweb MCP server module."""

from __future__ import annotations

import asyncio
import json

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app
from aweb.mcp import create_mcp_app


async def _init_agent(client: AsyncClient, slug: str, alias: str) -> dict:
    """Bootstrap a project + agent + API key via /v1/init."""
    resp = await client.post(
        "/v1/init",
        json={
            "project_slug": slug,
            "alias": alias,
            "human_name": f"Human {alias}",
            "agent_type": "agent",
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# JSON-RPC helpers
# ---------------------------------------------------------------------------

_PROTOCOL_VERSION = "2025-03-26"
_REQ_ID = 0


def _next_id() -> int:
    global _REQ_ID
    _REQ_ID += 1
    return _REQ_ID


def _jsonrpc(method: str, params: dict | None = None) -> dict:
    msg: dict = {"jsonrpc": "2.0", "method": method, "id": _next_id()}
    if params is not None:
        msg["params"] = params
    return msg


_MCP_ACCEPT = "application/json, text/event-stream"


async def _mcp_initialize(mc: AsyncClient, headers: dict | None = None) -> tuple[dict, str]:
    """Send MCP initialize + initialized, return (result, session_id)."""
    h = {"Accept": _MCP_ACCEPT, **(headers or {})}
    resp = await mc.post(
        "/mcp",
        json=_jsonrpc(
            "initialize",
            {
                "protocolVersion": _PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "0.1"},
            },
        ),
        headers=h,
    )
    assert resp.status_code == 200, resp.text
    session_id = resp.headers.get("mcp-session-id", "")

    # Send initialized notification
    notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    await mc.post(
        "/mcp",
        json=notif,
        headers={"Accept": _MCP_ACCEPT, "mcp-session-id": session_id, **(headers or {})},
    )
    return resp.json(), session_id


async def _mcp_call(
    mc: AsyncClient, method: str, params: dict, session_id: str, headers: dict | None = None
) -> dict:
    """Send a JSON-RPC request to the MCP endpoint and return the response."""
    h = {"Accept": _MCP_ACCEPT, "mcp-session-id": session_id, **(headers or {})}
    resp = await mc.post(
        "/mcp",
        json=_jsonrpc(method, params),
        headers=h,
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _tool_call(
    mc: AsyncClient, tool_name: str, arguments: dict, session_id: str, headers: dict
) -> dict:
    """Call an MCP tool and return the parsed JSON result."""
    result = await _mcp_call(
        mc, "tools/call", {"name": tool_name, "arguments": arguments}, session_id, headers=headers
    )
    content = result["result"]["content"]
    assert len(content) >= 1
    assert content[0]["type"] == "text"
    return json.loads(content[0]["text"])


async def _setup_mcp_session(aweb_db_infra, slug: str, alias: str) -> dict:
    """Create agent via REST, return (api_key, agent_data)."""
    rest_app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(rest_app):
        async with AsyncClient(transport=ASGITransport(app=rest_app), base_url="http://test") as rc:
            return await _init_agent(rc, slug, alias)


# ---------------------------------------------------------------------------
# Scaffold tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mcp_app_can_be_created(aweb_db_infra):
    """create_mcp_app returns an ASGI app."""
    mcp_app = create_mcp_app(db_infra=aweb_db_infra)
    assert mcp_app is not None


@pytest.mark.asyncio
async def test_mcp_initialize_without_auth_rejected(aweb_db_infra):
    """Unauthenticated requests are rejected."""
    mcp_app = create_mcp_app(db_infra=aweb_db_infra)
    async with LifespanManager(mcp_app):
        async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as mc:
            resp = await mc.post(
                "/mcp",
                json=_jsonrpc(
                    "initialize",
                    {
                        "protocolVersion": _PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": {"name": "test", "version": "0.1"},
                    },
                ),
            )
            assert resp.status_code == 401


@pytest.mark.asyncio
async def test_mcp_initialize_with_auth(aweb_db_infra):
    """Authenticated MCP initialization succeeds."""
    agent = await _setup_mcp_session(aweb_db_infra, "mcp-init", "alice")
    auth = {"Authorization": f"Bearer {agent['api_key']}"}

    mcp_app = create_mcp_app(db_infra=aweb_db_infra)
    async with LifespanManager(mcp_app):
        async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as mc:
            result, _ = await _mcp_initialize(mc, headers=auth)
            assert result["result"]["serverInfo"]["name"] == "aweb"


@pytest.mark.asyncio
async def test_mcp_lists_all_tools(aweb_db_infra):
    """tools/list returns all registered aweb tools."""
    agent = await _setup_mcp_session(aweb_db_infra, "mcp-tools", "alice")
    auth = {"Authorization": f"Bearer {agent['api_key']}"}

    mcp_app = create_mcp_app(db_infra=aweb_db_infra)
    async with LifespanManager(mcp_app):
        async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as mc:
            _, session_id = await _mcp_initialize(mc, headers=auth)
            result = await _mcp_call(mc, "tools/list", {}, session_id, headers=auth)

            tool_names = {t["name"] for t in result["result"]["tools"]}
            expected = {
                "whoami",
                "send_mail",
                "check_inbox",
                "ack_message",
                "list_agents",
                "heartbeat",
                "chat_send",
                "chat_pending",
                "chat_history",
                "chat_read",
                "contacts_list",
                "contacts_add",
                "contacts_remove",
                "lock_acquire",
                "lock_release",
                "lock_list",
            }
            assert expected == tool_names


# ---------------------------------------------------------------------------
# whoami
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mcp_whoami(aweb_db_infra):
    """whoami tool returns the authenticated agent's identity."""
    agent = await _setup_mcp_session(aweb_db_infra, "mcp-whoami", "alice")
    auth = {"Authorization": f"Bearer {agent['api_key']}"}

    mcp_app = create_mcp_app(db_infra=aweb_db_infra)
    async with LifespanManager(mcp_app):
        async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as mc:
            _, sid = await _mcp_initialize(mc, headers=auth)
            data = await _tool_call(mc, "whoami", {}, sid, auth)

            assert data["alias"] == "alice"
            assert data["project_id"] == agent["project_id"]
            assert data["agent_id"] == agent["agent_id"]


# ---------------------------------------------------------------------------
# Mail tools
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mcp_send_and_check_mail(aweb_db_infra):
    """send_mail delivers a message that check_inbox retrieves."""
    # Create two agents in the same project
    rest_app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(rest_app):
        async with AsyncClient(transport=ASGITransport(app=rest_app), base_url="http://test") as rc:
            alice = await _init_agent(rc, "mcp-mail", "alice")
            bob = await _init_agent(rc, "mcp-mail", "bob")

    mcp_app = create_mcp_app(db_infra=aweb_db_infra)
    auth_alice = {"Authorization": f"Bearer {alice['api_key']}"}
    auth_bob = {"Authorization": f"Bearer {bob['api_key']}"}

    async with LifespanManager(mcp_app):
        async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as mc:
            # Alice sends mail to bob
            _, sid_a = await _mcp_initialize(mc, headers=auth_alice)
            send_result = await _tool_call(
                mc,
                "send_mail",
                {"to_alias": "bob", "subject": "Hello", "body": "Hi Bob!"},
                sid_a,
                auth_alice,
            )
            assert send_result["status"] == "delivered"
            message_id = send_result["message_id"]

            # Bob checks inbox
            _, sid_b = await _mcp_initialize(mc, headers=auth_bob)
            inbox = await _tool_call(mc, "check_inbox", {"unread_only": True}, sid_b, auth_bob)
            assert len(inbox["messages"]) == 1
            msg = inbox["messages"][0]
            assert msg["from_alias"] == "alice"
            assert msg["subject"] == "Hello"
            assert msg["body"] == "Hi Bob!"
            assert msg["read"] is False

            # Bob acks the message
            ack = await _tool_call(mc, "ack_message", {"message_id": message_id}, sid_b, auth_bob)
            assert ack["status"] == "acknowledged"

            # Inbox is now empty when filtering unread
            inbox2 = await _tool_call(mc, "check_inbox", {"unread_only": True}, sid_b, auth_bob)
            assert len(inbox2["messages"]) == 0


@pytest.mark.asyncio
async def test_mcp_send_mail_to_nonexistent_agent(aweb_db_infra):
    """send_mail returns error for unknown recipient."""
    agent = await _setup_mcp_session(aweb_db_infra, "mcp-mail-err", "alice")
    auth = {"Authorization": f"Bearer {agent['api_key']}"}

    mcp_app = create_mcp_app(db_infra=aweb_db_infra)
    async with LifespanManager(mcp_app):
        async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as mc:
            _, sid = await _mcp_initialize(mc, headers=auth)
            data = await _tool_call(
                mc,
                "send_mail",
                {"to_alias": "nobody", "body": "test"},
                sid,
                auth,
            )
            assert "error" in data


# ---------------------------------------------------------------------------
# list_agents
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mcp_list_agents(aweb_db_infra):
    """list_agents returns all agents in the project."""
    rest_app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(rest_app):
        async with AsyncClient(transport=ASGITransport(app=rest_app), base_url="http://test") as rc:
            alice = await _init_agent(rc, "mcp-agents", "alice")
            await _init_agent(rc, "mcp-agents", "bob")

    auth = {"Authorization": f"Bearer {alice['api_key']}"}
    mcp_app = create_mcp_app(db_infra=aweb_db_infra)

    async with LifespanManager(mcp_app):
        async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as mc:
            _, sid = await _mcp_initialize(mc, headers=auth)
            data = await _tool_call(mc, "list_agents", {}, sid, auth)

            aliases = {a["alias"] for a in data["agents"]}
            assert aliases == {"alice", "bob"}
            assert data["project_id"] == alice["project_id"]


# ---------------------------------------------------------------------------
# heartbeat
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mcp_heartbeat_without_redis(aweb_db_infra):
    """heartbeat gracefully handles missing Redis."""
    agent = await _setup_mcp_session(aweb_db_infra, "mcp-hb", "alice")
    auth = {"Authorization": f"Bearer {agent['api_key']}"}

    mcp_app = create_mcp_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(mcp_app):
        async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as mc:
            _, sid = await _mcp_initialize(mc, headers=auth)
            data = await _tool_call(mc, "heartbeat", {}, sid, auth)
            # Should still return agent info even without Redis
            assert data["agent_id"] == agent["agent_id"]


# ---------------------------------------------------------------------------
# Chat tools
# ---------------------------------------------------------------------------


async def _setup_two_agents(aweb_db_infra, slug: str):
    """Create two agents (alice, bob) in the same project via REST."""
    rest_app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(rest_app):
        async with AsyncClient(transport=ASGITransport(app=rest_app), base_url="http://test") as rc:
            alice = await _init_agent(rc, slug, "alice")
            bob = await _init_agent(rc, slug, "bob")
    return alice, bob


@pytest.mark.asyncio
async def test_mcp_chat_send_and_receive(aweb_db_infra):
    """chat_send creates a session and delivers a message that chat_pending shows."""
    alice, bob = await _setup_two_agents(aweb_db_infra, "mcp-chat")
    auth_alice = {"Authorization": f"Bearer {alice['api_key']}"}
    auth_bob = {"Authorization": f"Bearer {bob['api_key']}"}

    mcp_app = create_mcp_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(mcp_app):
        async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as mc:
            # Alice sends a chat message to Bob
            _, sid_a = await _mcp_initialize(mc, headers=auth_alice)
            result = await _tool_call(
                mc,
                "chat_send",
                {"to_alias": "bob", "message": "Hey Bob!"},
                sid_a,
                auth_alice,
            )
            assert result["delivered"] is True
            assert "session_id" in result
            session_id = result["session_id"]

            # Bob sees it in pending
            _, sid_b = await _mcp_initialize(mc, headers=auth_bob)
            pending = await _tool_call(mc, "chat_pending", {}, sid_b, auth_bob)
            assert len(pending["pending"]) == 1
            assert pending["pending"][0]["session_id"] == session_id
            assert pending["pending"][0]["unread_count"] == 1


@pytest.mark.asyncio
async def test_mcp_chat_history(aweb_db_infra):
    """chat_history returns messages for a session."""
    alice, bob = await _setup_two_agents(aweb_db_infra, "mcp-chat-hist")
    auth_alice = {"Authorization": f"Bearer {alice['api_key']}"}
    auth_bob = {"Authorization": f"Bearer {bob['api_key']}"}

    mcp_app = create_mcp_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(mcp_app):
        async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as mc:
            _, sid_a = await _mcp_initialize(mc, headers=auth_alice)
            result = await _tool_call(
                mc,
                "chat_send",
                {"to_alias": "bob", "message": "Hello"},
                sid_a,
                auth_alice,
            )
            session_id = result["session_id"]

            # Bob gets history
            _, sid_b = await _mcp_initialize(mc, headers=auth_bob)
            history = await _tool_call(
                mc,
                "chat_history",
                {"session_id": session_id},
                sid_b,
                auth_bob,
            )
            assert len(history["messages"]) == 1
            assert history["messages"][0]["body"] == "Hello"
            assert history["messages"][0]["from_alias"] == "alice"


@pytest.mark.asyncio
async def test_mcp_chat_read(aweb_db_infra):
    """chat_read marks messages as read."""
    alice, bob = await _setup_two_agents(aweb_db_infra, "mcp-chat-read")
    auth_alice = {"Authorization": f"Bearer {alice['api_key']}"}
    auth_bob = {"Authorization": f"Bearer {bob['api_key']}"}

    mcp_app = create_mcp_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(mcp_app):
        async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as mc:
            _, sid_a = await _mcp_initialize(mc, headers=auth_alice)
            result = await _tool_call(
                mc,
                "chat_send",
                {"to_alias": "bob", "message": "Read me"},
                sid_a,
                auth_alice,
            )
            session_id = result["session_id"]
            message_id = result["message_id"]

            # Bob marks it as read
            _, sid_b = await _mcp_initialize(mc, headers=auth_bob)
            read_result = await _tool_call(
                mc,
                "chat_read",
                {"session_id": session_id, "up_to_message_id": message_id},
                sid_b,
                auth_bob,
            )
            assert read_result["status"] == "read"
            assert read_result["messages_marked"] == 1

            # Pending is now empty
            pending = await _tool_call(mc, "chat_pending", {}, sid_b, auth_bob)
            assert len(pending["pending"]) == 0


@pytest.mark.asyncio
async def test_mcp_chat_reply_in_session(aweb_db_infra):
    """chat_send with session_id replies in an existing session."""
    alice, bob = await _setup_two_agents(aweb_db_infra, "mcp-chat-reply")
    auth_alice = {"Authorization": f"Bearer {alice['api_key']}"}
    auth_bob = {"Authorization": f"Bearer {bob['api_key']}"}

    mcp_app = create_mcp_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(mcp_app):
        async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as mc:
            # Alice starts conversation
            _, sid_a = await _mcp_initialize(mc, headers=auth_alice)
            result = await _tool_call(
                mc,
                "chat_send",
                {"to_alias": "bob", "message": "Question?"},
                sid_a,
                auth_alice,
            )
            session_id = result["session_id"]

            # Bob replies using session_id
            _, sid_b = await _mcp_initialize(mc, headers=auth_bob)
            reply = await _tool_call(
                mc,
                "chat_send",
                {"session_id": session_id, "message": "Answer!"},
                sid_b,
                auth_bob,
            )
            assert reply["delivered"] is True
            assert reply["session_id"] == session_id

            # Alice sees both messages in history
            history = await _tool_call(
                mc,
                "chat_history",
                {"session_id": session_id},
                sid_a,
                auth_alice,
            )
            assert len(history["messages"]) == 2
            assert history["messages"][0]["body"] == "Question?"
            assert history["messages"][1]["body"] == "Answer!"


@pytest.mark.asyncio
async def test_mcp_chat_send_wait(aweb_db_infra):
    """chat_send with wait=true returns the reply when it arrives."""
    alice, bob = await _setup_two_agents(aweb_db_infra, "mcp-chat-wait")
    auth_alice = {"Authorization": f"Bearer {alice['api_key']}"}
    auth_bob = {"Authorization": f"Bearer {bob['api_key']}"}

    mcp_app = create_mcp_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(mcp_app):
        async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as mc:
            _, sid_a = await _mcp_initialize(mc, headers=auth_alice)
            _, sid_b = await _mcp_initialize(mc, headers=auth_bob)

            # Alice sends with wait=true in background
            async def alice_send():
                return await _tool_call(
                    mc,
                    "chat_send",
                    {"to_alias": "bob", "message": "Ping?", "wait": True, "wait_seconds": 5},
                    sid_a,
                    auth_alice,
                )

            send_task = asyncio.create_task(alice_send())
            await asyncio.sleep(0.8)  # Let alice's polling start

            # Bob replies
            # First, get session_id from pending
            pending = await _tool_call(mc, "chat_pending", {}, sid_b, auth_bob)
            assert len(pending["pending"]) == 1
            session_id = pending["pending"][0]["session_id"]

            await _tool_call(
                mc,
                "chat_send",
                {"session_id": session_id, "message": "Pong!"},
                sid_b,
                auth_bob,
            )

            # Alice's wait should return with the reply
            result = await asyncio.wait_for(send_task, timeout=10)
            assert result["timed_out"] is False
            assert len(result["replies"]) >= 1
            assert result["replies"][0]["body"] == "Pong!"
            assert result["replies"][0]["from_alias"] == "bob"


@pytest.mark.asyncio
async def test_mcp_chat_send_wait_timeout(aweb_db_infra):
    """chat_send with wait=true returns timed_out when no reply arrives."""
    alice, _ = await _setup_two_agents(aweb_db_infra, "mcp-chat-timeout")
    auth_alice = {"Authorization": f"Bearer {alice['api_key']}"}

    mcp_app = create_mcp_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(mcp_app):
        async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as mc:
            _, sid_a = await _mcp_initialize(mc, headers=auth_alice)
            result = await _tool_call(
                mc,
                "chat_send",
                {"to_alias": "bob", "message": "Hello?", "wait": True, "wait_seconds": 1},
                sid_a,
                auth_alice,
            )
            assert result["timed_out"] is True
            assert result["replies"] == []


@pytest.mark.asyncio
async def test_mcp_chat_send_to_nonexistent_agent(aweb_db_infra):
    """chat_send returns error for unknown recipient."""
    agent = await _setup_mcp_session(aweb_db_infra, "mcp-chat-err", "alice")
    auth = {"Authorization": f"Bearer {agent['api_key']}"}

    mcp_app = create_mcp_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(mcp_app):
        async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as mc:
            _, sid = await _mcp_initialize(mc, headers=auth)
            data = await _tool_call(
                mc,
                "chat_send",
                {"to_alias": "nobody", "message": "test"},
                sid,
                auth,
            )
            assert "error" in data


# ---------------------------------------------------------------------------
# Contacts tools
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mcp_contacts_add_list_remove(aweb_db_infra):
    """contacts_add, contacts_list, contacts_remove work end-to-end."""
    agent = await _setup_mcp_session(aweb_db_infra, "mcp-contacts", "alice")
    auth = {"Authorization": f"Bearer {agent['api_key']}"}

    mcp_app = create_mcp_app(db_infra=aweb_db_infra)
    async with LifespanManager(mcp_app):
        async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as mc:
            _, sid = await _mcp_initialize(mc, headers=auth)

            # Add a contact
            added = await _tool_call(
                mc, "contacts_add", {"contact_address": "other-project"}, sid, auth
            )
            assert added["status"] == "added"
            assert added["contact_address"] == "other-project"
            contact_id = added["contact_id"]

            # List contacts
            listed = await _tool_call(mc, "contacts_list", {}, sid, auth)
            assert len(listed["contacts"]) == 1
            assert listed["contacts"][0]["contact_address"] == "other-project"

            # Remove contact
            removed = await _tool_call(mc, "contacts_remove", {"contact_id": contact_id}, sid, auth)
            assert removed["status"] == "removed"

            # List is now empty
            listed2 = await _tool_call(mc, "contacts_list", {}, sid, auth)
            assert len(listed2["contacts"]) == 0


@pytest.mark.asyncio
async def test_mcp_contacts_add_duplicate(aweb_db_infra):
    """contacts_add returns error for duplicate contacts."""
    agent = await _setup_mcp_session(aweb_db_infra, "mcp-contacts-dup", "alice")
    auth = {"Authorization": f"Bearer {agent['api_key']}"}

    mcp_app = create_mcp_app(db_infra=aweb_db_infra)
    async with LifespanManager(mcp_app):
        async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as mc:
            _, sid = await _mcp_initialize(mc, headers=auth)
            await _tool_call(mc, "contacts_add", {"contact_address": "ext"}, sid, auth)
            dup = await _tool_call(mc, "contacts_add", {"contact_address": "ext"}, sid, auth)
            assert "error" in dup


# ---------------------------------------------------------------------------
# Lock tools
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mcp_lock_acquire_release(aweb_db_infra):
    """lock_acquire and lock_release work end-to-end."""
    agent = await _setup_mcp_session(aweb_db_infra, "mcp-locks", "alice")
    auth = {"Authorization": f"Bearer {agent['api_key']}"}

    mcp_app = create_mcp_app(db_infra=aweb_db_infra)
    async with LifespanManager(mcp_app):
        async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as mc:
            _, sid = await _mcp_initialize(mc, headers=auth)

            # Acquire lock
            acquired = await _tool_call(
                mc, "lock_acquire", {"resource_key": "build/main"}, sid, auth
            )
            assert acquired["status"] == "acquired"
            assert acquired["resource_key"] == "build/main"

            # List shows the lock
            locks = await _tool_call(mc, "lock_list", {}, sid, auth)
            assert len(locks["reservations"]) == 1
            assert locks["reservations"][0]["resource_key"] == "build/main"

            # Release lock
            released = await _tool_call(
                mc, "lock_release", {"resource_key": "build/main"}, sid, auth
            )
            assert released["status"] == "released"

            # List is now empty
            locks2 = await _tool_call(mc, "lock_list", {}, sid, auth)
            assert len(locks2["reservations"]) == 0


@pytest.mark.asyncio
async def test_mcp_lock_acquire_conflict(aweb_db_infra):
    """lock_acquire returns error when resource is already locked."""
    alice, bob = await _setup_two_agents(aweb_db_infra, "mcp-locks-conflict")
    auth_alice = {"Authorization": f"Bearer {alice['api_key']}"}
    auth_bob = {"Authorization": f"Bearer {bob['api_key']}"}

    mcp_app = create_mcp_app(db_infra=aweb_db_infra)
    async with LifespanManager(mcp_app):
        async with AsyncClient(transport=ASGITransport(app=mcp_app), base_url="http://test") as mc:
            _, sid_a = await _mcp_initialize(mc, headers=auth_alice)
            _, sid_b = await _mcp_initialize(mc, headers=auth_bob)

            # Alice acquires
            await _tool_call(mc, "lock_acquire", {"resource_key": "deploy"}, sid_a, auth_alice)

            # Bob tries to acquire same lock
            conflict = await _tool_call(
                mc, "lock_acquire", {"resource_key": "deploy"}, sid_b, auth_bob
            )
            assert "error" in conflict
            assert conflict["holder_alias"] == "alice"
