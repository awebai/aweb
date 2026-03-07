"""Tests for MCP Agent Mail-compatible messaging tools."""

import json

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from beadhub.api import create_app


def _auth_headers(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


async def _rpc(client, api_key, method, params=None):
    body = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        body["params"] = params
    resp = await client.post("/mcp", json=body, headers=_auth_headers(api_key))
    assert resp.status_code == 200, resp.text
    return resp.json()


def _tool_call(name, arguments):
    return {"name": name, "arguments": arguments}


def _extract_payload(rpc_result):
    """Extract the JSON payload from an MCP tools/call result."""
    text = rpc_result["result"]["content"][0]["text"]
    return json.loads(text)


async def _setup_two_agents(client, init_workspace):
    """Create two agents in the same project for messaging tests."""
    sender = await init_workspace(
        client,
        project_slug="mcp-mail",
        repo_origin="git@github.com:test/mcp-mail-sender.git",
        alias="sender",
    )
    recipient = await init_workspace(
        client,
        project_slug="mcp-mail",
        repo_origin="git@github.com:test/mcp-mail-recipient.git",
        alias="recipient",
    )
    return sender, recipient


@pytest.mark.asyncio
async def test_send_message(db_infra, async_redis, init_workspace):
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            sender, recipient = await _setup_two_agents(client, init_workspace)

            result = await _rpc(
                client,
                sender["api_key"],
                "tools/call",
                _tool_call(
                    "send_message",
                    {
                        "project_key": sender["project_slug"],
                        "sender_name": "sender",
                        "to": ["recipient"],
                        "subject": "Hello",
                        "body_md": "Test message body",
                    },
                ),
            )

            payload = _extract_payload(result)
            assert payload["count"] == 1
            assert len(payload["deliveries"]) == 1
            assert payload["deliveries"][0]["to"] == "recipient"
            assert payload["deliveries"][0]["status"] == "delivered"


@pytest.mark.asyncio
async def test_fetch_inbox(db_infra, async_redis, init_workspace):
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            sender, recipient = await _setup_two_agents(client, init_workspace)

            # Send a message first
            await _rpc(
                client,
                sender["api_key"],
                "tools/call",
                _tool_call(
                    "send_message",
                    {
                        "project_key": sender["project_slug"],
                        "sender_name": "sender",
                        "to": ["recipient"],
                        "subject": "Inbox test",
                        "body_md": "Check your inbox",
                    },
                ),
            )

            # Fetch recipient's inbox
            result = await _rpc(
                client,
                recipient["api_key"],
                "tools/call",
                _tool_call(
                    "fetch_inbox",
                    {
                        "project_key": recipient["project_slug"],
                        "agent_name": "recipient",
                    },
                ),
            )

            payload = _extract_payload(result)
            assert isinstance(payload, list)
            assert len(payload) >= 1
            msg = payload[0]
            assert msg["subject"] == "Inbox test"
            assert msg["from_alias"] == "sender"


@pytest.mark.asyncio
async def test_acknowledge_message(db_infra, async_redis, init_workspace):
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            sender, recipient = await _setup_two_agents(client, init_workspace)

            # Send a message
            send_result = await _rpc(
                client,
                sender["api_key"],
                "tools/call",
                _tool_call(
                    "send_message",
                    {
                        "project_key": sender["project_slug"],
                        "sender_name": "sender",
                        "to": ["recipient"],
                        "subject": "Ack test",
                        "body_md": "Please acknowledge",
                    },
                ),
            )
            message_id = _extract_payload(send_result)["deliveries"][0]["message_id"]

            # Acknowledge it
            result = await _rpc(
                client,
                recipient["api_key"],
                "tools/call",
                _tool_call(
                    "acknowledge_message",
                    {
                        "project_key": recipient["project_slug"],
                        "agent_name": "recipient",
                        "message_id": message_id,
                    },
                ),
            )

            payload = _extract_payload(result)
            assert payload["message_id"] == message_id
            assert payload["acknowledged"] is True
            assert "acknowledged_at" in payload


@pytest.mark.asyncio
async def test_mark_message_read(db_infra, async_redis, init_workspace):
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            sender, recipient = await _setup_two_agents(client, init_workspace)

            # Send a message
            send_result = await _rpc(
                client,
                sender["api_key"],
                "tools/call",
                _tool_call(
                    "send_message",
                    {
                        "project_key": sender["project_slug"],
                        "sender_name": "sender",
                        "to": ["recipient"],
                        "subject": "Read test",
                        "body_md": "Mark me read",
                    },
                ),
            )
            message_id = _extract_payload(send_result)["deliveries"][0]["message_id"]

            # Mark as read
            result = await _rpc(
                client,
                recipient["api_key"],
                "tools/call",
                _tool_call(
                    "mark_message_read",
                    {
                        "project_key": recipient["project_slug"],
                        "agent_name": "recipient",
                        "message_id": message_id,
                    },
                ),
            )

            payload = _extract_payload(result)
            assert payload["message_id"] == message_id
            assert payload["read"] is True
            assert "read_at" in payload


@pytest.mark.asyncio
async def test_reply_message(db_infra, async_redis, init_workspace):
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            sender, recipient = await _setup_two_agents(client, init_workspace)

            # Send original message
            send_result = await _rpc(
                client,
                sender["api_key"],
                "tools/call",
                _tool_call(
                    "send_message",
                    {
                        "project_key": sender["project_slug"],
                        "sender_name": "sender",
                        "to": ["recipient"],
                        "subject": "Thread test",
                        "body_md": "Start a conversation",
                    },
                ),
            )
            original = _extract_payload(send_result)
            message_id = original["deliveries"][0]["message_id"]

            # Reply
            result = await _rpc(
                client,
                recipient["api_key"],
                "tools/call",
                _tool_call(
                    "reply_message",
                    {
                        "project_key": recipient["project_slug"],
                        "message_id": message_id,
                        "sender_name": "recipient",
                        "body_md": "This is a reply",
                    },
                ),
            )

            payload = _extract_payload(result)
            assert payload["count"] == 1
            assert payload["reply_to"] == message_id
            assert "thread_id" in payload


@pytest.mark.asyncio
async def test_fetch_inbox_with_limit(db_infra, async_redis, init_workspace):
    """fetch_inbox respects the limit parameter."""
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            sender, recipient = await _setup_two_agents(client, init_workspace)

            # Send two messages
            for subj in ["First", "Second"]:
                await _rpc(
                    client,
                    sender["api_key"],
                    "tools/call",
                    _tool_call(
                        "send_message",
                        {
                            "project_key": sender["project_slug"],
                            "sender_name": "sender",
                            "to": ["recipient"],
                            "subject": subj,
                            "body_md": f"Body of {subj}",
                        },
                    ),
                )

            # Fetch with limit=1
            result = await _rpc(
                client,
                recipient["api_key"],
                "tools/call",
                _tool_call(
                    "fetch_inbox",
                    {
                        "project_key": recipient["project_slug"],
                        "agent_name": "recipient",
                        "limit": 1,
                    },
                ),
            )

            payload = _extract_payload(result)
            assert isinstance(payload, list)
            assert len(payload) == 1


@pytest.mark.asyncio
async def test_fetch_inbox_cross_agent_forbidden(db_infra, async_redis, init_workspace):
    """An agent cannot read another agent's inbox."""
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            sender, _recipient = await _setup_two_agents(client, init_workspace)

            # Sender tries to read recipient's inbox
            result = await _rpc(
                client,
                sender["api_key"],
                "tools/call",
                _tool_call(
                    "fetch_inbox",
                    {
                        "project_key": sender["project_slug"],
                        "agent_name": "recipient",
                    },
                ),
            )

            # Should get an error, not the inbox
            assert "error" in result


@pytest.mark.asyncio
async def test_send_message_to_multiple_recipients(db_infra, async_redis, init_workspace):
    app = create_app(db_infra=db_infra, redis=async_redis, serve_frontend=False)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            sender = await init_workspace(
                client,
                project_slug="mcp-multi",
                repo_origin="git@github.com:test/mcp-multi-sender.git",
                alias="sender",
            )
            r1 = await init_workspace(
                client,
                project_slug="mcp-multi",
                repo_origin="git@github.com:test/mcp-multi-r1.git",
                alias="recip-one",
            )
            r2 = await init_workspace(
                client,
                project_slug="mcp-multi",
                repo_origin="git@github.com:test/mcp-multi-r2.git",
                alias="recip-two",
            )

            result = await _rpc(
                client,
                sender["api_key"],
                "tools/call",
                _tool_call(
                    "send_message",
                    {
                        "project_key": sender["project_slug"],
                        "sender_name": "sender",
                        "to": ["recip-one", "recip-two"],
                        "subject": "Broadcast",
                        "body_md": "To both of you",
                    },
                ),
            )

            payload = _extract_payload(result)
            assert payload["count"] == 2
            assert len(payload["deliveries"]) == 2
            delivered_to = {d["to"] for d in payload["deliveries"]}
            assert delivered_to == {"recip-one", "recip-two"}
