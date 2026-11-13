"""The operator's switch for federated mail and chat leaving this server.

AWEB_FEDERATION_OUTBOUND unset keeps today's behaviour, delivering to any origin
the transport admits. ``off`` delivers nowhere, and a list of origins delivers
only to those. A refused send answers 403 naming the setting, before the
delivery origin is resolved or connected to.

Every delivery here is real: the server's own mail and chat routes, or its MCP
tools, send through the address-checked transport to a loopback listener. The
listener counts connections, and the resolver records lookups.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest
from awid.registry import Address, AddressDelivery, KeyResolution

import test_chat_http
import test_messages_http
from aweb.config import get_settings
from aweb.identity_auth_deps import MessagingAuth, get_messaging_auth
from aweb.mcp.tools import mail as mail_tools
from did_key_fixtures import named_did_key
from test_federation_delivery_transport import (
    ISOLATED_DEVELOPMENT,
    Hosts,
    Listener,
    _mcp_sender,
    _registered_tools,
    _signed,
    _transport,
)

SETTING = "AWEB_FEDERATION_OUTBOUND"


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _bob_at(origin: str) -> Address:
    return Address(
        address_id="addr-remote-bob",
        domain="otherco.com",
        name="bob",
        did_aw="did:aw:bob",
        current_did_key=named_did_key("bob"),
        reachability="public",
        created_at=datetime.now(timezone.utc).isoformat(),
        delivery=AddressDelivery(origin=origin),
    )


def _remote_answer(message_id: str, conversation_id: str, timestamp: str) -> bytes:
    return json.dumps({
        "message_id": message_id,
        "conversation_id": conversation_id,
        "session_id": conversation_id,
        "status": "delivered",
        "delivered_at": timestamp,
    }).encode()


async def _send_mail(db, origin: str, listener: Listener, hosts: Hosts) -> httpx.Response:
    """POST /v1/messages from a local agent to otherco.com/bob, whose delivery origin is ``origin``."""
    alice_key, _, alice_did = test_messages_http._make_keypair()
    await test_messages_http._insert_team(db, "backend:acme.com")
    agent_id = await test_messages_http._insert_agent(
        db, team_id="backend:acme.com", alias="alice", did_key=alice_did,
        did_aw="did:aw:alice", address="acme.com/alice",
    )
    registry = AsyncMock()
    registry.resolve_address = AsyncMock(return_value=_bob_at(origin))
    app = test_messages_http._build_test_app(db, registry)
    app.state.federation_mail_transport = _transport(hosts, ISOLATED_DEVELOPMENT)
    app.dependency_overrides[get_messaging_auth] = lambda: MessagingAuth(
        did_key=alice_did, did_aw="did:aw:alice", address="acme.com/alice",
        team_id="backend:acme.com", alias="alice", agent_id=agent_id,
    )
    message_id, conversation_id, timestamp = str(uuid4()), str(uuid4()), _now()
    listener.body = _remote_answer(message_id, conversation_id, timestamp)
    signed_payload, signature = _signed(alice_key, {
        "body": "hello", "conversation_id": conversation_id, "from": "acme.com/alice",
        "from_did": alice_did, "from_stable_id": "did:aw:alice", "message_id": message_id,
        "subject": "outbound", "timestamp": timestamp, "to": "otherco.com/bob",
        "to_did": named_did_key("bob"), "to_stable_id": "did:aw:bob", "type": "mail",
    })
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        return await client.post("/v1/messages", json={
            "to_address": "otherco.com/bob", "subject": "outbound", "body": "hello",
            "conversation_id": conversation_id, "message_id": message_id, "timestamp": timestamp,
            "from_did": alice_did, "signature": signature, "signed_payload": signed_payload,
        })


async def _send_chat(db, origin: str, listener: Listener, hosts: Hosts) -> httpx.Response:
    """POST /v1/chat/sessions from a local agent to otherco.com/bob, whose delivery origin is ``origin``."""
    alice_key, _, alice_did = test_chat_http._make_keypair()
    await db.execute(
        "INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key) "
        "VALUES ('backend:acme.com', 'acme.com', 'backend', $1)",
        named_did_key("team-1"),
    )
    agent_id = await db.fetch_value(
        """
        INSERT INTO {{tables.agents}}
            (team_id, alias, did_key, did_aw, address, identity_scope, role, inbound_mode, did_aw_verified_key)
        VALUES ('backend:acme.com', 'alice', $1, 'did:aw:alice', 'acme.com/alice', 'global', 'developer', 'open', $1)
        RETURNING agent_id
        """,
        alice_did,
    )
    registry = AsyncMock()
    registry.resolve_key = AsyncMock(
        return_value=KeyResolution(did_aw="did:aw:bob", current_did_key=named_did_key("bob"))
    )
    registry.resolve_address = AsyncMock(return_value=_bob_at(origin))
    app = test_chat_http._build_test_app(db, registry)
    app.state.public_origin = "https://local.example"
    app.state.federation_chat_transport = _transport(hosts, ISOLATED_DEVELOPMENT)
    app.dependency_overrides[get_messaging_auth] = lambda: MessagingAuth(
        did_key=alice_did, did_aw="did:aw:alice", address="acme.com/alice",
        team_id="backend:acme.com", alias="alice", agent_id=agent_id,
    )
    session_id, message_id, timestamp = str(uuid4()), str(uuid4()), _now()
    listener.body = _remote_answer(message_id, session_id, timestamp)
    signed_payload, signature = _signed(alice_key, {
        "body": "outbound chat", "conversation_id": session_id, "from": "acme.com/alice",
        "from_did": alice_did, "from_stable_id": "did:aw:alice", "message_id": message_id,
        "timestamp": timestamp, "to": "otherco.com/bob", "to_did": named_did_key("bob"),
        "to_stable_id": "did:aw:bob", "type": "chat",
    })
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        return await client.post("/v1/chat/sessions", json={
            "session_id": session_id, "to_addresses": ["otherco.com/bob"], "message": "outbound chat",
            "from_did": alice_did, "message_id": message_id, "timestamp": timestamp,
            "signature": signature, "signed_payload": signed_payload,
        })


async def _stored_mail(db) -> int:
    return await db.fetch_value("SELECT COUNT(*) FROM {{tables.messages}}")


async def _stored_chat(db) -> int:
    return await db.fetch_value("SELECT COUNT(*) FROM {{tables.chat_messages}}")


def _assert_refused_before_the_network(response: httpx.Response, origin: str, why: str, listener, hosts) -> None:
    assert response.status_code == 403, response.text
    assert response.json() == {"detail": f"Federated delivery to {origin} is refused: {SETTING} {why}"}
    assert hosts.queries == []
    assert listener.connections == 0


def test_the_setting_is_named_once():
    from aweb.config import FEDERATION_OUTBOUND_SETTING

    assert FEDERATION_OUTBOUND_SETTING == SETTING


@pytest.mark.asyncio
async def test_unset_keeps_delivering_to_any_admitted_origin(aweb_cloud_db, monkeypatch):
    monkeypatch.delenv(SETTING, raising=False)
    db = aweb_cloud_db.aweb_db
    async with Listener() as listener:
        hosts = Hosts({"peer.test": ("127.0.0.1",)})
        response = await _send_mail(db, f"http://peer.test:{listener.port}", listener, hosts)

        assert response.status_code == 200, response.text
        assert listener.connections == 1
        assert listener.requests[0].startswith(b"POST /v1/federation/messages HTTP/1.1\r\n")
    assert await _stored_mail(db) == 1


@pytest.mark.asyncio
async def test_off_refuses_mail_before_resolving_or_connecting(aweb_cloud_db, monkeypatch):
    monkeypatch.setenv(SETTING, "off")
    db = aweb_cloud_db.aweb_db
    async with Listener() as listener:
        hosts = Hosts({"peer.test": ("127.0.0.1",)})
        origin = f"http://peer.test:{listener.port}"
        response = await _send_mail(db, origin, listener, hosts)

        _assert_refused_before_the_network(response, origin, "is off", listener, hosts)
    assert await _stored_mail(db) == 0


@pytest.mark.asyncio
async def test_off_refuses_chat_before_resolving_or_connecting(aweb_cloud_db, monkeypatch):
    monkeypatch.setenv(SETTING, "OFF")
    db = aweb_cloud_db.aweb_db
    async with Listener() as listener:
        hosts = Hosts({"peer.test": ("127.0.0.1",)})
        origin = f"http://peer.test:{listener.port}"
        response = await _send_chat(db, origin, listener, hosts)

        _assert_refused_before_the_network(response, origin, "is off", listener, hosts)
    assert await _stored_chat(db) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_an_allowlisted_origin_receives_the_send(kind, aweb_cloud_db, monkeypatch):
    db = aweb_cloud_db.aweb_db
    send, stored = (_send_mail, _stored_mail) if kind == "mail" else (_send_chat, _stored_chat)
    async with Listener() as listener:
        origin = f"http://peer.test:{listener.port}"
        # Listed in a different but equivalent spelling, beside another origin.
        monkeypatch.setenv(SETTING, f" https://elsewhere.example , HTTP://Peer.Test:{listener.port}/ ")
        hosts = Hosts({"peer.test": ("127.0.0.1",)})

        response = await send(db, origin, listener, hosts)

        assert response.status_code == 200, response.text
        assert hosts.queries == ["peer.test"]
        assert listener.connections == 1
    assert await stored(db) >= 1


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_an_origin_the_allowlist_does_not_name_is_refused(kind, aweb_cloud_db, monkeypatch):
    db = aweb_cloud_db.aweb_db
    send, stored = (_send_mail, _stored_mail) if kind == "mail" else (_send_chat, _stored_chat)
    async with Listener() as listener:
        origin = f"http://peer.test:{listener.port}"
        # The same host on another port is another origin.
        monkeypatch.setenv(SETTING, f"https://elsewhere.example,http://peer.test:{listener.port + 1}")
        hosts = Hosts({"peer.test": ("127.0.0.1",)})

        response = await send(db, origin, listener, hosts)

        _assert_refused_before_the_network(response, origin, "does not list this origin", listener, hosts)
    assert await stored(db) == 0


@pytest.mark.asyncio
async def test_off_refuses_an_mcp_reply_in_a_federated_conversation(aweb_cloud_db, monkeypatch):
    monkeypatch.setenv(SETTING, "off")
    db = aweb_cloud_db.aweb_db
    sender = await _mcp_sender(db, monkeypatch, mail_tools)
    async with Listener() as listener:
        origin = f"http://peer.test:{listener.port}"
        conversation_id = uuid4()
        await db.execute(
            """
            INSERT INTO {{tables.conversations}} (conversation_id, conversation_type, team_id, created_by_did)
            VALUES ($1, 'mail', $2, 'did:aw:alice')
            """,
            conversation_id, sender.team_id,
        )
        await db.execute(
            """
            INSERT INTO {{tables.conversation_participants}} (
                conversation_id, did, agent_id, alias, address, delivery_origin, current_did_key, transport_hint, role
            )
            VALUES
                ($1, 'did:aw:alice', $2, 'alice', 'acme.com/alice', NULL, $3, 'sender', 'initiator'),
                ($1, 'did:aw:bob', NULL, 'bob', 'otherco.com/bob', $4, $5, $6, 'participant')
            """,
            conversation_id, sender.agent_id, sender.did, origin, named_did_key("bob"), f"federation:{origin}",
        )
        hosts = Hosts({"peer.test": ("127.0.0.1",)})
        authority = SimpleNamespace(delivery_transport=_transport(hosts, ISOLATED_DEVELOPMENT))
        tools = _registered_tools(db, authority, sender.signer)

        result = json.loads(await tools.funcs["send_mail"](
            conversation_id=str(conversation_id), subject="Re", body="federated reply", plaintext=True,
        ))

        assert result == {"error": f"Federated delivery to {origin} is refused: {SETTING} is off"}
        assert hosts.queries == []
        assert listener.connections == 0
    assert await _stored_mail(db) == 0


@pytest.mark.parametrize(
    "value",
    ["https://peer.example/path", "off,https://peer.example", "ftp://peer.example", "https://user@peer.example"],
)
def test_an_invalid_setting_refuses_start_up_naming_the_setting(value, monkeypatch):
    monkeypatch.setenv(SETTING, value)
    monkeypatch.setenv("AWEB_DATABASE_URL", "postgresql://u:p@localhost:5432/aweb")
    monkeypatch.setenv("AWID_SERVICE_TOKEN", "a" * 64)
    with pytest.raises(ValueError, match=SETTING):
        get_settings()


@pytest.mark.asyncio
async def test_an_invalid_setting_refuses_every_send(aweb_cloud_db, monkeypatch):
    # A host that embeds aweb without loading its settings still fails closed.
    monkeypatch.setenv(SETTING, "https://peer.example/path")
    db = aweb_cloud_db.aweb_db
    async with Listener() as listener:
        hosts = Hosts({"peer.test": ("127.0.0.1",)})
        origin = f"http://peer.test:{listener.port}"
        response = await _send_mail(db, origin, listener, hosts)

        _assert_refused_before_the_network(response, origin, "is not a valid setting", listener, hosts)
    assert await _stored_mail(db) == 0
