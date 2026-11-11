"""MCP mail and chat sends over a stored federation route behave as the REST routes do.

Exercised through the real mounted MCP app and the REST app over ASGI, with
real PostgreSQL. The remote server, the AWID registry and the agent wake
publisher are recorded at their boundaries.
"""

import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import httpx
import pytest
import pytest_asyncio

from awid.registry import Address, AddressDelivery, IDTreeEnrollment, KeyResolution
from awid.signing import sign_message
from aweb.federation.envelope import verify_federation_envelope
from aweb.internal_auth import build_internal_auth_header_value
from aweb.mcp.server import create_mcp_app
from aweb.mcp.signing import HostedMessageSigningResult, canonical_signed_payload
from aweb.routes.chat import router as chat_router
from identity_binding_support import seed_verified_bindings
from test_mcp_mutation_hook_parity import _RecordingRedis
from test_messages_http import (
    _build_test_app,
    _insert_agent,
    _insert_team,
    _make_keypair,
    _signed_identity_headers,
)

TEAM = "ops:acme.com"
INTERNAL_SECRET = "federated-send-parity-test-secret"
OWN_ORIGIN = "http://test"
REMOTE_ORIGIN = "https://remote.example"
REMOTE_ADDRESS = "otherco.com/rita"
REMOTE_DID_AW = "did:aw:rita"


class _RecordingWakePublisher:
    def __init__(self):
        self.submitted = []

    def submit(self, wakes):
        self.submitted.append({key: set(kinds) for key, kinds in wakes.items()})


@pytest_asyncio.fixture
async def server(aweb_cloud_db, monkeypatch):
    db = aweb_cloud_db.aweb_db
    await _insert_team(db, TEAM)
    keys = {}
    agents = {}
    for alias in ("pilot", "bob"):
        sk, _, did_key = _make_keypair()
        keys[alias] = (sk, did_key)
        agents[alias] = await _insert_agent(
            db, team_id=TEAM, alias=alias, did_key=did_key,
            did_aw=f"did:aw:{alias}", address=f"acme.com/{alias}",
        )
        await db.execute(
            """INSERT INTO {{tables.workspaces}}
               (workspace_id, team_id, agent_id, alias, workspace_type)
               VALUES ($1, $2, $3, $4, 'hosted_mcp')""",
            uuid4(), TEAM, UUID(agents[alias]), alias,
        )
    _, _, remote_did_key = _make_keypair()
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", INTERNAL_SECRET)

    signed = []

    async def signer(**kwargs):
        fields = dict(kwargs["payload"])
        signed.append(fields)
        sk, did_key = keys["pilot"]
        payload = canonical_signed_payload(fields)
        return HostedMessageSigningResult(
            from_did=did_key, signing_key_id=did_key, signed_payload=payload,
            signature=sign_message(sk, payload.encode()),
        )

    deliveries = []

    async def remote_server(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        envelope = body["envelope"]
        verify_federation_envelope(envelope, body["signature"])
        deliveries.append(SimpleNamespace(
            url=str(request.url), body=body, id_chain=request.headers.get("X-AWID-ID-Chain"),
        ))
        return httpx.Response(200, json={
            "message_id": envelope["message_id"],
            "conversation_id": envelope["conversation_id"],
            "session_id": envelope["conversation_id"],
            "status": "delivered",
            "delivered_at": envelope["timestamp"],
        })

    async def resolve_key_fresh(did_aw):
        alias = did_aw.removeprefix("did:aw:")
        return KeyResolution(
            did_aw=did_aw, current_did_key=keys[alias][1], id_tree=IDTreeEnrollment(False, None),
        )

    async def resolve_address_fresh(domain, name):
        return Address(
            address_id=f"addr-{name}", domain=domain, name=name, did_aw=f"did:aw:{name}",
            current_did_key=keys[name][1], created_at=datetime.now(timezone.utc).isoformat(),
        )

    registry = AsyncMock()
    registry.resolve_key_fresh = AsyncMock(side_effect=resolve_key_fresh)
    registry.resolve_address_fresh = AsyncMock(side_effect=resolve_address_fresh)
    registry.resolve_address = AsyncMock(return_value=Address(
        address_id="addr-rita", domain="otherco.com", name="rita", did_aw=REMOTE_DID_AW,
        current_did_key=remote_did_key, created_at=datetime.now(timezone.utc).isoformat(),
        delivery=AddressDelivery(origin=REMOTE_ORIGIN),
    ))

    transport = httpx.MockTransport(remote_server)
    wakes = _RecordingWakePublisher()
    app = _build_test_app(db, registry)
    app.include_router(chat_router)
    seed_verified_bindings(app, *((f"did:aw:{alias}", did, f"acme.com/{alias}")
                                  for alias, (_, did) in keys.items()))
    assert app.state.public_origin == OWN_ORIGIN
    app.state.federation_mail_transport = transport
    app.state.federation_chat_transport = transport
    app.state.agent_wake_publisher = wakes
    mcp = create_mcp_app(
        db_infra=app.state.db, redis=_RecordingRedis(), registry_client=registry, hosted_signer=signer,
        federation_mail_transport=transport, federation_chat_transport=transport,
    )
    app.mount("/mcp", mcp)
    await mcp.startup()

    async def mail_thread(*, recipient_did, recipient_alias, recipient_address, recipient_key, origin):
        conversation_id = uuid4()
        await db.execute(
            """INSERT INTO {{tables.conversations}}
               (conversation_id, conversation_type, team_id, created_by_did)
               VALUES ($1, 'mail', $2, 'did:aw:pilot')""",
            conversation_id, TEAM,
        )
        await db.execute(
            """INSERT INTO {{tables.conversation_participants}}
               (conversation_id, did, agent_id, alias, address, delivery_origin, current_did_key,
                transport_hint, role)
               VALUES
                   ($1, 'did:aw:pilot', $2, 'pilot', 'acme.com/pilot', NULL, $3, 'local', 'initiator'),
                   ($1, $4, NULL, $5, $6, $7, $8, 'federation:' || $7, 'participant')""",
            conversation_id, UUID(agents["pilot"]), keys["pilot"][1],
            recipient_did, recipient_alias, recipient_address, origin, recipient_key,
        )
        return str(conversation_id)

    async def remote_mail_thread():
        return await mail_thread(
            recipient_did=REMOTE_DID_AW, recipient_alias="rita", recipient_address=REMOTE_ADDRESS,
            recipient_key=remote_did_key, origin=REMOTE_ORIGIN,
        )

    async def own_origin_mail_thread():
        return await mail_thread(
            recipient_did="did:aw:bob", recipient_alias="bob", recipient_address="acme.com/bob",
            recipient_key=keys["bob"][1], origin=OWN_ORIGIN,
        )

    async def remote_chat_session():
        session_id = uuid4()
        await db.execute(
            "INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by) VALUES ($1, $2, 'pilot')",
            session_id, TEAM,
        )
        await db.execute(
            """INSERT INTO {{tables.chat_participants}}
               (session_id, did, agent_id, alias, address, delivery_origin, current_did_key)
               VALUES
                   ($1, 'did:aw:pilot', $2, 'pilot', 'acme.com/pilot', NULL, $3),
                   ($1, $4, NULL, 'rita', $5, $6, $7)""",
            session_id, UUID(agents["pilot"]), keys["pilot"][1],
            REMOTE_DID_AW, REMOTE_ADDRESS, REMOTE_ORIGIN, remote_did_key,
        )
        await db.execute(
            """INSERT INTO {{tables.conversations}}
               (conversation_id, conversation_type, team_id, created_by_did)
               VALUES ($1, 'chat', $2, 'did:aw:pilot')""",
            session_id, TEAM,
        )
        await db.execute(
            """INSERT INTO {{tables.conversation_participants}}
               (conversation_id, did, agent_id, alias, address, delivery_origin, current_did_key,
                transport_hint, role)
               VALUES
                   ($1, 'did:aw:pilot', $2, 'pilot', 'acme.com/pilot', NULL, $3, 'chat', 'initiator'),
                   ($1, $4, NULL, 'rita', $5, $6, $7, 'chat', 'participant')""",
            session_id, UUID(agents["pilot"]), keys["pilot"][1],
            REMOTE_DID_AW, REMOTE_ADDRESS, REMOTE_ORIGIN, remote_did_key,
        )
        return str(session_id)

    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=OWN_ORIGIN) as client:

            async def mcp_call(tool, **arguments):
                principal = str(uuid4())
                headers = {
                    "Accept": "application/json, text/event-stream", "X-Team-ID": TEAM,
                    "X-User-ID": principal, "X-AWEB-Actor-ID": agents["pilot"],
                    "X-AWEB-Auth": build_internal_auth_header_value(
                        secret=INTERNAL_SECRET, team_id=TEAM,
                        principal_type="u", principal_id=principal, actor_id=agents["pilot"],
                    ),
                }
                response = await client.post("/mcp/", headers=headers, json={
                    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": tool, "arguments": arguments},
                })
                assert response.status_code == 200, response.text
                result = response.json()
                assert "error" not in result, result
                payload = json.loads(result["result"]["content"][0]["text"])
                assert "error" not in payload, payload
                return payload

            async def rest_send(path, body_fields, signed_fields):
                """Send as pilot over REST, signing the given fields under a message id of its own."""
                sk, did_key = keys["pilot"]
                fields = {**signed_fields, "message_id": str(uuid4())}
                payload = canonical_signed_payload(fields)
                data = json.dumps({
                    **body_fields,
                    "from_did": did_key,
                    "message_id": fields["message_id"],
                    "timestamp": fields["timestamp"],
                    "signature": sign_message(sk, payload.encode()),
                    "signed_payload": payload,
                }).encode()
                response = await client.post(
                    path, content=data,
                    headers={
                        "Content-Type": "application/json",
                        **_signed_identity_headers(sk, did_key, "", data),
                    },
                )
                assert response.status_code == 200, response.text
                return response.json()

            yield SimpleNamespace(
                db=db, signed=signed, deliveries=deliveries, wakes=wakes,
                mcp_call=mcp_call, rest_send=rest_send, remote_mail_thread=remote_mail_thread,
                own_origin_mail_thread=own_origin_mail_thread, remote_chat_session=remote_chat_session,
            )
    finally:
        await mcp.shutdown()


def _without_message_identity(delivery):
    """A federated delivery's envelope and signed payload without the fields unique to one message."""
    envelope = dict(delivery.body["envelope"])
    signed = json.loads(envelope.pop("signed_payload"))
    for field in ("message_id", "timestamp"):
        envelope.pop(field)
        signed.pop(field)
    return envelope, signed


def _assert_same_delivery(from_mcp, from_rest):
    mcp_envelope, mcp_signed = _without_message_identity(from_mcp)
    rest_envelope, rest_signed = _without_message_identity(from_rest)
    assert mcp_envelope == rest_envelope
    assert mcp_signed == rest_signed
    assert from_mcp.url == from_rest.url
    assert sorted(from_mcp.body) == sorted(from_rest.body)
    assert from_mcp.id_chain == from_rest.id_chain


@pytest.mark.asyncio
async def test_mcp_mail_on_an_own_origin_federation_route_wakes_the_recipient(server):
    conversation_id = await server.own_origin_mail_thread()

    sent = await server.mcp_call(
        "send_mail", conversation_id=conversation_id, subject="re", body="status", plaintext=True,
    )

    stored = await server.db.fetch_one(
        "SELECT to_did FROM {{tables.messages}} WHERE message_id = $1", UUID(sent["message_id"]),
    )
    assert stored["to_did"] == "did:aw:bob"
    assert server.deliveries == []
    woken = {}
    for wakes in server.wakes.submitted:
        for key, kinds in wakes.items():
            woken.setdefault(key, set()).update(kinds)
    assert "mail" in woken.get("did:did:aw:bob", set()), server.wakes.submitted


@pytest.mark.asyncio
async def test_mcp_federated_mail_sends_the_envelope_the_route_sends(server):
    conversation_id = await server.remote_mail_thread()

    await server.mcp_call(
        "send_mail", conversation_id=conversation_id, subject="re", body="status", plaintext=True,
    )
    await server.rest_send(
        "/v1/messages",
        {"conversation_id": conversation_id, "subject": "re", "body": "status"},
        server.signed[-1],
    )

    from_mcp, from_rest = server.deliveries
    assert from_mcp.body["envelope"]["type"] == "mail"
    _assert_same_delivery(from_mcp, from_rest)


@pytest.mark.asyncio
async def test_mcp_federated_chat_sends_the_envelope_the_route_sends(server):
    session_id = await server.remote_chat_session()

    await server.mcp_call("chat_send", session_id=session_id, message="status", plaintext=True)
    await server.rest_send(
        f"/v1/chat/sessions/{session_id}/messages", {"body": "status"}, server.signed[-1],
    )

    from_mcp, from_rest = server.deliveries
    assert from_mcp.body["envelope"]["type"] == "chat"
    _assert_same_delivery(from_mcp, from_rest)
