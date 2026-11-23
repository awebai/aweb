"""MCP/REST continuation parity against actual native and AWID servers.

The shared sender/receiver fixture owns PostgreSQL, Redis, namespace custody
and HTTP listeners. Observers forward requests and wakes to their real owners.
"""

import json
from types import SimpleNamespace
from uuid import UUID, uuid4

import httpx
import pytest
import pytest_asyncio

from aweb.agent_wake import AgentWakePublisher, read_wake_marks
from aweb.application_state import application_registry_client
from aweb.federation.envelope import verify_federation_envelope
from aweb.internal_auth import build_internal_auth_header_value
from aweb.mcp.server import create_mcp_app
from aweb.mcp.signing import HostedMessageSigningResult, canonical_signed_payload
from awid.signing import sign_message
from test_dashboard_privacy import TEAM, privacy_app as privacy_app
from test_messages_http import _signed_identity_headers, _signed_team_headers
from test_same_origin_delivery import (
    foreign_receiver as foreign_receiver,
    same_origin as same_origin,
    same_origin_registry_socket as same_origin_registry_socket,
)

__all__ = ["foreign_receiver", "same_origin"]

INTERNAL_SECRET = "federated-send-parity-test-secret"


class ObservedFederationHTTP(httpx.AsyncBaseTransport):
    """Record the signed wire and forward it to the actual receiving server."""

    def __init__(self):
        self.inner = httpx.AsyncHTTPTransport()
        self.deliveries = []

    async def handle_async_request(self, request):
        body = json.loads(request.content)
        verify_federation_envelope(body["envelope"], body["signature"])
        response = await self.inner.handle_async_request(request)
        self.deliveries.append(
            SimpleNamespace(
                url=str(request.url),
                body=body,
                id_chain=request.headers.get("X-AWID-ID-Chain"),
                status=response.status_code,
            )
        )
        return response

    async def aclose(self):
        await self.inner.aclose()


class ObservedWakePublisher(AgentWakePublisher):
    """Record submissions while retaining actual Redis publication."""

    def __init__(self, redis):
        super().__init__(redis)
        self.submitted = []

    def submit(self, wakes):
        self.submitted.append({key: set(kinds) for key, kinds in wakes.items()})
        super().submit(wakes)


@pytest_asyncio.fixture
async def server(same_origin, foreign_receiver, monkeypatch):
    env = same_origin.env
    actor = env.actors["alice"]
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", INTERNAL_SECRET)
    # Public first contact establishes the sender and stored remote route.
    prime, submitted = await same_origin.send("mail", "global")
    assert prime.status_code == 200, prime.text
    sender_stable = submitted.signed["from_stable_id"]
    certificate = prime.request.headers["X-AWID-Team-Certificate"]
    signed = []

    async def signer(**kwargs):
        fields = dict(kwargs["payload"])
        signed.append(fields)
        payload = canonical_signed_payload(fields)
        return HostedMessageSigningResult(
            from_did=actor.did,
            signing_key_id=actor.did,
            signed_payload=payload,
            signature=sign_message(actor.sk, payload.encode()),
        )

    transport = ObservedFederationHTTP()
    wakes = ObservedWakePublisher(env.redis)
    previous_publisher = getattr(env.app.state, "agent_wake_publisher", None)
    previous_mail = getattr(env.app.state, "federation_mail_transport", None)
    previous_chat = getattr(env.app.state, "federation_chat_transport", None)
    env.app.state.agent_wake_publisher = wakes
    env.app.state.federation_mail_transport = transport
    env.app.state.federation_chat_transport = transport
    mcp = create_mcp_app(
        db_infra=env.infra,
        redis=env.redis,
        registry_client=application_registry_client(env.app.state),
        federation_authority=env.app.state.federation_authority,
        hosted_signer=signer,
        federation_mail_transport=transport,
        federation_chat_transport=transport,
        public_origin=env.app.state.public_origin,
    )
    env.app.mount("/federated-parity-mcp", mcp)
    await mcp.startup()

    async def remote_mail_thread():
        return str(submitted.conversation_id)

    async def own_origin_mail_thread():
        # A retained own-origin route has a real resident, not a new authority
        # inferred from the stored transport field.
        await same_origin.resident()
        await env.db.execute(
            "UPDATE {{tables.conversation_participants}} SET delivery_origin=$1, "
            "transport_hint='federation:' || $1 "
            "WHERE conversation_id=$2 AND did=$3",
            env.app.state.public_origin,
            submitted.conversation_id,
            same_origin.target_did,
        )
        return str(submitted.conversation_id)

    async def remote_chat_session():
        session_id, message_id = str(uuid4()), str(uuid4())
        fields = dict(submitted.signed)
        fields.update(
            type="chat",
            conversation_id=session_id,
            message_id=message_id,
            body="Open the real remote chat",
            sender_leaving=True,
        )
        fields.pop("subject")
        fields.pop("priority")
        payload = canonical_signed_payload(fields)
        data = json.dumps(
            dict(
                session_id=session_id,
                to_addresses=[same_origin.target_address],
                message=fields["body"],
                leaving=True,
                from_did=actor.did,
                message_id=message_id,
                timestamp=fields["timestamp"],
                signed_payload=payload,
                signature=sign_message(actor.sk, payload.encode()),
            )
        ).encode()
        response = await env.client.post(
            "/v1/chat/sessions",
            content=data,
            headers={
                **_signed_team_headers(actor.sk, actor.did, TEAM, certificate, data),
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 200, response.text
        transport.deliveries.clear()
        return session_id

    async def mcp_call(tool, **arguments):
        principal = str(uuid4())
        headers = {
            "Accept": "application/json, text/event-stream",
            "X-Team-ID": TEAM,
            "X-User-ID": principal,
            "X-AWEB-Actor-ID": str(actor.id),
            "X-AWEB-Auth": build_internal_auth_header_value(
                secret=INTERNAL_SECRET,
                team_id=TEAM,
                principal_type="u",
                principal_id=principal,
                actor_id=str(actor.id),
            ),
        }
        response = await env.client.post(
            "/federated-parity-mcp/",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": tool, "arguments": arguments},
            },
        )
        assert response.status_code == 200, response.text
        result = response.json()
        assert "error" not in result, result
        payload = json.loads(result["result"]["content"][0]["text"])
        assert "error" not in payload, payload
        return payload

    async def rest_send(path, body_fields, signed_fields):
        fields = {**signed_fields, "message_id": str(uuid4())}
        payload = canonical_signed_payload(fields)
        data = json.dumps(
            {
                **body_fields,
                "from_did": actor.did,
                "message_id": fields["message_id"],
                "timestamp": fields["timestamp"],
                "signed_payload": payload,
                "signature": sign_message(actor.sk, payload.encode()),
            }
        ).encode()
        response = await env.client.post(
            path,
            content=data,
            headers={
                "Content-Type": "application/json",
                **_signed_identity_headers(actor.sk, actor.did, sender_stable, data),
            },
        )
        assert response.status_code == 200, response.text
        return response.json()

    try:
        yield SimpleNamespace(
            db=env.db,
            redis=env.redis,
            remote_db=foreign_receiver.db,
            signed=signed,
            deliveries=transport.deliveries,
            wakes=wakes,
            target_did=same_origin.target_did,
            mcp_call=mcp_call,
            rest_send=rest_send,
            remote_mail_thread=remote_mail_thread,
            own_origin_mail_thread=own_origin_mail_thread,
            remote_chat_session=remote_chat_session,
        )
    finally:
        await mcp.shutdown()
        await wakes.close()
        await transport.aclose()
        env.app.state.agent_wake_publisher = previous_publisher
        env.app.state.federation_mail_transport = previous_mail
        env.app.state.federation_chat_transport = previous_chat


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
        "send_mail",
        conversation_id=conversation_id,
        subject="re",
        body="status",
        plaintext=True,
    )

    stored = await server.db.fetch_one(
        "SELECT to_did FROM {{tables.messages}} WHERE message_id = $1",
        UUID(sent["message_id"]),
    )
    assert stored["to_did"] == server.target_did
    assert server.deliveries == []
    woken: dict[str, set[str]] = {}
    for wakes in server.wakes.submitted:
        for key, kinds in wakes.items():
            woken.setdefault(key, set()).update(kinds)
    assert "mail" in woken.get("did:" + server.target_did, set()), server.wakes.submitted
    await server.wakes.close()
    marks = await read_wake_marks(server.redis, ["did:" + server.target_did])
    assert marks[("did:" + server.target_did, "mail")] is not None


@pytest.mark.asyncio
async def test_mcp_federated_mail_sends_the_envelope_the_route_sends(server):
    conversation_id = await server.remote_mail_thread()

    await server.mcp_call(
        "send_mail",
        conversation_id=conversation_id,
        subject="re",
        body="status",
        plaintext=True,
    )
    await server.rest_send(
        "/v1/messages",
        {"conversation_id": conversation_id, "subject": "re", "body": "status"},
        server.signed[-1],
    )

    from_mcp, from_rest = server.deliveries
    assert from_mcp.body["envelope"]["type"] == "mail"
    _assert_same_delivery(from_mcp, from_rest)
    for delivery in (from_mcp, from_rest):
        assert delivery.status == 200
        message_id = UUID(delivery.body["envelope"]["message_id"])
        table = "messages" if delivery.body["envelope"]["type"] == "mail" else "chat_messages"
        row = await server.remote_db.fetch_one(
            f"SELECT body, signed_payload FROM {{{{tables.{table}}}}} WHERE message_id=$1",
            message_id,
        )
        assert row["body"] == "status"
        assert row["signed_payload"] == delivery.body["envelope"]["signed_payload"]


@pytest.mark.asyncio
async def test_mcp_federated_chat_sends_the_envelope_the_route_sends(server):
    session_id = await server.remote_chat_session()

    await server.mcp_call("chat_send", session_id=session_id, message="status", plaintext=True)
    await server.rest_send(
        f"/v1/chat/sessions/{session_id}/messages",
        {"body": "status"},
        server.signed[-1],
    )

    from_mcp, from_rest = server.deliveries
    assert from_mcp.body["envelope"]["type"] == "chat"
    _assert_same_delivery(from_mcp, from_rest)
    for delivery in (from_mcp, from_rest):
        assert delivery.status == 200
        message_id = UUID(delivery.body["envelope"]["message_id"])
        table = "messages" if delivery.body["envelope"]["type"] == "mail" else "chat_messages"
        row = await server.remote_db.fetch_one(
            f"SELECT body, signed_payload FROM {{{{tables.{table}}}}} WHERE message_id=$1",
            message_id,
        )
        assert row["body"] == "status"
        assert row["signed_payload"] == delivery.body["envelope"]["signed_payload"]
