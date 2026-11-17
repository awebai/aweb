"""Explicit addresses must select AWID identities, not team display aliases.

The server and AWID apps, database queries, auth and message writes are real.
Disposable identities, membership rows and registry records are provisioned.
The outage case injects an HTTP 503 at the registry transport boundary only.
"""

import json
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from aweb.internal_auth import build_internal_auth_header_value
from aweb.mcp.server import create_mcp_app
from aweb.mcp.signing import HostedMessageSigningResult
from awid.signing import canonical_json_bytes, sign_message
from identity_binding_support import register_global_identity
from starlette.responses import JSONResponse
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_messages_http import (
    _encode_certificate,
    _make_certificate,
    _make_keypair,
    _signed_identity_headers,
    _signed_team_headers,
)

ADDRESS = "example.test/bob"


@pytest_asyncio.fixture
async def address_collision(privacy_app, monkeypatch):  # noqa: F811 -- imported pytest fixture
    env = privacy_app
    # Alice's teammate has the display alias bob but no global address.
    # The registry's bob is a DIFFERENT identity, whose team alias is carol.
    target = env.actors["carol"]
    stable_id = await register_global_identity(env, target, ADDRESS)
    await env.db.execute(
        """UPDATE {{tables.agents}}
           SET did_aw=$1, address=$2, identity_scope='global', did_aw_verified_key=did_key
           WHERE agent_id=$3""",
        stable_id, ADDRESS, target.id,
    )
    # Confirm the actual AWID response before observing sends. This is not a
    # resolver stub or a local row pretending to be registry evidence.
    registry = env.app.state.awid_registry_client
    binding = await registry.resolve_address_fresh("example.test", "bob")
    assert binding.did_aw == stable_id
    assert binding.current_did_key == target.did

    signing_calls = []

    async def signer(**kwargs):
        signing_calls.append(kwargs)
        actor = env.actors["alice"]
        assert kwargs["agent_id"] == str(actor.id)
        canonical = canonical_json_bytes(kwargs["payload"])
        return HostedMessageSigningResult(
            from_did=actor.did, signing_key_id=actor.did,
            signature=sign_message(actor.sk, canonical), signed_payload=canonical.decode(),
        )

    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    principal = str(uuid4())
    proxy_headers = {
        "X-AWEB-Auth": build_internal_auth_header_value(
            secret="test-internal-auth-secret", team_id=TEAM,
            principal_type="k", principal_id=principal, actor_id=str(env.actors["alice"].id),
        ),
        "X-Team-ID": TEAM, "X-API-Key": principal,
        "X-AWEB-Actor-ID": str(env.actors["alice"].id),
    }
    mcp = create_mcp_app(
        db_infra=env.infra, redis=env.redis, registry_client=registry,
        public_origin=env.app.state.public_origin, hosted_signer=signer,
    )
    env.app.mount("/address-mcp", mcp)
    await mcp.startup()

    identity_sk, _, identity_did = _make_keypair()

    async def request(surface, recipient=ADDRESS, *, identity_only=False, signed_recipient=None):
        actor = env.actors["alice"]
        if surface in {"mcp_mail", "hosted_mcp_mail"}:
            payload = {
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "send_mail", "arguments": {
                    "to": recipient, "subject": "Address authority", "body": "hello", "plaintext": True,
                }},
            }
            path = "/address-mcp/"
        elif surface == "mail":
            selector = "to_address" if "/" in recipient else "to_alias"
            payload = {selector: recipient, "subject": "Address authority", "body": "hello"}
            path = "/v1/messages"
        else:
            selector = "to_addresses" if "/" in recipient else "to_aliases"
            payload = {selector: [recipient], "message": "hello", "leaving": True}
            path = "/v1/chat/sessions"
        # Authenticate the sender, but supply NO signed recipient binding.
        # This is the server input when a local CLI's address lookup failed;
        # MCP similarly resolves before it has any signed message binding.
        if signed_recipient is not None:
            timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            message_id = str(uuid4())
            envelope = {
                "type": "chat" if surface == "chat" else "mail", "from": "alice", "from_did": actor.did,
                "to": recipient, "to_did": signed_recipient.did,
                "body": payload.get("body", payload.get("message")),
                "timestamp": timestamp, "message_id": message_id,
            }
            if surface == "chat":
                payload["session_id"] = str(uuid4())
                envelope.update(conversation_id=payload["session_id"], sender_leaving=True, wait_seconds=None)
            else:
                envelope["subject"] = payload["subject"]
            canonical = canonical_json_bytes(envelope)
            payload.update(from_did=actor.did, timestamp=timestamp, message_id=message_id,
                           signed_payload=canonical.decode(), signature=sign_message(actor.sk, canonical))
        raw = json.dumps(payload).encode()
        return await env.client.post(path, content=raw, headers={
            **(proxy_headers if surface == "hosted_mcp_mail" else
               _signed_identity_headers(identity_sk, identity_did, "", raw) if identity_only else
               _signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate, raw)),
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        })
    async def send(surface, recipient=ADDRESS, **kwargs):
        response = await request(surface, recipient, **kwargs)
        assert response.status_code == 200, response.text
        result = response.json()
        if surface in {"mcp_mail", "hosted_mcp_mail"}:
            assert "error" not in result, result
            tool = result["result"]
            assert not tool.get("isError"), tool
            result = json.loads(tool["content"][0]["text"])
            assert "error" not in result, result
        return result

    try:
        yield SimpleNamespace(env=env, stable_id=stable_id, send=send, request=request, signing_calls=signing_calls)
    finally:
        await mcp.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["mail", "chat", "mcp_mail", "hosted_mcp_mail"])
@pytest.mark.parametrize("duplicate_alias", [False, True], ids=["same-team-shadow", "two-team-collision"])
async def test_registered_address_wins_over_local_aliases(address_collision, surface, duplicate_alias):
    fixture = address_collision
    env = fixture.env
    if duplicate_alias:
        team = "other:example.test"
        await env.db.execute(
            """INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
               VALUES ($1, 'example.test', 'other', $2)""", team, env.team_did,
        )
        _, _, other_key = _make_keypair()
        await env.db.execute(
            """INSERT INTO {{tables.agents}}
               (agent_id, team_id, alias, did_key, identity_scope, inbound_mode)
               VALUES ($1, $2, 'bob', $3, 'local', 'open')""", uuid4(), team, other_key,
        )

    result = await fixture.send(surface)
    if surface == "chat":
        participants = await env.db.fetch_all(
            "SELECT did FROM {{tables.chat_participants}} WHERE session_id=$1",
            UUID(result["session_id"]),
        )
        assert {row["did"] for row in participants} == {env.actors["alice"].did, fixture.stable_id}
    else:
        message = await env.db.fetch_one(
            "SELECT to_did FROM {{tables.messages}} WHERE message_id=$1", UUID(result["message_id"]),
        )
        assert message["to_did"] == fixture.stable_id


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["mail", "chat", "mcp_mail", "hosted_mcp_mail"])
async def test_bare_alias_still_selects_the_team_member(address_collision, surface):
    fixture = address_collision
    env = fixture.env
    result = await fixture.send(surface, "bob")
    if surface == "chat":
        participants = await env.db.fetch_all(
            "SELECT did FROM {{tables.chat_participants}} WHERE session_id=$1",
            UUID(result["session_id"]),
        )
        assert {row["did"] for row in participants} == {env.actors["alice"].did, env.actors["bob"].did}
    else:
        message = await env.db.fetch_one(
            "SELECT to_did FROM {{tables.messages}} WHERE message_id=$1", UUID(result["message_id"]),
        )
        assert message["to_did"] == env.actors["bob"].did


async def _remove_registered_address(env):
    # The real namespace remains verified. Only the address is absent.
    await env.registry_db.execute(
        "DELETE FROM {{tables.public_addresses}} WHERE name='bob'",
    )
    assert await env.app.state.awid_registry_client.resolve_address_fresh("example.test", "bob") is None


async def _assert_local_bob(fixture, surface, result):
    env = fixture.env
    if surface == "chat":
        participants = await env.db.fetch_all(
            "SELECT did FROM {{tables.chat_participants}} WHERE session_id=$1",
            UUID(result["session_id"]),
        )
        assert {row["did"] for row in participants} == {env.actors["alice"].did, env.actors["bob"].did}
    else:
        message = await env.db.fetch_one(
            "SELECT to_did FROM {{tables.messages}} WHERE message_id=$1", UUID(result["message_id"]),
        )
        assert message["to_did"] == env.actors["bob"].did


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["mail", "chat", "mcp_mail"])
async def test_derived_local_address_survives_registry_absence(address_collision, surface):
    """Compatibility control: the displayed address of a local agent still works."""
    fixture = address_collision
    await _remove_registered_address(fixture.env)
    result = await fixture.send(surface)
    await _assert_local_bob(fixture, surface, result)


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["mail", "chat", "mcp_mail", "hosted_mcp_mail"])
@pytest.mark.parametrize("registry_status", [503, 404], ids=["outage", "uncoded-proxy-404"])
async def test_derived_local_address_refuses_registry_outage(address_collision, surface, registry_status, monkeypatch):
    fixture = address_collision
    env = fixture.env
    await _remove_registered_address(env)
    transport = env.app.state.awid_registry_client.transport
    registry_app = transport.app
    lookups = []

    async def unavailable_address(scope, receive, send):
        if scope["type"] == "http" and scope["path"].endswith("/addresses/bob"):
            lookups.append(scope["path"])
            await JSONResponse({"detail": "unavailable upstream"}, status_code=registry_status)(
                scope, receive, send,
            )
        else:
            await registry_app(scope, receive, send)

    # Leave all authentication, namespace and other registry endpoints real.
    monkeypatch.setattr(transport, "app", unavailable_address)
    response = await fixture.request(surface)
    if surface in {"mcp_mail", "hosted_mcp_mail"}:
        assert response.status_code == 200, response.text
        result = json.loads(response.json()["result"]["content"][0]["text"])
        assert result.get("reason") == "sender_registry_unavailable", result
        assert "message_id" not in result
    else:
        assert response.status_code == 503, response.text
        assert "sender_registry_unavailable" in response.text
    assert lookups, "The explicit address must be asked of the registry"
    for table in ("messages", "chat_sessions"):
        row = await env.db.fetch_one("SELECT count(*) AS n FROM {{tables." + table + "}}")
        assert row["n"] == 0, "A refused lookup must create no delivery or session"


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["mail", "chat", "mcp_mail"])
async def test_registered_address_wins_over_other_team_alias(address_collision, surface):
    fixture = address_collision
    env = fixture.env
    team = "other:example.test"
    await env.db.execute(
        """INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
           VALUES ($1, 'example.test', 'other', $2)""", team, env.team_did,
    )
    await env.db.execute(
        "UPDATE {{tables.agents}} SET team_id=$1 WHERE agent_id=$2", team, env.actors["bob"].id,
    )
    result = await fixture.send(surface)
    if surface == "chat":
        participants = await env.db.fetch_all(
            "SELECT did FROM {{tables.chat_participants}} WHERE session_id=$1",
            UUID(result["session_id"]),
        )
        assert {row["did"] for row in participants} == {env.actors["alice"].did, fixture.stable_id}
    else:
        message = await env.db.fetch_one(
            "SELECT to_did FROM {{tables.messages}} WHERE message_id=$1", UUID(result["message_id"]),
        )
        assert message["to_did"] == fixture.stable_id


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["mail", "chat", "mcp_mail"])
async def test_derived_address_selects_own_team_despite_duplicate_alias(address_collision, surface):
    fixture = address_collision
    env = fixture.env
    await _remove_registered_address(env)
    team = "other:example.test"
    await env.db.execute(
        """INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
           VALUES ($1, 'example.test', 'other', $2)""", team, env.team_did,
    )
    _, _, key = _make_keypair()
    await env.db.execute(
        """INSERT INTO {{tables.agents}} (agent_id, team_id, alias, did_key, identity_scope, inbound_mode)
           VALUES ($1, $2, 'bob', $3, 'local', 'open')""", uuid4(), team, key,
    )
    result = await fixture.send(surface)
    await _assert_local_bob(fixture, surface, result)


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["mail", "chat", "mcp_mail"])
async def test_absent_address_never_selects_a_global_alias(address_collision, surface):
    fixture = address_collision
    env = fixture.env
    await _remove_registered_address(env)
    await env.db.execute(
        "UPDATE {{tables.agents}} SET alias='local-bob' WHERE agent_id=$1", env.actors["bob"].id,
    )
    await env.db.execute(
        "UPDATE {{tables.agents}} SET alias='bob' WHERE agent_id=$1", env.actors["carol"].id,
    )
    response = await fixture.request(surface)
    if surface in {"mcp_mail", "hosted_mcp_mail"}:
        assert response.status_code == 200, response.text
        result = json.loads(response.json()["result"]["content"][0]["text"])
        assert "error" in result and "message_id" not in result, result
    else:
        assert response.status_code == 404, response.text
        assert "recipient_identity_not_found" in response.text
    for table in ("messages", "chat_sessions"):
        row = await env.db.fetch_one("SELECT count(*) AS n FROM {{tables." + table + "}}")
        assert row["n"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["mail", "chat", "mcp_mail"])
@pytest.mark.parametrize("identity_only", [False, True], ids=["other-team", "no-team"])
async def test_derived_address_preserves_outside_team_refusal(address_collision, surface, identity_only):
    fixture = address_collision
    env = fixture.env
    await _remove_registered_address(env)
    team = "other:example.test"
    await env.db.execute(
        """INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
           VALUES ($1, 'example.test', 'other', $2)""", team, env.team_did,
    )
    await env.db.execute(
        "UPDATE {{tables.agents}} SET team_id=$1 WHERE agent_id=$2", team, env.actors["bob"].id,
    )
    occupied = await fixture.request(surface, identity_only=identity_only)
    unused = await fixture.request(surface, "example.test/unused", identity_only=identity_only)
    assert occupied.status_code == unused.status_code
    if surface in {"mcp_mail", "hosted_mcp_mail"}:
        assert occupied.status_code == 200, occupied.text
        result = json.loads(occupied.json()["result"]["content"][0]["text"])
        assert "error" in result and "message_id" not in result, result
    else:
        assert occupied.status_code == 404, occupied.text
        assert occupied.json()["reason"] == "local_recipient_route_missing"
        assert unused.json()["reason"] == "recipient_identity_not_found"
    for table in ("messages", "chat_sessions"):
        row = await env.db.fetch_one("SELECT count(*) AS n FROM {{tables." + table + "}}")
        assert row["n"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["mail", "chat"])
async def test_signed_visible_recipient_binding_works_without_address_registry(address_collision, surface, monkeypatch):
    fixture = address_collision
    env = fixture.env
    transport = env.app.state.awid_registry_client.transport
    registry_app = transport.app
    lookups = []

    async def unavailable_address(scope, receive, send):
        if scope["type"] == "http" and "/addresses/" in scope["path"]:
            lookups.append(scope["path"])
            await JSONResponse({"detail": "unavailable upstream"}, status_code=503)(scope, receive, send)
        else:
            await registry_app(scope, receive, send)

    monkeypatch.setattr(transport, "app", unavailable_address)
    result = await fixture.send(surface, signed_recipient=env.actors["bob"])
    await _assert_local_bob(fixture, surface, result)
    assert lookups == [], "A verified matching visible binding needs no address lookup"


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["hosted_mcp_mail"])
async def test_hosted_bare_alias_works_during_address_registry_outage(address_collision, surface, monkeypatch):
    fixture = address_collision
    env = fixture.env
    transport = env.app.state.awid_registry_client.transport
    registry_app = transport.app
    lookups = []

    async def unavailable_address(scope, receive, send):
        if scope["type"] == "http" and "/addresses/" in scope["path"]:
            lookups.append(scope["path"])
            await JSONResponse({"detail": "unavailable upstream"}, status_code=503)(scope, receive, send)
        else:
            await registry_app(scope, receive, send)

    monkeypatch.setattr(transport, "app", unavailable_address)
    result = await fixture.send(surface, "bob")
    await _assert_local_bob(fixture, surface, result)
    assert lookups == []
    if surface == "hosted_mcp_mail":
        assert len(fixture.signing_calls) == 1
        assert fixture.signing_calls[0]["payload"]["to_did"] == env.actors["bob"].did


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["mail", "chat", "hosted_mcp_mail"])
@pytest.mark.parametrize("absence", [
    {"detail": {"code": "address_not_found", "message": "Address not found"}},
    {"detail": "Address not found"},
    {"detail": "Namespace not found"},
], ids=["coded", "released-address", "released-namespace"])
async def test_only_c2_absence_allows_own_team_label(address_collision, surface, absence, monkeypatch):
    fixture = address_collision
    env = fixture.env
    await _remove_registered_address(env)
    transport = env.app.state.awid_registry_client.transport
    registry_app = transport.app

    async def absent_address(scope, receive, send):
        if scope["type"] == "http" and scope["path"].endswith("/addresses/bob"):
            await JSONResponse(absence, status_code=404)(scope, receive, send)
        else:
            await registry_app(scope, receive, send)

    monkeypatch.setattr(transport, "app", absent_address)
    result = await fixture.send(surface)
    await _assert_local_bob(fixture, surface, result)


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["mail", "chat"])
async def test_signed_binding_cannot_select_a_different_registered_identity(address_collision, surface):
    fixture = address_collision
    # The genuine sender signature names Alice's key for Bob's registered
    # address. Neither a local alias nor the registry may erase that constraint.
    response = await fixture.request(surface, signed_recipient=fixture.env.actors["alice"])
    assert response.status_code == 422, response.text
    for table in ("messages", "chat_sessions"):
        assert await fixture.env.db.fetch_val("SELECT count(*) FROM {{tables." + table + "}}") == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["mail", "chat"])
@pytest.mark.parametrize("contact_state", ["exact", "pending", "absent"])
async def test_signed_cross_team_local_recipient_uses_existing_admission(address_collision, surface, contact_state):
    fixture = address_collision
    env = fixture.env
    alice, bob = env.actors["alice"], env.actors["bob"]
    sender_address = "example.test/alice"
    sender_id = await register_global_identity(env, alice, sender_address)
    await env.db.execute(
        """UPDATE {{tables.agents}} SET did_aw=$1,address=$2,identity_scope='global',
           did_aw_verified_key=did_key WHERE agent_id=$3""", sender_id, sender_address, alice.id,
    )
    alice.certificate = _encode_certificate(_make_certificate(
        env.team_sk, env.team_did, alice.did, team_id=TEAM, alias="alice",
        identity_scope="global", member_did_aw=sender_id, member_address=sender_address,
        certificate_id="privacy-alice-global",
    ))
    other_team = "other:example.test"
    await env.db.execute(
        """INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
           VALUES ($1, 'example.test', 'other', $2)""", other_team, env.team_did,
    )
    await env.db.execute("UPDATE {{tables.agents}} SET team_id=$1 WHERE agent_id=$2", other_team, bob.id)
    if contact_state != "absent":
        from aweb.messaging.contacts import add_contact

        await add_contact(
            env.infra, owner_did=bob.did, contact_address=sender_address,
            contact_did_aw=sender_id, binding_controller_did=env.team_did,
            label="Sender", status="active" if contact_state == "exact" else "pending",
        )
    response = await fixture.request(surface, signed_recipient=bob)
    if contact_state == "exact":
        assert response.status_code == 200, response.text
        result = response.json()
        if surface == "mail":
            row = await env.db.fetch_one(
                "SELECT to_did FROM {{tables.messages}} WHERE message_id=$1", UUID(result["message_id"]),
            )
            assert row["to_did"] == bob.did
        else:
            rows = await env.db.fetch_all(
                "SELECT did FROM {{tables.chat_participants}} WHERE session_id=$1", UUID(result["session_id"]),
            )
            assert {row["did"] for row in rows} == {sender_id, bob.did}
    else:
        assert response.status_code == 404, response.text
        assert response.json()["reason"] == "local_recipient_route_missing"
        assert response.json()["retryable"] is False
        for table in ("messages", "chat_sessions"):
            assert await env.db.fetch_val("SELECT count(*) FROM {{tables." + table + "}}") == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["mail", "chat"])
async def test_unrecorded_self_hosted_namespace_keeps_teammate_label(privacy_app, surface, monkeypatch):
    """Post-release regression: a real private team has no public AWID record.

    Real UDP DNS returns NXDOMAIN; the configured AWID and application are
    real. No authority/read result is replaced. The current strict-discovery
    choice refuses this send; retain the expected released teammate delivery.
    """
    import asyncio

    import dns.asyncresolver
    import dns.message
    import dns.rcode
    from aweb.federation.activation import build_federation_authority_activation
    from aweb.messaging.address_auth import namespace_uses_home_registry

    env = privacy_app
    registry = env.app.state.awid_registry_client
    assert await registry.get_namespace_fresh("example.test") is None
    assert not await namespace_uses_home_registry(env.infra, registry, "example.test")
    queries = []

    class NoPublicRecord(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.transport = transport

        def datagram_received(self, data, address):
            request = dns.message.from_wire(data)
            queries.append(str(request.question[0].name))
            response = dns.message.make_response(request)
            response.set_rcode(dns.rcode.NXDOMAIN)
            self.transport.sendto(response.to_wire(), address)

    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        NoPublicRecord, local_addr=("127.0.0.1", 0),
    )
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = ["127.0.0.1"]
    resolver.port = transport.get_extra_info("sockname")[1]
    resolver.timeout = resolver.lifetime = 1
    monkeypatch.setattr(dns.asyncresolver, "default_resolver", resolver)
    activation = build_federation_authority_activation(env.infra, public_origin=env.app.state.public_origin)
    env.app.state.federation_authority = activation
    try:
        payload = ({"to_address": ADDRESS, "subject": "Local teammate", "body": "hello"}
                   if surface == "mail" else
                   {"to_addresses": [ADDRESS], "message": "hello", "leaving": True})
        raw = json.dumps(payload).encode()
        alice = env.actors["alice"]
        response = await env.client.post(
            "/v1/messages" if surface == "mail" else "/v1/chat/sessions", content=raw,
            headers={**_signed_team_headers(alice.sk, alice.did, TEAM, alice.certificate, raw),
                     "Content-Type": "application/json"},
        )
        assert response.status_code == 200, {"response": response.text, "dns_queries": queries}
    finally:
        await activation.aclose()
        transport.close()
