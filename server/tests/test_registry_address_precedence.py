"""Explicit addresses must select AWID identities, not team display aliases.

The server and AWID apps, database queries, auth and message writes are real.
Disposable identities, membership rows and registry records are provisioned.
The outage case injects an HTTP 503 at the registry transport boundary only.
"""

import json
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from aweb.mcp.server import create_mcp_app
from identity_binding_support import register_global_identity
from starlette.responses import JSONResponse
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_messages_http import (
    _make_keypair,
    _signed_identity_headers,
    _signed_team_headers,
)

ADDRESS = "example.test/bob"


@pytest_asyncio.fixture
async def address_collision(privacy_app):  # noqa: F811 -- imported pytest fixture
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

    mcp = create_mcp_app(
        db_infra=env.infra, redis=env.redis, registry_client=registry,
        public_origin=env.app.state.public_origin,
    )
    env.app.mount("/address-mcp", mcp)
    await mcp.startup()

    identity_sk, _, identity_did = _make_keypair()

    async def request(surface, recipient=ADDRESS, *, identity_only=False):
        actor = env.actors["alice"]
        if surface == "mcp_mail":
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
        raw = json.dumps(payload).encode()
        return await env.client.post(path, content=raw, headers={
            **(_signed_identity_headers(identity_sk, identity_did, "", raw) if identity_only else
               _signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate, raw)),
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        })
    async def send(surface, recipient=ADDRESS):
        response = await request(surface, recipient)
        assert response.status_code == 200, response.text
        result = response.json()
        if surface == "mcp_mail":
            assert "error" not in result, result
            tool = result["result"]
            assert not tool.get("isError"), tool
            result = json.loads(tool["content"][0]["text"])
            assert "error" not in result, result
        return result

    try:
        yield SimpleNamespace(env=env, stable_id=stable_id, send=send, request=request)
    finally:
        await mcp.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["mail", "chat", "mcp_mail"])
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
@pytest.mark.parametrize("surface", ["mail", "chat", "mcp_mail"])
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
@pytest.mark.parametrize("surface", ["mail", "chat", "mcp_mail"])
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
    if surface == "mcp_mail":
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
    if surface == "mcp_mail":
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
async def test_derived_address_refusal_does_not_reveal_other_teams(address_collision, surface, identity_only):
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
    assert occupied.json() == unused.json()
    if surface == "mcp_mail":
        assert occupied.status_code == 200, occupied.text
        result = json.loads(occupied.json()["result"]["content"][0]["text"])
        assert "error" in result and "message_id" not in result, result
    else:
        assert occupied.status_code == 404, occupied.text
        assert "recipient_identity_not_found" in occupied.text
    for table in ("messages", "chat_sessions"):
        row = await env.db.fetch_one("SELECT count(*) AS n FROM {{tables." + table + "}}")
        assert row["n"] == 0
