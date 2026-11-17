"""Handle selection through real mounted MCP, registry, storage and delivery.

Activity-based selection cases characterize existing behavior pending a product
ruling; they do not establish that it is the intended contact contract.
"""

import json
from types import SimpleNamespace
from uuid import UUID

import pytest
import pytest_asyncio
from aweb.mcp.server import create_mcp_app
from identity_binding_support import register_global_identity
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_messages_http import _signed_team_headers

NAMESPACE = "contact_team.test"
LOOKALIKE = "contactXteam.test"


@pytest_asyncio.fixture
async def handle_app(privacy_app):  # noqa: F811 -- imported fixture
    env = privacy_app
    identities = {}

    async def register(alias, namespace):
        actor = env.actors[alias]
        address = f"{namespace}/{alias}"
        stable = await register_global_identity(env, actor, address)
        await env.db.execute(
            """UPDATE {{tables.agents}}
               SET did_aw=$1,address=$2,identity_scope='global',did_aw_verified_key=did_key
               WHERE agent_id=$3""", stable, address, actor.id,
        )
        binding = await env.app.state.awid_registry_client.resolve_address_fresh(namespace, alias)
        assert binding.did_aw == stable
        assert binding.current_did_key == actor.did
        identities[alias] = stable
        return stable

    async def activity(*aliases):
        # Explicit ordering, without sleeps or dependency on wall-clock ties.
        for index, alias in enumerate(aliases):
            await env.db.execute(
                "UPDATE {{tables.workspaces}} SET last_seen_at="
                "TIMESTAMPTZ '2026-01-01T00:00:00Z' + $1 * INTERVAL '1 hour' "
                "WHERE agent_id=$2", index, env.actors[alias].id,
            )

    mcp = create_mcp_app(
        db_infra=env.infra, redis=env.redis,
        registry_client=env.app.state.awid_registry_client,
        public_origin=env.app.state.public_origin,
    )
    env.app.mount("/handle-mcp", mcp)
    await mcp.startup()

    async def call(tool, **arguments):
        raw = json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        }).encode()
        actor = env.actors["alice"]
        response = await env.client.post("/handle-mcp/", content=raw, headers={
            **_signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate, raw),
            "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
        })
        assert response.status_code == 200, response.text
        rpc = response.json()
        assert "error" not in rpc, rpc
        result = rpc["result"]
        assert not result.get("isError"), result
        return json.loads(result["content"][0]["text"])

    async def contact(handle):
        result = await call("add_contact_by_handle", handle=handle)
        assert result["status"] == "pending", result
        return result["contact_id"]

    async def send(contact_id, channel):
        return await call(
            "send_message_to_contact", contact_id=contact_id,
            message="Handle resolution probe", channel=channel,
        )

    async def recipient(result, channel):
        assert "error" not in result, result
        if channel == "mail":
            row = await env.db.fetch_one(
                "SELECT to_did FROM {{tables.messages}} WHERE message_id=$1", UUID(result["message_id"]),
            )
            assert row is not None
            return row["to_did"]
        rows = await env.db.fetch_all(
            "SELECT did FROM {{tables.chat_participants}} WHERE session_id=$1 AND did<>$2",
            UUID(result["session_id"]), env.actors["alice"].did,
        )
        assert len(rows) == 1
        return rows[0]["did"]

    try:
        yield SimpleNamespace(
            env=env, register=register, activity=activity, contact=contact,
            send=send, recipient=recipient, identities=identities,
        )
    finally:
        await mcp.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize("channel", ["mail", "chat"])
@pytest.mark.parametrize("shadow", [False, True], ids=["literal-only", "newer-lookalike"])
async def test_handle_namespace_underscore_is_literal(handle_app, channel, shadow):
    f = handle_app
    expected = await f.register("bob", NAMESPACE)
    if shadow:
        await f.register("carol", LOOKALIKE)
        await f.activity("bob", "carol")
    contact_id = await f.contact("@" + NAMESPACE)
    result = await f.send(contact_id, channel)
    assert await f.recipient(result, channel) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("channel", ["mail", "chat"])
async def test_handle_without_literal_namespace_does_not_deliver_to_lookalike(handle_app, channel):
    f = handle_app
    await f.register("carol", LOOKALIKE)
    contact_id = await f.contact("@" + NAMESPACE)
    result = await f.send(contact_id, channel)
    assert "error" in result, result
    assert await f.env.db.fetch_val("SELECT count(*) FROM {{tables.messages}}") == 0
    assert await f.env.db.fetch_val("SELECT count(*) FROM {{tables.chat_messages}}") == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("channel", ["mail", "chat"])
@pytest.mark.parametrize("named", [False, True], ids=["bare-activity-characterization", "explicit-agent-control"])
async def test_handle_activity_selection_characterization(handle_app, channel, named):
    f = handle_app
    bob = await f.register("bob", NAMESPACE)
    carol = await f.register("carol", NAMESPACE)
    await f.activity("carol", "bob")
    contact_id = await f.contact("@" + NAMESPACE + ("/bob" if named else ""))
    first = await f.recipient(await f.send(contact_id, channel), channel)
    await f.activity("bob", "carol")
    second = await f.recipient(await f.send(contact_id, channel), channel)
    # Observation of main's behavior, kept separate from the wildcard bug:
    # the same saved bare contact chooses a different DID on the second send.
    assert first == bob
    assert second == (bob if named else carol)
