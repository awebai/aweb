"""Saved-contact sends through mounted MCP, real HTTP/AWID, PostgreSQL and Redis.

SQL provisions identities only. No authentication, resolver or delivery mocks.
"""

from __future__ import annotations

import json
from uuid import UUID, uuid4

import pytest

from aweb.federation.activation import build_federation_authority_activation
from aweb.mcp.server import create_mcp_app
from identity_binding_support import register_global_identity
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_messages_http import (
    _encode_certificate,
    _make_certificate,
    _signed_team_headers,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("channel", ["mail", "chat"])
@pytest.mark.parametrize("reassigned", [False, True])
async def test_mounted_mcp_send_to_saved_contact(
    privacy_app, monkeypatch, channel, reassigned
):
    env = privacy_app
    alice, bob = env.actors["alice"], env.actors["bob"]
    async with registry_listener(env) as (registry, registry_origin):
        for name, actor in env.actors.items():
            address = f"example.test/{name}"
            stable = await register_global_identity(env, actor, address)
            await env.db.execute(
                """UPDATE {{tables.agents}} SET did_aw=$1, address=$2,
                   identity_scope='global', did_aw_verified_key=did_key WHERE agent_id=$3""",
                stable,
                address,
                actor.id,
            )
            actor.certificate = _encode_certificate(
                _make_certificate(
                    env.team_sk,
                    env.team_did,
                    actor.did,
                    team_id=TEAM,
                    alias=name,
                    identity_scope="global",
                    member_did_aw=stable,
                    member_address=address,
                )
            )
        origin = str(env.client.base_url).rstrip("/")
        await env.registry_db.execute(
            "UPDATE {{tables.dns_namespaces}} SET default_delivery_origin=$1, last_verified_at=clock_timestamp()",
            origin,
        )
        monkeypatch.setenv("APP_ENV", "development")
        monkeypatch.setenv("AWEB_FEDERATION_TEST", "1")
        monkeypatch.setenv("AWEB_FEDERATION_TEST_DEFAULT_REGISTRY", "1")
        monkeypatch.setenv("AWID_REGISTRY_URL", registry_origin)
        authority = build_federation_authority_activation(
            env.infra, public_origin=origin
        )
        mcp = create_mcp_app(
            db_infra=env.infra,
            redis=env.redis,
            registry_client=registry,
            federation_authority=authority,
            public_origin=origin,
        )
        env.app.mount("/contact-send-mcp", mcp)
        await mcp.startup()
        try:

            async def call(name, **arguments):
                body = json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": name, "arguments": arguments},
                    }
                ).encode()
                response = await env.client.post(
                    "/contact-send-mcp/",
                    content=body,
                    headers={
                        **_signed_team_headers(
                            alice.sk, alice.did, TEAM, alice.certificate, body
                        ),
                        "Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream",
                    },
                )
                assert response.status_code == 200, response.text
                result = response.json()
                assert "error" not in result, result
                tool = result["result"]
                assert not tool.get("isError"), tool
                value = json.loads(tool["content"][0]["text"])
                return value

            added = await call("add_contact", address="example.test/bob")
            assert "error" not in added, added
            if reassigned:
                # A valid registry reassignment leaves an old local projection
                # in another team. Contact lookup and send must not resolve the
                # same name under different visibility rules and change identity.
                other_team = f"contact-{uuid4().hex[:12]}:example.test"
                await env.db.execute(
                    "INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key) "
                    "VALUES ($1, 'example.test', $2, $3)",
                    other_team,
                    other_team.split(":", 1)[0],
                    env.team_did,
                )
                await env.db.execute(
                    "UPDATE {{tables.agents}} SET team_id=$1 WHERE agent_id=$2",
                    other_team,
                    bob.id,
                )
                carol_did = await env.db.fetch_value(
                    "SELECT did_aw FROM {{tables.agents}} WHERE agent_id=$1",
                    env.actors["carol"].id,
                )
                await registry.reassign_address(
                    "example.test", "bob", carol_did, env.team_sk
                )
                refused = await call(
                    "send_message_to_contact",
                    contact_id=added["contact_id"],
                    channel=channel,
                    message="must not change identity",
                    subject="saved contact",
                )
                assert refused == {
                    "error": "This address now belongs to a different identity. Check the contact and explicitly bind it again before sending.",
                    "reason": "contact_identity_binding_required",
                }
                for table in ("messages", "chat_messages"):
                    assert (
                        await env.db.fetch_value(
                            "SELECT count(*) FROM {{tables." + table + "}}"
                        )
                        == 0
                    )
                return
            conversation = None
            for message in ("first contact send", "another contact send"):
                sent = await call(
                    "send_message_to_contact",
                    contact_id=added["contact_id"],
                    channel=channel,
                    message=message,
                    subject="saved contact",
                )
                assert "error" not in sent, sent
                current = sent.get("conversation_id") or sent.get("session_id")
                assert current
                if conversation is not None:
                    assert (
                        (current != conversation)
                        if channel == "mail"
                        else (current == conversation)
                    )
                conversation = current
                table = "messages" if channel == "mail" else "chat_messages"
                row = await env.db.fetch_one(
                    "SELECT * FROM {{tables." + table + "}} WHERE message_id=$1",
                    UUID(sent["message_id"]),
                )
                assert row is not None
                assert row["body"] == message
        finally:
            await mcp.shutdown()
            await authority.aclose()
