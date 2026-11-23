"""Saved-contact sends through mounted MCP, real HTTP/AWID, PostgreSQL and Redis.

Identities, membership and address custody go through product routes.
"""

from __future__ import annotations

import json
from uuid import UUID, uuid4

import pytest

from aweb.application_state import application_registry_client
from aweb.federation.activation import build_federation_authority_activation
from aweb.mcp.server import create_mcp_app
from messaging_actor_support import (
    admit_messaging_actor,
    archive_messaging_actor,
    register_messaging_team,
)
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import TEAM, privacy_app as privacy_app
from test_messages_http import _signed_team_headers

__all__ = ["privacy_app"]


@pytest.mark.asyncio
@pytest.mark.parametrize("channel", ["mail", "chat"])
@pytest.mark.parametrize("reassigned", [False, True])
async def test_mounted_mcp_send_to_saved_contact(
    privacy_app, monkeypatch, channel, reassigned
):
    env = privacy_app
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("AWID_ALLOW_INSECURE_DELIVERY_ORIGIN", "1")
    actors = {
        name: await admit_messaging_actor(
            env,
            alias=name,
            team_id=TEAM,
            signing_key=actor.sk,
            address=f"example.test/{name}",
        )
        for name, actor in env.actors.items()
    }
    alice, bob, carol = (actors[name] for name in ("alice", "bob", "carol"))
    origin = str(env.client.base_url).rstrip("/")
    controller_client = env.app.state.awid_registry_client
    await controller_client.update_namespace_delivery_origin(
        "example.test", env.namespace_sk, origin
    )
    async with registry_listener(env) as (registry, registry_origin):
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
                            alice.signing_key,
                            alice.did_key,
                            alice.team_id,
                            alice.certificate,
                            body,
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
                await register_messaging_team(env, team_id=other_team)
                await admit_messaging_actor(
                    env,
                    alias="bob",
                    team_id=other_team,
                    signing_key=bob.signing_key,
                    address=bob.address,
                )
                await archive_messaging_actor(
                    env.db, env.redis, team_id=bob.team_id, agent_id=bob.agent_id,
                    registry_client=application_registry_client(env.app.state),
                )
                await controller_client.reassign_address(
                    "example.test", "bob", carol.stable_id, env.namespace_sk
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
                            f"SELECT count(*) FROM {{{{tables.{table}}}}}"
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
                    f"SELECT * FROM {{{{tables.{table}}}}} WHERE message_id=$1",
                    UUID(sent["message_id"]),
                )
                assert row is not None
                assert row["body"] == message
        finally:
            await mcp.shutdown()
            await authority.aclose()
