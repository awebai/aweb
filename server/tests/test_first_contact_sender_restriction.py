# ruff: noqa: F811 -- pytest imports the shared real-stack fixtures by name.
"""A host-restricted sender makes first contact only within a relationship.

The serving application's ``first_contact_sender_policy`` marks a sender. For
that sender every first-contact recipient is treated as ``team_and_contacts``:
a current shared team or an exact contact held by the recipient admits it.
Replies in a stored conversation are unchanged. Sends run through the real
HTTP and MCP apps, AWID, PostgreSQL, Redis and a second real server; the
policy is the host's own seam, installed as a host would install it.
"""

from __future__ import annotations

import json
from uuid import uuid4

import pytest

from aweb.mcp.server import create_mcp_app
from aweb.messaging.delivery_policy import SenderRestriction
from messaging_actor_support import add_messaging_contact, admit_privacy_actor, set_messaging_inbound_mode
from test_dashboard_privacy import TEAM, privacy_app as privacy_app
from test_messages_http import _signed_team_headers
from test_same_origin_delivery import (
    foreign_receiver as foreign_receiver,
    same_origin as same_origin,
    same_origin_registry_socket as same_origin_registry_socket,
)

__all__ = ["foreign_receiver", "privacy_app", "same_origin", "same_origin_registry_socket"]

OUTSIDE_TEAM = "outside:example.test"
RESTRICTION = SenderRestriction(
    reason="email_unverified",
    detail="Confirm your email address to message agents outside your teams and contacts.",
)
SENT_EVENTS = {"message.sent", "chat.message_sent"}
EFFECT_TABLES = (
    "messages",
    "chat_messages",
    "conversations",
    "chat_sessions",
    "conversation_participants",
    "chat_participants",
    "message_ingress_receipts",
    "federation_mutation_outbox",
)


def restrict(env, *restricted_dids):
    """Install a host policy restricting ``restricted_dids``; record each call."""
    calls = []

    async def policy(db, sender):
        calls.append(sender.did_key)
        return RESTRICTION if sender.did_key in restricted_dids else None

    env.app.state.first_contact_sender_policy = policy
    return calls


async def effects(db):
    return {
        table: await db.fetch_value("SELECT count(*) FROM {{tables." + table + "}}")
        for table in EFFECT_TABLES
    }


def sent_events(env):
    return [event for event, _context in env.dispatched if event in SENT_EVENTS]


async def post(env, actor, team, path, payload):
    body = json.dumps(payload).encode()
    headers = _signed_team_headers(actor.sk, actor.did, team, actor.certificate, body)
    return await env.client.post(
        path, content=body, headers={**headers, "Content-Type": "application/json"}
    )


async def first_contact(env, sender, team, recipient, kind):
    if kind == "mail":
        return await post(
            env, sender, team, "/v1/messages",
            {"to_did": recipient.did, "subject": "First contact", "body": "hello"},
        )
    return await post(
        env, sender, team, "/v1/chat/sessions",
        {"to_dids": [recipient.did], "message": "hello"},
    )


async def open_recipient(env):
    bob = await admit_privacy_actor(env, "bob", address="example.test/bob")
    await set_messaging_inbound_mode(env, bob.registered, "open")
    return bob


async def stranger(env):
    return await admit_privacy_actor(
        env, "alice", team_id=OUTSIDE_TEAM, address="example.test/alice", new_identity=True
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_restricted_stranger_is_refused_by_open_recipient(privacy_app, kind):
    env = privacy_app
    bob = await open_recipient(env)
    alice = await stranger(env)
    calls = restrict(env, alice.did)
    before = await effects(env.db)
    events_before = sent_events(env)

    response = await first_contact(env, alice, OUTSIDE_TEAM, bob, kind)

    assert response.status_code == 403, response.text
    assert response.json() == {"detail": RESTRICTION.detail, "reason": RESTRICTION.reason}
    assert await effects(env.db) == before
    assert sent_events(env) == events_before
    assert calls == [alice.did]


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_restricted_teammate_is_admitted(privacy_app, kind):
    env = privacy_app
    bob = await open_recipient(env)
    alice = await admit_privacy_actor(env, "alice", address="example.test/alice")
    calls = restrict(env, alice.did)

    response = await first_contact(env, alice, TEAM, bob, kind)

    assert response.status_code == 200, response.text
    assert calls == [alice.did]


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_recipient_contact_admits_restricted_stranger(privacy_app, kind):
    env = privacy_app
    bob = await open_recipient(env)
    alice = await stranger(env)
    await add_messaging_contact(env, bob.registered, address=alice.address)
    calls = restrict(env, alice.did)

    response = await first_contact(env, alice, OUTSIDE_TEAM, bob, kind)

    assert response.status_code == 200, response.text
    assert calls == [alice.did]


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("policy", ["not_installed", "unrestricted"])
async def test_unrestricted_stranger_reaches_open_recipient(privacy_app, kind, policy):
    env = privacy_app
    bob = await open_recipient(env)
    alice = await stranger(env)
    calls = restrict(env) if policy == "unrestricted" else []

    response = await first_contact(env, alice, OUTSIDE_TEAM, bob, kind)

    assert response.status_code == 200, response.text
    assert calls == ([alice.did] if policy == "unrestricted" else [])


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_restricted_sender_replies_to_a_stranger_who_wrote_first(privacy_app, kind):
    env = privacy_app
    bob = await open_recipient(env)
    alice = await stranger(env)
    await set_messaging_inbound_mode(env, alice.registered, "open")
    opened = await first_contact(env, bob, TEAM, alice, kind)
    assert opened.status_code == 200, opened.text
    calls = restrict(env, alice.did)

    if kind == "mail":
        reply = await post(
            env, alice, OUTSIDE_TEAM, "/v1/messages",
            {"conversation_id": opened.json()["conversation_id"], "subject": "Re", "body": "reply"},
        )
    else:
        reply = await post(
            env, alice, OUTSIDE_TEAM,
            f"/v1/chat/sessions/{opened.json()['session_id']}/messages",
            {"body": "reply"},
        )

    assert reply.status_code == 200, reply.text
    assert calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_restricted_sender_meets_a_stricter_recipient_policy_unchanged(privacy_app, kind):
    env = privacy_app
    bob = await admit_privacy_actor(env, "bob", address="example.test/bob")
    await set_messaging_inbound_mode(env, bob.registered, "contacts_only")
    alice = await stranger(env)
    restrict(env, alice.did)

    response = await first_contact(env, alice, OUTSIDE_TEAM, bob, kind)

    assert response.status_code == 403, response.text
    assert response.json()["reason"] == "recipient_policy_rejected"


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_unavailable_policy_refuses_first_contact(privacy_app, kind, caplog):
    env = privacy_app
    bob = await open_recipient(env)
    alice = await stranger(env)

    async def unavailable(db, sender):
        raise RuntimeError("host account store unavailable")

    env.app.state.first_contact_sender_policy = unavailable
    before = await effects(env.db)

    with caplog.at_level("WARNING", logger="aweb.messaging.delivery_policy"):
        response = await first_contact(env, alice, OUTSIDE_TEAM, bob, kind)

    assert response.status_code == 503, response.text
    assert response.json() == {"detail": "Sender policy is unavailable. Try again later."}
    assert await effects(env.db) == before
    assert [
        record.getMessage()
        for record in caplog.records
        if record.name == "aweb.messaging.delivery_policy"
    ] == ["first_contact_sender_policy_unavailable failure_type=RuntimeError"]


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("restricted", [True, False], ids=["restricted", "unrestricted"])
async def test_signed_send_to_open_resident_of_another_team(same_origin, kind, restricted):
    env = same_origin.env
    await same_origin.resident(inbound_mode="open")
    alice = env.actors["alice"]
    calls = restrict(env, *([alice.did] if restricted else []))
    before = await same_origin.effects()

    response, _ = await same_origin.send(kind, "global")

    assert calls == [alice.did]
    if restricted:
        assert response.status_code == 403, response.text
        assert response.json() == {"detail": RESTRICTION.detail, "reason": RESTRICTION.reason}
        assert await same_origin.effects() == before
    else:
        assert response.status_code == 200, response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("restricted", [True, False], ids=["restricted", "unrestricted"])
async def test_first_contact_to_another_server(same_origin, foreign_receiver, kind, restricted):
    env = same_origin.env
    alice = env.actors["alice"]
    calls = restrict(env, *([alice.did] if restricted else []))
    before = await same_origin.effects()
    remote_before = await effects(foreign_receiver.db)

    response, submitted = await same_origin.send(kind, "global")

    assert calls == [alice.did]
    if restricted:
        assert response.status_code == 403, response.text
        assert response.json() == {"detail": RESTRICTION.detail, "reason": RESTRICTION.reason}
        assert foreign_receiver.ingress == []
        assert await same_origin.effects() == before
        assert await effects(foreign_receiver.db) == remote_before
    else:
        assert response.status_code == 200, response.text
        assert foreign_receiver.ingress == ["/v1/federation/messages"]


async def mcp_first_contact(same_origin, kind):
    env = same_origin.env
    mcp = create_mcp_app(
        db_infra=env.infra,
        redis=env.redis,
        registry_client=env.app.state.awid_registry_client,
        federation_authority=env.app.state.federation_authority,
        public_origin=env.app.state.public_origin,
    )
    mount = f"/restriction-mcp-{uuid4().hex[:8]}"
    env.app.mount(mount, mcp)
    await mcp.startup()
    try:
        actor = env.actors["alice"]
        arguments = (
            dict(to=same_origin.target_address, body="First contact", plaintext=True)
            if kind == "mail"
            else dict(to_address=same_origin.target_address, message="First contact", plaintext=True)
        )
        raw = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "send_mail" if kind == "mail" else "chat_send",
                    "arguments": arguments,
                },
            }
        ).encode()
        response = await env.client.post(
            mount + "/",
            content=raw,
            headers={
                **_signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate, raw),
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
        )
        assert response.status_code == 200, response.text
        result = response.json()["result"]
        assert not result.get("isError"), result
        return json.loads(result["content"][0]["text"])
    finally:
        await mcp.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("restricted", [True, False], ids=["restricted", "unrestricted"])
async def test_hosted_mcp_first_contact_to_open_resident(same_origin, kind, restricted):
    env = same_origin.env
    await same_origin.resident(inbound_mode="open")
    alice = env.actors["alice"]
    calls = restrict(env, *([alice.did] if restricted else []))
    before = await same_origin.effects()
    events_before = sent_events(env)

    result = await mcp_first_contact(same_origin, kind)

    assert calls == [alice.did]
    if restricted:
        assert result == {"error": RESTRICTION.detail, "reason": RESTRICTION.reason}
        assert await same_origin.effects() == before
        assert sent_events(env) == events_before
    else:
        assert "error" not in result, result


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_hosted_mcp_first_contact_to_another_server(same_origin, foreign_receiver, kind):
    env = same_origin.env
    alice = env.actors["alice"]
    calls = restrict(env, alice.did)
    before = await same_origin.effects()

    result = await mcp_first_contact(same_origin, kind)

    assert calls == [alice.did]
    assert result == {"error": RESTRICTION.detail, "reason": RESTRICTION.reason}
    assert foreign_receiver.ingress == []
    assert await same_origin.effects() == before
