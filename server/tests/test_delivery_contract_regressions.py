# ruff: noqa: F811 -- pytest imports the real shared fixture by name.
"""Delivery boundaries through the real apps, keys, registry and databases."""

import json
import asyncio
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

from awid.signing import canonical_json_bytes, sign_message
from aweb.mcp.server import create_mcp_app
from messaging_actor_support import admit_messaging_actor
from test_dashboard_privacy import TEAM, privacy_app as privacy_app
from test_messages_http import _signed_team_headers

__all__ = ["privacy_app"]


async def _send(env, payload):
    actor = env.actors["alice"]
    body = json.dumps(payload).encode()
    return await env.client.post(
        "/v1/messages",
        content=body,
        headers={
            **_signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate, body),
            "Content-Type": "application/json",
        },
    )


async def _self_delete_workspace(env, actor):
    deleted = await env.client.delete(
        f"/v1/workspaces/{actor.workspace}",
        headers=_signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate),
    )
    assert deleted.status_code == 200, deleted.text
    assert deleted.json()["identity_deleted"]


@pytest.mark.asyncio
@pytest.mark.parametrize("selector", ["to_did", "to_stable_id", "to_address"])
async def test_matching_agent_selector_preserves_identity_participant(
    privacy_app, selector
):
    env = privacy_app
    bob = env.actors["bob"]
    if selector == "to_stable_id":
        recipient = await admit_messaging_actor(
            env, alias="bob", team_id=TEAM, signing_key=bob.sk
        )
        assert recipient.agent_id == str(bob.id)
        target = recipient.stable_id
    else:
        target = bob.did if selector == "to_did" else "example.test/bob"
    payload = {
        selector: target,
        "to_agent_id": str(bob.id),
        "body": "matching identity",
    }
    response = await _send(env, payload)
    assert response.status_code == 200, response.text
    participant = await env.db.fetch_one(
        "SELECT agent_id FROM {{tables.conversation_participants}} WHERE conversation_id=$1 AND did=$2",
        UUID(response.json()["conversation_id"]),
        target if selector != "to_address" else bob.did,
    )
    assert participant is not None and participant["agent_id"] is None
    mismatch = await _send(env, {**payload, "to_agent_id": str(env.actors["carol"].id)})
    assert mismatch.status_code == 422, mismatch.text
    assert mismatch.json()["detail"].endswith("Check the recipient and try again.")
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.messages}}") == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "resolved,supplied",
    [
        ("to_stable_id", "to_did"),
        ("to_stable_id", "to_alias"),
        ("to_did", "to_alias"),
        ("to_address", "to_alias"),
        ("to_address", "to_stable_id"),
        ("to_address", "to_did"),
        ("to_agent_id", "to_alias"),
    ],
)
async def test_mail_selector_disagreement_is_actionable_without_affecting_matching_send(
    privacy_app,
    resolved,
    supplied,
):
    env = privacy_app
    refs = {}
    for name in ("bob", "carol"):
        actor = env.actors[name]
        recipient = await admit_messaging_actor(
            env, alias=name, team_id=TEAM, signing_key=actor.sk
        )
        assert recipient.agent_id == str(actor.id)
        refs[name] = dict(
            to_agent_id=str(actor.id),
            to_alias=name,
            to_did=actor.did,
            to_stable_id=recipient.stable_id,
            to_address="example.test/" + name,
        )
    matching = {
        resolved: refs["bob"][resolved],
        supplied: refs["bob"][supplied],
        "body": "Matching selector neighbour",
    }
    sent = await _send(env, matching)
    assert sent.status_code == 200, sent.text
    refused = await _send(env, {**matching, supplied: refs["carol"][supplied]})
    assert refused.status_code == 422, refused.text
    assert refused.json()["detail"] == (
        f"{supplied} must match the {resolved} recipient. Check the recipient and try again."
    )
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.messages}}") == 1
    assert (
        await env.db.fetch_value("SELECT count(*) FROM {{tables.conversations}}") == 1
    )


@pytest.mark.asyncio
async def test_mail_without_recipient_names_a_recovery_action(privacy_app):
    env = privacy_app
    refused = await _send(env, {"body": "No selected recipient"})
    assert refused.status_code == 422, refused.text
    assert refused.json()["detail"] == (
        "Must provide to_did, to_address, to_agent_id, or to_alias. Choose a recipient and retry."
    )
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.messages}}") == 0
    assert (
        await env.db.fetch_value("SELECT count(*) FROM {{tables.conversations}}") == 0
    )


@pytest.mark.asyncio
async def test_mail_continuation_mismatch_explains_how_to_keep_or_change_the_thread(
    privacy_app,
):
    env = privacy_app
    first = await _send(env, {"to_did": env.actors["bob"].did, "body": "First message"})
    assert first.status_code == 200, first.text
    conversation_id = first.json()["conversation_id"]
    refused = await _send(
        env,
        {
            "conversation_id": conversation_id,
            "to_did": env.actors["carol"].did,
            "body": "Conflicting thread recipient",
        },
    )
    assert refused.status_code == 409, refused.text
    assert refused.json()["detail"] == (
        "conversation_id recipient does not match the requested recipient. Use the stored recipient or start a new conversation."
    )
    continued = await _send(
        env, {"conversation_id": conversation_id, "body": "Same participant"}
    )
    assert continued.status_code == 200, continued.text
    assert continued.json()["conversation_id"] == conversation_id
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.messages}}") == 2


@pytest.mark.asyncio
async def test_mail_missing_native_recipient_explains_reconnection_and_keeps_live_neighbour(
    privacy_app,
):
    env = privacy_app
    await _self_delete_workspace(env, env.actors["carol"])
    refused = await _send(
        env, {"to_did": env.actors["carol"].did, "body": "Unavailable identity"}
    )
    assert refused.status_code == 404, refused.text
    assert refused.json()["detail"] == (
        "Recipient name does not identify a current member of the team. Check the name; if the agent exists, ask it to reconnect with a current team certificate."
    )
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.messages}}") == 0
    assert (
        await env.db.fetch_value("SELECT count(*) FROM {{tables.conversations}}") == 0
    )
    live = await _send(env, {"to_did": env.actors["bob"].did, "body": "Live neighbour"})
    assert live.status_code == 200, live.text


@pytest.mark.asyncio
async def test_real_concurrent_mail_collision_keeps_one_message_and_actionable_wire_code(
    privacy_app,
):
    env = privacy_app
    conversation_id = str(uuid4())
    payload = {
        "to_did": env.actors["bob"].did,
        "conversation_id": conversation_id,
        "body": "Concurrent creation",
    }
    tasks = []
    # Both reads finish before either INSERT: PostgreSQL provides the barrier.
    async with env.db.transaction() as blocker:
        await blocker.execute("LOCK TABLE {{tables.conversations}} IN SHARE MODE")
        tasks = [asyncio.create_task(_send(env, payload)) for _ in range(2)]
        try:
            async with asyncio.timeout(5):
                while True:
                    waiting = await env.db.fetch_value(
                        "SELECT count(*) FROM pg_locks WHERE relation='aweb.conversations'::regclass "
                        "AND mode='RowExclusiveLock' AND NOT granted"
                    )
                    if waiting >= 2:
                        break
                    if any(task.done() for task in tasks):
                        raise AssertionError(
                            "Mail request ended before the concurrent INSERT barrier"
                        )
                    await asyncio.sleep(0.01)
        except BaseException:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
    responses = await asyncio.gather(*tasks)
    assert sorted(response.status_code for response in responses) == [200, 409], [
        r.text for r in responses
    ]
    loser = next(response for response in responses if response.status_code == 409)
    assert loser.json() == {
        "detail": "conversation_exists",
        "recovery_action": "Continue the existing conversation or choose a new conversation_id and retry.",
    }
    assert (
        await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.messages}} WHERE conversation_id=$1",
            UUID(conversation_id),
        )
        == 1
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("valid", [True, False])
@pytest.mark.parametrize("recipient_claims", [True, False])
async def test_plaintext_send_verifies_signature_before_any_effect(
    privacy_app, valid, recipient_claims
):
    env = privacy_app
    alice, bob, carol = (env.actors[name] for name in ("alice", "bob", "carol"))
    message_id, conversation_id = str(uuid4()), str(uuid4())
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    signed = {
        "type": "mail",
        "from": "alice",
        "from_did": alice.did,
        "body": "signature-bound",
        "subject": "",
        "message_id": message_id,
        "conversation_id": conversation_id,
        "timestamp": timestamp,
    }
    if recipient_claims:
        signed.update(to=bob.did, to_did=bob.did)
    original = canonical_json_bytes(signed).decode()
    response = await _send(
        env,
        {
            "to_did": bob.did,
            "from_did": alice.did,
            "body": signed["body"],
            "message_id": message_id,
            "conversation_id": conversation_id,
            "timestamp": timestamp,
            "signed_payload": original,
            "signature": sign_message(
                alice.sk if valid else carol.sk, original.encode()
            ),
        },
    )
    if valid:
        assert response.status_code == 200, response.text
        row = await env.db.fetch_one(
            "SELECT signed_payload FROM {{tables.messages}} WHERE message_id=$1",
            UUID(message_id),
        )
        assert row["signed_payload"] == original
    else:
        assert response.status_code == 422, response.text
        assert (
            response.json()["detail"]
            == "The message signature does not verify. Sign the message again with the authenticated sender's key and resend it."
        )
        for table in (
            "messages",
            "conversations",
            "conversation_participants",
            "message_ingress_receipts",
        ):
            assert (
                await env.db.fetch_value(f"SELECT count(*) FROM {{{{tables.{table}}}}}")
                == 0
            )


@pytest.mark.asyncio
async def test_mounted_mcp_mail_reports_the_same_removed_sender_state(privacy_app):
    env = privacy_app
    sent = await _send(env, {"to_alias": "bob", "body": "before sender retirement"})
    assert sent.status_code == 200, sent.text
    await _self_delete_workspace(env, env.actors["alice"])
    bob = env.actors["bob"]
    headers = _signed_team_headers(bob.sk, bob.did, TEAM, bob.certificate)
    inbox = await env.client.get("/v1/messages/inbox", headers=headers)
    assert inbox.status_code == 200, inbox.text
    expected = inbox.json()["messages"][0]["sender_membership"]
    assert expected["state"] == "inactive"
    mcp = create_mcp_app(
        db_infra=env.infra,
        redis=env.redis,
        registry_client=env.app.state.awid_registry_client,
        public_origin=str(env.client.base_url).rstrip("/"),
    )
    env.app.mount("/sender-state-mcp", mcp)
    await mcp.startup()
    try:
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "check_mail",
                    "arguments": {},
                },
            }
        ).encode()
        response = await env.client.post(
            "/sender-state-mcp/",
            content=body,
            headers={
                **_signed_team_headers(bob.sk, bob.did, TEAM, bob.certificate, body),
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
        )
        assert response.status_code == 200, response.text
        tool = response.json()["result"]
        assert not tool.get("isError"), tool
        messages = json.loads(tool["content"][0]["text"])["messages"]
        assert messages[0]["sender_membership"] == expected
    finally:
        await mcp.shutdown()
