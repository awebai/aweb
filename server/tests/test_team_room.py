"""Team rooms through real HTTP, PostgreSQL, Redis and certificate auth."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4
from types import SimpleNamespace

import pytest
from awid.signing import canonical_json_bytes, sign_message
from test_dashboard_privacy import privacy_app, TEAM  # noqa: F401
from test_messages_http import _signed_team_headers, _make_keypair, _make_certificate, _encode_certificate


def headers(actor, body=b""):
    return {**_signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate, body),
            "Content-Type": "application/json"}


async def metadata(env, actor="alice"):
    response = await env.client.get("/v1/room", headers=headers(env.actors[actor]))
    assert response.status_code == 200, response.text
    return response.json()


def post_payload(env, room, *, actor="alice", text="Team announcement", **changes):
    sender = env.actors[actor]
    payload = dict(type="chat", conversation_id=room["room_id"], message_id=str(uuid4()),
                   from_did=sender.did, to="team-room:" + TEAM, to_did="", subject="Update",
                   body=text, timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    payload["from"] = actor
    payload.update(changes)
    canonical = canonical_json_bytes(payload).decode()
    return dict(room_id=room["room_id"], signed_payload=canonical,
                signature=sign_message(sender.sk, canonical.encode()), signing_key_id=sender.did)


async def post(env, room, *, actor="alice", payload=None, **changes):
    payload = payload or post_payload(env, room, actor=actor, **changes)
    body = json.dumps(payload).encode()
    return await env.client.post("/v1/room/messages", content=body, headers=headers(env.actors[actor], body))


@pytest.mark.asyncio
async def test_room_is_shared_and_history_includes_posts_before_join(privacy_app):
    env = privacy_app
    room = await metadata(env)
    assert room["team_id"] == TEAM
    assert room["confidentiality"] == "server_readable"
    assert room["history_visibility"] == "current_and_future_members"
    payload = post_payload(env, room)
    sent = await post(env, room, payload=payload)
    assert sent.status_code == 200, sent.text
    item = sent.json()
    assert item["signed_payload"] == payload["signed_payload"]
    # A real newly admitted member, created after the post, reads full history.
    sk, _, did = _make_keypair()
    member = uuid4()
    await env.db.execute("INSERT INTO {{tables.agents}} (agent_id,team_id,did_key,alias,identity_scope,inbound_mode) VALUES ($1,$2,$3,'dave','local','open')", member, TEAM, did)
    certificate = _encode_certificate(_make_certificate(env.team_sk, env.team_did, did, team_id=TEAM, alias="dave", identity_scope="local", certificate_id="room-dave"))
    newcomer = SimpleNamespace(sk=sk, did=did, certificate=certificate)
    read = await env.client.get("/v1/room/messages", headers=headers(newcomer))
    assert read.status_code == 200, read.text
    assert [m["message_id"] for m in read.json()["messages"]] == [item["message_id"]]
    assert read.json()["messages"][0]["body"] == "Team announcement"
    exact = await env.client.get("/v1/room/messages/" + item["message_id"], headers=headers(env.actors["bob"]))
    assert exact.json() == item
    assert await env.db.fetch_val("SELECT count(*) FROM {{tables.messages}}") == 0
    assert await env.db.fetch_val("SELECT count(*) FROM {{tables.chat_messages}}") == 0
    assert env.dispatched == []  # Explicit reads; no broadcast or wakes.


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value", [
    ("to", "team-room:other:example.test"), ("conversation_id", str(uuid4())),
    ("from_did", "did:key:wrong"), ("from_stable_id", "did:aw:unverified"),
    ("type", "mail"), ("to_did", "did:key:some-recipient"),
    ("timestamp", (datetime.now(timezone.utc)-timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")),
])
async def test_room_refuses_wrong_signed_bindings(privacy_app, field, value):
    room = await metadata(privacy_app)
    response = await post(privacy_app, room, **{field: value})
    assert response.status_code == 422, response.text
    assert await privacy_app.db.fetch_val("SELECT count(*) FROM {{tables.room_messages}}") == 0


@pytest.mark.asyncio
async def test_room_signature_tampering_and_idempotent_replay(privacy_app):
    env = privacy_app
    room = await metadata(env)
    payload = post_payload(env, room)
    bad = dict(payload, signed_payload=payload["signed_payload"].replace("Team announcement", "Different content"))
    assert (await post(env, room, payload=bad)).status_code == 403
    first = await post(env, room, payload=payload)
    assert first.status_code == 200, first.text
    assert (await post(env, room, payload=payload)).json() == first.json()
    conflict = post_payload(env, room, message_id=first.json()["message_id"], text="Another post")
    assert (await post(env, room, payload=conflict)).status_code == 409
    assert await env.db.fetch_val("SELECT count(*) FROM {{tables.room_messages}}") == 1


@pytest.mark.asyncio
async def test_room_paging_and_foreign_cursor_refusal(privacy_app):
    env = privacy_app
    room = await metadata(env)
    ids = []
    for i in range(3):
        response = await post(env, room, text=str(i))
        assert response.status_code == 200, response.text
        ids.append(response.json()["message_id"])
    first = await env.client.get("/v1/room/messages?limit=2", headers=headers(env.actors["bob"]))
    page = first.json()
    assert [m["message_id"] for m in page["messages"]] == ids[:2]
    assert page["has_more"]
    second = await env.client.get("/v1/room/messages", params={"limit":2, "after":page["next_cursor"]}, headers=headers(env.actors["bob"]))
    assert [m["message_id"] for m in second.json()["messages"]] == ids[2:]
    assert second.json()["has_more"] is False
    invalid = await env.client.get("/v1/room/messages?after=not-a-cursor", headers=headers(env.actors["bob"]))
    assert invalid.status_code == 422


@pytest.mark.asyncio
async def test_room_removed_member_and_e2ee_refuse(privacy_app):
    env = privacy_app
    room = await metadata(env)
    payload = dict(post_payload(env, room), e2ee=True)
    refused = await post(env, room, payload=payload)
    assert refused.status_code == 422
    assert "room_e2ee_unsupported" in refused.text
    await env.db.execute("UPDATE {{tables.agents}} SET status='inactive' WHERE agent_id=$1", env.actors["alice"].id)
    assert (await env.client.get("/v1/room/messages", headers=headers(env.actors["alice"]))).status_code == 403
    assert (await post(env, room)).status_code == 403
    assert (await env.client.get("/v1/room/messages")).status_code == 401


@pytest.mark.asyncio
async def test_room_keeps_adjacent_id_chain(privacy_app):
    from test_id_chain_message_metadata import _bundle
    from awid.id_certificates import encode_id_chain_header
    env = privacy_app
    room = await metadata(env)
    payload = post_payload(env, room)
    body = json.dumps(payload).encode()
    chain = _bundle(env.actors["alice"].did)
    signed_headers = headers(env.actors["alice"], body)
    signed_headers["X-AWID-ID-Chain"] = encode_id_chain_header(chain)
    result = await env.client.post("/v1/room/messages", content=body, headers=signed_headers)
    assert result.status_code == 200, result.text
    assert result.json()["id_chain"] == chain
    assert result.json()["signed_payload"] == payload["signed_payload"]


@pytest.mark.asyncio
async def test_ordinary_chat_refuses_team_room_target(privacy_app):
    env = privacy_app
    room = await metadata(env)
    room_post = post_payload(env, room)
    signed = json.loads(room_post["signed_payload"])
    payload = dict(to_aliases=["bob"], message=signed["body"], session_id=room["room_id"],
                   message_id=signed["message_id"], timestamp=signed["timestamp"], from_did=signed["from_did"],
                   signature=room_post["signature"], signed_payload=room_post["signed_payload"])
    body = json.dumps(payload).encode()
    result = await env.client.post("/v1/chat/sessions", content=body, headers=headers(env.actors["alice"], body))
    assert result.status_code == 422, result.text
    assert await env.db.fetch_val("SELECT count(*) FROM {{tables.chat_messages}}") == 0
