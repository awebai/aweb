"""Participant Messages API against real auth, AWID, PostgreSQL and HTTP."""
from datetime import datetime, timezone
import json
from urllib.parse import urlencode
from uuid import UUID, uuid4

import pytest
import pytest_asyncio

from identity_binding_support import register_global_identity
from test_dashboard_privacy import TEAM, _request as _key_request, privacy_app  # noqa: F401
from test_messages_http import _make_keypair, _signed_identity_headers


async def _request(env, actor, method, path, body=None):
    if actor != "bob":
        return await _key_request(env, actor, method, path, body)
    # The dashboard acts as ONE proven global human, not a selected team actor.
    identity = env.actors[actor]
    content = json.dumps(body).encode() if body is not None else b""
    headers = _signed_identity_headers(identity.sk, identity.did, env.human_did, content)
    headers["Content-Type"] = "application/json"
    return await env.client.request(method, path, content=content, headers=headers)


@pytest_asyncio.fixture
async def human_messages(privacy_app):
    env = privacy_app
    human = env.actors["bob"]
    stable = await register_global_identity(env, human)
    await env.db.execute(
        "UPDATE {{tables.agents}} SET did_aw=$1,identity_scope='global',agent_type='human' WHERE agent_id=$2",
        stable, human.id,
    )
    env.human_did = stable
    admitted = await _request(env, "bob", "GET", "/v1/messages/inbox")
    assert admitted.status_code == 200, admitted.text
    return env


async def mail(env, sender="alice", **values):
    body = {"to_did": env.actors["bob"].did, "subject": "First subject", "body": "incoming", **values}
    if "conversation_id" in values:
        body.pop("to_did")
    response = await _request(env, sender, "POST", "/v1/messages", body)
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.asyncio
async def test_bound_details_and_whole_thread_batch_unread_across_teams(human_messages):
    env = human_messages
    other_team = f"other-{uuid4().hex[:12]}:example.test"
    await env.db.execute("INSERT INTO {{tables.teams}} (team_id,namespace,team_name,team_did_key) VALUES ($1,'example.test','other',$2)", other_team, env.team_did)
    await env.db.execute("UPDATE {{tables.agents}} SET team_id=$1,alias='alice' WHERE agent_id=$2", other_team, env.actors["carol"].id)
    first = await mail(env)
    await mail(env, conversation_id=first["conversation_id"], subject="Later subject")
    separate = await mail(env)
    await mail(env, "carol")
    await mail(env, "bob", conversation_id=first["conversation_id"], body="outgoing")
    self_sent = await mail(env, "bob")
    # A stored multi-peer thread contributes its incoming count under each peer.
    await env.db.execute(
        "INSERT INTO {{tables.conversation_participants}} (conversation_id,did,agent_id,alias,transport_hint) VALUES ($1,$2,$3,'alice','local')",
        UUID(first["conversation_id"]), env.actors["carol"].did, env.actors["carol"].id,
    )
    # Settings changes never outrank actual message activity.
    await env.db.execute("UPDATE {{tables.conversations}} SET updated_at=NOW()+INTERVAL '1 day' WHERE conversation_id=$1", UUID(separate["conversation_id"]))
    read_before = await env.db.fetch_all("SELECT message_id,read_at FROM {{tables.messages}} ORDER BY message_id")
    page = await _request(env, "bob", "GET", "/v1/conversations?" + urlencode({
        "conversation_type": "mail", "participant_did": env.actors["alice"].did, "limit": 1,
    }))
    assert page.status_code == 200, page.text
    item = page.json()["conversations"][0]
    assert item["conversation_id"] == first["conversation_id"]
    assert item["title"] == "First subject"
    assert item["unread_count"] == 2
    details = {entry["participant_ref"]["did"]: entry for entry in item["participant_details"]}
    for who in ("alice", "carol"):
        assert details[env.actors[who].did] == {
            "participant_ref": {"kind": "native", "did": env.actors[who].did}, "alias": "alice",
            "address": "example.test/alice" if who == "alice" else None,
        }
    _, _, unseen = _make_keypair()
    peers = [env.actors["alice"].did, env.actors["carol"].did, unseen, env.human_did, env.actors["alice"].did]
    path = "/v1/conversations/unread-counts?" + urlencode({"conversation_type": "mail", "participant_did": peers}, doseq=True)
    summary = await _request(env, "bob", "GET", path)
    assert summary.status_code == 200, summary.text
    assert summary.json() == {"counts": [
        {"participant_did": peers[0], "unread_count": 3},
        {"participant_did": peers[1], "unread_count": 3},
        {"participant_did": unseen, "unread_count": 0},
        {"participant_did": env.human_did, "unread_count": 4},
    ]}
    assert read_before == await env.db.fetch_all("SELECT message_id,read_at FROM {{tables.messages}} ORDER BY message_id")
    # A displayed incoming ID may be acknowledged; other incoming messages remain.
    ack = await _request(env, "bob", "POST", f"/v1/messages/{first['message_id']}/ack")
    assert ack.status_code == 200, ack.text
    summary = await _request(env, "bob", "GET", path)
    assert summary.json()["counts"][0]["unread_count"] == 2
    assert summary.json()["counts"][1]["unread_count"] == 2
    self_page = await _request(env, "bob", "GET", "/v1/conversations?conversation_type=mail")
    own = next(row for row in self_page.json()["conversations"] if row["conversation_id"] == self_sent["conversation_id"])
    assert own["unread_count"] == 0
    # A roster peer is not an authorization parameter: another identity sees only its inbox.
    foreign = await _request(env, "carol", "GET", path)
    assert foreign.status_code == 200, foreign.text
    assert all(row["unread_count"] == 0 for row in foreign.json()["counts"])


@pytest.mark.asyncio
@pytest.mark.parametrize("mixed", [False, True])
async def test_equal_time_conversations_page_without_gaps(human_messages, mixed):
    env = human_messages
    expected = set()
    for _ in range(4):
        sent = await mail(env)
        expected.add(("mail", sent["conversation_id"], None))
    boundary = datetime.now(timezone.utc)
    await env.db.execute("UPDATE {{tables.messages}} SET created_at=$1", boundary)
    if mixed:
        legacy = uuid4()
        await env.db.execute(
            "INSERT INTO {{tables.messages}} (message_id,from_did,to_did,from_alias,to_alias,subject,body,created_at) VALUES ($1,$2,$3,'alice','bob','Legacy','legacy',$4)",
            legacy, env.actors["alice"].did, env.human_did, boundary,
        )
        expected.add(("mail", None, str(legacy)))
        session = uuid4()
        await env.db.execute("INSERT INTO {{tables.chat_sessions}} (session_id,team_id,created_by) VALUES ($1,$2,$3)", session, TEAM, env.actors["alice"].did)
        for alias, did in (("alice", env.actors["alice"].did), ("bob", env.human_did)):
            await env.db.execute("INSERT INTO {{tables.chat_participants}} (session_id,did,alias) VALUES ($1,$2,$3)", session, did, alias)
        await env.db.execute("INSERT INTO {{tables.chat_messages}} (session_id,from_did,from_alias,body,created_at) VALUES ($1,$2,'alice','chat',$3)", session, env.actors["alice"].did, boundary)
        expected.add(("chat", str(session), None))
    seen = []
    cursor = None
    cursors = set()
    for _ in range(len(expected) + 1):
        params = {"limit": 2}
        if not mixed:
            params["conversation_type"] = "mail"
        if cursor:
            params["cursor"] = cursor
        response = await _request(env, "bob", "GET", "/v1/conversations?" + urlencode(params))
        assert response.status_code == 200, response.text
        data = response.json()
        for row in data["conversations"]:
            assert row["participant_details"]
            if row["legacy_message_id"]:
                assert row["conversation_id"] is None
                assert row["status"] == "legacy"
        seen.extend((row["conversation_type"], row["conversation_id"], row["legacy_message_id"]) for row in data["conversations"])
        cursor = data["next_cursor"]
        if cursor is None:
            break
        assert cursor not in cursors
        cursors.add(cursor)
    assert len(seen) == len(set(seen)) == len(expected)
    assert set(seen) == expected
    # A filter or caller change starts a new traversal, never reuses a boundary.
    changed = await _request(env, "bob", "GET", "/v1/conversations?" + urlencode({"cursor": next(iter(cursors)), "participant_did": env.actors["alice"].did}))
    assert changed.status_code == 400, changed.text
    changed_actor = await _request(env, "alice", "GET", "/v1/conversations?" + urlencode({"cursor": next(iter(cursors)), **({"conversation_type": "mail"} if not mixed else {})}))
    assert changed_actor.status_code == 400, changed_actor.text


@pytest.mark.asyncio
async def test_old_timestamp_cursor_refuses_with_restart_instruction(human_messages):
    response = await _request(human_messages, "bob", "GET", "/v1/conversations?cursor=2026-10-31T00:00:00Z")
    assert response.status_code == 400, response.text
    assert "first page" in response.json()["detail"]


@pytest.mark.asyncio
async def test_unread_batch_is_bounded_and_does_not_accept_aliases(human_messages):
    env = human_messages
    for query in ("", "participant_did=alice", "participant_did=" + env.actors["alice"].did + "&conversation_type=chat",
                  urlencode({"participant_did": [env.actors["alice"].did] * 101}, doseq=True)):
        response = await _request(env, "bob", "GET", "/v1/conversations/unread-counts?" + query)
        assert response.status_code == 422, response.text
    response = await _request(env, "bob", "GET", "/v1/conversations/unread-counts?" + urlencode({"participant_did": [f"did:aw:peer-{i}" for i in range(100)]}, doseq=True))
    assert response.status_code == 200, response.text
    assert len(response.json()["counts"]) == 100
    assert all(row["unread_count"] == 0 for row in response.json()["counts"])
