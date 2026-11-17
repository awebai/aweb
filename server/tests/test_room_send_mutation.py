"""Room metering uses the existing send mutation, without session delivery."""

import json

import pytest
from aweb.events import ChatMessageEvent, MessageDeliveredEvent
from aweb.mutation_hooks import _translate
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_team_room import headers, metadata, post, post_payload


def test_translate_room_send_has_no_chat_session_event():
    assert _translate("chat.message_sent", {
        "message_kind": "room", "room_id": "room", "conversation_id": "room",
        "from_agent_id": "sender", "message_id": "post", "team_id": TEAM,
    }) is None


@pytest.mark.parametrize("kind,event_class", [
    ("message.sent", MessageDeliveredEvent), ("chat.message_sent", ChatMessageEvent),
])
def test_translate_existing_sends_unchanged(kind, event_class):
    event = _translate(kind, {
        "from_agent_id": "sender", "to_agent_id": "recipient", "message_id": "message",
        "session_id": "session", "to_aliases": ["bob"], "preview": "hello", "subject": "subject",
    })
    assert isinstance(event, event_class)
    assert event.message_id == "message"
    if kind == "chat.message_sent":
        assert event.session_id == "session"
        assert event.to_aliases == ["bob"]
    else:
        assert event.workspace_id == "recipient"
        assert event.subject == "subject"


@pytest.mark.asyncio
async def test_room_post_emits_one_send_after_commit_no_replay_or_refusal(privacy_app, monkeypatch):  # noqa: F811
    env = privacy_app
    published, signals = [], []

    async def capture_event(_redis, event):
        published.append(event)

    async def capture_signal(_redis, **context):
        signals.append(context)

    monkeypatch.setattr("aweb.mutation_hooks.publish_event", capture_event)
    monkeypatch.setattr("aweb.mutation_hooks.publish_chat_session_signal", capture_signal)
    room = await metadata(env)
    payload = post_payload(env, room)
    first = await post(env, room, payload=payload)
    assert first.status_code == 200, first.text
    assert len(env.dispatched) == 1
    kind, context = env.dispatched[0]
    assert kind == "chat.message_sent"
    assert context == {
        "team_id": TEAM,
        "from_agent_id": str(env.actors["alice"].id),
        "from_did": env.actors["alice"].did,
        "from_did_aw": None,
        "from_alias": "alice",
        "message_id": first.json()["message_id"],
        "conversation_id": room["room_id"],
        "room_id": room["room_id"],
        "message_kind": "room",
        "content_mode": "legacy_plaintext_v1",
    }
    assert not published and not signals
    assert (await post(env, room, payload=payload)).json() == first.json()
    refused = await post(env, room, to="team-room:other:example.test")
    assert refused.status_code == 422, refused.text
    assert len(env.dispatched) == 1
    assert not published and not signals
    assert await env.db.fetch_val("SELECT count(*) FROM {{tables.room_messages}}") == 1
    assert await env.db.fetch_val("SELECT count(*) FROM {{tables.room_post_notices}}") == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["mail", "chat"])
async def test_other_send_mutations_unchanged(privacy_app, surface):  # noqa: F811
    env = privacy_app
    if surface == "mail":
        path = "/v1/messages"
        payload = {"to_alias": "bob", "subject": "subject", "body": "hello"}
        expected = "message.sent"
    else:
        path = "/v1/chat/sessions"
        payload = {"to_aliases": ["bob"], "message": "hello", "leaving": True}
        expected = "chat.message_sent"
    raw = json.dumps(payload).encode()
    response = await env.client.post(path, content=raw, headers=headers(env.actors["alice"], raw))
    assert response.status_code == 200, response.text
    assert len(env.dispatched) == 1
    kind, context = env.dispatched[0]
    assert kind == expected
    assert context["from_agent_id"] == str(env.actors["alice"].id)
    assert context["message_id"] == response.json()["message_id"]
    assert context["team_id"] == TEAM
    assert "room_id" not in context and "message_kind" not in context


@pytest.mark.asyncio
async def test_rolled_back_room_post_emits_no_send(privacy_app, monkeypatch):  # noqa: F811
    env = privacy_app
    room = await metadata(env)

    def fail_before_commit(*_args, **_kwargs):
        raise RuntimeError("injected failure after room insert, before commit")

    monkeypatch.setattr("aweb.messaging.room.record_agent_wake", fail_before_commit)
    response = await post(env, room)
    assert response.status_code == 500, response.text
    assert env.dispatched == []
    assert await env.db.fetch_val("SELECT count(*) FROM {{tables.room_messages}}") == 0
    assert await env.db.fetch_val("SELECT count(*) FROM {{tables.room_post_notices}}") == 0
