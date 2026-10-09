"""Conversation pages through real apps/auth, PostgreSQL, Redis and HTTP."""

import asyncio
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest

from awid.pagination import encode_cursor
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401


async def _conversation(env, count=507):
    sent = await _request(env, "alice", "POST", "/v1/messages", {
        "to_did": env.actors["bob"].did, "body": "initial",
    })
    assert sent.status_code == 200, sent.text
    conversation = sent.json()["conversation_id"]
    initial = sent.json()["message_id"]
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    await env.db.execute(
        "UPDATE {{tables.messages}} SET created_at=$2 WHERE message_id=$1",
        UUID(initial), base,
    )
    # Tied timestamps deliberately cross page boundaries. Insertion order and
    # message IDs disagree so a timestamp-only cursor cannot accidentally pass.
    rows = [(str(uuid4()), base + timedelta(seconds=i // 7 + 1)) for i in range(count - 1)]
    for message_id, created_at in rows:
        await env.db.execute(
            """INSERT INTO {{tables.messages}}
            (message_id, conversation_id, team_id, from_did, to_did,
             from_alias, to_alias, subject, body, created_at)
            VALUES ($1,$2,$3,$4,$5,'alice','bob','history',$6,$7)""",
            UUID(message_id), UUID(conversation), TEAM,
            env.actors["alice"].did, env.actors["bob"].did, message_id, created_at,
        )
    expected = [item[0] for item in sorted([(initial, base), *rows], key=lambda item: (item[1], item[0]))]
    return conversation, expected


@pytest.mark.asyncio
async def test_newest_pages_over_500_with_appends_and_timestamp_ties(privacy_app):
    env = privacy_app
    conversation, ascending = await _conversation(env)
    path = f"/v1/messages/conversations/{conversation}"
    first = await _request(env, "bob", "GET", path + "?order=desc&limit=200")
    assert first.status_code == 200, first.text
    page = first.json()
    assert [m["message_id"] for m in page["messages"]] == ascending[::-1][:200]
    assert page["has_more"] and page["next_cursor"]
    seen = [m["message_id"] for m in page["messages"]]

    # Real concurrent sends after opening history must neither displace nor
    # duplicate older rows when the reader continues backwards.
    appends = await asyncio.gather(*[
        _request(env, "alice", "POST", "/v1/messages", {
            "conversation_id": conversation, "body": f"concurrent {i}",
        }) for i in range(3)
    ])
    assert all(r.status_code == 200 for r in appends), [r.text for r in appends]
    while page["has_more"]:
        response = await _request(env, "bob", "GET", path + "?order=desc&limit=113&cursor=" + page["next_cursor"])
        assert response.status_code == 200, response.text
        page = response.json()
        seen.extend(m["message_id"] for m in page["messages"])
    assert page["next_cursor"] is None
    assert seen == ascending[::-1]
    latest = await _request(env, "alice", "GET", path + "?order=desc&limit=3")
    assert {m["message_id"] for m in latest.json()["messages"]} == {r.json()["message_id"] for r in appends}


@pytest.mark.asyncio
async def test_legacy_default_order_and_500_limit_remain_pageable(privacy_app):
    env = privacy_app
    conversation, ascending = await _conversation(env)
    path = f"/v1/messages/conversations/{conversation}"
    default = await _request(env, "alice", "GET", path)
    assert default.status_code == 200, default.text
    assert [m["message_id"] for m in default.json()["messages"]] == ascending[:200]
    response = await _request(env, "alice", "GET", path + "?limit=500")
    assert response.status_code == 200, response.text
    page = response.json()
    assert [m["message_id"] for m in page["messages"]] == ascending[:500]
    assert page["has_more"] and page["next_cursor"]
    last = await _request(env, "alice", "GET", path + "?cursor=" + page["next_cursor"])
    assert [m["message_id"] for m in last.json()["messages"]] == ascending[500:]
    assert last.json()["has_more"] is False
    assert last.json()["next_cursor"] is None


@pytest.mark.asyncio
async def test_conversation_cursor_does_not_authorize_nonparticipant(privacy_app):
    env = privacy_app
    conversation, _ = await _conversation(env, 3)
    path = f"/v1/messages/conversations/{conversation}"
    page = await _request(env, "alice", "GET", path + "?order=desc&limit=1")
    cursor = page.json()["next_cursor"]
    assert cursor
    denied = await _request(env, "carol", "GET", path + "?order=desc&cursor=" + cursor)
    assert denied.status_code == 403, denied.text
    assert "history" not in denied.text
    anonymous = await env.client.get(path + "?order=desc&cursor=" + cursor)
    assert anonymous.status_code == 401
