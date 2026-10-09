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


@pytest.mark.asyncio
async def test_polling_drains_bursts_and_preserves_empty_watermark(privacy_app):
    env = privacy_app
    conversation, ascending = await _conversation(env, 15)
    path = f"/v1/messages/conversations/{conversation}"
    first = await _request(env, "bob", "GET", path + "?order=desc&limit=5")
    watermark = first.json()["after_cursor"]
    assert watermark
    idle = await _request(env, "bob", "GET", path + "?after=" + watermark)
    assert idle.status_code == 200, idle.text
    assert idle.json()["messages"] == []
    assert idle.json()["after_cursor"] == watermark
    assert idle.json()["has_more"] is False
    assert idle.json()["next_cursor"] is None

    # Server acceptance orders these appends independently of client timestamps.
    sends = await asyncio.gather(*[
        _request(env, "alice", "POST", "/v1/messages", {
            "conversation_id": conversation, "body": f"poll burst {i}",
        }) for i in range(5)
    ])
    assert all(r.status_code == 200 for r in sends), [r.text for r in sends]
    seen = []
    for _ in range(3):
        response = await _request(env, "bob", "GET", path + "?limit=2&after=" + watermark)
        assert response.status_code == 200, response.text
        page = response.json()
        seen.extend(page["messages"])
        assert page["after_cursor"] != watermark
        watermark = page["after_cursor"]
        if page["has_more"]:
            assert page["next_cursor"] == watermark
        else:
            assert page["next_cursor"] is None
    assert [m["message_id"] for m in seen] == [m["message_id"] for m in sorted(seen, key=lambda m: (m["created_at"], m["message_id"]))]
    assert {m["message_id"] for m in seen} == {r.json()["message_id"] for r in sends}
    assert len(seen) == 5
    idle = await _request(env, "alice", "GET", path + "?after=" + watermark)
    assert idle.json()["messages"] == []
    assert idle.json()["after_cursor"] == watermark
    denied = await _request(env, "carol", "GET", path + "?after=" + watermark)
    assert denied.status_code == 403
    assert all(m["message_id"] not in ascending for m in seen)
    read_state = await env.db.fetch_all(
        "SELECT read_at FROM {{tables.messages}} WHERE conversation_id=$1", UUID(conversation),
    )
    assert all(row["read_at"] is None for row in read_state)


@pytest.mark.asyncio
async def test_cursor_validation_and_conversation_scope(privacy_app):
    env = privacy_app
    conversation, _ = await _conversation(env, 3)
    path = f"/v1/messages/conversations/{conversation}"
    first = await _request(env, "bob", "GET", path + "?order=desc&limit=1")
    cursor = first.json()["next_cursor"]
    assert cursor
    bad_values = [
        "", "not-json", "x" * 8193, encode_cursor({}),
        encode_cursor({"created_at": "2025-01-01T00:00:00+00:00", "message_id": str(uuid4())}),
    ]
    valid_fields = {
        "kind": "mail_conversation", "conversation_id": conversation, "order": "desc",
        "created_at": "2025-01-01T00:00:00+00:00", "message_id": str(uuid4()),
    }
    for field, value in [
        ("conversation_id", str(uuid4())), ("order", "asc"), ("kind", "inbox"),
        ("created_at", "2025-01-01"), ("created_at", []), ("created_at", "bogus"),
        ("message_id", []), ("message_id", "bogus"),
        ("created_at", "0001-01-01T00:00:00+23:59"),
    ]:
        bad_values.append(encode_cursor({**valid_fields, field: value}))
    for bad in bad_values:
        response = await _request(env, "bob", "GET", path + "?order=desc&cursor=" + bad)
        assert response.status_code == 422, response.text
        assert response.json()["detail"] == "Invalid mail conversation cursor"
    for query in [
        "order=sideways", "limit=0", "limit=501", "cursor=" + cursor,
        "order=desc&after=" + cursor, "cursor=" + cursor + "&after=" + cursor,
    ]:
        response = await _request(env, "bob", "GET", path + "?" + query)
        assert response.status_code == 422, (query, response.text)

    # Same valid actor and both conversations: mismatch is still refused.
    sent = await _request(env, "alice", "POST", "/v1/messages", {
        "to_did": env.actors["carol"].did, "body": "other conversation",
    })
    other = sent.json()["conversation_id"]
    response = await _request(env, "alice", "GET", f"/v1/messages/conversations/{other}?order=desc&cursor={cursor}")
    assert response.status_code == 422, response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1, 7, 500])
async def test_exact_full_page_is_complete_and_forward_poll_handles_ties(privacy_app, count):
    env = privacy_app
    conversation, ascending = await _conversation(env, count)
    path = f"/v1/messages/conversations/{conversation}"
    full = await _request(env, "bob", "GET", path + f"?order=desc&limit={count}")
    assert full.status_code == 200, full.text
    assert [m["message_id"] for m in full.json()["messages"]] == ascending[::-1]
    assert full.json()["has_more"] is False
    assert full.json()["next_cursor"] is None
    assert full.json()["after_cursor"]
    # Even a drained page anchors at its newest row, not its last DESC row.
    idle = await _request(env, "bob", "GET", path + "?after=" + full.json()["after_cursor"])
    assert idle.status_code == 200, idle.text
    assert idle.json()["messages"] == []
    assert idle.json()["after_cursor"] == full.json()["after_cursor"]
    # Starting at the oldest row and moving forward crosses identical times.
    oldest = await _request(env, "bob", "GET", path + "?limit=1")
    watermark = oldest.json()["after_cursor"]
    seen = [oldest.json()["messages"][0]["message_id"]]
    while True:
        page = (await _request(env, "bob", "GET", path + "?limit=113&after=" + watermark)).json()
        seen.extend(m["message_id"] for m in page["messages"])
        watermark = page["after_cursor"]
        if not page["has_more"]:
            break
    assert seen == ascending


@pytest.mark.asyncio
async def test_pagination_keeps_encrypted_projection_and_public_dashboard_isolation(privacy_app):
    from test_dashboard import _make_jwt

    env = privacy_app
    conversation, ascending = await _conversation(env, 2)
    encrypted_id = ascending[-1]
    await env.db.execute(
        """UPDATE {{tables.messages}} SET subject='', body='', content_mode='encrypted_v2',
        message_version=2, encrypted_envelope='{"ciphertext":"opaque"}',
        encrypted_ciphertext='opaque', encrypted_key_wraps='[]',
        encrypted_ciphertext_hash='sha256:test', encrypted_ciphertext_size=6,
        encrypted_key_wraps_hash='sha256:test', encrypted_inner_header_hash='sha256:test',
        encrypted_suite='test', encrypted_signing_key_id='test', signed_envelope_hash='sha256:test'
        WHERE message_id=$1""", UUID(encrypted_id),
    )
    path = f"/v1/messages/conversations/{conversation}?order=desc&limit=1"
    for actor in ("alice", "bob"):
        response = await _request(env, actor, "GET", path)
        assert response.status_code == 200, response.text
        page = response.json()
        row = page["messages"][0]
        assert row["message_id"] == encrypted_id
        assert row["encrypted_envelope"] == {"ciphertext": "opaque"}
        assert "subject" not in row and "body" not in row
        cursor = page["next_cursor"]
        next_page = await _request(env, actor, "GET", path + "&cursor=" + cursor)
        assert next_page.json()["messages"][0]["content_mode"] == "legacy_plaintext_v1"
    for headers in ({}, {"X-Dashboard-Token": _make_jwt([TEAM])}):
        response = await env.client.get(path + "&cursor=" + cursor, headers=headers)
        assert response.status_code == 401
        assert "opaque" not in response.text
    denied = await _request(env, "carol", "GET", path + "&cursor=" + cursor)
    assert denied.status_code == 403
    assert "opaque" not in denied.text

    # A legitimate but empty conversation still has no invented message cursor.
    await env.db.execute("DELETE FROM {{tables.messages}} WHERE conversation_id=$1", UUID(conversation))
    empty = await _request(env, "alice", "GET", path)
    assert empty.json() == {"messages": [], "has_more": False, "next_cursor": None, "after_cursor": None}


@pytest.mark.asyncio
async def test_direct_handler_old_arguments_keep_native_defaults(privacy_app):
    from starlette.requests import Request

    from aweb.identity_auth_deps import MessagingAuth
    from aweb.routes.messages import get_mail_conversation

    env = privacy_app
    conversation, ascending = await _conversation(env, 3)
    actor = env.actors["bob"]
    # Embedded hosts pass the authenticated identity and DB explicitly and omit
    # new optional query fields. FastAPI does not resolve defaults on this path.
    result = await get_mail_conversation(
        Request({"type": "http", "app": env.app}),
        conversation_id=conversation, db=env.infra, limit=2,
        auth=MessagingAuth(did_key=actor.did, did_aw=None, address=None, team_id=TEAM, alias="bob", agent_id=str(actor.id)),
    )
    assert [m.message_id for m in result.messages] == ascending[:2]
    assert result.has_more is True
    assert result.next_cursor
    assert result.after_cursor
