"""A live chat stream delivers every message and read receipt, whatever order
their timestamps and their commits come in.

A message or receipt is stamped by the process that writes it, before its
transaction commits. Two things follow, and each test here produces one of them
deterministically:

- Two writers can commit in the opposite order to their stamps. The earlier
  stamped write is held in an open transaction, exactly as the attachment and
  native-ingress send paths hold it (the same service function, run on a
  transaction through TransactionInfra), while a later stamped write commits
  and is delivered.
- A writer whose clock is behind stamps a time the stream has already passed.
  The clock the send path reads (aweb.messaging.chat.datetime) is set back for
  one request, as it would be on a server process with a slow clock.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest

import aweb.messaging.chat as chat_service
from aweb.db import TransactionInfra
from aweb.events import publish_chat_session_signal
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401  (fixture)
from test_messages_http import _signed_team_headers

# The stream polls at least every 2 s without a wake; anything committed is
# delivered well inside this.
DELIVERY_BOUND_SECONDS = 6
CLOCK_LAG = timedelta(seconds=30)


class _SlowClock(datetime):
    """The clock of a process running CLOCK_LAG behind."""

    @classmethod
    def now(cls, tz=None):
        return datetime.now(tz) - CLOCK_LAG


async def _group_chat(env) -> UUID:
    """A session of alice, bob and carol, opened by alice."""
    response = await _request(env, "alice", "POST", "/v1/chat/sessions", {
        "to_dids": [env.actors["bob"].did, env.actors["carol"].did], "message": "opening",
    })
    assert response.status_code == 200, response.text
    return UUID(response.json()["session_id"])


async def _post_message(env, actor, session_id, body) -> str:
    response = await _request(env, actor, "POST", f"/v1/chat/sessions/{session_id}/messages", {"body": body})
    assert response.status_code == 200, response.text
    return response.json()["message_id"]


async def _post_read(env, actor, session_id, message_id) -> None:
    response = await _request(env, actor, "POST", f"/v1/chat/sessions/{session_id}/read", {
        "message_ids": [message_id],
    })
    assert response.status_code == 200, response.text
    assert response.json()["messages_marked"] == 1


@asynccontextmanager
async def _bob_live_frames(env, session_id, frame_type):
    """Frames of one type from bob's live stream, opened without replay."""
    bob = env.actors["bob"]
    deadline = (datetime.now(timezone.utc) + timedelta(seconds=60)).isoformat()
    async with env.client.stream(
        "GET", f"/v1/chat/sessions/{session_id}/stream", params={"deadline": deadline},
        headers=_signed_team_headers(bob.sk, bob.did, TEAM, bob.certificate), timeout=None,
    ) as stream:
        assert stream.status_code == 200

        async def frames():
            async for line in stream.aiter_lines():
                if line.startswith("data: "):
                    event = json.loads(line[6:])
                    if event.get("type") == frame_type:
                        yield event

        yield frames()


async def _expect_frame(frames, what):
    try:
        async with asyncio.timeout(DELIVERY_BOUND_SECONDS):
            return await anext(frames)
    except TimeoutError:
        pytest.fail(f"{what} never arrived on the live stream")


@pytest.mark.asyncio
async def test_message_committed_after_a_later_stamped_one_is_delivered(privacy_app):  # noqa: F811
    env = privacy_app
    session_id = await _group_chat(env)
    async with _bob_live_frames(env, session_id, "message") as frames:
        async with env.db.transaction() as tx:
            stamped_first = await chat_service.send_in_session(
                TransactionInfra(env.infra, tx),
                session_id=session_id, sender_did=env.actors["alice"].did, body="stamped first, committed second",
            )
            assert stamped_first is not None
            stamped_second = await _post_message(env, "carol", session_id, "stamped second, committed first")
            delivered = await _expect_frame(frames, "the message committed first")
            assert delivered["message_id"] == stamped_second
        await publish_chat_session_signal(env.redis, session_id=str(session_id), signal_type="message")
        late_commit = await _expect_frame(frames, "the message stamped first and committed second")
    assert late_commit["message_id"] == str(stamped_first["message_id"])
    assert late_commit["body"] == "stamped first, committed second"


@pytest.mark.asyncio
async def test_message_stamped_by_a_slow_clock_is_delivered(privacy_app, monkeypatch):  # noqa: F811
    env = privacy_app
    session_id = await _group_chat(env)
    async with _bob_live_frames(env, session_id, "message") as frames:
        on_time = await _post_message(env, "carol", session_id, "stamped on time")
        delivered = await _expect_frame(frames, "the message stamped on time")
        assert delivered["message_id"] == on_time
        with monkeypatch.context() as slow_process:
            slow_process.setattr(chat_service, "datetime", _SlowClock)
            behind = await _post_message(env, "alice", session_id, "stamped by a slow clock")
        late_stamp = await _expect_frame(frames, "the message stamped by a slow clock")
    assert late_stamp["message_id"] == behind
    assert late_stamp["body"] == "stamped by a slow clock"


@pytest.mark.asyncio
async def test_read_receipt_committed_after_a_later_stamped_one_is_delivered(privacy_app):  # noqa: F811
    env = privacy_app
    session_id = await _group_chat(env)
    from_bob = await _post_message(env, "bob", session_id, "read me")
    async with _bob_live_frames(env, session_id, "read_receipt") as frames:
        async with env.db.transaction() as tx:
            stamped_first = await chat_service.mark_messages_read(
                TransactionInfra(env.infra, tx),
                session_id=session_id, participant_did=env.actors["alice"].did, message_ids=[from_bob],
            )
            assert stamped_first["messages_marked"] == 1
            await _post_read(env, "carol", session_id, from_bob)
            delivered = await _expect_frame(frames, "the read receipt committed first")
            assert delivered["reader_alias"] == "carol"
        await publish_chat_session_signal(env.redis, session_id=str(session_id), signal_type="read_receipt")
        late_commit = await _expect_frame(frames, "the read receipt stamped first and committed second")
    assert late_commit["reader_alias"] == "alice"
    assert late_commit["up_to_message_id"] == from_bob


@pytest.mark.asyncio
async def test_read_receipt_stamped_by_a_slow_clock_is_delivered(privacy_app, monkeypatch):  # noqa: F811
    env = privacy_app
    session_id = await _group_chat(env)
    from_bob = await _post_message(env, "bob", session_id, "read me")
    async with _bob_live_frames(env, session_id, "read_receipt") as frames:
        await _post_read(env, "carol", session_id, from_bob)
        delivered = await _expect_frame(frames, "the read receipt stamped on time")
        assert delivered["reader_alias"] == "carol"
        with monkeypatch.context() as slow_process:
            slow_process.setattr(chat_service, "datetime", _SlowClock)
            await _post_read(env, "alice", session_id, from_bob)
        late_stamp = await _expect_frame(frames, "the read receipt stamped by a slow clock")
    assert late_stamp["reader_alias"] == "alice"
    assert late_stamp["up_to_message_id"] == from_bob
