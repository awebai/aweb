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
from aweb.federation.delivery import deliver_federated_phase_b
from aweb.mcp.tools import chat as chat_tools
from test_agent_wake_latency import mcp_call, wake_app  # noqa: F401  (fixtures)
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401  (fixture)
from test_federation_activation_delivery import _envelope, _seed_sender_authority, _seed_stored_route
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


def _bob_stream(env, session_id, **params):
    bob = env.actors["bob"]
    deadline = (datetime.now(timezone.utc) + timedelta(seconds=60)).isoformat()
    return env.client.stream(
        "GET", f"/v1/chat/sessions/{session_id}/stream", params={"deadline": deadline, **params},
        headers=_signed_team_headers(bob.sk, bob.did, TEAM, bob.certificate), timeout=None,
    )


@asynccontextmanager
async def _bob_live_frames(env, session_id, *frame_types, **params):
    """Frames of the given types from bob's stream; without params it is live only."""
    async with _bob_stream(env, session_id, **params) as stream:
        assert stream.status_code == 200, await stream.aread()

        async def frames():
            async for line in stream.aiter_lines():
                if line.startswith("data: "):
                    event = json.loads(line[6:])
                    if event.get("type") in frame_types:
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


@pytest.mark.asyncio
async def test_federated_message_committed_after_the_stream_opened_is_delivered(privacy_app):  # noqa: F811
    """Federated delivery stamps with the database clock inside its transaction.

    The delivery is held at its before_commit seam, after the stamp and with the
    session row locked, while bob's stream opens; it commits afterwards.
    """
    env = privacy_app
    bob = env.actors["bob"]
    envelope = _envelope(kind="chat").model_copy(update={
        "target_did_aw": bob.did, "target_current_did_key": bob.did, "body": "stamped before the stream opened",
    })
    token = await _seed_sender_authority(env.db, envelope)
    recipient = dict(await env.db.fetch_one(
        "SELECT agent_id, team_id, did_key, did_aw, address, alias, inbound_mode "
        "FROM {{tables.agents}} WHERE agent_id = $1", bob.id,
    ))
    stored_route = await _seed_stored_route(env.db, envelope, recipient)
    # Bob's first certificate-signed request records the certificate on his
    # agent row, which the held delivery locks; make that request beforehand.
    async with _bob_stream(env, envelope.conversation_id) as first_request:
        assert first_request.status_code == 200
    stamped = asyncio.Event()
    stream_open = asyncio.Event()

    async def hold_commit():
        stamped.set()
        await stream_open.wait()

    delivery = asyncio.create_task(deliver_federated_phase_b(
        env.infra, envelope=envelope, signature="signed-chat", recipient=recipient, authority_token=token,
        stored_route_continuation=True, stored_route_snapshot=stored_route, before_commit=hold_commit,
    ))
    try:
        async with asyncio.timeout(DELIVERY_BOUND_SECONDS):
            await asyncio.wait({asyncio.ensure_future(stamped.wait()), delivery}, return_when=asyncio.FIRST_COMPLETED)
        assert not delivery.done(), delivery.result()
        async with _bob_live_frames(env, envelope.conversation_id, "message") as frames:
            stream_open.set()
            await delivery
            await publish_chat_session_signal(env.redis, session_id=envelope.conversation_id, signal_type="message")
            late_commit = await _expect_frame(frames, "the federated message committed after the stream opened")
    finally:
        stream_open.set()
        await asyncio.gather(delivery, return_exceptions=True)
    assert late_commit["message_id"] == envelope.message_id
    assert late_commit["body"] == "stamped before the stream opened"


@pytest.mark.asyncio
async def test_more_messages_with_one_timestamp_than_a_page_are_all_delivered(privacy_app):  # noqa: F811
    env = privacy_app
    alice = env.actors["alice"]
    session_id = await _group_chat(env)
    burst = [f"burst {n}" for n in range(1, 206)]
    async with _bob_live_frames(env, session_id, "message") as frames:
        await env.db.execute(
            """
            INSERT INTO {{tables.chat_messages}} (session_id, from_agent_id, from_did, from_alias, body, created_at)
            SELECT $1, $2, $3, 'alice', 'burst ' || n, $4 FROM generate_series(1, $5) n
            """,
            session_id, alice.id, alice.did, datetime.now(timezone.utc), len(burst),
        )
        await publish_chat_session_signal(env.redis, session_id=str(session_id), signal_type="message")
        delivered = [
            (await _expect_frame(frames, f"message {n} of {len(burst)} with one timestamp"))["body"]
            for n in range(1, len(burst) + 1)
        ]
    assert delivered == burst


@pytest.mark.asyncio
async def test_frames_carry_one_increasing_seq_across_messages_and_read_receipts(privacy_app):  # noqa: F811
    env = privacy_app
    session_id = await _group_chat(env)
    from_bob = await _post_message(env, "bob", session_id, "read me")
    async with _bob_live_frames(env, session_id, "message", "read_receipt") as frames:
        await _post_message(env, "carol", session_id, "first")
        await _post_read(env, "alice", session_id, from_bob)
        last = await _post_message(env, "carol", session_id, "last")
        seen = []
        while not seen or seen[-1].get("message_id") != last:
            seen.append(await _expect_frame(frames, "a frame up to the last message"))
    assert {frame["type"] for frame in seen} == {"message", "read_receipt"}
    assert ("alice", from_bob) in {(frame.get("reader_alias"), frame.get("up_to_message_id")) for frame in seen}
    assert all(isinstance(frame.get("seq"), int) for frame in seen), seen
    numbers = [frame["seq"] for frame in seen]
    assert numbers == sorted(set(numbers)), numbers


@pytest.mark.asyncio
async def test_after_seq_resumes_exactly_after_a_number(privacy_app):  # noqa: F811
    env = privacy_app
    session_id = await _group_chat(env)
    one = await _post_message(env, "carol", session_id, "one")
    two = await _post_message(env, "carol", session_id, "two")
    async with _bob_live_frames(env, session_id, "message", after_seq=0) as frames:
        replayed = [await _expect_frame(frames, f"replayed message {n}") for n in (1, 2, 3)]
    assert [frame["body"] for frame in replayed] == ["opening", "one", "two"]
    assert [frame["message_id"] for frame in replayed[1:]] == [one, two]

    async with _bob_live_frames(env, session_id, "message", after_seq=replayed[1]["seq"]) as frames:
        resumed = [await _expect_frame(frames, "the message after the resumed number")]
        three = await _post_message(env, "carol", session_id, "three")
        resumed.append(await _expect_frame(frames, "the message sent after the reconnect"))
    assert [frame["message_id"] for frame in resumed] == [two, three]
    assert resumed[0]["seq"] == replayed[2]["seq"] < resumed[1]["seq"]

    history = await _request(env, "bob", "GET", f"/v1/chat/sessions/{session_id}/messages")
    assert history.status_code == 200, history.text
    history_seq = {item["message_id"]: item["seq"] for item in history.json()["messages"]}
    for frame in replayed + resumed:
        assert history_seq[frame["message_id"]] == frame["seq"]


@pytest.mark.asyncio
async def test_after_and_after_seq_together_are_refused(privacy_app):  # noqa: F811
    env = privacy_app
    session_id = await _group_chat(env)
    async with _bob_stream(env, session_id, after=datetime.now(timezone.utc).isoformat(), after_seq=0) as stream:
        assert stream.status_code == 422


@pytest.mark.asyncio
async def test_after_seq_past_the_session_counter_starts_live(privacy_app):  # noqa: F811
    env = privacy_app
    session_id = await _group_chat(env)
    async with _bob_live_frames(env, session_id, "message", after_seq=10**9) as frames:
        sent = await _post_message(env, "carol", session_id, "after an impossible cursor")
        delivered = await _expect_frame(frames, "the message sent after the stream opened")
    assert delivered["message_id"] == sent


@pytest.mark.asyncio
async def test_mcp_wait_returns_a_reply_stamped_before_the_callers_message(wake_app, mcp_call, monkeypatch):  # noqa: F811
    env = wake_app
    session_id = await _group_chat(env)
    waiting = asyncio.Event()
    real_register_waiting = chat_tools.register_waiting

    async def observed_register_waiting(*args, **kwargs):
        waiting.set()
        return await real_register_waiting(*args, **kwargs)

    monkeypatch.setattr(chat_tools, "register_waiting", observed_register_waiting)
    call = asyncio.create_task(mcp_call(
        "alice", "send_chat", conversation_id=str(session_id), message="anyone there?", wait=True, wait_seconds=4,
    ))
    try:
        async with asyncio.timeout(DELIVERY_BOUND_SECONDS):
            await asyncio.wait({asyncio.ensure_future(waiting.wait()), call}, return_when=asyncio.FIRST_COMPLETED)
        assert not call.done(), call.result()
        with monkeypatch.context() as slow_process:
            slow_process.setattr(chat_service, "datetime", _SlowClock)
            reply = await _post_message(env, "bob", session_id, "stamped by a slow clock")
    finally:
        result = await call
    assert [item["message_id"] for item in result["replies"]] == [reply], result
    assert result["timed_out"] is False


@pytest.mark.asyncio
async def test_read_up_to_leaves_unread_a_message_committed_after_the_named_one(privacy_app, monkeypatch):  # noqa: F811
    env = privacy_app
    session_id = await _group_chat(env)
    named = await _post_message(env, "alice", session_id, "named")
    with monkeypatch.context() as slow_process:
        slow_process.setattr(chat_service, "datetime", _SlowClock)
        committed_later = await _post_message(env, "carol", session_id, "stamped earlier, committed later")
    marked = await _request(env, "bob", "POST", f"/v1/chat/sessions/{session_id}/read", {"up_to_message_id": named})
    assert marked.status_code == 200, marked.text
    unread = await _request(env, "bob", "GET", f"/v1/chat/sessions/{session_id}/messages?unread_only=true")
    assert unread.status_code == 200, unread.text
    assert [item["message_id"] for item in unread.json()["messages"]] == [committed_later]
