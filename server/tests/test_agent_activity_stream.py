"""Agent activity frames for one chat session stream (docs/agent-activity.md, Delivery).

The projection is driven with relayed values exactly as the relay script
stores and publishes them; the ordering cases use the real relay and a real
Redis subscription.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from uuid import uuid4

import pytest
import pytest_asyncio
from redis.asyncio import Redis

from aweb.agent_activity import relay_activity
from aweb.messaging.activity_stream import SessionActivity

SESSION = "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b"
OTHER_SESSION = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
T = "2026-10-16T16:20:00Z"


def _event(*, turn_id, seq, phase="tool", session_id=SESSION, **changes):
    event = {
        "v": 1,
        "type": "agent_activity",
        "from_did": "did:key:z6MkAgent",
        "team_id": "default:acme.aweb.ai",
        "session_id": session_id,
        "turn_id": turn_id,
        "seq": seq,
        "phase": phase,
        "timestamp": T,
        "expires_at": "2026-10-16T16:21:00Z",
    }
    if phase == "tool":
        event.update(tool="Bash", summary="Running pytest")
    event.update(changes)
    return event


def _relayed(agent_id, rev, event):
    # The shape the relay script stores and publishes.
    return json.dumps({
        "rev": rev, "agent_id": agent_id, "alias": "bob",
        "signed_payload": f"payload-{rev}", "signature": f"signature-{rev}", "event": event,
    })


def _frame(frame):
    assert frame is not None
    event_line, data_line, blank, end = frame.split("\n")
    assert (event_line, blank, end) == ("event: agent_activity", "", "")
    assert data_line.startswith("data: ")
    return json.loads(data_line[len("data: "):])


AGENT = str(uuid4())


def _projection():
    return SessionActivity(SESSION, {AGENT: "bob"})


def test_same_session_event_is_the_full_signed_frame():
    frame = _frame(_projection().accept(_relayed(AGENT, 1, _event(turn_id="A", seq=1))))

    assert frame == {
        "agent": "bob",
        "signed_payload": "payload-1",
        "signature": "signature-1",
        "from_did": "did:key:z6MkAgent",
        "phase": "tool",
        "tool": "Bash",
        "summary": "Running pytest",
        "turn_id": "A",
        "seq": 1,
        "expires_at": "2026-10-16T16:21:00Z",
    }


@pytest.mark.parametrize("session_id", [OTHER_SESSION, None])
def test_work_elsewhere_reveals_only_that_the_agent_is_busy(session_id):
    frame = _frame(_projection().accept(_relayed(AGENT, 1, _event(turn_id="A", seq=1, session_id=session_id))))

    assert frame == {"agent": "bob", "phase": "busy_elsewhere", "expires_at": "2026-10-16T16:21:00Z"}


def test_end_of_a_turn_elsewhere_clears_without_details():
    projection = _projection()
    projection.accept(_relayed(AGENT, 1, _event(turn_id="A", seq=1, session_id=OTHER_SESSION)))

    frame = _frame(projection.accept(_relayed(AGENT, 2, _event(turn_id="A", seq=2, phase="turn_ended", session_id=OTHER_SESSION))))

    assert frame == {"agent": "bob", "phase": "cleared"}


def test_equal_second_events_from_before_the_snapshot_are_not_projected():
    # The protocol review's trace: snapshot B/2 at T; queued before it A/9 and B/1, both at T.
    projection = _projection()
    snapshot = _frame(projection.accept(_relayed(AGENT, 3, _event(turn_id="B", seq=2))))

    stale_a = projection.accept(_relayed(AGENT, 1, _event(turn_id="A", seq=9)))
    stale_b = projection.accept(_relayed(AGENT, 2, _event(turn_id="B", seq=1)))
    next_b = _frame(projection.accept(_relayed(AGENT, 4, _event(turn_id="B", seq=3))))

    assert (snapshot["turn_id"], snapshot["seq"]) == ("B", 2)
    assert (stale_a, stale_b) == (None, None)
    assert (next_b["turn_id"], next_b["seq"]) == ("B", 3)


def test_a_stale_end_elsewhere_does_not_clear_a_newer_turn():
    projection = _projection()
    projection.accept(_relayed(AGENT, 5, _event(turn_id="B", seq=1, session_id=OTHER_SESSION)))

    stale_end = projection.accept(_relayed(AGENT, 4, _event(turn_id="A", seq=9, phase="turn_ended", session_id=OTHER_SESSION)))

    assert stale_end is None


def test_events_of_agents_outside_the_session_are_ignored():
    assert _projection().accept(_relayed(str(uuid4()), 1, _event(turn_id="A", seq=1))) is None


@pytest_asyncio.fixture
async def redis():
    async with Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True) as client:
        yield client


async def _relay(redis, agent_id, event):
    return await relay_activity(
        redis, agent_id=agent_id, alias="bob", signed_payload="p", signature="s",
        event=event, now=datetime.now(timezone.utc),
    )


def _live(**changes):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return _event(
        timestamp=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        expires_at=(now + timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        **changes,
    )


@pytest.mark.asyncio
async def test_an_event_between_subscribe_and_snapshot_gives_exactly_one_frame(redis):
    agent_id = str(uuid4())
    projection = SessionActivity(SESSION, {agent_id: "bob"})
    async with redis.pubsub() as pubsub:
        await projection.subscribe(pubsub)
        await _relay(redis, agent_id, _live(turn_id="A", seq=1))

        frames = await projection.snapshot(redis)
        queued = await pubsub.get_message(ignore_subscribe_messages=True, timeout=2)

    assert [_frame(frame)["seq"] for frame in frames] == [1]
    assert queued is not None and projection.owns(queued["channel"])
    assert projection.accept(queued["data"]) is None


@pytest.mark.asyncio
async def test_subscribe_confirms_every_agent_channel_before_returning(redis):
    agents = {str(uuid4()): "bob", str(uuid4()): "carol"}
    projection = SessionActivity(SESSION, agents)
    async with redis.pubsub() as pubsub:
        await projection.subscribe(pubsub)

        counts = dict(await redis.pubsub_numsub(*projection.channels))

    assert counts == {channel: 1 for channel in projection.channels}


@pytest.mark.asyncio
async def test_snapshot_of_an_ended_turn_elsewhere_is_a_clear(redis):
    agent_id = str(uuid4())
    await _relay(redis, agent_id, _live(turn_id="A", seq=1, session_id=None))
    await _relay(redis, agent_id, _live(turn_id="A", seq=2, phase="turn_ended", session_id=None))

    frames = await SessionActivity(SESSION, {agent_id: "bob"}).snapshot(redis)

    assert [_frame(frame) for frame in frames] == [{"agent": "bob", "phase": "cleared"}]
