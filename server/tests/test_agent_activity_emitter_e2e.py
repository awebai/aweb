"""channel-core's activity emitter against the real server (aweb-acah.2 S2a).

The packaged channel-core emitter and publisher run in Node
(activity_emitter_host.mjs) against the real app, AWID registry, PostgreSQL
and Redis. The test reads what the server relayed. Fixture provisioning and
the host owner's opt-in file are the only direct state.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import subprocess

import pytest

from test_agent_activity_http import _session
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401

REPO = Path(__file__).resolve().parents[2]
HOST = Path(__file__).with_name("activity_emitter_host.mjs")


@pytest.fixture(scope="module")
def channel_core_build():
    build = subprocess.run(["npm", "run", "build"], cwd=REPO / "channel-core", capture_output=True, text=True)
    assert build.returncode == 0, build.stdout + build.stderr


def _opt_in(tmp_path, value="status"):
    root = tmp_path / "identity"
    root.mkdir(exist_ok=True)
    (root / "activity.yaml").write_text(f"activity: {value}\n")
    return root


async def _run_emitter(env, actor, identity_root, steps):
    identity = env.actors[actor]
    spec = {
        "base_url": str(env.client.base_url).rstrip("/"),
        "did": identity.did,
        "seed_hex": identity.sk.hex(),
        "team_id": TEAM,
        "certificate": identity.certificate,
        "identity_root": str(identity_root),
        "work_root": "/home/agent/project",
        "steps": steps,
    }
    process = await asyncio.create_subprocess_exec(
        "node", str(HOST), stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(process.communicate(json.dumps(spec).encode()), timeout=30)
    assert process.returncode == 0, stderr.decode()
    return json.loads(stdout.decode().strip().splitlines()[-1])


async def _relayed(pubsub, count, timeout=2.0):
    messages = []
    async with asyncio.timeout(timeout + count):
        while len(messages) < count:
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=timeout)
            if message is not None:
                messages.append(json.loads(message["data"]))
    return messages


@pytest.mark.asyncio
async def test_an_attributed_turn_reaches_the_server_signed_and_in_order(privacy_app, channel_core_build, tmp_path):
    env = privacy_app
    session_id = await _session(env, "bob", "alice")
    root = _opt_in(tmp_path)
    async with env.redis.pubsub() as pubsub:
        await pubsub.subscribe(f"agent-activity:{env.actors['alice'].id}")
        await pubsub.get_message(timeout=1)

        result = await _run_emitter(env, "alice", root, [
            {"op": "wake", "session_id": session_id},
            {"op": "turn_started"},
            {"op": "wait", "ms": 600},
            {"op": "tool", "name": "Bash", "input": {"command": "pytest -q tests/"}},
            {"op": "wait", "ms": 600},
            {"op": "turn_ended"},
        ])
        relayed = await _relayed(pubsub, 3)

    assert result == {"outcomes": ["accepted", "accepted", "accepted"], "logs": []}
    events = [message["event"] for message in relayed]
    assert [message["rev"] for message in relayed] == [1, 2, 3]
    assert [(event["phase"], event["seq"]) for event in events] == [("turn_started", 1), ("tool", 2), ("turn_ended", 3)]
    assert {event["session_id"] for event in events} == {session_id}
    assert {event["from_did"] for event in events} == {env.actors["alice"].did}
    assert (events[1]["tool"], events[1]["summary"]) == ("Bash", "Running pytest")
    assert len({event["turn_id"] for event in events}) == 1


@pytest.mark.asyncio
async def test_without_the_opt_in_nothing_is_sent(privacy_app, channel_core_build, tmp_path):
    env = privacy_app
    root = _opt_in(tmp_path, "off")

    result = await _run_emitter(env, "alice", root, [{"op": "turn_started"}, {"op": "turn_ended"}])

    assert result == {"outcomes": [], "logs": []}
    assert await env.redis.get(f"agent-activity:{env.actors['alice'].id}") is None


@pytest.mark.asyncio
async def test_a_foreign_session_is_refused_per_event_and_publishing_continues(privacy_app, channel_core_build, tmp_path):
    env = privacy_app
    foreign = await _session(env, "bob", "carol")
    root = _opt_in(tmp_path)

    result = await _run_emitter(env, "alice", root, [
        {"op": "wake", "session_id": foreign},
        {"op": "turn_started"},
        {"op": "turn_ended"},
        {"op": "turn_started"},
        {"op": "turn_ended"},
    ])

    assert result["outcomes"] == ["session_refused", "session_refused", "accepted", "accepted"]
    assert result["logs"] == []
    latest = json.loads(await env.redis.get(f"agent-activity:{env.actors['alice'].id}"))
    assert (latest["event"]["phase"], latest["event"]["session_id"]) == ("turn_ended", None)


@pytest.mark.asyncio
async def test_the_servers_rate_limit_is_honoured_and_the_turn_still_ends(privacy_app, channel_core_build, tmp_path):
    env = privacy_app
    root = _opt_in(tmp_path)
    steps = []
    for _ in range(6):
        steps += [{"op": "turn_started"}, {"op": "turn_ended"}]

    result = await _run_emitter(env, "alice", root, steps)

    # Ten per 5-second window: the eleventh is refused and dropped, the twelfth
    # waits out Retry-After and is then accepted.
    assert result["outcomes"] == ["accepted"] * 10 + ["rate_limited", "accepted"]
    latest = json.loads(await env.redis.get(f"agent-activity:{env.actors['alice'].id}"))
    assert latest["event"]["phase"] == "turn_ended"
    assert latest["rev"] == 11
