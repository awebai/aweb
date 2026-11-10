"""A chat stream delivers every message posted after the client saw its 200.

The stream's response headers are on the wire before the generator body runs, so
the work between the 200 and the stream being fully set up is the window these
tests hold open: a message posted inside it is delivered, not skipped.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest

from aweb.routes import chat as chat_routes
from test_agent_wake_latency import _open_chat
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401  (fixture)
from test_messages_http import _signed_team_headers


async def _message_frames(stream):
    async for line in stream.aiter_lines():
        if line.startswith("data: "):
            event = json.loads(line[6:])
            if event.get("type") == "message":
                yield event


@pytest.mark.asyncio
async def test_message_posted_between_the_200_and_stream_setup_is_delivered(privacy_app, monkeypatch):  # noqa: F811
    env = privacy_app
    session_id = (await _open_chat(env, message="before the stream"))["session_id"]
    setup_reached = asyncio.Event()
    release_setup = asyncio.Event()
    real_get_contact_addresses = chat_routes.get_contact_addresses

    async def held_setup(*args, **kwargs):
        setup_reached.set()
        await release_setup.wait()
        return await real_get_contact_addresses(*args, **kwargs)

    monkeypatch.setattr(chat_routes, "get_contact_addresses", held_setup)
    bob = env.actors["bob"]
    deadline = (datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat()
    async with env.client.stream(
        "GET", f"/v1/chat/sessions/{session_id}/stream", params={"deadline": deadline},
        headers=_signed_team_headers(bob.sk, bob.did, TEAM, bob.certificate), timeout=None,
    ) as stream:
        assert stream.status_code == 200
        async with asyncio.timeout(5):
            await setup_reached.wait()
        posted = await _request(env, "alice", "POST", f"/v1/chat/sessions/{session_id}/messages", {
            "body": "posted after the 200",
        })
        assert posted.status_code == 200, posted.text
        release_setup.set()
        async with asyncio.timeout(6):
            frame = await anext(_message_frames(stream))
    assert frame["message_id"] == posted.json()["message_id"]
    assert frame["body"] == "posted after the 200"
