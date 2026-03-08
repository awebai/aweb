"""Tests for the per-agent SSE event stream."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app


def auth(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


def _short_deadline(seconds: float = 0.3) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


async def _collect_sse_text(
    *,
    client: AsyncClient,
    url: str,
    params: dict[str, str],
    headers: dict[str, str],
) -> str:
    resp = await client.get(url, params=params, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.text


def _parse_sse_events(text: str) -> list[dict]:
    """Parse SSE text into a list of {event, data} dicts."""
    events = []
    for block in text.split("\n\n"):
        block = block.strip()
        if not block or block.startswith(":"):
            continue
        event_type = None
        data = None
        for line in block.split("\n"):
            if line.startswith("event: "):
                event_type = line[7:]
            elif line.startswith("data: "):
                data = line[6:]
        if event_type and data:
            events.append({"event": event_type, "data": json.loads(data)})
    return events


async def _init_project(c: AsyncClient, slug: str = "evt-test", alias: str = "alice") -> dict:
    resp = await c.post("/v1/init", json={"project_slug": slug, "alias": alias})
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.mark.asyncio
async def test_event_stream_connects(aweb_db_infra):
    """GET /v1/events/stream returns SSE content type and a connected event."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            info = await _init_project(c)
            resp = await c.get(
                "/v1/events/stream",
                params={"deadline": _short_deadline()},
                headers=auth(info["api_key"]),
            )
            assert resp.status_code == 200
            assert "text/event-stream" in resp.headers["content-type"]
            events = _parse_sse_events(resp.text)
            connected = [e for e in events if e["event"] == "connected"]
            assert len(connected) == 1
            assert connected[0]["data"]["agent_id"] == info["agent_id"]


@pytest.mark.asyncio
async def test_event_stream_mail_wake(aweb_db_infra):
    """Receiving mail triggers a mail_message event."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # Set up two agents in the same project
            info_a = await _init_project(c, alias="alice")
            info_b = (await c.post(
                "/v1/init", json={"project_slug": "evt-test", "alias": "bob"}
            )).json()

            # Send a mail from bob to alice
            await c.post(
                "/v1/messages",
                headers=auth(info_b["api_key"]),
                json={"to_alias": "alice", "body": "hey", "subject": "ping"},
            )

            # Alice's event stream should show a mail_message event
            text = await _collect_sse_text(
                client=c,
                url="/v1/events/stream",
                params={"deadline": _short_deadline()},
                headers=auth(info_a["api_key"]),
            )
            events = _parse_sse_events(text)
            mail_events = [e for e in events if e["event"] == "mail_message"]
            assert len(mail_events) >= 1
            assert mail_events[0]["data"]["from_alias"] == "bob"


@pytest.mark.asyncio
async def test_event_stream_chat_wake(aweb_db_infra):
    """Receiving a chat message triggers a chat_message event."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            info_a = await _init_project(c, alias="alice")
            info_b = (await c.post(
                "/v1/init", json={"project_slug": "evt-test", "alias": "bob"}
            )).json()

            # Create a chat session
            sess = await c.post(
                "/v1/chat/sessions",
                headers=auth(info_b["api_key"]),
                json={"to_aliases": ["alice"], "message": "hello"},
            )
            assert sess.status_code == 200, sess.text

            # Alice's event stream should show a chat_message event
            text = await _collect_sse_text(
                client=c,
                url="/v1/events/stream",
                params={"deadline": _short_deadline()},
                headers=auth(info_a["api_key"]),
            )
            events = _parse_sse_events(text)
            chat_events = [e for e in events if e["event"] == "chat_message"]
            assert len(chat_events) >= 1
            assert chat_events[0]["data"]["from_alias"] == "bob"


@pytest.mark.asyncio
async def test_event_stream_work_available(aweb_db_infra):
    """Creating an unclaimed task triggers a work_available event."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            info = await _init_project(c)

            # Create a task (unclaimed, open, no blockers = ready work)
            await c.post(
                "/v1/tasks",
                headers=auth(info["api_key"]),
                json={"title": "New work"},
            )

            text = await _collect_sse_text(
                client=c,
                url="/v1/events/stream",
                params={"deadline": _short_deadline()},
                headers=auth(info["api_key"]),
            )
            events = _parse_sse_events(text)
            work_events = [e for e in events if e["event"] == "work_available"]
            assert len(work_events) >= 1


@pytest.mark.asyncio
async def test_event_stream_blocked_task_excluded(aweb_db_infra):
    """Blocked tasks do not appear as work_available; unblocking makes them appear."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            info = await _init_project(c)
            hdrs = auth(info["api_key"])

            # Create a blocker and a dependent task
            blocker = (await c.post("/v1/tasks", headers=hdrs, json={"title": "Blocker"})).json()
            dependent = (await c.post("/v1/tasks", headers=hdrs, json={"title": "Dependent"})).json()

            # dependent depends on blocker
            dep_resp = await c.post(
                f"/v1/tasks/{dependent['task_ref']}/deps",
                headers=hdrs,
                json={"depends_on": blocker["task_ref"]},
            )
            assert dep_resp.status_code == 200, dep_resp.text

            # Stream should NOT show dependent as work_available (it's blocked)
            text = await _collect_sse_text(
                client=c,
                url="/v1/events/stream",
                params={"deadline": _short_deadline()},
                headers=hdrs,
            )
            events = _parse_sse_events(text)
            work_events = [e for e in events if e["event"] == "work_available"]
            work_ids = {e["data"]["task_id"] for e in work_events}
            # blocker is ready (open, unclaimed, no deps), dependent is not
            assert blocker["task_id"] in work_ids
            assert dependent["task_id"] not in work_ids

            # Close the blocker — now dependent should become ready
            close_resp = await c.patch(
                f"/v1/tasks/{blocker['task_ref']}",
                headers=hdrs,
                json={"status": "closed"},
            )
            assert close_resp.status_code == 200, close_resp.text

            # New stream should show dependent as work_available
            text = await _collect_sse_text(
                client=c,
                url="/v1/events/stream",
                params={"deadline": _short_deadline()},
                headers=hdrs,
            )
            events = _parse_sse_events(text)
            work_events = [e for e in events if e["event"] == "work_available"]
            work_ids = {e["data"]["task_id"] for e in work_events}
            assert dependent["task_id"] in work_ids
            # blocker is closed, so no longer in ready tasks
            assert blocker["task_id"] not in work_ids


@pytest.mark.asyncio
async def test_event_stream_scoped_to_agent(aweb_db_infra):
    """Events are scoped — agent only sees their own mail/chat."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            info_a = await _init_project(c, alias="alice")
            info_b = (await c.post(
                "/v1/init", json={"project_slug": "evt-test", "alias": "bob"}
            )).json()
            info_c = (await c.post(
                "/v1/init", json={"project_slug": "evt-test", "alias": "charlie"}
            )).json()

            # Bob sends mail to charlie (not alice)
            await c.post(
                "/v1/messages",
                headers=auth(info_b["api_key"]),
                json={"to_alias": "charlie", "body": "hey charlie"},
            )

            # Alice's stream should NOT have mail_message events
            text = await _collect_sse_text(
                client=c,
                url="/v1/events/stream",
                params={"deadline": _short_deadline()},
                headers=auth(info_a["api_key"]),
            )
            events = _parse_sse_events(text)
            mail_events = [e for e in events if e["event"] == "mail_message"]
            assert len(mail_events) == 0
