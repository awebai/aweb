"""Tests for the status SSE stream endpoint."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app


def auth(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


def _short_deadline() -> str:
    """Return an ISO deadline ~1s from now."""
    from datetime import timedelta

    return (datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat()


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


async def _init_project(c: AsyncClient, slug: str = "sse-test", alias: str = "alice") -> dict:
    resp = await c.post("/v1/init", json={"project_slug": slug, "alias": alias})
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.mark.asyncio
async def test_status_stream_emits_snapshot(aweb_db_infra):
    """GET /v1/status/stream emits an initial snapshot event."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            info = await _init_project(c)
            text = await _collect_sse_text(
                client=c,
                url="/v1/status/stream",
                params={"deadline": _short_deadline()},
                headers=auth(info["api_key"]),
            )
            events = _parse_sse_events(text)
            # Should have at least a snapshot event
            snapshots = [e for e in events if e["event"] == "snapshot"]
            assert len(snapshots) >= 1
            snap = snapshots[0]["data"]
            assert snap["project_id"] == info["project_id"]
            assert len(snap["agents"]) >= 1
            alice = next(a for a in snap["agents"] if a["alias"] == "alice")
            assert "agent_id" in alice


@pytest.mark.asyncio
async def test_status_stream_includes_claims(aweb_db_infra):
    """Snapshot includes active claims."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            info = await _init_project(c)
            api_key = info["api_key"]

            # Create and assign a task
            task = await c.post("/v1/tasks", headers=auth(api_key), json={"title": "Stream task"})
            task_ref = task.json()["task_ref"]
            await c.patch(
                f"/v1/tasks/{task_ref}",
                headers=auth(api_key),
                json={"assignee_agent_id": info["agent_id"]},
            )

            text = await _collect_sse_text(
                client=c,
                url="/v1/status/stream",
                params={"deadline": _short_deadline()},
                headers=auth(api_key),
            )
            events = _parse_sse_events(text)
            snapshots = [e for e in events if e["event"] == "snapshot"]
            assert len(snapshots) >= 1
            assert len(snapshots[0]["data"]["claims"]) == 1
            assert snapshots[0]["data"]["claims"][0]["title"] == "Stream task"


@pytest.mark.asyncio
async def test_status_stream_includes_active_policy(aweb_db_infra):
    """Snapshot includes active policy info."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            info = await _init_project(c)
            api_key = info["api_key"]

            pol = await c.post("/v1/policies", headers=auth(api_key), json={"content": {"v": 1}})
            policy_id = pol.json()["policy_id"]
            await c.post(f"/v1/policies/{policy_id}/activate", headers=auth(api_key))

            text = await _collect_sse_text(
                client=c,
                url="/v1/status/stream",
                params={"deadline": _short_deadline()},
                headers=auth(api_key),
            )
            events = _parse_sse_events(text)
            snapshots = [e for e in events if e["event"] == "snapshot"]
            assert len(snapshots) >= 1
            assert snapshots[0]["data"]["active_policy"]["policy_id"] == policy_id


@pytest.mark.asyncio
async def test_status_stream_content_type(aweb_db_infra):
    """Stream returns text/event-stream content type."""
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            info = await _init_project(c)
            resp = await c.get(
                "/v1/status/stream",
                params={"deadline": _short_deadline()},
                headers=auth(info["api_key"]),
            )
            assert resp.status_code == 200
            assert "text/event-stream" in resp.headers["content-type"]
