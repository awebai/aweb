"""Expected dashboard configuration refusals precede the SSE response."""

import json

import pytest
import pytest_asyncio

from aweb.embedding import OutboxRecoveryOwnership
from test_dashboard_privacy import TEAM, _make_jwt, _next_event, privacy_stack


@pytest_asyncio.fixture
async def privacy_app(shared_test_pool, monkeypatch):
    async with privacy_stack(
        shared_test_pool, monkeypatch, outbox_recovery=OutboxRecoveryOwnership.HOST
    ) as env:
        yield env


@pytest.mark.asyncio
async def test_missing_selected_registry_refuses_before_stream_headers(privacy_app):
    env = privacy_app
    del env.app.state.awid_registry_client

    async with env.client.stream(
        "GET",
        f"/v1/teams/{TEAM}/events/stream",
        headers={"X-Dashboard-Token": _make_jwt([TEAM])},
    ) as response:
        assert response.status_code == 503
        assert response.headers["content-type"].startswith("application/json")
        body = await response.aread()
        detail = json.loads(body)["detail"]
        assert detail["code"] == "registry_client_unavailable"
        assert detail["message"].endswith(
            "Configure the serving registry client and start the application before retrying."
        )
        assert b"event: connected" not in body


@pytest.mark.asyncio
async def test_configured_registry_opens_connected_then_snapshot(privacy_app):
    env = privacy_app
    async with env.client.stream(
        "GET",
        f"/v1/teams/{TEAM}/events/stream",
        headers={"X-Dashboard-Token": _make_jwt([TEAM])},
    ) as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        lines = response.aiter_lines()
        connected = await _next_event(lines)
        snapshot = await _next_event(lines)
        assert connected["type"] == "connected"
        assert connected["team_id"] == TEAM
        assert snapshot["type"] == "snapshot"
        assert snapshot["team_id"] == TEAM
        assert "online_aliases" in snapshot
        assert "active_claims" in snapshot
