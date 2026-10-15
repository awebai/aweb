"""aweb's own observations for agents without a status host (aweb-acah.3 S4).

The fallback health object, docs/agent-health.md "Fallback for agents without
a status host", through the real app, AWID registry, PostgreSQL and Redis.
Streams, heartbeats and grants go through their real routes. The only direct
state writes are fixture provisioning; the listening window is shortened
where a test must see it pass.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

import aweb.agent_health
import aweb.routes.events
from test_agent_health_http import _health
from test_agent_status_host_http import _team_request
from test_dashboard import _make_jwt
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_identity_grants import _grant_headers, _session_keypair
from test_messages_http import _signed_team_headers


def _when(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


async def _open_stream(env, alias):
    # An elapsed deadline returns the initial snapshot and ends, so the open
    # is finite and deterministic.
    actor = env.actors[alias]
    deadline = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    response = await env.client.get(
        "/v1/events/stream",
        params={"deadline": deadline},
        headers=_signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate),
    )
    assert response.status_code == 200, response.text


async def _mint_grant(env, alias):
    _, grant_did = _session_keypair()
    minted = await _team_request(
        env, alias, "POST", "/v1/identity-grants",
        {"grant_did_key": grant_did, "scopes": ["mail.read"], "ttl_seconds": 600},
    )
    assert minted.status_code == 200, minted.text
    return minted.json()["grant_id"]


async def _grant_heartbeat(env, alias):
    # Grant requests are signed for the server's public origin, which an
    # embedding host supplies through app.state.
    origin = str(env.client.base_url).rstrip("/")
    env.app.state.public_origin = origin
    signing_key, grant_did = _session_keypair()
    minted = await _team_request(
        env, alias, "POST", "/v1/identity-grants",
        {"grant_did_key": grant_did, "scopes": ["presence.write"], "ttl_seconds": 600},
    )
    assert minted.status_code == 200, minted.text
    beat = await env.client.post(
        "/v1/agents/heartbeat",
        headers=_grant_headers(
            signing_key=signing_key, did_key=grant_did, grant_id=minted.json()["grant_id"],
            method="POST", path="/v1/agents/heartbeat", aud=origin,
        ),
    )
    assert beat.status_code == 200, beat.text


@pytest.mark.asyncio
async def test_agent_without_observations_reports_none(privacy_app):
    env = privacy_app

    assert await _health(env, "alice") == {
        "source": "aweb",
        "listening": False,
        "listening_since": None,
        "last_active": None,
        "connection": None,
    }


@pytest.mark.asyncio
async def test_open_event_stream_shows_listening(privacy_app):
    env = privacy_app
    before = datetime.now(timezone.utc).replace(microsecond=0)

    await _open_stream(env, "alice")
    health = await _health(env, "alice")

    assert health["listening"] is True
    assert before <= _when(health["listening_since"]) <= datetime.now(timezone.utc)
    assert (await _health(env, "bob"))["listening"] is False


@pytest.mark.asyncio
async def test_listening_ends_when_the_stream_stops_refreshing(privacy_app, monkeypatch):
    env = privacy_app
    monkeypatch.setattr(aweb.agent_health, "LISTENING_WINDOW_SECONDS", 1)
    await _open_stream(env, "alice")
    started = (await _health(env, "alice"))["listening_since"]

    await asyncio.sleep(2.1)
    health = await _health(env, "alice")

    assert health["listening"] is False
    assert _when(health["listening_since"]) >= _when(started)


@pytest.mark.asyncio
async def test_heartbeat_sets_last_active(privacy_app, monkeypatch):
    env = privacy_app
    # The heartbeat route reads settings from the environment; the fixture's
    # database is supplied through app.state, as an embedding host does.
    monkeypatch.setenv("AWEB_DATABASE_URL", "postgresql://unused/test")
    before = datetime.now(timezone.utc).replace(microsecond=0)
    actor = env.actors["alice"]
    beat = await _team_request(
        env, "alice", "POST", "/v1/workspaces/heartbeat",
        {"workspace_id": str(actor.workspace), "alias": "alice"},
    )
    assert beat.status_code == 200, beat.text

    health = await _health(env, "alice")

    assert before <= _when(health["last_active"]) <= datetime.now(timezone.utc)


@pytest.mark.asyncio
async def test_grant_heartbeat_alone_sets_last_active(privacy_app):
    env = privacy_app
    before = datetime.now(timezone.utc).replace(microsecond=0)

    await _grant_heartbeat(env, "alice")
    health = await _health(env, "alice")

    assert before <= _when(health["last_active"]) <= datetime.now(timezone.utc)
    workspace = await env.db.fetch_one(
        "SELECT last_seen_at FROM {{tables.workspaces}} WHERE workspace_id = $1", env.actors["alice"].workspace,
    )
    assert workspace["last_seen_at"] is None


@pytest.mark.asyncio
async def test_grant_seat_shows_its_connection(privacy_app):
    env = privacy_app
    grant_id = await _mint_grant(env, "alice")

    assert (await _health(env, "alice"))["connection"] == "active"
    assert (await _health(env, "bob"))["connection"] is None

    revoked = await _team_request(env, "alice", "POST", f"/v1/identity-grants/{grant_id}/revoke")
    assert revoked.status_code == 200, revoked.text

    assert (await _health(env, "alice"))["connection"] == "revoked"


@pytest.mark.asyncio
async def test_any_active_grant_makes_the_seat_active(privacy_app):
    env = privacy_app
    await _mint_grant(env, "alice")
    newest = await _mint_grant(env, "alice")
    # The newest grant is revoked, so only the any-active rule keeps the seat active.
    revoked = await _team_request(env, "alice", "POST", f"/v1/identity-grants/{newest}/revoke")
    assert revoked.status_code == 200, revoked.text

    assert (await _health(env, "alice"))["connection"] == "active"


@pytest.mark.asyncio
async def test_anonymous_public_reader_never_sees_the_connection(privacy_app):
    env = privacy_app
    await _mint_grant(env, "alice")
    await _open_stream(env, "alice")

    for path in (f"/v1/teams/{TEAM}/agents", f"/v1/teams/{TEAM}/agents/alice"):
        for headers in ({}, {"X-Dashboard-Token": "invalid"}, {"X-Dashboard-Token": _make_jwt(["other:example.test"])}):
            response = await env.client.get(path, headers=headers)
            assert response.status_code == 200, response.text
            body = response.json()
            health = body["health"] if "health" in body else next(
                agent["health"] for agent in body["agents"] if agent["alias"] == "alice"
            )
            assert health["connection"] is None
            assert health["listening"] is True

    assert (await _health(env, "alice"))["connection"] == "active"


@pytest.mark.asyncio
async def test_open_stream_keeps_listening_past_the_window(privacy_app, monkeypatch):
    env = privacy_app
    monkeypatch.setattr(aweb.routes.events, "LISTENING_REFRESH_SECONDS", 0.2)
    monkeypatch.setattr(aweb.agent_health, "LISTENING_WINDOW_SECONDS", 2.5)
    actor = env.actors["alice"]
    deadline = (datetime.now(timezone.utc) + timedelta(seconds=6)).isoformat()
    opened = asyncio.Event()

    async def hold_stream():
        async with env.client.stream(
            "GET", "/v1/events/stream", params={"deadline": deadline},
            headers=_signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate), timeout=10,
        ) as response:
            assert response.status_code == 200
            async for _ in response.aiter_lines():
                opened.set()

    holder = asyncio.create_task(hold_stream())
    try:
        await asyncio.wait_for(opened.wait(), 5)
        await asyncio.sleep(0.5)
        started = (await _health(env, "alice"))["listening_since"]

        await asyncio.sleep(4)
        health = await _health(env, "alice")

        assert health["listening"] is True
        assert health["listening_since"] == started
    finally:
        holder.cancel()
        await asyncio.gather(holder, return_exceptions=True)


@pytest.mark.asyncio
async def test_embedding_app_calling_the_route_in_process_gets_observations(privacy_app):
    # An embedding application may call the route function directly with
    # request, team_id and db, as Cloud does; Redis comes from app.state.
    from starlette.requests import Request

    from aweb.routes.dashboard import list_team_agents

    env = privacy_app
    await _open_stream(env, "alice")
    request = Request({
        "type": "http", "method": "GET", "path": f"/v1/teams/{TEAM}/agents", "query_string": b"",
        "headers": [(b"x-dashboard-token", _make_jwt([TEAM]).encode())], "app": env.app,
    })

    listed = await list_team_agents(request, TEAM, db=env.infra)

    health = next(agent["health"] for agent in listed["agents"] if agent["alias"] == "alice")
    assert health["listening"] is True
