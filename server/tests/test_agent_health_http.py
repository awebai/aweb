"""The dashboard's agent health object through the real app, PostgreSQL and Redis.

GET /v1/teams/{team_id}/agents and /agents/{alias} carry an additive
``health`` object computed in one place (aweb-acah.3, docs/agent-health.md
"Reading"). Statuses are published through the real routes; the only direct
state writes are fixture provisioning and clearing the per-agent rate window.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from test_agent_status_publish_http import _body, _designate, _document, _publish, _ts
from test_agent_status_host_http import _team_request
from test_dashboard import _make_jwt
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401

NOT_REPORTED = {
    "source": "host",
    "reachable": "unknown",
    "reason_text": "Its server hasn't reported yet",
    "fixing_by": None,
    "fixing_text": None,
    "observed_at": None,
    "valid_until": None,
    "stale": False,
    "verified": False,
    "signed_payload": None,
    "signature": None,
}


async def _health(env, alias):
    headers = {"X-Dashboard-Token": _make_jwt([TEAM])}
    listed = await env.client.get(f"/v1/teams/{TEAM}/agents", headers=headers)
    assert listed.status_code == 200, listed.text
    detail = await env.client.get(f"/v1/teams/{TEAM}/agents/{alias}", headers=headers)
    assert detail.status_code == 200, detail.text
    from_list = next(agent["health"] for agent in listed.json()["agents"] if agent["alias"] == alias)
    assert detail.json()["health"] == from_list
    return from_list


def _reported(env, publisher, document, *, stale=False):
    body = _body(env, publisher, document)
    return {
        "source": "host",
        "reachable": document["reachable"],
        "reason_text": (document.get("reason") or {}).get("text"),
        "fixing_by": (document.get("fixing") or {}).get("by"),
        "fixing_text": (document.get("fixing") or {}).get("text"),
        "observed_at": document["observed_at"],
        "valid_until": document["valid_until"],
        "stale": stale,
        "verified": True,
        "signed_payload": body["signed_payload"],
        "signature": body["signature"],
    }


@pytest.mark.asyncio
async def test_agent_without_host_or_status_is_left_to_aweb(privacy_app):
    env = privacy_app

    assert await _health(env, "alice") == {"source": "aweb"}


@pytest.mark.asyncio
async def test_self_published_status_is_the_health(privacy_app):
    env = privacy_app
    document = _document(env, "alice", "alice")
    published = await _publish(env, "alice", "alice", document)
    assert published.status_code == 200, published.text

    assert await _health(env, "alice") == _reported(env, "alice", document)


@pytest.mark.asyncio
async def test_designated_host_that_has_not_reported_says_so(privacy_app):
    env = privacy_app
    await _designate(env, "alice", "bob")

    assert await _health(env, "alice") == NOT_REPORTED


@pytest.mark.asyncio
async def test_host_report_is_the_health_and_a_reachable_report_has_no_reason(privacy_app):
    env = privacy_app
    await _designate(env, "alice", "bob")
    document = _document(env, "alice", "bob", reachable="yes")
    published = await _publish(env, "bob", "alice", document)
    assert published.status_code == 200, published.text

    health = await _health(env, "alice")

    assert health == _reported(env, "bob", document)
    assert (health["reason_text"], health["fixing_by"], health["fixing_text"]) == (None, None, None)


@pytest.mark.asyncio
async def test_report_past_valid_until_is_stale_on_read(privacy_app):
    env = privacy_app
    observed = datetime.now(timezone.utc).replace(microsecond=0)
    document = _document(
        env, "alice", "alice", observed_at=_ts(observed), valid_until=_ts(observed + timedelta(seconds=1)),
    )
    published = await _publish(env, "alice", "alice", document)
    assert published.status_code == 200, published.text
    assert (await _health(env, "alice"))["stale"] is False

    await asyncio.sleep(2.1)

    assert await _health(env, "alice") == _reported(env, "alice", document, stale=True)


@pytest.mark.asyncio
async def test_host_that_left_the_team_falls_back_to_aweb(privacy_app):
    env = privacy_app
    await _designate(env, "alice", "bob")
    published = await _publish(env, "bob", "alice", _document(env, "alice", "bob"))
    assert published.status_code == 200, published.text

    retired = await _team_request(env, "bob", "DELETE", f"/v1/workspaces/{env.actors['bob'].workspace}")
    assert retired.status_code == 200, retired.text

    assert await _health(env, "alice") == {"source": "aweb"}


@pytest.mark.asyncio
async def test_each_agent_gets_its_own_health_in_the_list(privacy_app):
    env = privacy_app
    await _designate(env, "alice", "bob")
    carol = _document(env, "carol", "carol", reachable="degraded")
    published = await _publish(env, "carol", "carol", carol)
    assert published.status_code == 200, published.text

    assert await _health(env, "alice") == NOT_REPORTED
    assert await _health(env, "bob") == {"source": "aweb"}
    assert await _health(env, "carol") == _reported(env, "carol", carol)


@pytest.mark.asyncio
async def test_public_team_shows_health_to_anonymous_readers(privacy_app):
    # Health has the public directory's visibility, like last_seen
    # (docs/agent-health.md "Reading"); changing that must be deliberate.
    env = privacy_app
    document = _document(env, "alice", "alice")
    published = await _publish(env, "alice", "alice", document)
    assert published.status_code == 200, published.text

    listed = await env.client.get(f"/v1/teams/{TEAM}/agents")
    detail = await env.client.get(f"/v1/teams/{TEAM}/agents/alice")

    assert listed.status_code == 200, listed.text
    assert detail.status_code == 200, detail.text
    expected = _reported(env, "alice", document)
    assert next(agent["health"] for agent in listed.json()["agents"] if agent["alias"] == "alice") == expected
    assert detail.json()["health"] == expected


@pytest.mark.asyncio
async def test_private_team_shows_health_only_with_a_dashboard_token(privacy_app):
    env = privacy_app
    await env.registry_db.execute(
        "UPDATE {{tables.teams}} SET visibility = 'private' WHERE domain = 'example.test'",
    )
    document = _document(env, "alice", "alice")
    published = await _publish(env, "alice", "alice", document)
    assert published.status_code == 200, published.text

    for path in (f"/v1/teams/{TEAM}/agents", f"/v1/teams/{TEAM}/agents/alice"):
        anonymous = await env.client.get(path)
        assert anonymous.status_code == 401, anonymous.text
        assert "health" not in anonymous.text

    assert await _health(env, "alice") == _reported(env, "alice", document)
