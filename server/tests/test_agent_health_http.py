"""The dashboard's agent health object through the real app, PostgreSQL and Redis.

GET /v1/teams/{team_id}/agents and /agents/{alias} carry an additive
``health`` object computed in one place (aweb-acah.3, docs/agent-health.md
"Reading"). Statuses are published through the real routes; the only direct
state writes are fixture provisioning, clearing the per-agent rate window, and
storing a correctly signed report whose validity has already ended, which no
publish can produce.
"""

from __future__ import annotations

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

    assert (await _health(env, "alice"))["source"] == "aweb"


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


async def _store_expired_report(env, publisher, subject, document):
    """Store a signed report exactly as the publish route does, after its validity ended."""
    body = _body(env, publisher, document)
    await env.db.execute(
        """
        INSERT INTO {{tables.agent_status}} (
            agent_id, team_id, publisher_did, seq, reachable, reason_code, fixing_by,
            observed_at, valid_until, signed_payload, signature
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        ON CONFLICT (agent_id) DO UPDATE
        SET publisher_did = EXCLUDED.publisher_did, seq = EXCLUDED.seq,
            reachable = EXCLUDED.reachable, reason_code = EXCLUDED.reason_code,
            fixing_by = EXCLUDED.fixing_by, observed_at = EXCLUDED.observed_at,
            valid_until = EXCLUDED.valid_until, signed_payload = EXCLUDED.signed_payload,
            signature = EXCLUDED.signature, received_at = NOW()
        """,
        env.actors[subject].id,
        TEAM,
        env.actors[publisher].did,
        document["seq"],
        document["reachable"],
        document["reason"]["code"],
        document["fixing"]["by"],
        datetime.fromisoformat(document["observed_at"].replace("Z", "+00:00")),
        datetime.fromisoformat(document["valid_until"].replace("Z", "+00:00")),
        body["signed_payload"],
        body["signature"],
    )


@pytest.mark.asyncio
async def test_report_past_valid_until_is_stale_on_read(privacy_app):
    # No read here may straddle a validity boundary: the live report is valid
    # for minutes, and the expired one ended minutes before the test began.
    env = privacy_app
    now = datetime.now(timezone.utc).replace(microsecond=0)
    live = _document(
        env, "alice", "alice", observed_at=_ts(now), valid_until=_ts(now + timedelta(minutes=5)),
    )
    published = await _publish(env, "alice", "alice", live)
    assert published.status_code == 200, published.text
    assert await _health(env, "alice") == _reported(env, "alice", live, stale=False)

    expired = _document(
        env, "alice", "alice", seq=live["seq"] + 1,
        observed_at=_ts(now - timedelta(minutes=10)), valid_until=_ts(now - timedelta(minutes=5)),
    )
    await _store_expired_report(env, "alice", "alice", expired)

    assert await _health(env, "alice") == _reported(env, "alice", expired, stale=True)


@pytest.mark.asyncio
async def test_host_that_left_the_team_falls_back_to_aweb(privacy_app):
    env = privacy_app
    await _designate(env, "alice", "bob")
    published = await _publish(env, "bob", "alice", _document(env, "alice", "bob"))
    assert published.status_code == 200, published.text

    retired = await _team_request(env, "bob", "DELETE", f"/v1/workspaces/{env.actors['bob'].workspace}")
    assert retired.status_code == 200, retired.text

    assert (await _health(env, "alice"))["source"] == "aweb"


@pytest.mark.asyncio
async def test_each_agent_gets_its_own_health_in_the_list(privacy_app):
    env = privacy_app
    await _designate(env, "alice", "bob")
    carol = _document(env, "carol", "carol", reachable="degraded")
    published = await _publish(env, "carol", "carol", carol)
    assert published.status_code == 200, published.text

    assert await _health(env, "alice") == NOT_REPORTED
    assert (await _health(env, "bob"))["source"] == "aweb"
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
