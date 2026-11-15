"""Service registration follows the team's key as the server holds it.

A team key changed by the namespace controller's act moves the key this server
holds, so registration signed by the new key succeeds (aweb-adcj). A key the
registry serves without such an act stays refused.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from awid.signing import canonical_json_bytes, sign_message
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_messages_http import _make_keypair
from test_team_key_pinning import (  # noqa: F401
    _substitute_registry_team_key,
    pinning,
    register_namespace_controller,
    rotate_team_key,
)

SERVICE = "https://aweb.example.test"


async def _register(env, team_sk):
    body = {
        "awid_team_id": TEAM,
        "service_url": SERVICE,
        "dry_run": False,
        "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    body["controller_signature"] = sign_message(team_sk, canonical_json_bytes({
        "operation": "team_service_register", **{k: body[k] for k in ("awid_team_id", "service_url", "dry_run", "timestamp")},
    }))
    return await env.client.post("/api/v1/teams/service-register", json=body)


async def _held_key(env):
    return await env.db.fetch_value("SELECT team_did_key FROM {{tables.teams}} WHERE team_id = $1", TEAM)


@pytest.fixture
def registering(pinning, monkeypatch):
    monkeypatch.setenv("AWEB_DISCOVERY_ORIGIN", SERVICE)
    return pinning


@pytest.mark.asyncio
async def test_registration_signed_by_a_key_the_controller_moved_to_is_synced(registering):
    env = registering
    await register_namespace_controller(env, env.namespace_did)
    next_sk, _, next_did = _make_keypair()
    await rotate_team_key(env, env.namespace_sk, env.namespace_did, next_did)

    response = await _register(env, next_sk)

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "synced"
    assert await _held_key(env) == next_did


@pytest.mark.asyncio
async def test_registration_under_a_key_with_no_controller_act_is_refused(registering):
    env = registering
    await register_namespace_controller(env, env.namespace_did)
    substituted_sk, _, substituted_did = _make_keypair()
    await _substitute_registry_team_key(env, substituted_did)

    response = await _register(env, substituted_sk)

    assert response.status_code == 401, response.text
    assert response.json()["detail"] == "team_key_unverified"
    assert await _held_key(env) == env.team_did


@pytest.mark.asyncio
async def test_registration_by_the_held_key_is_synced(registering):
    env = registering

    response = await _register(env, env.team_sk)

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "synced"
