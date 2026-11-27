"""Service registration follows the team's key as the server holds it.

A team key changed by the namespace controller's act moves the key this server
holds, so registration signed by the new key succeeds (aweb-adcj). A key the
registry serves without such an act stays refused.
"""

from __future__ import annotations

import asyncio
from contextlib import aclosing
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from awid.registry import CachedRegistryClient
from awid.signing import canonical_json_bytes, sign_message
from test_dashboard_privacy import TEAM, TEAM_NAME
from test_dashboard_privacy import privacy_app as privacy_app
from test_messages_http import _make_keypair
from test_team_key_pinning import (  # noqa: F401
    _substitute_registry_team_key,
    pinning as pinning,
    register_namespace_controller,
    rotate_team_key,
)

__all__ = ["pinning"]

SERVICE = "https://aweb.example.test"


async def _register(env, team_sk, *, team_id=TEAM, dry_run=False, timestamp=None):
    body = {
        "awid_team_id": team_id,
        "service_url": SERVICE,
        "dry_run": dry_run,
        "timestamp": (timestamp or datetime.now(timezone.utc))
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
    }
    body["controller_signature"] = sign_message(
        team_sk,
        canonical_json_bytes(
            {
                "operation": "team_service_register",
                **{
                    k: body[k]
                    for k in ("awid_team_id", "service_url", "dry_run", "timestamp")
                },
            }
        ),
    )
    return await env.client.post("/api/v1/teams/service-register", json=body)


async def _held_key(env):
    return await env.db.fetch_value(
        "SELECT team_did_key FROM {{tables.teams}} WHERE team_id = $1", TEAM
    )


@pytest.fixture
def registering(pinning, monkeypatch):
    monkeypatch.setenv("AWEB_DISCOVERY_ORIGIN", SERVICE)
    return pinning


@pytest.mark.asyncio
async def test_registration_signed_by_a_key_the_controller_moved_to_is_synced(
    registering,
):
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
    assert (
        response.json()["detail"]
        == "team_key_unverified: The team key change could not be verified. Ask the team administrator to verify the namespace controller's current key-change record, then retry."
    )
    assert await _held_key(env) == env.team_did


@pytest.mark.asyncio
@pytest.mark.parametrize("dry_run", [False, True])
async def test_registration_refuses_a_served_key_that_does_not_match_the_admitted_key(
    registering,
    dry_run,
):
    env = registering
    await register_namespace_controller(env, env.namespace_did)
    assert (await _register(env, env.team_sk)).status_code == 200
    stale_sk, _, stale_did = _make_keypair()
    await rotate_team_key(env, env.namespace_sk, env.namespace_did, stale_did)
    async with aclosing(
        CachedRegistryClient(
            registry_url=f"http://registration-cache-{dry_run}.test".lower(),
            redis_client=env.redis,
            transport=env.registry.transport,
        )
    ) as registry:
        assert (
            await registry.get_team_public_key("example.test", TEAM_NAME) == stale_did
        )
        env.app.state.awid_registry_client = registry
        # Another real rotation leaves the SDK cache behind the live act. The
        # server never admitted the intermediate key.
        _, _, current_did = _make_keypair()
        await rotate_team_key(env, env.namespace_sk, env.namespace_did, current_did)
        stale = await _register(env, stale_sk, dry_run=dry_run)

    assert stale.status_code == 401, stale.text
    assert stale.json()["detail"].startswith("team_key_unverified: ")
    assert await _held_key(env) == env.team_did


@pytest.mark.asyncio
async def test_registration_by_the_held_key_is_synced(registering):
    env = registering

    response = await _register(env, env.team_sk)

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "synced"


async def _new_registry_team(env):
    await register_namespace_controller(env, env.namespace_did)
    name = f"registration-{uuid4().hex[:12]}"
    team_sk, _, team_did = _make_keypair()
    await env.app.state.awid_registry_client.register_team(
        domain="example.test",
        name=name,
        display_name="",
        team_did_key=team_did,
        visibility="public",
        namespace_controller_signing_key=env.namespace_sk,
    )
    return f"{name}:example.test", team_sk, team_did


@pytest.mark.asyncio
async def test_repeated_registration_returns_synced_without_duplicate(registering):
    env = registering
    team_id, team_sk, team_did = await _new_registry_team(env)

    first = await _register(env, team_sk, team_id=team_id)
    repeated = await _register(env, team_sk, team_id=team_id)

    assert first.status_code == 200, first.text
    assert first.json()["status"] == "created"
    assert repeated.status_code == 200, repeated.text
    assert repeated.json()["status"] == "synced"
    assert (
        await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.teams}} WHERE team_id=$1 AND team_did_key=$2",
            team_id,
            team_did,
        )
        == 1
    )


@pytest.mark.asyncio
async def test_dry_run_does_not_admit_a_new_team(registering):
    env = registering
    team_id, team_sk, _ = await _new_registry_team(env)

    response = await _register(env, team_sk, team_id=team_id, dry_run=True)

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "dry-run"
    assert response.json()["team_id"] is None
    assert (
        await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.teams}} WHERE team_id=$1",
            team_id,
        )
        == 0
    )


@pytest.mark.asyncio
async def test_concurrent_registration_returns_created_and_synced(registering):
    env = registering
    team_id, team_sk, team_did = await _new_registry_team(env)
    requests = []
    # Both real HTTP requests finish the absent-row read before either INSERT.
    async with env.db.transaction() as tx:
        await tx.execute("LOCK TABLE {{tables.teams}} IN SHARE MODE")
        requests = [
            asyncio.create_task(_register(env, team_sk, team_id=team_id))
            for _ in range(2)
        ]
        try:
            async with asyncio.timeout(10):
                while True:
                    waiting = await env.db.fetch_value(
                        "SELECT count(*) FROM pg_locks WHERE relation='aweb.teams'::regclass "
                        "AND mode='RowExclusiveLock' AND NOT granted",
                    )
                    if waiting == 2:
                        break
                    if any(request.done() for request in requests):
                        raise AssertionError(
                            "Registration ended before both concurrent INSERTs"
                        )
                    await asyncio.sleep(0.01)
        except BaseException:
            for request in requests:
                request.cancel()
            await asyncio.gather(*requests, return_exceptions=True)
            raise

    responses = await asyncio.gather(*requests)
    assert [response.status_code for response in responses] == [200, 200], [
        r.text for r in responses
    ]
    assert sorted(response.json()["status"] for response in responses) == [
        "created",
        "synced",
    ]
    assert (
        await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.teams}} WHERE team_id=$1 AND team_did_key=$2",
            team_id,
            team_did,
        )
        == 1
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("refusal", ["timestamp", "signature"])
@pytest.mark.parametrize("dry_run", [False, True])
async def test_invalid_registration_cannot_advance_the_pin(
    registering, refusal, dry_run
):
    env = registering
    await register_namespace_controller(env, env.namespace_did)
    next_sk, _, next_did = _make_keypair()
    await rotate_team_key(env, env.namespace_sk, env.namespace_did, next_did)
    before = await env.db.fetch_one(
        "SELECT team_did_key, team_key_act_at FROM {{tables.teams}} WHERE team_id=$1",
        TEAM,
    )
    response = await _register(
        env,
        env.team_sk if refusal == "signature" else next_sk,
        dry_run=dry_run,
        timestamp=datetime.now(timezone.utc) - timedelta(hours=1)
        if refusal == "timestamp"
        else None,
    )
    assert response.status_code == 422, response.text
    assert response.json()["detail"]["code"] == "invalid_controller_" + refusal
    assert (
        await env.db.fetch_one(
            "SELECT team_did_key, team_key_act_at FROM {{tables.teams}} WHERE team_id=$1",
            TEAM,
        )
        == before
    )
