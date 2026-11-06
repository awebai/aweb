"""AWID rotation replaces controller authority even when OSS retains its hint.

Only setup uses SQL. Rotation, controller signatures, OSS route authorization
and mutations use the real apps with PostgreSQL, Redis and the AWID client.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio

import awid.registry as registry_module
from awid.registry import CachedRegistryClient
from awid.signing import canonical_json_bytes, sign_message
from test_dashboard_privacy import TEAM, TEAM_NAME, privacy_app  # noqa: F401
from test_messages_http import _make_keypair


def _headers(sk, did, payload):
    timestamp = datetime.now(timezone.utc).isoformat()
    signature = sign_message(sk, canonical_json_bytes({**payload, "timestamp": timestamp}))
    return {
        "Authorization": f"DIDKey {did} {signature}",
        "X-AWEB-Timestamp": timestamp,
    }


async def _controller_action(env, operation, sk, did):
    if operation == "status_host":
        previous = await env.db.fetch_value(
            "SELECT host_did FROM {{tables.agent_status_hosts}} WHERE agent_id=$1",
            env.actors["alice"].id,
        ) or ""
        # Alternate hosts so every accepted request performs a real change.
        host = env.actors["carol" if previous == env.actors["bob"].did else "bob"].did
        body = {"team_id": TEAM, "host_did": host, "previous_host_did": previous}
        signed = {**body, "operation": "set_agent_status_host", "agent_alias": "alice"}
        response = await env.client.put(
            "/v1/agents/alice/status-host", json=body, headers=_headers(sk, did, signed),
        )
        stored = await env.db.fetch_value(
            "SELECT host_did FROM {{tables.agent_status_hosts}} WHERE agent_id=$1",
            env.actors["alice"].id,
        )
        return response, stored, host

    previous = await env.db.fetch_value(
        "SELECT did_key FROM {{tables.agents}} WHERE agent_id=$1", env.actors["alice"].id,
    )
    _, _, next_key = _make_keypair()
    body = {
        "team_id": TEAM, "old_did_key": previous, "new_did_key": next_key,
        "old_certificate_id": "rotation-old", "new_certificate_id": "rotation-new",
    }
    signed = {**body, "operation": "replace_local_identity_key", "agent_alias": "alice"}
    response = await env.client.post(
        "/v1/agents/alice/replace-key", json=body, headers=_headers(sk, did, signed),
    )
    stored = await env.db.fetch_value(
        "SELECT did_key FROM {{tables.agents}} WHERE agent_id=$1", env.actors["alice"].id,
    )
    return response, stored, next_key


@pytest_asyncio.fixture
async def rotation_app(privacy_app):
    env = privacy_app
    registry = CachedRegistryClient(
        registry_url=f"http://registry-{uuid4().hex}.test", redis_client=env.redis,
        transport=httpx.ASGITransport(app=env.registry_app),
    )
    original = env.app.state.awid_registry_client
    env.app.state.awid_registry_client = registry
    try:
        yield env
    finally:
        env.app.state.awid_registry_client = original
        await registry.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["replace_key", "status_host"])
@pytest.mark.parametrize("age", [59, 61])
async def test_awid_rotation_replaces_oss_controller_authority(rotation_app, monkeypatch, operation, age):
    env = rotation_app
    clock = [1_000_000]
    monkeypatch.setattr(registry_module, "_cache_now", lambda: clock[0])
    namespace_sk, _, namespace_did = _make_keypair()
    next_sk, _, next_did = _make_keypair()
    await env.registry_db.execute(
        "INSERT INTO {{tables.dns_namespaces}} (domain, controller_did, verification_status) "
        "VALUES ('example.test', $1, 'verified')", namespace_did,
    )

    # The controller has working authority before rotation; a member does not.
    member = env.actors["bob"]
    refused, _, _ = await _controller_action(env, operation, member.sk, member.did)
    assert refused.status_code == 403, refused.text
    before, stored, expected = await _controller_action(env, operation, env.team_sk, env.team_did)
    assert before.status_code == 200, before.text
    assert stored == expected
    # Warm the real SDK cache even on the unfixed server, whose controller
    # routes currently bypass it. The fix must honor its freshness bound.
    assert await env.app.state.awid_registry_client.get_team_public_key("example.test", TEAM_NAME) == env.team_did

    # Rotate through the actual namespace-controller-authorized AWID endpoint.
    # The OSS database deliberately keeps its original, now stale key hint.
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=env.registry_app), base_url="http://registry.test",
    ) as registry_http:
        rotated = await registry_http.post(
            f"/v1/namespaces/example.test/teams/{TEAM_NAME}/rotate",
            json={"new_team_did_key": next_did},
            headers=_headers(namespace_sk, namespace_did, {
                "domain": "example.test", "operation": "rotate_team_key",
                "name": TEAM_NAME, "new_team_did_key": next_did,
            }),
        )
        assert rotated.status_code == 200, rotated.text
        assert rotated.json()["key_changed"] is True
        current = await registry_http.get(f"/v1/namespaces/example.test/teams/{TEAM_NAME}")
        assert current.status_code == 200, current.text
        assert current.json()["team_did_key"] == next_did
    assert await env.db.fetch_value(
        "SELECT team_did_key FROM {{tables.teams}} WHERE team_id=$1", TEAM,
    ) == env.team_did
    clock[0] += age

    # Both requests have valid signatures and live mutation preconditions.
    # Read the current precondition for each, so acceptance of the old key
    # cannot cause a neighboring conflict to mask the new controller's result.
    old, old_stored, old_expected = await _controller_action(env, operation, env.team_sk, env.team_did)
    new, stored, expected = await _controller_action(env, operation, next_sk, next_did)
    expected_statuses = (200, 403) if age < 60 else (403, 200)
    assert (old.status_code, new.status_code) == expected_statuses, {
        "former_controller": {"status": old.status_code, "body": old.json()},
        "current_controller": {"status": new.status_code, "body": new.json()},
    }
    if age < 60:
        assert old_stored == old_expected == stored
    else:
        assert old_stored != old_expected
        assert stored == expected
