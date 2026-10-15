"""Status-host designation through the real app, AWID registry, PostgreSQL and Redis.

An agent names the one team member whose signed status reports speak for it
(aweb-acah.3, docs/agent-health.md). Only fixture provisioning uses SQL; auth,
routing and storage are the production code paths.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json

import pytest

from awid.signing import canonical_json_bytes, sign_message
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_messages_http import _make_keypair, _signed_team_headers


async def _team_request(env, actor, method, path, body=None):
    identity = env.actors[actor]
    content = json.dumps(body).encode() if body is not None else b""
    headers = _signed_team_headers(identity.sk, identity.did, TEAM, identity.certificate, content)
    headers["Content-Type"] = "application/json"
    return await env.client.request(method, path, content=content, headers=headers)


async def _controller_request(env, alias, *, host_did, previous_host_did, signer=None):
    signing_key, signer_did = signer or (env.team_sk, env.team_did)
    timestamp = datetime.now(timezone.utc).isoformat()
    canonical = canonical_json_bytes({
        "operation": "set_agent_status_host",
        "team_id": TEAM,
        "agent_alias": alias,
        "host_did": host_did,
        "previous_host_did": previous_host_did,
        "timestamp": timestamp,
    })
    body = {"team_id": TEAM, "host_did": host_did, "previous_host_did": previous_host_did}
    return await env.client.put(
        f"/v1/agents/{alias}/status-host",
        content=json.dumps(body).encode(),
        headers={
            "Authorization": f"DIDKey {signer_did} {sign_message(signing_key, canonical)}",
            "X-AWEB-Timestamp": timestamp,
            "Content-Type": "application/json",
        },
    )


async def _stored_host(env, actor):
    row = await env.db.fetch_one(
        "SELECT host_did, designated_by_did FROM {{tables.agent_status_hosts}} WHERE agent_id = $1",
        env.actors[actor].id,
    )
    return dict(row) if row else None


@pytest.mark.asyncio
async def test_agent_designates_a_team_member_as_its_status_host(privacy_app):
    env = privacy_app
    bob = env.actors["bob"].did

    response = await _team_request(env, "alice", "PUT", "/v1/agents/me/status-host", {"host_did": bob})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["alias"] == "alice"
    assert body["host_did"] == bob
    assert body["designated_by_did"] == env.actors["alice"].did
    assert await _stored_host(env, "alice") == {"host_did": bob, "designated_by_did": env.actors["alice"].did}

    shown = await _team_request(env, "alice", "GET", "/v1/agents/me/status-host")
    assert shown.status_code == 200, shown.text
    assert shown.json()["host_did"] == bob
    assert shown.json()["host_active"] is True


@pytest.mark.asyncio
async def test_designation_is_replaced_and_cleared(privacy_app):
    env = privacy_app
    bob, carol = env.actors["bob"].did, env.actors["carol"].did

    assert (await _team_request(env, "alice", "PUT", "/v1/agents/me/status-host", {"host_did": bob})).status_code == 200
    replaced = await _team_request(env, "alice", "PUT", "/v1/agents/me/status-host", {"host_did": carol})
    assert replaced.status_code == 200, replaced.text
    assert (await _stored_host(env, "alice"))["host_did"] == carol

    for _ in range(2):
        cleared = await _team_request(env, "alice", "DELETE", "/v1/agents/me/status-host")
        assert cleared.status_code == 200, cleared.text
        assert cleared.json()["host_did"] is None
    assert await _stored_host(env, "alice") is None
    shown = await _team_request(env, "alice", "GET", "/v1/agents/me/status-host")
    assert shown.json()["host_did"] is None
    assert shown.json()["host_active"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "host_did,detail",
    [
        ("outsider", "host_did is not an active member of this team"),
        ("did:aw:2CiZ88hVF4JuQim8nnSuyeiV2HF2", "host_did must be a did:key"),
        ("", "host_did must be a did:key"),
    ],
)
async def test_designation_refuses_a_host_that_is_not_a_member_did_key(privacy_app, host_did, detail):
    env = privacy_app
    if host_did == "outsider":
        _, _, host_did = _make_keypair()

    response = await _team_request(env, "alice", "PUT", "/v1/agents/me/status-host", {"host_did": host_did})

    assert response.status_code == 422, response.text
    assert response.json()["detail"] == detail
    assert await _stored_host(env, "alice") is None


@pytest.mark.asyncio
async def test_designation_refuses_a_deleted_member_as_host(privacy_app):
    env = privacy_app
    await env.db.execute(
        "UPDATE {{tables.agents}} SET deleted_at = NOW(), status = 'deleted' WHERE agent_id = $1",
        env.actors["bob"].id,
    )

    response = await _team_request(
        env, "alice", "PUT", "/v1/agents/me/status-host", {"host_did": env.actors["bob"].did},
    )

    assert response.status_code == 422, response.text
    assert response.json()["detail"] == "host_did is not an active member of this team"


@pytest.mark.asyncio
async def test_grant_callers_cannot_designate(privacy_app):
    env = privacy_app
    for method in ("PUT", "DELETE", "GET"):
        response = await env.client.request(
            method,
            "/v1/agents/me/status-host",
            headers={"Authorization": "AWEB-Grant DIDKey did:key:z6Mkexample sig"},
        )
        assert response.status_code == 403, response.text
        assert response.json()["detail"] == "outside grant scope"


@pytest.mark.asyncio
async def test_host_that_left_the_team_is_shown_inactive(privacy_app):
    env = privacy_app
    bob = env.actors["bob"].did
    assert (await _team_request(env, "alice", "PUT", "/v1/agents/me/status-host", {"host_did": bob})).status_code == 200
    await env.db.execute(
        "UPDATE {{tables.agents}} SET deleted_at = NOW(), status = 'deleted' WHERE agent_id = $1",
        env.actors["bob"].id,
    )

    shown = await _team_request(env, "alice", "GET", "/v1/agents/me/status-host")

    assert shown.status_code == 200, shown.text
    assert shown.json()["host_did"] == bob
    assert shown.json()["host_active"] is False


@pytest.mark.asyncio
async def test_controller_sets_and_clears_with_the_current_host_as_precondition(privacy_app):
    env = privacy_app
    bob, carol = env.actors["bob"].did, env.actors["carol"].did

    first = await _controller_request(env, "alice", host_did=bob, previous_host_did="")
    assert first.status_code == 200, first.text
    assert first.json()["designated_by_did"] == env.team_did
    assert await _stored_host(env, "alice") == {"host_did": bob, "designated_by_did": env.team_did}

    stale = await _controller_request(env, "alice", host_did=carol, previous_host_did="")
    assert stale.status_code == 409, stale.text
    assert stale.json()["detail"] == "Status host changed since previous_host_did"
    assert (await _stored_host(env, "alice"))["host_did"] == bob

    cleared = await _controller_request(env, "alice", host_did="", previous_host_did=bob)
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["host_did"] is None
    assert await _stored_host(env, "alice") is None


@pytest.mark.asyncio
async def test_controller_path_refuses_a_member_signature(privacy_app):
    env = privacy_app
    alice = env.actors["alice"]

    response = await _controller_request(
        env, "alice", host_did=env.actors["bob"].did, previous_host_did="", signer=(alice.sk, alice.did),
    )

    assert response.status_code == 403, response.text
    assert response.json()["detail"] == "Team controller authorization is required to set a status host"
    assert await _stored_host(env, "alice") is None


@pytest.mark.asyncio
async def test_controller_path_refuses_a_non_member_host(privacy_app):
    env = privacy_app
    _, _, outsider = _make_keypair()

    response = await _controller_request(env, "alice", host_did=outsider, previous_host_did="")

    assert response.status_code == 422, response.text
    assert response.json()["detail"] == "host_did is not an active member of this team"


@pytest.mark.asyncio
async def test_retiring_the_agent_removes_its_designation(privacy_app):
    env = privacy_app
    assert (await _team_request(
        env, "alice", "PUT", "/v1/agents/me/status-host", {"host_did": env.actors["bob"].did},
    )).status_code == 200

    retired = await _team_request(env, "alice", "DELETE", f"/v1/workspaces/{env.actors['alice'].workspace}")

    assert retired.status_code == 200, retired.text
    assert await _stored_host(env, "alice") is None
