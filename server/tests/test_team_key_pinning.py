"""A team key the server admitted is not replaced by an unsigned registry answer.

The registry operator is modelled by writing the registry's own tables: that is
exactly the power the threat gives it. Rotation goes through the real AWID
route. DNS, the root the namespace controller is checked against, is the one
external answer the tests supply.
"""

from __future__ import annotations

import json
import logging
from contextlib import aclosing
from datetime import datetime, timezone
from types import SimpleNamespace

import httpx
import pytest
from aweb.api import create_app
from awid.registry import CachedRegistryClient
from awid.signing import canonical_json_bytes, sign_message
from awid_service.testing import TXTAnswers
from test_dashboard_privacy import TEAM, TEAM_NAME
from test_dashboard_privacy import privacy_app as privacy_app
from test_messages_http import (
    _encode_certificate,
    _make_certificate,
    _make_keypair,
    _signed_team_headers,
)

__all__ = ["privacy_app"]


def _controller_headers(sk, did, payload):
    timestamp = datetime.now(timezone.utc).isoformat()
    signature = sign_message(sk, canonical_json_bytes({**payload, "timestamp": timestamp}))
    return {"Authorization": f"DIDKey {did} {signature}", "X-AWEB-Timestamp": timestamp}


async def register_namespace_controller(env, did: str) -> None:
    """Reuse the independent namespace controller retained by the producer."""
    controller = await env.registry.ensure_namespace(domain="example.test")
    assert controller == env.namespace_sk
    assert did == env.namespace_did


async def rotate_team_key(env, controller_sk, controller_did, new_team_did: str) -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=env.registry_app),
        base_url="http://registry.test",
    ) as registry_http:
        rotated = await registry_http.post(
            f"/v1/namespaces/example.test/teams/{TEAM_NAME}/rotate",
            json={"new_team_did_key": new_team_did},
            headers=_controller_headers(
                controller_sk,
                controller_did,
                {
                    "domain": "example.test",
                    "operation": "rotate_team_key",
                    "name": TEAM_NAME,
                    "new_team_did_key": new_team_did,
                },
            ),
        )
    assert rotated.status_code == 200, rotated.text


async def _substitute_registry_team_key(env, did_key: str) -> None:
    await env.registry_db.execute(
        "UPDATE {{tables.teams}} SET team_did_key = $2 WHERE domain = 'example.test' AND name = $1",
        TEAM_NAME,
        did_key,
    )


def _member(team_sk, team_did, alias):
    sk, _, did = _make_keypair()
    certificate = _encode_certificate(
        _make_certificate(
            team_sk,
            team_did,
            did,
            team_id=TEAM,
            alias=alias,
            identity_scope="local",
            certificate_id=f"pinning-{alias}-{did[-8:]}",
        )
    )
    return sk, did, certificate


async def _connect(env, member):
    agent_sk, agent_did, certificate = member
    body = json.dumps(
        {
            "hostname": "host",
            "workspace_path": f"/work/{agent_did[-8:]}",
            "repo_origin": "",
            "role": "developer",
            "human_name": "member",
            "agent_type": "agent",
        }
    ).encode()
    headers = _signed_team_headers(agent_sk, agent_did, TEAM, certificate, body)
    headers["Content-Type"] = "application/json"
    return await env.client.post("/v1/connect", content=body, headers=headers)


async def _roster(env, member):
    agent_sk, agent_did, certificate = member
    return await env.client.get(
        "/v1/agents", headers=_signed_team_headers(agent_sk, agent_did, TEAM, certificate)
    )


async def _pin(env):
    return await env.db.fetch_one(
        "SELECT team_did_key, team_key_act_at FROM {{tables.teams}} WHERE team_id = $1",
        TEAM,
    )


@pytest.fixture
def pinning(privacy_app, monkeypatch):
    monkeypatch.setenv("AWEB_ENFORCE_TEAM_KEY_PINS", "true")
    env = privacy_app
    env.dns = TXTAnswers({"_awid.example.test": env.namespace_did})
    env.app.state.awid_txt_resolver = env.dns
    return env


@pytest.mark.asyncio
async def test_substituted_registry_team_key_does_not_admit_a_forged_member(pinning):
    env = pinning
    await register_namespace_controller(env, env.namespace_did)
    bob = env.actors["bob"]
    admitted = await env.client.get(
        "/v1/agents",
        headers=_signed_team_headers(bob.sk, bob.did, TEAM, bob.certificate),
    )
    assert admitted.status_code == 200, admitted.text

    forger_team_sk, _, forger_team_did = _make_keypair()
    forger = _member(forger_team_sk, forger_team_did, "mallory")
    await _substitute_registry_team_key(env, forger_team_did)

    connected = await _connect(env, forger)
    roster = await _roster(env, forger)

    assert (connected.status_code, roster.status_code) == (401, 401), (connected.text, roster.text)
    assert (
        connected.json()["detail"]
        == "team_key_unverified: The team key change could not be verified. Ask the team administrator to verify the namespace controller's current key-change record, then retry."
    )
    assert (
        roster.json()["detail"]
        == "team_key_unverified: The team key change could not be verified. Ask the team administrator to verify the namespace controller's current key-change record, then retry."
    )
    assert (
        await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.agents}} WHERE team_id = $1 AND did_key = $2",
            TEAM,
            forger[1],
        )
        == 0
    )
    assert (await _pin(env))["team_did_key"] == env.team_did


@pytest.mark.asyncio
async def test_rotation_signed_by_the_dns_controller_moves_the_pin(pinning):
    env = pinning
    await register_namespace_controller(env, env.namespace_did)
    next_sk, _, next_did = _make_keypair()
    await rotate_team_key(env, env.namespace_sk, env.namespace_did, next_did)

    rotated_member = _member(next_sk, next_did, "dave")
    connected = await _connect(env, rotated_member)

    assert connected.status_code == 200, connected.text
    assert (await _roster(env, rotated_member)).status_code == 200
    pin = await _pin(env)
    assert pin["team_did_key"] == next_did
    assert pin["team_key_act_at"] is not None
    bob = env.actors["bob"]
    former = await env.client.get(
        "/v1/agents", headers=_signed_team_headers(bob.sk, bob.did, TEAM, bob.certificate)
    )
    assert former.status_code == 401, former.text


@pytest.mark.asyncio
async def test_rotation_by_a_controller_dns_does_not_name_is_refused(pinning):
    env = pinning
    # The registry's own namespace row names a controller DNS does not.
    registry_sk, _, registry_did = _make_keypair()
    # Model a dishonest registry row while independent DNS retains the actual controller.
    await env.registry_db.execute(
        "UPDATE {{tables.dns_namespaces}} SET controller_did=$1 WHERE domain='example.test'",
        registry_did,
    )
    next_sk, _, next_did = _make_keypair()
    await rotate_team_key(env, registry_sk, registry_did, next_did)

    response = await _connect(env, _member(next_sk, next_did, "mallory"))

    assert response.status_code == 401, response.text
    assert (
        response.json()["detail"]
        == "team_key_unverified: The team key change could not be verified. Ask the team administrator to verify the namespace controller's current key-change record, then retry."
    )
    assert (await _pin(env))["team_did_key"] == env.team_did


@pytest.mark.asyncio
async def test_an_older_act_cannot_roll_the_pin_back(pinning):
    env = pinning
    await register_namespace_controller(env, env.namespace_did)
    first_sk, _, first_did = _make_keypair()
    await rotate_team_key(env, env.namespace_sk, env.namespace_did, first_did)
    assert (await _connect(env, _member(first_sk, first_did, "erin"))).status_code == 200
    first_act = await env.registry_db.fetch_one(
        "SELECT * FROM {{tables.team_key_acts}} WHERE team_did_key = $1",
        first_did,
    )
    second_sk, _, second_did = _make_keypair()
    await rotate_team_key(env, env.namespace_sk, env.namespace_did, second_did)
    assert (await _connect(env, _member(second_sk, second_did, "frank"))).status_code == 200

    # The registry serves the first key again, with its genuine but older act.
    await env.registry_db.execute(
        "DELETE FROM {{tables.team_key_acts}} WHERE act_id <> $1", first_act["act_id"]
    )
    await _substitute_registry_team_key(env, first_did)
    response = await _connect(env, _member(first_sk, first_did, "grace"))

    assert response.status_code == 401, response.text
    assert (
        response.json()["detail"]
        == "team_key_unverified: The team key change could not be verified. Ask the team administrator to verify the namespace controller's current key-change record, then retry."
    )
    assert (await _pin(env))["team_did_key"] == second_did


@pytest.mark.asyncio
async def test_before_enforcement_a_mismatch_is_logged_and_moves_the_pin(
    pinning, monkeypatch, caplog
):
    env = pinning
    monkeypatch.setenv("AWEB_ENFORCE_TEAM_KEY_PINS", "false")
    await register_namespace_controller(env, env.namespace_did)
    substituted_sk, _, substituted_did = _make_keypair()
    await _substitute_registry_team_key(env, substituted_did)

    with caplog.at_level(logging.WARNING, logger="awid.team_key_acts"):
        # The staged measuring mode serves the registry's key, as before pinning.
        response = await _connect(env, _member(substituted_sk, substituted_did, "measured"))

    assert response.status_code == 200, response.text
    # The key certificates were verified under is the team's one current key here.
    assert (await _pin(env))["team_did_key"] == substituted_did
    lines = [r.getMessage() for r in caplog.records if r.getMessage().startswith("team_key_pin_")]
    assert lines == [
        f"team_key_pin_mismatch team={TEAM} pinned={env.team_did} served={substituted_did} reason=no_act enforced=false",
        f"team_key_pin_moved_without_act team={TEAM} from={env.team_did} to={substituted_did} reason=no_act",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("enforce", ["true", "false"])
async def test_a_served_key_the_act_does_not_name_keeps_the_pin_with_one_act_read(
    pinning, monkeypatch, enforce
):
    env = pinning
    monkeypatch.setenv("AWEB_ENFORCE_TEAM_KEY_PINS", enforce)
    await register_namespace_controller(env, env.namespace_did)
    current_sk, _, current_did = _make_keypair()
    await rotate_team_key(env, env.namespace_sk, env.namespace_did, current_did)
    member = _member(current_sk, current_did, "steady")
    assert (await _connect(env, member)).status_code == 200
    # The registry serves another key beside its genuine latest act, whose
    # signed bytes name the pinned key.
    substituted = _make_keypair()[2]
    await _substitute_registry_team_key(env, substituted)
    await env.registry_db.execute(
        "UPDATE {{tables.team_key_acts}} SET team_did_key = $1 WHERE team_did_key = $2",
        substituted,
        current_did,
    )
    client_type = type(env.app.state.awid_registry_client)
    reads = []
    read_act = client_type.get_team_key_act

    async def counted(self, domain, name):
        reads.append((domain, name))
        return await read_act(self, domain, name)

    monkeypatch.setattr(client_type, "get_team_key_act", counted)

    first = await _roster(env, member)
    assert first.status_code == 200, first.text
    statuses = [(await _roster(env, member)).status_code for _ in range(5)]

    assert statuses == [200] * 5
    assert len(reads) == 1
    assert (await _pin(env))["team_did_key"] == current_did


@pytest.mark.asyncio
async def test_an_embedding_app_without_a_resolver_still_authenticates(pinning):
    # An embedding host may mount aweb's team auth in an app create_app did not build.
    env = pinning
    del env.app.state.awid_txt_resolver
    bob = env.actors["bob"]
    response = await env.client.get(
        "/v1/agents", headers=_signed_team_headers(bob.sk, bob.did, TEAM, bob.certificate)
    )
    assert response.status_code == 200, response.text


@pytest.mark.asyncio
async def test_a_warm_old_key_request_refuses_after_another_worker_moves_the_pin(pinning, monkeypatch):
    env = pinning
    fresh_registry = env.app.state.awid_registry_client
    member = _member(env.team_sk, env.team_did, "warm")
    async with aclosing(CachedRegistryClient(
        registry_url="https://pinning-cache.test", redis_client=env.redis,
        transport=env.registry.transport,
    )) as cached_registry:
        monkeypatch.setattr(env.app.state, "awid_registry_client", cached_registry)
        assert (await _connect(env, member)).status_code == 200
        assert (await _roster(env, member)).status_code == 200
        await register_namespace_controller(env, env.namespace_did)
        next_sk, _, next_did = _make_keypair()
        await rotate_team_key(env, env.namespace_sk, env.namespace_did, next_did)

        # This worker starts after rotation and shares the serving database.
        worker_app = create_app()
        worker_app.state.db = env.infra
        worker_app.state.redis = env.redis
        worker_app.state.awid_registry_client = fresh_registry
        worker_app.state.awid_txt_resolver = env.dns
        worker_app.state.public_origin = env.app.state.public_origin
        worker_app.state.on_mutation = env.app.state.on_mutation
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=worker_app), base_url=env.client.base_url,
        ) as worker:
            moved = await _connect(SimpleNamespace(client=worker), _member(next_sk, next_did, "moved"))
            assert moved.status_code == 200, moved.text
        assert (await _pin(env))["team_did_key"] == next_did
        assert await cached_registry.get_team_public_key("example.test", TEAM_NAME) == env.team_did

        roster = await _roster(env, member)

    assert roster.status_code == 403, roster.text
    assert roster.json()["detail"] == (
        "Team membership is no longer current. "
        "Reconnect with a certificate issued under the team's current key."
    )
