"""How a connect answers when the registry refuses this server a private team's read.

A team deployment reads the registry with ordinary member keys of the teams it
serves, never with the registry service token, which reads every private
team's roster. Its answer to a member of a private team it does not serve is a
403 that says so. Only a server configured with the service token is told to
fix that token.
"""

from __future__ import annotations

import json
import logging
from uuid import uuid4

import httpx
import pytest

from awid.registry import RegistryClient
from test_connect_http import (  # noqa: F401
    _encode_certificate,
    _make_certificate,
    _make_keypair,
    _signed_request,
    connect_app,
)
from test_dashboard_privacy import TEAM, TEAM_NAME, privacy_app  # noqa: F401

REGISTRY_URL = "http://registry.test"


async def _connect(env, team_sk, team_did, team_id, alias):
    agent_sk, _, agent_did = _make_keypair()
    cert = _make_certificate(team_sk, team_did, agent_did, team_id=team_id, alias=alias, identity_scope="local")
    body = json.dumps({
        "hostname": "host", "workspace_path": f"/work/{alias}", "repo_origin": "",
        "role": "developer", "human_name": alias, "agent_type": "agent",
    }).encode()
    headers = _signed_request(agent_sk, agent_did, team_id, body)
    headers["X-AWID-Team-Certificate"] = _encode_certificate(cert)
    headers["Content-Type"] = "application/json"
    return await env.client.post("/v1/connect", content=body, headers=headers)


async def _with_registry_client(env, client):
    """Serve the rest of the test with aweb reading the registry through client."""
    previous = env.app.state.awid_registry_client
    env.app.state.awid_registry_client = client
    return previous


def _member_client(env, served_team_id):
    server_sk, _, _ = _make_keypair()
    return RegistryClient(
        registry_url=REGISTRY_URL,
        transport=httpx.ASGITransport(app=env.registry_app),
        member_signing_keys={served_team_id: bytes(server_sk)},
    )


async def _add_private_team(env, name):
    team_sk, _, team_did = _make_keypair()
    await env.registry_db.execute(
        "INSERT INTO {{tables.teams}} (domain, name, team_did_key, visibility) VALUES ('example.test', $1, $2, 'private')",
        name, team_did,
    )
    return team_sk, team_did


@pytest.mark.asyncio
async def test_member_of_a_private_team_this_server_does_not_serve_gets_403(connect_app, monkeypatch, caplog):
    monkeypatch.delenv("AWID_SERVICE_TOKEN", raising=False)
    client = _member_client(connect_app, TEAM)
    previous = await _with_registry_client(connect_app, client)
    outside = f"outside-{uuid4().hex[:8]}"
    outside_sk, outside_did = await _add_private_team(connect_app, outside)
    caplog.set_level(logging.INFO, logger="aweb.team_auth_deps")
    try:
        resp = await _connect(connect_app, outside_sk, outside_did, f"{outside}:example.test", "outsider")
    finally:
        connect_app.app.state.awid_registry_client = previous
        await client.aclose()

    assert resp.status_code == 403, resp.text
    detail = resp.json()["detail"]
    assert f"team {outside}:example.test is not served by this server" in detail
    assert "AWID_SERVICE_TOKEN" not in detail
    # A team this server does not serve is not a registry fault.
    records = [r for r in caplog.records if r.name == "aweb.team_auth_deps"]
    assert [(r.levelno, r.getMessage()) for r in records] == [
        (logging.INFO, f"Refused team key resolution for team {outside}:example.test, which this server does not serve"),
    ]


@pytest.mark.asyncio
async def test_served_private_team_refusing_this_servers_member_key_names_the_member_certificate(connect_app, monkeypatch):
    monkeypatch.delenv("AWID_SERVICE_TOKEN", raising=False)
    # This server holds a member key for its team, but the registry has no
    # current certificate for it: the team's controller must issue one.
    client = _member_client(connect_app, TEAM)
    previous = await _with_registry_client(connect_app, client)
    await connect_app.registry_db.execute(
        "UPDATE {{tables.teams}} SET visibility = 'private' WHERE domain = 'example.test' AND name = $1", TEAM_NAME,
    )
    try:
        resp = await _connect(connect_app, connect_app.team_sk, connect_app.team_did, TEAM, "newcomer")
    finally:
        connect_app.app.state.awid_registry_client = previous
        await client.aclose()

    assert resp.status_code == 503, resp.text
    detail = resp.json()["detail"]
    assert f"refused this server's member key for team {TEAM}" in detail
    assert "current member certificate" in detail
    assert "AWID_SERVICE_TOKEN" not in detail


@pytest.mark.asyncio
async def test_server_holding_the_service_token_is_told_to_fix_it(connect_app, monkeypatch):
    # privacy_app configures aweb with AWID_SERVICE_TOKEN; this client presents
    # a different one, so the registry's trusted lane refuses it.
    client = RegistryClient(
        registry_url=REGISTRY_URL,
        transport=httpx.ASGITransport(app=connect_app.registry_app),
        service_token="a-token-the-registry-does-not-hold-0123456789",
    )
    previous = await _with_registry_client(connect_app, client)
    outside = f"outside-{uuid4().hex[:8]}"
    outside_sk, outside_did = await _add_private_team(connect_app, outside)
    try:
        resp = await _connect(connect_app, outside_sk, outside_did, f"{outside}:example.test", "outsider")
    finally:
        connect_app.app.state.awid_registry_client = previous
        await client.aclose()

    assert resp.status_code == 503, resp.text
    assert "AWID_SERVICE_TOKEN" in resp.json()["detail"]
