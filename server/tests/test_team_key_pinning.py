"""A team key the server admitted is not replaced by an unsigned registry answer.

The registry operator is modelled by writing the registry's own table: that is
exactly the power the threat gives it. Everything else is the real AWID app,
the real aweb app and the real team-auth dependency.
"""

from __future__ import annotations

import json

import pytest

from test_dashboard_privacy import TEAM, TEAM_NAME, privacy_app  # noqa: F401
from test_messages_http import (
    _encode_certificate,
    _make_certificate,
    _make_keypair,
    _signed_team_headers,
)


async def _substitute_registry_team_key(env, did_key: str) -> None:
    await env.registry_db.execute(
        "UPDATE {{tables.teams}} SET team_did_key = $2 WHERE domain = 'example.test' AND name = $1",
        TEAM_NAME, did_key,
    )


async def _connect(env, agent_sk, agent_did, certificate):
    body = json.dumps({
        "hostname": "host", "workspace_path": "/work/mallory", "repo_origin": "",
        "role": "developer", "human_name": "mallory", "agent_type": "agent",
    }).encode()
    headers = _signed_team_headers(agent_sk, agent_did, TEAM, certificate, body)
    headers["Content-Type"] = "application/json"
    return await env.client.post("/v1/connect", content=body, headers=headers)


@pytest.mark.asyncio
async def test_substituted_registry_team_key_does_not_admit_a_forged_member(privacy_app):
    env = privacy_app
    bob = env.actors["bob"]
    admitted = await env.client.get(
        "/v1/agents", headers=_signed_team_headers(bob.sk, bob.did, TEAM, bob.certificate),
    )
    assert admitted.status_code == 200, admitted.text

    forger_team_sk, _, forger_team_did = _make_keypair()
    forger_sk, _, forger_did = _make_keypair()
    forged = _encode_certificate(_make_certificate(
        forger_team_sk, forger_team_did, forger_did, team_id=TEAM, alias="mallory",
        identity_scope="local", certificate_id="forged-mallory",
    ))
    await _substitute_registry_team_key(env, forger_team_did)

    connected = await _connect(env, forger_sk, forger_did, forged)
    roster = await env.client.get(
        "/v1/agents", headers=_signed_team_headers(forger_sk, forger_did, TEAM, forged),
    )

    assert (connected.status_code, roster.status_code) == (401, 401), (connected.text, roster.text)
    assert connected.json()["detail"] == "team_key_unverified"
    assert roster.json()["detail"] == "team_key_unverified"
    assert await env.db.fetch_value(
        "SELECT count(*) FROM {{tables.agents}} WHERE team_id = $1 AND did_key = $2", TEAM, forger_did,
    ) == 0
