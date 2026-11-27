"""HTTP and native MCP keep a global identity independent of team selection."""

from __future__ import annotations

import json
from uuid import uuid4

import pytest
from mcp_runtime_fixtures import mounted_mcp
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import TEAM
from test_dashboard_privacy import privacy_app as privacy_app
from test_messages_http import (
    _encode_certificate,
    _make_certificate,
    _signed_identity_headers,
    _signed_team_headers,
)

__all__ = ["privacy_app"]


async def _connect_global_member(env, *, actor, team_id: str, stable_did: str) -> str:
    certificate = _encode_certificate(
        _make_certificate(
            env.team_sk,
            env.team_did,
            actor.did,
            team_id=team_id,
            alias="bob",
            identity_scope="global",
            member_did_aw=stable_did,
            certificate_id="multi-" + uuid4().hex,
        )
    )
    body = b"{}"
    response = await env.client.post(
        "/v1/connect",
        content=body,
        headers={
            **_signed_team_headers(actor.sk, actor.did, team_id, certificate, body),
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 200, response.text
    return certificate


async def _call_tool(
    env, *, actor, stable_did: str, name: str, certificate=None, team_id=TEAM
):
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": {}},
        }
    ).encode()
    headers = (
        _signed_team_headers(actor.sk, actor.did, team_id, certificate, body)
        if certificate is not None
        else _signed_identity_headers(actor.sk, actor.did, stable_did, body)
    )
    response = await env.client.post(
        "/mcp/",
        content=body,
        headers={
            **headers,
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
    )
    assert response.status_code == 200, response.text
    result = response.json()
    assert "error" not in result, result
    assert not result["result"].get("isError"), result
    return json.loads(result["result"]["content"][0]["text"])


@pytest.mark.asyncio
@pytest.mark.parametrize("membership_count", [1, 2], ids=["one-team", "two-teams"])
async def test_global_identity_reads_use_same_auth_for_http_and_mcp(
    privacy_app, membership_count
):
    # Source model: Global And Local Identities (docs/identity-messaging-contract.md:124-144)
    # and Continuations (docs/identity-messaging-contract.md:282-296). A global
    # participant is one DID; two memberships do not require a team choice
    # for its inbox. A presented team certificate still selects that team.
    env = privacy_app
    actor = env.actors["bob"]
    async with registry_listener(env) as (registry, _):
        stable = (await registry.register_did(actor.did, actor.sk)).did_aw
        certificates = {
            TEAM: await _connect_global_member(
                env, actor=actor, team_id=TEAM, stable_did=stable
            )
        }
        if membership_count == 2:
            # Namespace control is fixture provisioning; team creation and
            # admission go through real signed registry and native routes.
            second_name = "second-" + uuid4().hex[:12]
            second = await registry.register_team(
                domain="example.test",
                name=second_name,
                display_name="Second team",
                team_did_key=env.team_did,
                visibility="public",
                namespace_controller_signing_key=env.namespace_sk,
            )
            certificates[second.team_id] = await _connect_global_member(
                env, actor=actor, team_id=second.team_id, stable_did=stable
            )
        inbox = await env.client.get(
            "/v1/messages/inbox",
            headers=_signed_identity_headers(actor.sk, actor.did, stable),
        )
        assert inbox.status_code == 200, inbox.text
        pending = await env.client.get(
            "/v1/chat/pending",
            headers=_signed_identity_headers(actor.sk, actor.did, stable),
        )
        assert pending.status_code == 200, pending.text
        async with mounted_mcp(
            env.app,
            db_infra=env.infra,
            redis=env.redis,
            registry_client=registry,
        ):
            for team_id, certificate in certificates.items():
                selected = await _call_tool(
                    env,
                    actor=actor,
                    stable_did=stable,
                    name="whoami",
                    certificate=certificate,
                    team_id=team_id,
                )
                assert selected["team_id"] == team_id
                assert selected["agent_id"]
            mail = await _call_tool(
                env, actor=actor, stable_did=stable, name="check_mail"
            )
            assert "error" not in mail, mail
            identity = await _call_tool(
                env, actor=actor, stable_did=stable, name="whoami"
            )
            assert identity["did_aw"] == stable
            if membership_count == 2:
                assert identity["team_id"] is None
                assert identity["agent_id"] is None
