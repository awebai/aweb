"""Local-only refusals retain their owner across actual send and discovery callers."""

import json
from dataclasses import replace
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from fastapi import HTTPException, Request

from aweb.identity_auth_deps import MessagingAuth
from aweb.routes.messaging import participant
from messaging_actor_support import register_messaging_team
from test_mcp_mail_conversation_parity import mail_server as mail_server
from test_messages_http import (
    _encode_certificate,
    _make_certificate,
    _make_keypair,
    _signed_identity_headers,
    _signed_team_headers,
)


async def admitted_local_recipient(server, *, team="eng:acme.com"):
    """Issue, register and connect a local member under its real team controller."""
    env = server.fixture
    await register_messaging_team(env, team_id=team)
    sk, _, did = _make_keypair()
    fields = _make_certificate(
        env.team_sk, env.team_did, did, team_id=team, alias="local-bob",
        identity_scope="local", certificate_id=f"local-policy-{uuid4()}",
    )
    certificate = _encode_certificate(fields)
    await server.registry.register_team_certificate(
        "acme.com", team.split(":")[0], team_controller_signing_key=env.team_sk,
        certificate_id=fields["certificate_id"], member_did_key=did,
        member_did_aw=None, member_address=None, alias="local-bob",
        identity_scope="local", certificate=certificate,
    )
    body = b'{"agent_type":"agent"}'
    connected = await env.client.post(
        "/v1/connect", content=body,
        headers={**_signed_team_headers(sk, did, team, certificate, body),
                 "Content-Type": "application/json"},
    )
    assert connected.status_code == 200, connected.text
    return SimpleNamespace(
        sk=sk, did=did, id=connected.json()["agent_id"], team=team,
        alias="local-bob", certificate=certificate,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("selector", ["did", "qualified-alias"])
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_mcp_local_only_targets_keep_not_routable_action_and_reason(
    mail_server, selector, kind
):
    env = mail_server
    bob = await admitted_local_recipient(env)
    target = bob.did if selector == "did" else "eng~local-bob"
    tool = "send_mail" if kind == "mail" else "send_chat"
    content = {"body": "refused mail"} if kind == "mail" else {"message": "refused chat"}
    refused = await env.mcp_call(tool, to=target, plaintext=True, **content)
    assert refused == {
        "error": "The recipient is not a registered address. A local identity has no address and is reachable only from inside its own team, by alias; a global identity is reachable by address once one is assigned. Check the address or use a teammate alias and retry.",
        "reason": "local_recipient_route_missing",
    }
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.messages}}") == 0
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.chat_messages}}") == 0


@pytest.mark.asyncio
async def test_http_local_agent_id_refusal_keeps_published_404(mail_server):
    env = mail_server
    bob = await admitted_local_recipient(env)
    body = json.dumps({"to_agent_id": bob.id, "body": "refused mail"}).encode()
    refused = await env.client.post(
        "/v1/messages", content=body,
        headers={**_signed_identity_headers(env.pilot_key, env.pilot_did, env.pilot_stable, body),
                 "X-Team-ID": "ops:acme.com", "Content-Type": "application/json"},
    )
    assert refused.status_code == 404, refused.text
    assert refused.json()["reason"] == "local_recipient_route_missing"
    assert refused.json()["retryable"] is False
    assert refused.json()["correlation_id"]
    assert "reachable only from inside its own team" in refused.json()["detail"]
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.messages}}") == 0


@pytest.mark.asyncio
async def test_participant_discovery_retains_legacy_403_and_member_neighbor(mail_server):
    env = mail_server
    bob = await admitted_local_recipient(env)
    request = Request({"type": "http", "app": env.fixture.app, "headers": []})
    # Component boundary: selected-team context is not verified team membership.
    outsider = MessagingAuth(
        did_key=env.pilot_did, did_aw=env.pilot_stable, address=None,
        team_id=bob.team, verified_team_id="ops:acme.com",
    )
    with pytest.raises(HTTPException) as refused:
        await participant(bob.alias, request, db=env.fixture.infra, auth=outsider)
    assert refused.value.status_code == 403
    assert "reachable only from inside its own team" in refused.value.detail
    member = replace(outsider, did_key=bob.did, did_aw=None, verified_team_id=bob.team)
    accepted = await participant(bob.alias, request, db=env.fixture.infra, auth=member)
    assert accepted["did_key"] == bob.did
    assert accepted["agent_id"] == str(UUID(bob.id))
