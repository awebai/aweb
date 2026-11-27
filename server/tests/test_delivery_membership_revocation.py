"""Revoked membership cannot grant same-team delivery; identity residence survives."""

import base64
import json
from uuid import UUID

import pytest

from aweb.application_state import application_registry_client
from messaging_actor_support import (
    RegisteredMessagingActor,
    admit_messaging_actor,
    register_messaging_team,
)
from test_current_member_selector_surfaces import _admit, _http
from test_dashboard_privacy import TEAM
from test_dashboard_privacy import privacy_app as privacy_app
from test_team_key_pinning import pinning as pinning

__all__ = ["pinning"]


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("revoked", ["recipient", "sender-with-other-team"])
@pytest.mark.parametrize("inbound_mode", ["open", "team_and_contacts"])
async def test_same_team_delivery_requires_unrevoked_membership(
    pinning, kind, revoked, inbound_mode
):
    env = pinning
    sender = await _admit(env, "revocationsender", global_identity=True)
    recipient = await _admit(env, "revocationrecipient", global_identity=True)
    preference = await _http(
        env,
        recipient,
        "PATCH",
        "/v1/agents/me/inbound-mode",
        {"inbound_mode": inbound_mode},
        identity_only=False,
    )
    assert preference.status_code == 200, preference.text
    if revoked == "sender-with-other-team":
        other_team = "remaining:example.test"
        await register_messaging_team(env, team_id=other_team)
        existing = RegisteredMessagingActor(
            signing_key=sender.sk,
            did_key=sender.did,
            stable_id=sender.stable,
            address=sender.address,
            team_id=TEAM,
            agent_id=str(sender.id),
            certificate=sender.certificate,
        )
        other = await admit_messaging_actor(
            env, alias="remainingmember", team_id=other_team, existing_identity=existing
        )
        assert other.stable_id == sender.stable and other.agent_id != str(sender.id)
        subject = sender
    else:
        subject = recipient
    certificate_id = json.loads(base64.b64decode(subject.certificate))["certificate_id"]
    name, domain = TEAM.split(":", 1)
    await application_registry_client(env.app.state).revoke_team_certificate(
        domain,
        name,
        team_controller_signing_key=env.team_sk,
        certificate_id=certificate_id,
    )
    row = await env.db.fetch_one(
        "SELECT a.status, a.accepted_team_did_key, t.team_did_key "
        "FROM {{tables.agents}} a JOIN {{tables.teams}} t USING(team_id) "
        "WHERE a.agent_id=$1",
        subject.id,
    )
    assert row["status"] == "active"
    assert row["accepted_team_did_key"] == row["team_did_key"]
    before_mail = await env.db.fetch_value("SELECT COUNT(*) FROM {{tables.messages}}")
    before_chat = await env.db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.chat_messages}}"
    )
    path, payload = (
        ("/v1/messages", {"to_address": recipient.address, "body": "revocation policy"})
        if kind == "mail"
        else (
            "/v1/chat/sessions",
            {"to_addresses": [recipient.address], "message": "revocation policy"},
        )
    )
    response = await _http(env, sender, "POST", path, payload, identity_only=True)
    expected = 200 if inbound_mode == "open" else 403
    assert response.status_code == expected, response.text
    if expected == 403:
        assert "verified team members" in response.text
        assert (
            await env.db.fetch_value("SELECT COUNT(*) FROM {{tables.messages}}")
            == before_mail
        )
        assert (
            await env.db.fetch_value("SELECT COUNT(*) FROM {{tables.chat_messages}}")
            == before_chat
        )
    elif kind == "mail":
        stored = await env.db.fetch_one(
            "SELECT from_did, to_did, body FROM {{tables.messages}} WHERE message_id=$1",
            UUID(response.json()["message_id"]),
        )
        assert (stored["from_did"], stored["to_did"], stored["body"]) == (
            sender.stable,
            recipient.stable,
            "revocation policy",
        )
    else:
        stored = await env.db.fetch_one(
            "SELECT from_did, body FROM {{tables.chat_messages}} WHERE session_id=$1",
            UUID(response.json()["session_id"]),
        )
        assert (stored["from_did"], stored["body"]) == (
            sender.stable,
            "revocation policy",
        )
