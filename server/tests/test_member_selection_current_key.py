"""Recipient selection cannot restore a membership removed by real rotation."""

import json
from uuid import uuid4

import pytest

from aweb.internal_auth import build_internal_auth_header_value
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_member_team_key import _certificate, _change_key, _connect, _new_member, _row
from test_messages_http import _signed_identity_headers
from test_team_key_pinning import pinning  # noqa: F401


async def _send(env, sender, recipient, agent_id, *, kind, selector):
    if kind == "mail":
        target = {
            "alias": {"to_alias": recipient[2]},
            "id": {"to_agent_id": agent_id},
            "did": {"to_did": recipient[1]},
            "address": {"to_address": f"example.test/{recipient[2]}"},
        }[selector]
        path = "/v1/messages"
        payload = {**target, "subject": "membership", "body": "membership test"}
    else:
        target = {
            "alias": {"to_aliases": [recipient[2]]},
            "did": {"to_dids": [recipient[1]]},
            "address": {"to_addresses": [f"example.test/{recipient[2]}"]},
        }[selector]
        path = "/v1/chat/sessions"
        payload = {**target, "message": "membership test"}
    body = json.dumps(payload).encode()
    headers = _signed_identity_headers(sender[0], sender[1], "", body)
    headers["Content-Type"] = "application/json"
    return await env.client.post(path, headers=headers, content=body)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,selector", [
    ("mail", "alias"), ("mail", "id"), ("mail", "did"), ("mail", "address"),
    ("chat", "alias"), ("chat", "did"), ("chat", "address"),
])
async def test_every_local_selector_requires_current_membership(pinning, kind, selector):
    env = pinning
    sender, recipient = _new_member("selectsender"), _new_member("selectrecipient")
    for member in (sender, recipient):
        cert = _certificate(env.team_sk, env.team_did, member, member[2] + "-before")
        assert (await _connect(env, member, cert)).status_code == 200
    recipient_id = str((await _row(env, recipient))["agent_id"])
    before = await _send(env, sender, recipient, recipient_id, kind=kind, selector=selector)
    assert before.status_code == 200, before.text

    next_sk, next_did = await _change_key(env)
    assert (await _connect(env, sender, _certificate(next_sk, next_did, sender, "sender-after"))).status_code == 200
    refused = await _send(env, sender, recipient, recipient_id, kind=kind, selector=selector)
    assert refused.status_code == 404, refused.text

    assert (await _connect(env, recipient, _certificate(next_sk, next_did, recipient, "recipient-after"))).status_code == 200
    after = await _send(env, sender, recipient, recipient_id, kind=kind, selector=selector)
    assert after.status_code == 200, after.text


def _proxy_headers(actor_id):
    key_id = str(uuid4())
    return {
        "X-Team-ID": TEAM, "X-API-Key": key_id, "X-AWEB-Actor-ID": actor_id,
        "X-AWEB-Auth": build_internal_auth_header_value(
            secret="r2-disposable-proxy-secret", team_id=TEAM, principal_type="k",
            principal_id=key_id, actor_id=actor_id,
        ),
    }


@pytest.mark.asyncio
async def test_trusted_proxy_does_not_restore_superseded_actor(pinning, monkeypatch):
    env = pinning
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "true")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", "r2-disposable-proxy-secret")
    member = _new_member("proxyactor")
    assert (await _connect(env, member, _certificate(env.team_sk, env.team_did, member, "proxy-before"))).status_code == 200
    actor_id = str((await _row(env, member))["agent_id"])
    headers = _proxy_headers(actor_id)
    path = f"/v1/apps/installed?team_id={TEAM}"
    before = await env.client.get(path, headers=headers)
    assert before.status_code == 200, before.text

    next_sk, next_did = await _change_key(env)
    refused = await env.client.get(path, headers=headers)
    assert refused.status_code == 403, refused.text
    assert refused.json()["detail"] == "Team membership is no longer current. Reconnect with a certificate issued under the team's current key."

    assert (await _connect(env, member, _certificate(next_sk, next_did, member, "proxy-after"))).status_code == 200
    after = await env.client.get(path, headers=headers)
    assert after.status_code == 200, after.text
