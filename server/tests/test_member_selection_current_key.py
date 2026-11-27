"""Recipient selection cannot restore a membership removed by real rotation."""

import json
from enum import StrEnum
from uuid import uuid4

import pytest
from aweb.internal_auth import build_internal_auth_header_value
from test_dashboard_privacy import TEAM
from test_dashboard_privacy import privacy_app as privacy_app
from test_member_team_key import _certificate, _change_key, _connect, _new_member, _row
from test_messages_http import _signed_identity_headers
from test_team_key_pinning import pinning as pinning

__all__ = ["pinning"]


@pytest.fixture(autouse=True)
def proxy_settings_before_application_construction(monkeypatch):
    """The real application may capture these settings when its fixture starts."""
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "true")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", "r2-disposable-proxy-secret")


class MessageTransport(StrEnum):
    MAIL = "mail"
    CHAT = "chat"


class RecipientSelector(StrEnum):
    ALIAS = "alias"
    QUALIFIED_ALIAS = "qualified-alias"
    AGENT_ID = "id"
    DID = "did"
    ADDRESS = "address"


async def _send(
    env,
    *,
    sender,
    recipient,
    agent_id,
    kind: MessageTransport,
    selector: RecipientSelector,
):
    if kind is MessageTransport.MAIL:
        target = {
            RecipientSelector.ALIAS: {"to_alias": recipient[2]},
            RecipientSelector.QUALIFIED_ALIAS: {
                "to_alias": TEAM.split(":", 1)[0] + "~" + recipient[2]
            },
            RecipientSelector.AGENT_ID: {"to_agent_id": agent_id},
            RecipientSelector.DID: {"to_did": recipient[1]},
            RecipientSelector.ADDRESS: {"to_address": f"example.test/{recipient[2]}"},
        }[selector]
        path = "/v1/messages"
        payload = {**target, "subject": "membership", "body": "membership test"}
    else:
        target = {
            RecipientSelector.ALIAS: {"to_aliases": [recipient[2]]},
            RecipientSelector.QUALIFIED_ALIAS: {
                "to_aliases": [TEAM.split(":", 1)[0] + "~" + recipient[2]]
            },
            RecipientSelector.DID: {"to_dids": [recipient[1]]},
            RecipientSelector.ADDRESS: {
                "to_addresses": [f"example.test/{recipient[2]}"]
            },
        }[selector]
        path = "/v1/chat/sessions"
        payload = {**target, "message": "membership test"}
    body = json.dumps(payload).encode()
    headers = _signed_identity_headers(sender[0], sender[1], "", body)
    headers["Content-Type"] = "application/json"
    return await env.client.post(path, headers=headers, content=body)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind,selector",
    [
        (MessageTransport.MAIL, RecipientSelector.ALIAS),
        (MessageTransport.MAIL, RecipientSelector.QUALIFIED_ALIAS),
        (MessageTransport.MAIL, RecipientSelector.AGENT_ID),
        (MessageTransport.MAIL, RecipientSelector.DID),
        (MessageTransport.MAIL, RecipientSelector.ADDRESS),
        (MessageTransport.CHAT, RecipientSelector.ALIAS),
        (MessageTransport.CHAT, RecipientSelector.QUALIFIED_ALIAS),
        (MessageTransport.CHAT, RecipientSelector.DID),
        (MessageTransport.CHAT, RecipientSelector.ADDRESS),
    ],
)
async def test_every_local_selector_requires_current_membership(
    pinning, kind, selector
):
    env = pinning
    sender, recipient = _new_member("selectsender"), _new_member("selectrecipient")
    for member in (sender, recipient):
        cert = _certificate(env.team_sk, env.team_did, member, member[2] + "-before")
        assert (await _connect(env, member, cert)).status_code == 200
    recipient_id = str((await _row(env, recipient))["agent_id"])
    before = await _send(
        env,
        sender=sender,
        recipient=recipient,
        agent_id=recipient_id,
        kind=kind,
        selector=selector,
    )
    assert before.status_code == 200, before.text

    next_sk, next_did = await _change_key(env)
    assert (
        await _connect(
            env, sender, _certificate(next_sk, next_did, sender, "sender-after")
        )
    ).status_code == 200
    refused = await _send(
        env,
        sender=sender,
        recipient=recipient,
        agent_id=recipient_id,
        kind=kind,
        selector=selector,
    )
    assert refused.status_code == 404, refused.text
    assert (
        "Check the name; if the agent exists, ask it to reconnect with a current team certificate."
        in refused.json()["detail"]
    )

    # A stored local participant keeps its literal key. Losing membership
    # does not retire that participant or create succession to a new key.
    if kind is MessageTransport.MAIL:
        path = "/v1/messages"
        payload = {
            "conversation_id": before.json()["conversation_id"],
            "to_agent_id": recipient_id,
            "subject": "continuation",
            "body": "existing participant",
        }
    else:
        path = f"/v1/chat/sessions/{before.json()['session_id']}/messages"
        payload = {"body": "existing participant"}
    body = json.dumps(payload).encode()
    headers = _signed_identity_headers(sender[0], sender[1], "", body)
    continued = await env.client.post(
        path, content=body, headers={**headers, "Content-Type": "application/json"}
    )
    assert continued.status_code == 200, continued.text

    assert (
        await _connect(
            env,
            recipient,
            _certificate(next_sk, next_did, recipient, "recipient-after"),
        )
    ).status_code == 200
    after = await _send(
        env,
        sender=sender,
        recipient=recipient,
        agent_id=recipient_id,
        kind=kind,
        selector=selector,
    )
    assert after.status_code == 200, after.text


def _proxy_headers(actor_id):
    key_id = str(uuid4())
    return {
        "X-Team-ID": TEAM,
        "X-API-Key": key_id,
        "X-AWEB-Actor-ID": actor_id,
        "X-AWEB-Auth": build_internal_auth_header_value(
            secret="r2-disposable-proxy-secret",
            team_id=TEAM,
            principal_type="k",
            principal_id=key_id,
            actor_id=actor_id,
        ),
    }


@pytest.mark.asyncio
async def test_trusted_proxy_does_not_restore_superseded_actor(pinning):
    env = pinning
    member = _new_member("proxyactor")
    assert (
        await _connect(
            env, member, _certificate(env.team_sk, env.team_did, member, "proxy-before")
        )
    ).status_code == 200
    actor_id = str((await _row(env, member))["agent_id"])
    headers = _proxy_headers(actor_id)
    path = f"/v1/apps/installed?team_id={TEAM}"
    before = await env.client.get(path, headers=headers)
    assert before.status_code == 200, before.text

    next_sk, next_did = await _change_key(env)
    refused = await env.client.get(path, headers=headers)
    assert refused.status_code == 403, refused.text
    assert (
        refused.json()["detail"]
        == "Team membership is no longer current. Reconnect with a certificate issued under the team's current key."
    )

    assert (
        await _connect(
            env, member, _certificate(next_sk, next_did, member, "proxy-after")
        )
    ).status_code == 200
    after = await env.client.get(path, headers=headers)
    assert after.status_code == 200, after.text


@pytest.mark.asyncio
async def test_room_rechecks_current_membership_after_request_authentication(pinning):
    from aweb.messaging.room import room_metadata
    from aweb.service_errors import ForbiddenError
    from aweb.team_auth_deps import get_team_identity
    from starlette.requests import Request
    from test_messages_http import _signed_team_headers

    env = pinning
    member = _new_member("roomactor")
    certificate = _certificate(env.team_sk, env.team_did, member, "room-before")
    assert (await _connect(env, member, certificate)).status_code == 200
    headers = _signed_team_headers(member[0], member[1], TEAM, certificate)
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/v1/room",
            "headers": [
                (name.lower().encode(), value.encode())
                for name, value in headers.items()
            ],
            "app": env.app,
        }
    )
    actor = await get_team_identity(request, env.infra)
    before = await room_metadata(env.infra, actor)
    assert before["team_id"] == TEAM

    next_sk, next_did = await _change_key(env)
    with pytest.raises(ForbiddenError) as refused:
        await room_metadata(env.infra, actor)
    assert refused.value.detail == "Room requires current team membership"
    assert (
        await _connect(
            env, member, _certificate(next_sk, next_did, member, "room-after")
        )
    ).status_code == 200
    after = await room_metadata(env.infra, actor)
    assert after["room_id"] == before["room_id"]


@pytest.mark.asyncio
async def test_public_native_actor_lock_requires_current_member_under_real_rotation(
    pinning,
):
    from aweb.human_channels.authority import NativeMessagingSubject, lock_native_actors
    from aweb.human_channels.contract import ContractError

    env = pinning
    member = _new_member("nativeactor")
    certificate = _certificate(env.team_sk, env.team_did, member, "native-before")
    assert (await _connect(env, member, certificate)).status_code == 200
    # The public SDK receives exact actor facts produced by real admission;
    # no host authority hook or authenticated context is substituted here.
    member_row = await _row(env, member)
    subject = NativeMessagingSubject(
        member[1], member[1], str(member_row["agent_id"]), TEAM
    )

    async def read_locked():
        async with env.db.transaction() as transaction:
            return await lock_native_actors(
                env.infra, transaction.connection, (subject,)
            )

    assert await read_locked() == (subject,)
    next_sk, next_did = await _change_key(env)
    with pytest.raises(ContractError) as refused:
        await read_locked()
    assert refused.value.code == "forbidden"
    assert refused.value.field == (
        "Team membership is no longer current. "
        "Reconnect with a certificate issued under the team's current key."
    )
    assert (
        await _connect(
            env, member, _certificate(next_sk, next_did, member, "native-after")
        )
    ).status_code == 200
    assert await read_locked() == (subject,)
