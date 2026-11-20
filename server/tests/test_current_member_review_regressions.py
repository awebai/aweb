"""Review regressions with actual admitted members and stored conversations."""

from uuid import UUID

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from aweb.messaging.room import room_metadata
from aweb.messaging.sender_membership import sender_memberships
from aweb.service_errors import ForbiddenError
from aweb.team_auth_deps import resolve_team_identity, verify_request_certificate
from aweb.team_registry import registered_certificates, revoked_certificates
from test_current_member_selector_surfaces import (
    _admit,
    _capture_room_actor,
    _http,
)
from test_dashboard_privacy import TEAM
from test_member_team_key import _change_key
from test_messages_http import _signed_team_headers
from test_team_key_pinning import pinning as pinning


def _request(env, actor):
    return Request({
        "type": "http", "method": "GET", "path": "/v1/agents",
        "query_string": b"", "app": env.app,
        "headers": [
            (key.lower().encode(), value.encode())
            for key, value in _signed_team_headers(
                actor.sk, actor.did, TEAM, actor.certificate
            ).items()
        ],
    })


@pytest.mark.asyncio
@pytest.mark.parametrize("selector", ["to_alias", "to_address"])
async def test_mail_continuation_keeps_agent_and_current_key_binding(pinning, selector):
    env = pinning
    sender = await _admit(env, "continuationsender")
    target = await _admit(env, "continuationtarget", global_identity=True)
    first = await _http(env, sender, "POST", "/v1/messages", {
        selector: target.alias if selector == "to_alias" else target.address,
        "subject": "thread", "body": "first",
    })
    assert first.status_code == 200, first.text
    continuation = await _http(env, sender, "POST", "/v1/messages", {
        "conversation_id": first.json()["conversation_id"],
        "to_agent_id": str(target.id), "to_did": target.did,
        "subject": "thread", "body": "second",
    })
    assert continuation.status_code == 200, continuation.text
    row = await env.db.fetch_one(
        "SELECT conversation_id, to_did, body FROM {{tables.messages}} WHERE message_id=$1",
        UUID(continuation.json()["message_id"]),
    )
    assert (str(row["conversation_id"]), row["to_did"], row["body"]) == (
        first.json()["conversation_id"], target.stable, "second",
    )


@pytest.mark.asyncio
async def test_sender_membership_configuration_absence_is_unknown(pinning):
    env = pinning
    sender = await _admit(env, "membershipsourcer")
    recipient = await _admit(env, "membershipreader")
    sent = await _http(env, sender, "POST", "/v1/messages", {
        "to_alias": recipient.alias, "body": "stored provenance",
    })
    assert sent.status_code == 200, sent.text
    row = await env.db.fetch_one(
        "SELECT team_id, from_agent_id FROM {{tables.messages}} WHERE message_id=$1",
        UUID(sent.json()["message_id"]),
    )
    request = _request(env, recipient)
    known = await sender_memberships(request, env.infra, [row])
    key = (TEAM, str(sender.id))
    assert known[key].state == "active"
    registry = env.app.state.awid_registry_client
    env.app.state.awid_registry_client = None
    try:
        unknown = await sender_memberships(request, env.infra, [row])
        assert unknown[key].state == "unknown"
    finally:
        env.app.state.awid_registry_client = registry


@pytest.mark.asyncio
@pytest.mark.parametrize("reader", [registered_certificates, revoked_certificates])
async def test_unconfigured_team_registry_read_has_the_expected_503(reader):
    with pytest.raises(HTTPException) as refused:
        await reader(None, TEAM)
    assert refused.value.status_code == 503


@pytest.mark.asyncio
async def test_room_membership_refusal_keeps_the_released_client_sentence(pinning):
    env = pinning
    actor = await _admit(env, "roomcachedactor")
    identity = await _capture_room_actor(env, actor)
    assert (await room_metadata(env.infra, identity))["team_id"] == TEAM
    await _change_key(env)
    with pytest.raises(ForbiddenError) as refused:
        await room_metadata(env.infra, identity)
    assert (refused.value.status_code, refused.value.detail) == (
        403, "Room requires current team membership",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("missing_checked_key", [False, True])
async def test_certificate_acceptance_rechecks_current_member_after_verification(
    pinning, missing_checked_key
):
    env = pinning
    actor = await _admit(env, "certcachedactor")
    request = _request(env, actor)
    info = await verify_request_certificate(request, env.infra)
    assert info["verified_team_did_key"] == env.team_did
    assert (await resolve_team_identity(env.db, info, request=request)).agent_id == str(actor.id)
    if missing_checked_key:
        del info["verified_team_did_key"]
    else:
        await _change_key(env)
    before = await env.db.fetch_one(
        "SELECT certificate_id, accepted_team_did_key, did_aw_verified_key "
        "FROM {{tables.agents}} WHERE agent_id=$1", actor.id,
    )
    with pytest.raises(ValueError):
        await resolve_team_identity(env.db, info, request=request)
    assert await env.db.fetch_one(
        "SELECT certificate_id, accepted_team_did_key, did_aw_verified_key "
        "FROM {{tables.agents}} WHERE agent_id=$1", actor.id,
    ) == before
