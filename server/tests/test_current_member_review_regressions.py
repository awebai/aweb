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
    _readmit,
)
from test_dashboard_privacy import TEAM
from test_dashboard_privacy import privacy_app as privacy_app
from test_member_team_key import _change_key
from test_messages_http import _signed_identity_headers, _signed_team_headers
from test_team_key_pinning import pinning as pinning


def _request(env, actor):
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/v1/agents",
            "query_string": b"",
            "app": env.app,
            "headers": [
                (key.lower().encode(), value.encode())
                for key, value in _signed_team_headers(
                    actor.sk, actor.did, TEAM, actor.certificate
                ).items()
            ],
        }
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("selector", ["to_alias", "to_address"])
async def test_mail_continuation_keeps_agent_and_current_key_binding(pinning, selector):
    env = pinning
    sender = await _admit(env, "continuationsender")
    target = await _admit(env, "continuationtarget", global_identity=True)
    first = await _http(
        env,
        sender,
        "POST",
        "/v1/messages",
        {
            selector: target.alias if selector == "to_alias" else target.address,
            "subject": "thread",
            "body": "first",
        },
    )
    assert first.status_code == 200, first.text
    continuation = await _http(
        env,
        sender,
        "POST",
        "/v1/messages",
        {
            "conversation_id": first.json()["conversation_id"],
            "to_agent_id": str(target.id),
            "to_did": target.did,
            "subject": "thread",
            "body": "second",
        },
    )
    assert continuation.status_code == 200, continuation.text
    row = await env.db.fetch_one(
        "SELECT conversation_id, to_did, body FROM {{tables.messages}} WHERE message_id=$1",
        UUID(continuation.json()["message_id"]),
    )
    assert (str(row["conversation_id"]), row["to_did"], row["body"]) == (
        first.json()["conversation_id"],
        target.stable,
        "second",
    )


@pytest.mark.asyncio
async def test_sender_membership_configuration_absence_is_unknown(pinning):
    env = pinning
    sender = await _admit(env, "membershipsourcer")
    recipient = await _admit(env, "membershipreader")
    sent = await _http(
        env,
        sender,
        "POST",
        "/v1/messages",
        {
            "to_alias": recipient.alias,
            "body": "stored provenance",
        },
    )
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
        403,
        "Room requires current team membership",
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
        "FROM {{tables.agents}} WHERE agent_id=$1",
        actor.id,
    )
    with pytest.raises(ValueError):
        await resolve_team_identity(env.db, info, request=request)
    assert (
        await env.db.fetch_one(
            "SELECT certificate_id, accepted_team_did_key, did_aw_verified_key "
            "FROM {{tables.agents}} WHERE agent_id=$1",
            actor.id,
        )
        == before
    )


@pytest.mark.asyncio
async def test_a_superseded_claim_is_released_when_a_current_member_claims(pinning):
    env = pinning
    holder = await _admit(env, "claimholder")
    contender = await _admit(env, "claimcontender")
    created = await _http(env, holder, "POST", "/v1/tasks", {"title": "owned claim"})
    assert created.status_code == 200, created.text
    ref = created.json()["task_ref"]
    path = "/v1/tasks/" + ref
    claimed = await _http(env, holder, "PATCH", path, {"status": "in_progress"})
    assert claimed.status_code == 200, claimed.text
    conflict = await _http(env, contender, "PATCH", path, {"status": "in_progress"})
    assert conflict.status_code == 409, conflict.text
    next_key = await _change_key(env)
    await _readmit(env, contender, next_key)
    claimed = await _http(env, contender, "PATCH", path, {"status": "in_progress"})
    assert claimed.status_code == 200, claimed.text
    claims = await env.db.fetch_all(
        "SELECT c.alias, w.agent_id FROM {{tables.task_claims}} c "
        "JOIN {{tables.workspaces}} w ON w.workspace_id=c.workspace_id "
        "WHERE c.team_id=$1 AND c.task_ref=$2",
        TEAM,
        ref,
    )
    assert [(c["alias"], c["agent_id"]) for c in claims] == [(contender.alias, contender.id)]
    assert claimed.json()["assignee_alias"] == contender.alias


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["superseded", "inactive"])
async def test_identity_context_filters_members_before_projection_writes(pinning, change):
    from aweb.identity_auth_deps import lookup_identity_agent_context
    from aweb.identity_binding import verify_identity_binding

    env = pinning
    actor = await _admit(env, "projectiontarget", global_identity=True)
    request = _request(env, actor)
    # Acquire actual verified binding evidence on the original signed request.
    await verify_request_certificate(request, env.infra)
    binding = await verify_identity_binding(
        request,
        did_key=actor.did,
        did_aw=actor.stable,
        address=actor.address,
        fresh=True,
    )
    assert binding.fresh_observation
    if change == "superseded":
        await _change_key(env)
    else:
        # Negative native row state; this cannot manufacture member authority.
        await env.db.execute(
            "UPDATE {{tables.agents}} SET status='retired' WHERE agent_id=$1", actor.id
        )
    queries = []
    async with env.db.transaction() as tx:
        with tx.connection.query_logger(lambda event: queries.append(event.query)):
            assert (
                await lookup_identity_agent_context(
                    tx,
                    did_key=actor.did,
                    did_aw=actor.stable,
                    request=request,
                )
                is None
            )
            assert await tx.fetch_value("SELECT 1") == 1
    assert not [q for q in queries if "UPDATE" in q and "agents" in q], queries


@pytest.mark.asyncio
async def test_address_discovery_programming_error_is_not_stored_binding_authority(
    pinning, monkeypatch
):
    from aweb.identity_auth_deps import resolve_identity_auth

    env = pinning
    actor = await _admit(env, "discoveryerror", global_identity=True)
    headers = _signed_identity_headers(actor.sk, actor.did, actor.stable)
    request = Request(
        {
            **_request(env, actor).scope,
            "headers": [(key.lower().encode(), value.encode()) for key, value in headers.items()],
        }
    )

    async def invalid_dependency_call(_client, _did):
        # Fault injection only: request signature and binding verification run
        # normally. A programming error is not a registry-outage observation.
        raise TypeError("invalid discovery call")

    monkeypatch.setattr(
        type(env.app.state.awid_registry_client), "list_did_addresses", invalid_dependency_call
    )
    with pytest.raises(TypeError, match="invalid discovery call"):
        await resolve_identity_auth(request)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change", ["rotation", "rotation-and-readmission", "revocation", "inactive", "unchanged"]
)
async def test_certificate_stream_rechecks_its_original_authority_on_grant_cadence(pinning, change):
    from aweb.grant_streams import GRANT_STREAM_RECHECK_SECONDS, NeverGrantStreamGuard
    from aweb.team_auth_deps import get_team_identity

    env = pinning
    actor = await _admit(env, "streamoriginal")
    request = _request(env, actor)
    identity = await get_team_identity(request, env.infra)
    guard = NeverGrantStreamGuard(request, env.infra, identity)
    assert await guard.reason() is None
    if change.startswith("rotation"):
        key = await _change_key(env)
        if change == "rotation-and-readmission":
            await _readmit(env, actor, key)
    elif change == "revocation":
        from aweb.application_state import application_registry_client

        name, domain = TEAM.split(":", 1)
        await application_registry_client(env.app.state).revoke_team_certificate(
            domain,
            name,
            team_controller_signing_key=env.team_sk,
            certificate_id=identity.certificate_id,
        )
    elif change == "inactive":
        await env.db.execute(
            "UPDATE {{tables.agents}} SET status='retired' WHERE agent_id=$1", actor.id
        )
    # Advance only the cadence boundary, never authority or dependency results.
    guard.checked_at -= GRANT_STREAM_RECHECK_SECONDS + 1
    assert await guard.reason() == (
        None if change == "unchanged" else "team_membership_not_current"
    )


@pytest.mark.asyncio
async def test_an_open_certificate_event_stream_stops_after_rotation(pinning, monkeypatch):
    import asyncio
    from datetime import datetime, timedelta, timezone

    from aweb import grant_streams
    from aweb.routes import events
    from aweb.team_auth_deps import get_team_identity

    env = pinning
    actor = await _admit(env, "eventstreamoriginal")
    request = _request(env, actor)
    identity = await get_team_identity(request, env.infra)
    assert identity.verified_team_did_key == env.team_did
    assert grant_streams.GRANT_STREAM_RECHECK_SECONDS == events.GRANT_STREAM_RECHECK_SECONDS == 30
    # Shorten only the timer for this real stream; all authority/SQL/Redis
    # observations and the original admitted credential remain untouched.
    monkeypatch.setattr(grant_streams, "GRANT_STREAM_RECHECK_SECONDS", 0.05)
    monkeypatch.setattr(events, "GRANT_STREAM_RECHECK_SECONDS", 0.05)
    stream = events._sse_agent_events(
        request=request,
        db=env.infra,
        redis=env.redis,
        team_id=TEAM,
        agent_id=str(actor.id),
        identity=identity,
        deadline=datetime.now(timezone.utc) + timedelta(seconds=3),
    )
    try:
        assert await anext(stream) == ": keepalive\n\n"
        assert "event: connected\n" in await anext(stream)
        await _change_key(env)
        frames = []
        async with asyncio.timeout(4):
            async for frame in stream:
                frames.append(frame)
        assert any("event: team_membership_not_current\n" in frame for frame in frames), frames
        assert not any("event: actionable_" in frame for frame in frames), frames
    finally:
        await stream.aclose()
