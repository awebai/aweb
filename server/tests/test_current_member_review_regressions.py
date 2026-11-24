"""Review regressions with actual admitted members and stored conversations."""

import asyncio
import json
from types import SimpleNamespace
from uuid import UUID

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from aweb.events import TaskCreatedEvent, publish_event, team_events_channel_name
from aweb.application_state import application_registry_client
from aweb.lifecycle import LifecycleActor, LifecycleCascadeRequest, apply_lifecycle_cascade
from aweb.member_team_key import CurrentMembershipRequired
from aweb.messaging.sender_membership import sender_memberships
from aweb.team_auth_deps import resolve_team_identity, verify_request_certificate
from chat_pair_support import route_pair as route_pair
from test_current_member_selector_surfaces import (
    _admit,
    _http,
    _readmit,
)
from test_dashboard_privacy import TEAM, _next_event
from test_dashboard_privacy import privacy_app as privacy_app
from test_member_team_key import _change_key
from test_messages_http import _signed_identity_headers, _signed_team_headers
from test_service_registration_team_key import SERVICE, _register
from test_team_key_pinning import pinning as pinning

__all__ = ["pinning", "route_pair"]


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
async def test_unconfigured_team_registry_read_has_the_expected_503(pinning, monkeypatch):
    env = pinning
    monkeypatch.setenv("AWEB_DISCOVERY_ORIGIN", SERVICE)
    admitted = await _register(env, env.team_sk, dry_run=True)
    assert admitted.status_code == 200, admitted.text
    assert admitted.json()["status"] == "dry-run"

    monkeypatch.setattr(env.app.state, "awid_registry_client", None)
    refused = await _register(env, env.team_sk, dry_run=True)

    assert refused.status_code == 503, refused.text
    assert refused.json()["detail"] == {
        "code": "registry_client_unavailable",
        "message": (
            "Registry client is unavailable. Configure the serving registry client "
            "and start the application before retrying."
        ),
    }


async def _archive_global_member(env, actor):
    outcome = await apply_lifecycle_cascade(
        env.db,
        env.redis,
        LifecycleCascadeRequest(
            operation="archive_global_agent",
            actor=LifecycleActor(actor_id=None, actor_type="support", authority="operator"),
            team_id=TEAM,
            target_agent_id=str(actor.id),
            workspace_scope="all_for_agent",
            require_identity_scope="global",
        ),
        registry_client=application_registry_client(env.app.state),
    )
    assert outcome.errors == () and outcome.identity_archived


@pytest.mark.asyncio
async def test_workspace_rosters_follow_readmission_after_team_key_rotation(pinning):
    from mcp_runtime_fixtures import mounted_mcp
    from test_current_member_selector_surfaces import _tool

    env = pinning
    viewer = await _admit(env, "roster-viewer")
    peer = await _admit(env, "roster-peer")
    peer_workspace = await env.db.fetch_value(
        "SELECT workspace_id FROM {{tables.workspaces}} WHERE agent_id = $1", peer.id
    )
    paths = (
        "/v1/workspaces",
        f"/v1/workspaces/team?only_with_claims=false&always_include_workspace_id={peer_workspace}",
    )

    async def assert_peer_listed(expected):
        for path in paths:
            response = await _http(env, viewer, "GET", path)
            assert response.status_code == 200, response.text
            aliases = {row["alias"] for row in response.json()["workspaces"]}
            assert viewer.alias in aliases
            assert (peer.alias in aliases) is expected, (path, aliases)
        result = await _tool(env, viewer, "workspace_status", {"limit": 20})
        assert result["self"]["alias"] == viewer.alias
        aliases = {row["alias"] for row in result["team_agents"]}
        assert (peer.alias in aliases) is expected, result

    async with mounted_mcp(
        env.app, db_infra=env.infra, redis=env.redis,
        registry_client=application_registry_client(env.app.state),
    ):
        await assert_peer_listed(True)
        next_key = await _change_key(env)
        await _readmit(env, viewer, next_key)
        await assert_peer_listed(False)
        await _readmit(env, peer, next_key)
        await assert_peer_listed(True)


@pytest.mark.asyncio
async def test_room_membership_refusal_keeps_the_released_client_sentence(pinning):
    env = pinning
    actor = await _admit(env, "roomarchivedactor", global_identity=True)
    neighbor = await _admit(env, "roomcurrentactor")
    path = "/v1/room/messages"
    before = await _http(env, actor, "GET", path)
    assert before.status_code == 200, before.text

    await _archive_global_member(env, actor)

    refused = await _http(env, actor, "GET", path)
    assert refused.status_code == 403, refused.text
    assert refused.json() == {
        "detail": "Room requires current team membership",
        "reason": "team_membership_not_current",
    }
    allowed = await _http(env, neighbor, "GET", path)
    assert allowed.status_code == 200, allowed.text


@pytest.mark.asyncio
async def test_certificate_acceptance_refuses_http_if_the_checked_key_rotates(
    pinning, monkeypatch
):
    from aweb import team_auth_deps

    env = pinning
    actor = await _admit(env, "certcachedactor")
    path = "/v1/agents"
    admitted = await _http(env, actor, "GET", path)
    assert admitted.status_code == 200, admitted.text
    projection = (
        "SELECT certificate_id, accepted_team_did_key, did_aw_verified_key "
        "FROM {{tables.agents}} WHERE agent_id=$1"
    )
    before = await env.db.fetch_one(projection, actor.id)
    verified, resume = asyncio.Event(), asyncio.Event()
    verify = team_auth_deps.verify_request_certificate

    async def pause_after_verification(request, db, *, fresh=False):
        result = await verify(request, db, fresh=fresh)
        if result["did_key"] == actor.did:
            assert result["verified_team_did_key"] == env.team_did
            verified.set()
            await resume.wait()
        return result

    monkeypatch.setattr(team_auth_deps, "verify_request_certificate", pause_after_verification)
    async with asyncio.TaskGroup() as requests:
        old_request = requests.create_task(_http(env, actor, "GET", path))
        async with asyncio.timeout(5):
            await verified.wait()
            await _change_key(env)
        resume.set()

    refused = old_request.result()
    assert refused.status_code == 403, refused.text
    assert refused.json() == {"detail": (
        "Team membership is no longer current. Reconnect with a certificate "
        "issued under the team's current key."
    )}
    assert await env.db.fetch_one(projection, actor.id) == before


@pytest.mark.asyncio
async def test_certificate_acceptance_owner_refuses_a_missing_checked_key(pinning):
    env = pinning
    actor = await _admit(env, "certmissingkey")
    request = _request(env, actor)
    info = await verify_request_certificate(request, env.infra)
    assert info.pop("verified_team_did_key") == env.team_did
    projection = (
        "SELECT certificate_id, accepted_team_did_key, did_aw_verified_key "
        "FROM {{tables.agents}} WHERE agent_id=$1"
    )
    before = await env.db.fetch_one(projection, actor.id)
    with pytest.raises(
        CurrentMembershipRequired,
        match=r"^Team membership is no longer current\. Reconnect with a certificate issued under the team's current key\.$",
    ):
        await resolve_team_identity(env.db, info, request=request)
    assert await env.db.fetch_one(projection, actor.id) == before

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
    async with env.redis.pubsub() as events:
        await events.subscribe(team_events_channel_name(TEAM))
        subscribed = await events.get_message(timeout=2)
        assert subscribed and subscribed["type"] == "subscribe"
        claimed = await _http(env, contender, "PATCH", path, {"status": "in_progress"})
        assert claimed.status_code == 200, claimed.text
        transitions = []
        while message := await events.get_message(ignore_subscribe_messages=True, timeout=0.25):
            event = json.loads(message["data"])
            if event.get("task_ref") == ref and event["type"] in {"task.claimed", "task.unclaimed"}:
                transitions.append((event["type"], event["alias"]))
    claims = await env.db.fetch_all(
        "SELECT c.alias, w.agent_id FROM {{tables.task_claims}} c "
        "JOIN {{tables.workspaces}} w ON w.workspace_id=c.workspace_id "
        "WHERE c.team_id=$1 AND c.task_ref=$2",
        TEAM,
        ref,
    )
    assert [(c["alias"], c["agent_id"]) for c in claims] == [(contender.alias, contender.id)]
    assert claimed.json()["assignee_alias"] == contender.alias
    assert transitions == [("task.unclaimed", holder.alias), ("task.claimed", contender.alias)]


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
        await _archive_global_member(env, actor)
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
    "change", ["rotation", "rotation-and-readmission", "revocation", "inactive", "unchanged", "outage"]
)
async def test_certificate_stream_rechecks_its_original_authority_on_grant_cadence(
    pinning, change, monkeypatch,
):
    from aweb.grant_streams import (
        STREAM_AUTHORITY_RECHECK_SECONDS,
        NeverGrantStreamGuard,
        require_valid_stream_grant,
    )
    from aweb.team_auth_deps import get_team_identity

    env = pinning
    actor = await _admit(env, "streamoriginal", global_identity=change == "inactive")
    request = _request(env, actor)
    identity = await get_team_identity(request, env.infra)
    guard = NeverGrantStreamGuard(request, env.infra, identity)
    assert await guard.reason() is None
    if change.startswith("rotation"):
        key = await _change_key(env)
        if change == "rotation-and-readmission":
            await _readmit(env, actor, key)
    elif change == "revocation":
        name, domain = TEAM.split(":", 1)
        await application_registry_client(env.app.state).revoke_team_certificate(
            domain,
            name,
            team_controller_signing_key=env.team_sk,
            certificate_id=identity.certificate_id,
        )
    elif change == "inactive":
        await _archive_global_member(env, actor)
    elif change == "outage":
        monkeypatch.setattr(env.registry.transport, "down", True)
        with pytest.raises(HTTPException) as opening:
            await require_valid_stream_grant(request, env.infra, identity)
        assert opening.value.status_code == 503
    # Advance only the cadence boundary, never authority or dependency results.
    guard.checked_at -= STREAM_AUTHORITY_RECHECK_SECONDS + 1
    assert await guard.reason() == (
        None if change in {"unchanged", "outage"} else "team_membership_not_current"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["rotation", "revocation"])
async def test_an_open_certificate_event_stream_reuses_admission_and_rechecks(pinning, monkeypatch, change):
    from datetime import datetime, timedelta, timezone

    from aweb import grant_streams
    from aweb.connection_scope import request_memo
    from aweb.routes import events
    from awid.team_certificate import decode_team_certificate

    env = pinning
    actor = await _admit(env, "eventstreamoriginal")
    headers = _signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate)
    member_reads, standing_checks = [], []
    read_member = grant_streams.read_member_projection
    current_membership = grant_streams.current_membership

    async def observe_member_read(*args, **kwargs):
        member_reads.append(request_memo() is not None)
        return await read_member(*args, **kwargs)

    async def observe_standing(*args, **kwargs):
        standing_checks.append(request_memo() is not None)
        return await current_membership(*args, **kwargs)

    monkeypatch.setattr(grant_streams, "read_member_projection", observe_member_read)
    monkeypatch.setattr(grant_streams, "current_membership", observe_standing)
    assert grant_streams.STREAM_AUTHORITY_RECHECK_SECONDS == events.STREAM_AUTHORITY_RECHECK_SECONDS == 30
    monkeypatch.setattr(grant_streams, "STREAM_AUTHORITY_RECHECK_SECONDS", 0.05)
    monkeypatch.setattr(events, "STREAM_AUTHORITY_RECHECK_SECONDS", 0.05)
    deadline = datetime.now(timezone.utc) + timedelta(seconds=5)
    async with env.client.stream(
        "GET", "/v1/events/stream", headers=headers, params={"deadline": deadline.isoformat()}
    ) as response:
        assert response.status_code == 200
        lines = response.aiter_lines()
        assert await _next_event(lines) == {"agent_id": str(actor.id), "team_id": TEAM}
        if change == "rotation":
            await _change_key(env)
        else:
            name, domain = TEAM.split(":", 1)
            await application_registry_client(env.app.state).revoke_team_certificate(
                domain, name, team_controller_signing_key=env.team_sk,
                certificate_id=decode_team_certificate(actor.certificate)["certificate_id"],
            )
        terminal = await _next_event(lines)
        assert terminal["type"] == "team_membership_not_current", terminal
        async with asyncio.timeout(5):
            assert [line async for line in lines if line.startswith("data: ")] == []
    assert not any(standing_checks)
    if change == "revocation":
        assert standing_checks
    assert member_reads and not any(member_reads)


@pytest.mark.asyncio
async def test_an_open_certificate_status_stream_stops_after_rotation(pinning, monkeypatch):
    from aweb import grant_streams

    env = pinning
    actor = env.actors["bob"]
    workspace = str(actor.workspace)
    headers = _signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate)
    assert grant_streams.STREAM_AUTHORITY_RECHECK_SECONDS == 30
    clock = [0.0]
    monkeypatch.setattr(grant_streams, "time", SimpleNamespace(monotonic=lambda: clock[0]))

    async with env.client.stream(
        "GET", "/v1/status/stream", headers=headers, params={"workspace_id": workspace}
    ) as response:
        assert response.status_code == 200
        channel = f"events:{workspace}"
        async with asyncio.timeout(5):
            while not (await env.redis.pubsub_numsub(channel))[0][1]:
                await asyncio.sleep(0.01)
        lines = response.aiter_lines()
        await publish_event(env.redis, TaskCreatedEvent(workspace_id=workspace, task_ref="before-rotation"))
        before = await _next_event(lines)
        assert (before["type"], before["task_ref"]) == ("task.created", "before-rotation")

        await _change_key(env)
        clock[0] += grant_streams.STREAM_AUTHORITY_RECHECK_SECONDS
        await publish_event(env.redis, TaskCreatedEvent(workspace_id=workspace, task_ref="after-rotation"))
        terminal = await _next_event(lines)
        assert terminal["type"] == "team_membership_not_current", terminal
        async with asyncio.timeout(5):
            assert [line async for line in lines if line.startswith("data: ")] == []


@pytest.mark.asyncio
async def test_idle_certificate_status_stream_closes_at_cap_during_registry_read(pinning, monkeypatch):
    from aweb import grant_streams
    from aweb.routes import status
    from messaging_actor_support import admit_messaging_actor

    env = pinning
    actor = await admit_messaging_actor(env, alias="idlecertificatestream", team_id=TEAM, local=True)
    workspace = actor.workspace_id
    headers = _signed_team_headers(actor.signing_key, actor.did_key, TEAM, actor.certificate)
    assert grant_streams.STREAM_MAX_DURATION_SECONDS == status.STREAM_MAX_DURATION_SECONDS == 300
    monkeypatch.setattr(status, "STREAM_MAX_DURATION_SECONDS", 2)
    monkeypatch.setattr(grant_streams, "STREAM_AUTHORITY_RECHECK_SECONDS", 0.05)

    async with env.client.stream(
        "GET", "/v1/status/stream", headers=headers, params={"workspace_id": workspace}
    ) as response:
        assert response.status_code == 200
        channel = f"events:{workspace}"
        async with asyncio.timeout(4):
            while not (await env.redis.pubsub_numsub(channel))[0][1]:
                await asyncio.sleep(0.01)
            env.registry.transport.calls.clear()
            monkeypatch.setattr(env.registry.transport, "delay", 30)
            assert [line async for line in response.aiter_lines() if line.startswith("data: ")] == []
        assert any(request.url.path.endswith("/revocations") for request in env.registry.transport.calls)
        assert (await env.redis.pubsub_numsub(channel))[0][1] == 0


@pytest.mark.asyncio
async def test_proxy_stream_credential_does_not_require_native_certificate_evidence():
    from aweb.grant_streams import grant_terminal_reason, requires_stream_recheck

    # The host's opaque credential label supplies no native certificate proof.
    identity = SimpleNamespace(grant=None, certificate_id="host-credential")
    assert not requires_stream_recheck(identity)
    assert await grant_terminal_reason(None, None, identity) is None


@pytest.mark.asyncio
async def test_certificate_stream_refuses_missing_checked_key(pinning):
    from dataclasses import replace

    from aweb.grant_streams import grant_terminal_reason
    from aweb.identity_auth_deps import get_messaging_auth
    from aweb.team_auth_deps import get_team_identity

    env = pinning
    actor = await _admit(env, "streammissingkey")
    request = _request(env, actor)
    team_identity = await get_team_identity(request, env.infra)
    messaging_identity = await get_messaging_auth(request, env.infra)
    for identity in (team_identity, messaging_identity):
        assert identity.verified_team_did_key == env.team_did
        assert identity.certificate_verified is True
        assert await grant_terminal_reason(
            request, env.infra, replace(identity, verified_team_did_key=None)
        ) == "team_membership_not_current"


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_local_key_recipient_uses_the_authenticated_senders_team(pinning, kind):
    from messaging_actor_support import admit_messaging_actor, register_messaging_team
    from aweb.messaging.recipient_lookup import resolve_agent_by_did
    from aweb.service_errors import ConflictError

    env = pinning
    sender = await _admit(env, "selectedteamsender")
    recipient = await _admit(env, "selectedteamrecipient")
    other_team = "elsewhere:example.test"
    await register_messaging_team(env, team_id=other_team)
    other = await admit_messaging_actor(
        env,
        alias="otherteamrecipient",
        team_id=other_team,
        signing_key=recipient.sk,
        local=True,
    )
    assert other.did_key == recipient.did and other.agent_id != str(recipient.id)
    # Without any team selection the identity remains ambiguous.
    with pytest.raises(ConflictError):
        await resolve_agent_by_did(env.infra, recipient.did)
    path, payload = (
        ("/v1/messages", {"to_did": recipient.did, "body": "selected team"})
        if kind == "mail"
        else ("/v1/chat/sessions", {"to_dids": [recipient.did], "message": "selected team"})
    )
    response = await _http(env, sender, "POST", path, payload)
    assert response.status_code == 200, response.text
    if kind == "mail":
        row = await env.db.fetch_one(
            "SELECT to_did, to_alias, team_id, body FROM {{tables.messages}} WHERE message_id=$1",
            UUID(response.json()["message_id"]),
        )
        assert (row["to_did"], row["to_alias"], row["team_id"], row["body"]) == (
            recipient.did,
            recipient.alias,
            TEAM,
            "selected team",
        )
    else:
        row = await env.db.fetch_one(
            "SELECT did, alias FROM {{tables.chat_participants}} WHERE session_id=$1 AND did=$2",
            UUID(response.json()["session_id"]),
            recipient.did,
        )
        assert (row["did"], row["alias"]) == (recipient.did, recipient.alias)


@pytest.mark.asyncio
async def test_actor_lookup_cannot_use_a_current_row_in_a_different_team(pinning):
    from aweb.messaging.chat_send import resolve_actor_agent
    from aweb.team_auth_deps import get_team_identity
    from messaging_actor_support import admit_messaging_actor, register_messaging_team

    env = pinning
    actor = await _admit(env, "scopedchatactor")
    identity = await get_team_identity(_request(env, actor), env.infra)
    assert identity.team_id == TEAM and identity.agent_id == str(actor.id)
    other_team = "actors:example.test"
    await register_messaging_team(env, team_id=other_team)
    foreign = await admit_messaging_actor(
        env, alias="otherchatactor", team_id=other_team, signing_key=actor.sk, local=True,
    )
    eligible = await resolve_actor_agent(env.infra, [identity.did_key], team_id=identity.team_id)
    assert eligible["agent_id"] == actor.id
    await _change_key(env)
    foreign_row = await resolve_actor_agent(env.infra, [identity.did_key], team_id=other_team)
    assert str(foreign_row["agent_id"]) == foreign.agent_id

    assert await resolve_actor_agent(env.infra, [identity.did_key], team_id=identity.team_id) is None


@pytest.mark.asyncio
async def test_federation_participant_conflict_uses_the_federation_refusal_owner(route_pair):
    from messaging_actor_support import admit_messaging_actor
    from test_messages_http import _federated_mail_payload, _registered_routing_pair

    world = await _registered_routing_pair(route_pair)
    source, target = world.source, world.target
    other = await admit_messaging_actor(
        target.env, alias="alternate", team_id=target.actor.team_id,
        address=target.actor.address.rsplit("/", 1)[0] + "/alternate",
    )

    def payload(recipient, *, conversation_id=None):
        return _federated_mail_payload(
            sender_sk=source.actor.signing_key, sender_did_key=source.actor.did_key,
            sender_did_aw=source.actor.stable_id, sender_address=source.actor.address,
            sender_delivery_origin=source.node.origin, target_delivery_origin=target.node.origin,
            target_did_aw=recipient.stable_id, target_did_key=recipient.did_key,
            target_address=recipient.address, conversation_id=conversation_id,
        )

    path = "/v1/federation/messages"
    opened = await target.node.client.post(path, json=payload(target.actor))
    assert opened.status_code == 200, opened.text
    conversation_id = opened.json()["conversation_id"]
    continued = await target.node.client.post(
        path, json=payload(target.actor, conversation_id=conversation_id)
    )
    assert continued.status_code == 200, continued.text
    assert continued.json()["conversation_id"] == conversation_id

    conflicting = payload(other, conversation_id=conversation_id)
    refused = await target.node.client.post(path, json=conflicting)
    assert refused.status_code == 409, refused.text
    assert refused.json()["reason"] == "federation_conversation_invalid"
    stored = await target.node.db.fetch_all(
        "SELECT message_id, to_did FROM {{tables.messages}} WHERE conversation_id=$1",
        UUID(conversation_id),
    )
    assert {(str(row["message_id"]), row["to_did"]) for row in stored} == {
        (opened.json()["message_id"], target.actor.stable_id),
        (continued.json()["message_id"], target.actor.stable_id),
    }
    rejected_id = UUID(conflicting["envelope"]["message_id"])
    for table in ("message_ingress_receipts", "federation_mutation_outbox"):
        assert not await target.node.db.fetch_value(
            f"SELECT EXISTS(SELECT 1 FROM {{{{tables.{table}}}}} WHERE message_id=$1)",
            rejected_id,
        )


@pytest.mark.asyncio
async def test_mcp_recipient_binding_mismatch_describes_the_recipient(route_pair, monkeypatch):
    from dataclasses import replace

    from awid.did import did_key_from_signing_key
    from mcp_runtime_fixtures import mounted_mcp
    from messaging_actor_support import admit_messaging_actor
    from test_current_member_selector_surfaces import Actor, _tool
    from test_federation_recipient_attribution import _mail_to_resident
    from test_messages_http import _make_keypair, _registered_routing_pair

    world = await _registered_routing_pair(route_pair)
    alice, bob = world.source.actor, world.target.actor
    target = world.target.node
    opened = await target.client.post("/v1/federation/messages", json=_mail_to_resident(world))
    assert opened.status_code == 200, opened.text
    conversation_id = opened.json()["conversation_id"]

    # The two service origins now share a serving app, with Alice admitted at
    # the destination under the same DID. Her namespace keeps its controller.
    domain, name = alice.address.split("/", 1)
    controller = await world.source.node.registry.ensure_namespace(domain=domain)
    await target.registry.ensure_namespace(domain=domain, controller=controller)
    registry = target.server.app.state.awid_registry_client
    mapping = await registry.register_did(alice.did_key, alice.signing_key)
    assert mapping.did_aw == alice.stable_id
    await registry.register_address(
        domain, name, alice.stable_id, controller, current_did_key=alice.did_key,
    )
    route_pair.dns.records[(f"_awid.{domain}", "TXT")] = [
        f'"awid=v1;controller={did_key_from_signing_key(controller)};registry={target.registry_origin}"'
    ]
    await admit_messaging_actor(
        world.target.env, alias="movedalice", team_id=bob.team_id,
        existing_identity=replace(alice, address=""),
    )
    monkeypatch.setattr(
        target.server.app.state, "federation_public_origins", (target.origin, world.source.node.origin),
        raising=False,
    )
    actor = Actor(
        bob.signing_key, bob.did_key, "bob", bob.stable_id, bob.address,
        UUID(bob.agent_id), bob.certificate,
    )

    async with mounted_mcp(
        target.server.app, db_infra=target.server.db, redis=target.server.app.state.redis,
        registry_client=registry,
    ):
        args = {"conversation_id": conversation_id, "body": "continue the stored route", "plaintext": True}
        admitted = await _tool(target, actor, "send_mail", args, identity_only=True)
        assert "error" not in admitted and admitted["message_id"], admitted
        replacement_key, _, replacement_did = _make_keypair()
        replacement = await registry.register_did(replacement_did, replacement_key)
        await registry.reassign_address(domain, name, replacement.did_aw, bytes(controller))
        refused = await _tool(target, actor, "send_mail", args, identity_only=True)

    assert refused == {
        "error": "this recipient's key changed; resend the message",
        "reason": "identity_binding_mismatch",
    }
    stored = await target.db.fetch_all(
        "SELECT message_id, from_did, to_did FROM {{tables.messages}} WHERE conversation_id=$1",
        UUID(conversation_id),
    )
    assert {(str(row["message_id"]), row["from_did"], row["to_did"]) for row in stored} == {
        (opened.json()["message_id"], alice.stable_id, bob.stable_id),
        (admitted["message_id"], bob.stable_id, alice.stable_id),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,stable_selector", [("mail", False), ("mail", True), ("chat", False)])
async def test_a_verified_global_key_is_not_scoped_to_the_senders_team(
    pinning, kind, stable_selector
):
    from messaging_actor_support import (
        admit_messaging_actor,
        register_messaging_team,
        set_messaging_inbound_mode,
    )

    env = pinning
    sender = await _admit(env, "globalkeysender")
    other_team = "globalkeyrecipient:example.test"
    await register_messaging_team(env, team_id=other_team)
    target = await admit_messaging_actor(
        env,
        alias="globalkeytarget",
        team_id=other_team,
        address="example.test/globalkeytarget",
    )
    await set_messaging_inbound_mode(env, target, mode="open")
    if kind == "mail":
        payload = {"to_did": target.did_key, "body": "global key route"}
        if stable_selector:
            payload["to_stable_id"] = target.stable_id
        response = await _http(env, sender, "POST", "/v1/messages", payload)
    else:
        response = await _http(
            env,
            sender,
            "POST",
            "/v1/chat/sessions",
            {
                "to_dids": [target.did_key],
                "message": "global key route",
            },
        )
    assert response.status_code == 200, response.text
    if kind == "mail":
        row = await env.db.fetch_one(
            "SELECT from_did, to_did, body FROM {{tables.messages}} WHERE message_id=$1",
            UUID(response.json()["message_id"]),
        )
        assert (row["from_did"], row["to_did"], row["body"]) == (
            sender.did,
            target.stable_id,
            "global key route",
        )
    else:
        rows = await env.db.fetch_all(
            "SELECT did FROM {{tables.chat_participants}} WHERE session_id=$1",
            UUID(response.json()["session_id"]),
        )
        assert {row["did"] for row in rows} == {sender.did, target.stable_id}


@pytest.mark.asyncio
async def test_workspace_deletion_releases_its_claim_and_another_member_can_claim(pinning):
    env = pinning
    holder = await _admit(env, "retainedclaimholder")
    contender = await _admit(env, "replacementclaimholder")
    created = await _http(env, holder, "POST", "/v1/tasks", {"title": "retained claim"})
    assert created.status_code == 200, created.text
    ref = created.json()["task_ref"]
    claimed = await _http(env, holder, "PATCH", "/v1/tasks/" + ref, {"status": "in_progress"})
    assert claimed.status_code == 200, claimed.text
    claim = await env.db.fetch_one(
        "SELECT workspace_id, alias FROM {{tables.task_claims}} WHERE team_id=$1 AND task_ref=$2",
        TEAM,
        ref,
    )
    assert claim["alias"] == holder.alias
    path = f"/v1/workspaces/{claim['workspace_id']}"
    deleted = await _http(env, holder, "DELETE", path)
    assert deleted.status_code == 200, deleted.text
    assert deleted.json()["claims_released"] == 1
    assert deleted.json()["identity_deleted"] is True
    assert not await env.db.fetch_value(
        "SELECT EXISTS(SELECT 1 FROM {{tables.task_claims}} WHERE team_id=$1 AND task_ref=$2)",
        TEAM, ref,
    )
    replacement = await _http(env, contender, "PATCH", "/v1/tasks/" + ref, {"status": "in_progress"})
    assert replacement.status_code == 200, replacement.text
    assert replacement.json()["assignee_alias"] == contender.alias
    claims = await env.db.fetch_all(
        "SELECT alias FROM {{tables.task_claims}} WHERE team_id=$1 AND task_ref=$2", TEAM, ref,
    )
    assert [row["alias"] for row in claims] == [contender.alias]


@pytest.mark.asyncio
async def test_warm_certificate_authentication_can_read_a_delivery_locked_member(pinning):
    """A7's locked recheck must not serialize an unchanged reader with delivery."""
    import asyncio

    env = pinning
    actor = await _admit(env, "concurrentreader")
    warm = await _http(env, actor, "GET", "/v1/agents")
    assert warm.status_code == 200, warm.text
    before = await env.db.fetch_one(
        "SELECT certificate_id, accepted_team_did_key FROM {{tables.agents}} WHERE agent_id=$1",
        actor.id,
    )
    # Phase B holds precisely this SHARE lock through commit. Keep it held
    # while a real certificate-signed request authenticates, as when opening
    # an event stream before the delivery's commit/wake.
    async with env.db.transaction() as tx:
        await tx.fetch_value(
            "SELECT agent_id FROM {{tables.agents}} WHERE agent_id=$1 FOR SHARE", actor.id,
        )
        async with asyncio.timeout(6):
            response = await _http(env, actor, "GET", "/v1/agents")
        assert response.status_code == 200, response.text
    after = await env.db.fetch_one(
        "SELECT certificate_id, accepted_team_did_key FROM {{tables.agents}} WHERE agent_id=$1",
        actor.id,
    )
    assert dict(after) == dict(before)
