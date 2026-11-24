"""Real native roster budget and newest-of-all-three activity evidence."""

import base64
import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest
import pytest_asyncio
from pgdbm import AsyncDatabaseManager
from redis.asyncio.client import Pipeline

from aweb import connection_scope
from aweb.embedding import OutboxRecoveryOwnership
from aweb.grant_liveness import GrantLivenessFailurePolicy, valid_grant_liveness_by_workspace
from aweb.lifecycle_agent import AgentDisposition, apply_agent_disposition_on
from aweb.presence import clear_workspace_presence, update_agent_presence
from awid.identity_observation import IdentityKind
from awid.registry import RegistryError
from fastapi import HTTPException
from messaging_actor_support import admit_messaging_actor, register_messaging_team
from test_dashboard_privacy import TEAM, privacy_stack
from test_identity_grants import _grant_headers, _session_keypair
from test_messages_http import _signed_team_headers
from test_team_room import admit_room_member
from test_workspace_liveness_http import (
    GrantHeartbeatRoute,
    _root_last_seen,
    _send_grant_heartbeat,
    _send_member_request,
)


@pytest_asyncio.fixture
async def roster_stack(shared_test_pool, monkeypatch, request):
    async with privacy_stack(
        shared_test_pool, monkeypatch, outbox_recovery=OutboxRecoveryOwnership.HOST,
        workspace_counts=getattr(request, "param", None),
    ) as env:
        yield env


async def roster(env):
    actor = env.actors["alice"]
    response = await env.client.get(
        "/v1/agents",
        headers=_signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate),
    )
    assert response.status_code == 200, response.text
    return response.json()["agents"]


@pytest.mark.asyncio
async def test_warm_roster_uses_three_statements_and_one_pool_checkout(
    roster_stack, shared_test_pool, monkeypatch
):
    env = roster_stack
    await admit_room_member(env, alias="alice")
    await roster(env)
    statements, checkouts = [], []

    def observe_statement(original):
        async def observed(manager, sql, *args, **kwargs):
            if manager is env.db:
                statements.append(sql)
            return await original(manager, sql, *args, **kwargs)

        return observed

    for name in ("fetch_all", "fetch_one", "fetch_value", "execute"):
        monkeypatch.setattr(
            AsyncDatabaseManager,
            name,
            observe_statement(getattr(AsyncDatabaseManager, name)),
        )
    acquire = connection_scope._acquire_from

    async def observed_acquire(pool):
        if pool is shared_test_pool:
            checkouts.append(pool)
        return await acquire(pool)

    monkeypatch.setattr(connection_scope, "_acquire_from", observed_acquire)
    agents = await roster(env)
    assert any(agent["alias"] == "alice" for agent in agents)
    print(f"ROSTER_COST statements={len(statements)} checkouts={len(checkouts)}")
    assert len(statements) == 3, {"count": len(statements), "statements": statements}
    assert len(checkouts) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("roster_stack", [{"alice": 2}], indirect=True)
async def test_roster_projects_presence_for_listed_agent_workspaces(roster_stack, monkeypatch):
    env = roster_stack
    await admit_room_member(env, alias="alice")
    await admit_room_member(env, alias="carol")
    async with env.db.transaction() as tx:
        assert await apply_agent_disposition_on(
            tx, agent_ids=[env.actors["carol"].id], team_id=TEAM,
            disposition=AgentDisposition.DELETED, deleted_at=datetime.now(UTC),
        ) == 1
    alice_workspace, alternate_workspace = map(str, env.actors["alice"].workspace_ids)
    hidden = await admit_messaging_actor(
        env, team_id=TEAM, alias="roster-human", kind=IdentityKind.HUMAN,
    )
    await update_agent_presence(
        env.redis, workspace_id=hidden.workspace_id, alias="roster-human",
        team_id=TEAM, status="active",
    )
    seen = await update_agent_presence(
        env.redis, workspace_id=alternate_workspace, alias="alice", team_id=TEAM,
        status="listening", role="alternate-role",
    )
    await env.redis.hset(f"presence:{alternate_workspace}", "unshown_blob", "x" * 4096)
    presence_reads = []
    execute = Pipeline.execute

    async def observe_execute(pipeline, *args, **kwargs):
        presence_reads.extend(
            command for command, _ in pipeline.command_stack
            if command[0] in ("HMGET", "HGETALL") and command[1].startswith("presence:")
        )
        return await execute(pipeline, *args, **kwargs)

    monkeypatch.setattr(Pipeline, "execute", observe_execute)
    agents = await roster(env)
    assert all(agent["alias"] not in {"roster-human", "carol"} for agent in agents)
    alice = next(agent for agent in agents if agent["alias"] == "alice")
    assert alice["last_seen"] == seen
    assert alice["status"] == "listening"
    assert alice["role"] == "alternate-role"
    keys = {command[1] for command in presence_reads}
    assert f"presence:{hidden.workspace_id}" not in keys
    assert f"presence:{env.actors['carol'].workspace}" not in keys
    assert {f"presence:{alice_workspace}", f"presence:{alternate_workspace}"} <= keys
    assert all(
        command[0] == "HMGET"
        and set(command[2:]) == {"workspace_id", "team_id", "last_seen", "status", "role"}
        for command in presence_reads
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("required", [False, True])
async def test_roster_checks_distinct_grant_issuer_with_configured_registration(
    roster_stack, monkeypatch, required
):
    env = roster_stack
    monkeypatch.setenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", str(required).lower())
    issuer = await admit_room_member(env, alias="alice")
    viewer = await admit_room_member(env, alias="bob")
    grant_id = await _send_grant_heartbeat(env, path=GrantHeartbeatRoute.WORKSPACE)
    grant_seen = await env.db.fetch_value(
        "SELECT last_seen_at FROM {{tables.identity_grant_liveness}} WHERE grant_id=$1",
        grant_id,
    )
    name, domain = TEAM.split(":", 1)
    sdk = env.app.state.awid_registry_client
    client_type = type(sdk)
    revocations = client_type.get_team_revocations_for_certificates
    catalogs = client_type.list_team_certificates
    checked_ids, active_views = [], []

    async def observe_revocations(client, domain, name, certificate_ids, *, fresh=False):
        if client is sdk:
            checked_ids.extend(certificate_ids)
        return await revocations(client, domain, name, certificate_ids, fresh=fresh)

    async def observe_catalog(client, domain, name, *, active_only=True, signing_key=None):
        if client is sdk:
            active_views.append(active_only)
        return await catalogs(client, domain, name, active_only=active_only, signing_key=signing_key)

    monkeypatch.setattr(client_type, "get_team_revocations_for_certificates", observe_revocations)
    monkeypatch.setattr(client_type, "list_team_certificates", observe_catalog)
    response = await _send_member_request(env, alias="bob", method="GET", path="/v1/agents")
    assert response.status_code == 200, response.text
    alice = next(agent for agent in response.json()["agents"] if agent["alias"] == "alice")
    assert datetime.fromisoformat(alice["last_seen"]) == grant_seen
    assert checked_ids == [viewer["certificate_id"], issuer["certificate_id"]]
    assert active_views == ([False, False] if required else [])

    # Alice's certificate already passed both checks at ingress.
    checked_ids.clear()
    active_views.clear()
    agents = await roster(env)
    assert datetime.fromisoformat(next(
        agent["last_seen"] for agent in agents if agent["alias"] == "alice"
    )) == grant_seen
    assert checked_ids == [issuer["certificate_id"]]
    assert active_views == ([False] if required else [])

    await sdk.revoke_team_certificate(
        domain, name,
        team_controller_signing_key=env.team_sk,
        certificate_id=issuer["certificate_id"],
    )
    checked_ids.clear()
    active_views.clear()
    response = await _send_member_request(env, alias="bob", method="GET", path="/v1/agents")
    assert response.status_code == 200, response.text
    assert checked_ids == [viewer["certificate_id"], issuer["certificate_id"]]
    assert all(
        agent["alias"] != "alice" or agent["last_seen"] != alice["last_seen"]
        for agent in response.json()["agents"]
    )
    assert active_views == ([False] if required else [])


async def _publish_grant_liveness(env, actor):
    session_key, session_did = _session_keypair()
    body = json.dumps({
        "grant_did_key": session_did,
        "scopes": ["presence.write"],
        "ttl_seconds": 600,
    }).encode()
    minted = await env.client.post(
        "/v1/identity-grants",
        content=body,
        headers={
            **_signed_team_headers(
                actor.signing_key, actor.did_key, actor.team_id, actor.certificate, body
            ),
            "Content-Type": "application/json",
        },
    )
    assert minted.status_code == 200, minted.text
    grant_id = minted.json()["grant_id"]
    heartbeat = await env.client.post(
        "/v1/agents/heartbeat",
        headers=_grant_headers(
            signing_key=session_key,
            did_key=session_did,
            grant_id=grant_id,
            method="POST",
            path="/v1/agents/heartbeat",
            aud=env.app.state.public_origin,
        ),
    )
    assert heartbeat.status_code == 200, heartbeat.text
    return grant_id


@pytest.mark.asyncio
async def test_liveness_batches_twenty_two_live_issuers_by_team(roster_stack, monkeypatch):
    env = roster_stack
    monkeypatch.setenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", "false")
    other_team = f"budget-{uuid4().hex[:12]}:example.test"
    await register_messaging_team(env, team_id=other_team)
    grants, certificate_ids = {}, {}
    for team, size in ((TEAM, 20), (other_team, 2)):
        grants[team] = {}
        certificate_ids[team] = set()
        for index in range(size):
            actor = await admit_messaging_actor(
                env, team_id=team, alias=f"budget-{index}", local=True,
            )
            grants[team][actor.workspace_id] = await _publish_grant_liveness(env, actor)
            certificate_ids[team].add(json.loads(base64.b64decode(actor.certificate))["certificate_id"])
    workspace_ids = [workspace for team_grants in grants.values() for workspace in team_grants]

    sdk = env.app.state.awid_registry_client
    client_type = type(sdk)
    get_revocations = client_type.get_team_revocations_for_certificates
    reads = []
    unavailable = False

    async def observe_revocations(client, domain, name, ids, *, fresh=False):
        team = f"{name}:{domain}"
        if client is sdk:
            reads.append((team, set(ids)))
            if unavailable and team == other_team:
                raise RegistryError("fixture authority suspended", status_code=503)
        return await get_revocations(client, domain, name, ids, fresh=fresh)

    monkeypatch.setattr(client_type, "get_team_revocations_for_certificates", observe_revocations)
    result = await valid_grant_liveness_by_workspace(env.db, workspace_ids, registry_client=sdk)
    assert {workspace: str(row["grant_id"]) for workspace, row in result.items()} == (
        grants[TEAM] | grants[other_team]
    )
    assert sorted(reads) == sorted(certificate_ids.items())

    unavailable = True
    reads.clear()
    result = await valid_grant_liveness_by_workspace(env.db, workspace_ids, registry_client=sdk)
    assert {workspace: str(row["grant_id"]) for workspace, row in result.items()} == grants[TEAM]
    assert sorted(reads) == sorted(certificate_ids.items())

    with pytest.raises(HTTPException) as refusal:
        await valid_grant_liveness_by_workspace(
            env.db, workspace_ids, registry_client=sdk,
            failure_policy=GrantLivenessFailurePolicy.REQUIRE_KNOWN,
        )
    assert refusal.value.status_code == 503


@pytest.mark.asyncio
@pytest.mark.parametrize("newest", ["grant", "redis", "sql"])
async def test_listening_roster_keeps_the_newest_activity_source(roster_stack, newest):
    env = roster_stack
    actor = env.actors["alice"]
    await admit_room_member(env, alias="alice")
    sources = [name for name in ("grant", "redis", "sql") if name != newest] + [newest]
    times = {}
    try:
        for name in sources:
            if name == "grant":
                grant_id = await _send_grant_heartbeat(
                    env, path=GrantHeartbeatRoute.WORKSPACE
                )
                times[name] = await env.db.fetch_value(
                    "SELECT last_seen_at FROM {{tables.identity_grant_liveness}} WHERE grant_id=$1",
                    grant_id,
                )
            elif name == "redis":
                await update_agent_presence(
                    env.redis, workspace_id=str(actor.workspace), alias="alice",
                    team_id=TEAM, status="listening",
                )
                times[name] = datetime.fromisoformat(
                    await env.redis.hget(f"presence:{actor.workspace}", "last_seen")
                )
            else:
                connected = await _send_member_request(
                    env, alias="alice", method="POST", path="/v1/connect", body={}
                )
                assert connected.status_code == 200, connected.text
                times[name] = await _root_last_seen(env)
        assert all(times[newest] > times[other] for other in sources[:-1])
        agent = next(agent for agent in await roster(env) if agent["alias"] == "alice")
        assert agent["online"] is True
        assert agent["status"] == "listening"
        assert datetime.fromisoformat(agent["last_seen"]) == times[newest]
    finally:
        await clear_workspace_presence(env.redis, [str(actor.workspace)])


@pytest.mark.asyncio
async def test_invalid_newest_grant_does_not_hide_older_valid_activity(roster_stack):
    env = roster_stack
    actor = env.actors["alice"]
    await admit_room_member(env, alias="alice")
    older = await _send_grant_heartbeat(env, path=GrantHeartbeatRoute.WORKSPACE)
    newer = await _send_grant_heartbeat(env, path=GrantHeartbeatRoute.WORKSPACE)
    expected = await env.db.fetch_value(
        "SELECT last_seen_at FROM {{tables.identity_grant_liveness}} WHERE grant_id=$1",
        older,
    )
    newer_seen = await env.db.fetch_value(
        "SELECT last_seen_at FROM {{tables.identity_grant_liveness}} WHERE grant_id=$1",
        newer,
    )
    assert newer_seen > expected > await _root_last_seen(env)
    revoked = await env.client.post(
        f"/v1/identity-grants/{newer}/revoke",
        headers=_signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate),
    )
    assert revoked.status_code == 200, revoked.text
    # No root presence can supply the expected online time.
    await clear_workspace_presence(env.redis, [str(actor.workspace)])
    agent = next(agent for agent in await roster(env) if agent["alias"] == "alice")
    assert agent["online"] is True
    assert datetime.fromisoformat(agent["last_seen"]) == expected
