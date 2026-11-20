"""Agent HTTP consumers use the serving app, registry, PostgreSQL and Redis."""

import asyncio
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from nacl.public import PrivateKey

from aweb.embedding import OutboxRecoveryOwnership
from awid.e2ee_keys import (
    build_encryption_key_assertion,
    canonical_encryption_assertion,
)
from awid.signing import sign_message
from identity_binding_support import register_global_identity
from test_coordination_state_http import request_as
from test_dashboard_privacy import TEAM, privacy_stack
from test_messages_http import _encode_certificate, _make_certificate, _make_keypair


@pytest_asyncio.fixture
async def privacy_app(shared_test_pool, monkeypatch):
    async with privacy_stack(
        shared_test_pool, monkeypatch, outbox_recovery=OutboxRecoveryOwnership.HOST
    ) as env:
        yield env


async def _only_alice(env):
    # Supported inactive fixture rows are excluded by alias discovery.
    await env.db.execute(
        "UPDATE {{tables.workspaces}} SET deleted_at=NOW() WHERE team_id=$1 AND alias<>'alice'",
        TEAM,
    )
    await env.db.execute(
        "UPDATE {{tables.agents}} SET deleted_at=NOW() WHERE team_id=$1 AND alias<>'alice'",
        TEAM,
    )


async def _global_actor(env, alias="alice", *, address=""):
    actor = env.actors[alias]
    stable = await register_global_identity(env, actor, address)
    actor.certificate = _encode_certificate(
        _make_certificate(
            env.team_sk,
            env.team_did,
            actor.did,
            team_id=TEAM,
            alias=alias,
            identity_scope="global",
            member_did_aw=stable,
            member_address=address,
            certificate_id=f"global-{uuid4()}",
        )
    )
    response = await request_as(
        env,
        alias=alias,
        method="POST",
        path="/v1/connect",
        payload={"hostname": "test", "workspace_path": f"/global/{alias}"},
    )
    assert response.status_code == 200, response.text
    actor.workspace = UUID(response.json()["workspace_id"])
    assert response.json()["agent_id"] == str(actor.id)
    return stable


async def _suggest(env, payload=None):
    return await request_as(
        env,
        alias="alice",
        method="POST",
        path="/v1/agents/suggest-alias-prefix",
        payload=payload,
    )


@pytest.mark.asyncio
async def test_suggest_alias_prefix_returns_next_available_name(privacy_app):
    env = privacy_app
    response = await _suggest(env, {})
    assert response.status_code == 200, response.text
    assert response.json() == {
        "team_id": TEAM,
        "name_prefix": "charlie",
        "names": [{"name": "charlie"}],
    }


@pytest.mark.asyncio
async def test_suggest_alias_prefix_no_body_keeps_legacy_response_shape(privacy_app):
    env = privacy_app
    await _only_alice(env)
    response = await _suggest(env)
    assert response.status_code == 200, response.text
    assert response.json() == {"team_id": TEAM, "name_prefix": "bob"}


@pytest.mark.asyncio
async def test_suggest_alias_prefix_uses_agent_aliases_without_workspace_rows(
    privacy_app,
):
    env = privacy_app
    await _only_alice(env)
    await env.db.execute("DELETE FROM {{tables.workspaces}} WHERE team_id=$1", TEAM)
    response = await _suggest(env, {})
    assert response.status_code == 200, response.text
    assert response.json() == {
        "team_id": TEAM,
        "name_prefix": "bob",
        "names": [{"name": "bob"}],
    }


@pytest.mark.asyncio
async def test_suggest_alias_prefix_count_and_exclude_are_ordered(privacy_app):
    env = privacy_app
    response = await _suggest(env, {"exclude": ["charlie"], "count": 3})
    assert response.status_code == 200, response.text
    assert response.json() == {
        "team_id": TEAM,
        "name_prefix": "dave",
        "names": [{"name": "dave"}, {"name": "eve"}, {"name": "frank"}],
    }


@pytest.mark.asyncio
async def test_suggest_alias_prefix_global_uses_namespace_names_and_user_prefix(
    privacy_app,
):
    env = privacy_app
    await _global_actor(env, address="example.test/maria")
    registry = env.app.state.awid_registry_client
    # The names are published with independent namespace custody, not a list override.
    for domain, name in (
        ("example.test", "maria-alice"),
        ("example.test", "maria-bob"),
        ("example.test", "other-alice"),
        ("other.test", "maria-charlie"),
    ):
        sk, _, did = _make_keypair()
        stable = (await registry.register_did(did, sk)).did_aw
        controller = await env.registry.ensure_namespace(domain=domain)
        await registry.register_address(
            domain, name, stable, bytes(controller), current_did_key=did
        )
    response = await _suggest(
        env, {"scope": "global", "exclude": ["maria-charlie"], "count": 2}
    )
    assert response.status_code == 200, response.text
    assert response.json() == {
        "team_id": TEAM,
        "name_prefix": "maria-dave",
        "names": [{"name": "maria-dave"}, {"name": "maria-eve"}],
    }


@pytest.mark.asyncio
async def test_patch_agent_workspace_accepts_canonical_role_name(privacy_app):
    env = privacy_app
    await env.db.execute(
        "UPDATE {{tables.workspaces}} SET role='developer',workspace_type='manual' WHERE workspace_id=$1",
        env.actors["alice"].workspace,
    )
    response = await request_as(
        env,
        alias="alice",
        method="PATCH",
        path="/v1/agents/me",
        payload={"role_name": "Reviewer"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["role_name"] == "reviewer"
    assert response.json()["role"] == "reviewer"
    row = await env.db.fetch_one(
        "SELECT role,workspace_type FROM {{tables.workspaces}} WHERE workspace_id=$1",
        env.actors["alice"].workspace,
    )
    assert row["role"] == "reviewer"
    assert row["workspace_type"] == "manual"


@pytest.mark.asyncio
async def test_patch_agent_workspace_omission_preserves_concurrent_repo_binding(
    privacy_app, monkeypatch
):
    env = privacy_app
    await env.db.execute(
        "UPDATE {{tables.workspaces}} SET role='developer',workspace_type='manual' WHERE workspace_id=$1",
        env.actors["alice"].workspace,
    )
    reached, resume = asyncio.Event(), asyncio.Event()
    real_fetch = env.db.fetch_one
    first = True

    async def hold_read(query, *args, **kwargs):
        nonlocal first
        row = await real_fetch(query, *args, **kwargs)
        if first and "SELECT w.workspace_id, w.hostname" in query:
            first = False
            reached.set()
            await asyncio.wait_for(resume.wait(), 5)
        return row

    # Pause only scheduling after the actual SQL read; every result/write stays real.
    monkeypatch.setattr(env.db, "fetch_one", hold_read)
    role_request = asyncio.create_task(
        request_as(
            env,
            alias="alice",
            method="PATCH",
            path="/v1/agents/me",
            payload={"role_name": "Reviewer"},
        )
    )
    try:
        await asyncio.wait_for(reached.wait(), 5)
        repair = await request_as(
            env,
            alias="alice",
            method="PATCH",
            path="/v1/agents/me",
            payload={"repo_origin": "https://github.com/acme/backend.git"},
        )
        assert repair.status_code == 200, repair.text
    finally:
        resume.set()
        role = await asyncio.wait_for(role_request, 5)
    assert role.status_code == 200, role.text
    row = await env.db.fetch_one(
        "SELECT w.role,w.repo_id,w.workspace_type,r.canonical_origin "
        "FROM {{tables.workspaces}} w LEFT JOIN {{tables.repos}} r ON r.id=w.repo_id "
        "WHERE w.workspace_id=$1",
        env.actors["alice"].workspace,
    )
    assert row["role"] == "reviewer"
    assert str(row["repo_id"]) == repair.json()["repo_id"]
    assert row["workspace_type"] == "agent"
    assert row["canonical_origin"] == "github.com/acme/backend"


@pytest.mark.asyncio
async def test_patch_agent_workspace_repairs_ssh_over_443_repo_binding(privacy_app):
    env = privacy_app
    body = {"repo_origin": "ssh://git@ssh.github.com:443/acme/backend.git"}
    first = await request_as(
        env, alias="alice", method="PATCH", path="/v1/agents/me", payload=body
    )
    second = await request_as(
        env, alias="alice", method="PATCH", path="/v1/agents/me", payload=body
    )
    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert first.json()["canonical_origin"] == "github.com/acme/backend"
    assert second.json()["repo_id"] == first.json()["repo_id"]
    row = await env.db.fetch_one(
        "SELECT w.repo_id,w.workspace_type,r.canonical_origin FROM {{tables.workspaces}} w "
        "JOIN {{tables.repos}} r ON r.id=w.repo_id WHERE w.workspace_id=$1",
        env.actors["alice"].workspace,
    )
    assert str(row["repo_id"]) == first.json()["repo_id"]
    assert row["canonical_origin"] == "github.com/acme/backend"
    assert row["workspace_type"] == "agent"


@pytest.mark.asyncio
async def test_get_my_inbound_mode_returns_current_global_agent_policy(privacy_app):
    env = privacy_app
    await _global_actor(env)
    changed = await request_as(
        env,
        alias="alice",
        method="PATCH",
        path="/v1/agents/me/inbound-mode",
        payload={"inbound_mode": "contacts_only"},
    )
    assert changed.status_code == 200, changed.text
    response = await request_as(
        env, alias="alice", method="GET", path="/v1/agents/me/inbound-mode"
    )
    assert response.status_code == 200, response.text
    assert response.json() == {
        "agent_id": str(env.actors["alice"].id),
        "team_id": TEAM,
        "alias": "alice",
        "identity_scope": "global",
        "inbound_mode": "contacts_only",
        "configurable": True,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["team_and_contacts", "contacts_only", "open"])
async def test_patch_my_inbound_mode_updates_global_agent_policy(privacy_app, mode):
    env = privacy_app
    await _global_actor(env)
    response = await request_as(
        env,
        alias="alice",
        method="PATCH",
        path="/v1/agents/me/inbound-mode",
        payload={"inbound_mode": mode},
    )
    assert response.status_code == 200, response.text
    assert response.json()["inbound_mode"] == mode
    stored = await env.db.fetch_value(
        "SELECT inbound_mode FROM {{tables.agents}} WHERE agent_id=$1",
        env.actors["alice"].id,
    )
    assert stored == mode


@pytest.mark.asyncio
async def test_patch_my_inbound_mode_rejects_local_agent(privacy_app):
    response = await request_as(
        privacy_app,
        alias="alice",
        method="PATCH",
        path="/v1/agents/me/inbound-mode",
        payload={"inbound_mode": "contacts_only"},
    )
    assert response.status_code == 409, response.text
    assert "global" in response.text


def _assertion(actor, *, stable=None, now=None):
    return build_encryption_key_assertion(
        signing_key=actor.sk,
        identity_did=actor.did,
        identity_stable_id=stable,
        encryption_public_key=bytes(PrivateKey.generate().public_key),
        now=now,
    )


async def _publish(env, assertion):
    return await request_as(
        env,
        alias="alice",
        method="PUT",
        path="/v1/agents/me/encryption-key",
        payload=assertion,
    )


async def _listed_alice(env):
    response = await request_as(env, alias="alice", method="GET", path="/v1/agents")
    assert response.status_code == 200, response.text
    return next(
        row
        for row in response.json()["agents"]
        if row["agent_id"] == str(env.actors["alice"].id)
    )


@pytest.mark.asyncio
async def test_publish_my_encryption_key_for_local_agent_and_list_returns_verified_key(
    privacy_app,
):
    env = privacy_app
    assertion = _assertion(env.actors["alice"])
    publish = await _publish(env, assertion)
    assert publish.status_code == 200, publish.text
    assert (
        publish.json()["encryption_key"]["encryption_key_id"]
        == assertion["encryption_key_id"]
    )
    assert "identity_stable_id" not in publish.json()["encryption_key"]
    agent = await _listed_alice(env)
    assert agent["agent_id"] == str(env.actors["alice"].id)
    assert agent["repo"] is None
    assert (
        agent["encryption_key"]["encryption_key_id"] == assertion["encryption_key_id"]
    )
    assert "identity_stable_id" not in agent["encryption_key"]


@pytest.mark.asyncio
async def test_publish_my_encryption_key_preserves_signed_custody(privacy_app):
    env = privacy_app
    publish = await _publish(env, _assertion(env.actors["alice"]))
    assert publish.status_code == 200, publish.text
    assert publish.json()["encryption_key"]["custody"] == "self"
    agent = await _listed_alice(env)
    assert agent["agent_id"] == str(env.actors["alice"].id)
    assert agent["encryption_key"]["custody"] == "self"


@pytest.mark.asyncio
async def test_publish_my_encryption_key_rejects_unsigned_custody_mutation(privacy_app):
    env = privacy_app
    actor = env.actors["alice"]
    assertion = _assertion(actor)
    del assertion["custody"]
    assertion["signature"] = sign_message(
        actor.sk, canonical_encryption_assertion(assertion)
    )
    assertion["custody"] = "self"
    response = await _publish(env, assertion)
    assert response.status_code == 422, response.text
    assert "invalid signature" in response.json()["detail"]["message"]


@pytest.mark.asyncio
async def test_replayed_older_local_encryption_key_does_not_roll_back_listed_key(
    privacy_app,
):
    env = privacy_app
    now = datetime.now(timezone.utc)
    older = _assertion(env.actors["alice"], now=now - timedelta(minutes=2))
    newer = _assertion(env.actors["alice"], now=now - timedelta(minutes=1))
    for assertion in (older, newer, older):
        response = await _publish(env, assertion)
        assert response.status_code == 200, response.text
    agent = await _listed_alice(env)
    assert agent["encryption_key"]["encryption_key_id"] == newer["encryption_key_id"]


@pytest.mark.asyncio
async def test_publish_my_encryption_key_rejects_team_controller_substitution(
    privacy_app,
):
    env = privacy_app
    assertion = _assertion(env.actors["alice"])
    assertion["signature"] = sign_message(
        env.team_sk, canonical_encryption_assertion(assertion)
    )
    response = await _publish(env, assertion)
    assert response.status_code == 422, response.text
    assert response.json()["detail"]["code"] == "invalid_encryption_key_assertion"
    assert "invalid signature" in response.json()["detail"]["message"]


@pytest.mark.asyncio
async def test_publish_my_encryption_key_rejects_empty_local_stable_id_field(
    privacy_app,
):
    env = privacy_app
    assertion = _assertion(env.actors["alice"])
    assertion["identity_stable_id"] = ""
    assertion["signature"] = sign_message(
        env.actors["alice"].sk, canonical_encryption_assertion(assertion)
    )
    response = await _publish(env, assertion)
    assert response.status_code == 422, response.text
    assert "omit identity_stable_id" in response.json()["detail"]["message"]


@pytest.mark.asyncio
async def test_publish_my_encryption_key_requires_global_stable_id(privacy_app):
    env = privacy_app
    stable = await _global_actor(env)
    missing = await _publish(env, _assertion(env.actors["alice"]))
    assert missing.status_code == 422, missing.text
    assert "identity_stable_id" in missing.json()["detail"]["message"]
    response = await _publish(env, _assertion(env.actors["alice"], stable=stable))
    assert response.status_code == 200, response.text
    assert response.json()["encryption_key"]["identity_stable_id"] == stable
