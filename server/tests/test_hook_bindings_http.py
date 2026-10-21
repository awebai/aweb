"""The hook-binding routes: a member reads the team's bindings, and the team
owner's act activates or revokes one.

The caller's team identity is the routes' existing team-auth seam (tested in
its own suites). Everything the routes decide on, the owner act, the team's
current key in a real AWID registry and the bindings in PostgreSQL, is real.
"""

from __future__ import annotations

import base64

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import aweb.routes.apps as apps_routes
import aweb.routes.hook_bindings as hook_routes
from aweb.routes.hook_bindings import router as hook_bindings_router
from tests.test_app_registry_http import _DbShim
from tests.test_hook_binding_activation import (  # noqa: F401
    AUDIENCE,
    OTHER_TEAM,
    TEAM,
    Owner,
    _bindings,
    _hook_keys,
    _install,
    env,
)
from aweb.audit import AuditActor, set_verified_audit_actor
from aweb.team_auth_deps import TeamIdentity


def _identity(team_id: str):
    async def identity(request, db_infra) -> TeamIdentity:
        # Real team-certificate auth sets the verified operator-audit actor.
        set_verified_audit_actor(
            request,
            AuditActor(team_id=team_id, principal_type="c", auth_mode="team_auth_v2", did_key="did:key:z6Mkalice"),
        )
        return TeamIdentity(
            team_id=team_id, alias="alice", did_key="did:key:z6Mkalice", did_aw="did:aw:alice",
            address="acme.com/alice", agent_id="00000000-0000-0000-0000-000000000123",
            identity_scope="global", certificate_id="cert-001",
        )

    return identity


def _app(env, registry_client) -> FastAPI:
    app = FastAPI()
    app.include_router(hook_bindings_router)
    app.state.db = _DbShim(env.db)
    app.state.public_origin = AUDIENCE
    app.state.awid_registry_client = registry_client
    return app


async def _client(env, monkeypatch, *, team_id=TEAM) -> AsyncClient:
    monkeypatch.setattr(hook_routes, "get_team_identity", _identity(team_id))
    monkeypatch.setattr(apps_routes, "get_team_identity", _identity(team_id))
    app = _app(env, env.registry)
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


def _body(signing: bytes, signature: str) -> dict:
    return {"act": base64.b64encode(signing).decode(), "signature": signature}


@pytest.mark.asyncio
async def test_a_member_lists_the_teams_bindings_with_millisecond_times(env, monkeypatch):
    await _install(env.db)
    registration, production = await _bindings(env)
    async with await _client(env, monkeypatch) as client:
        signing, signature = env.owner.sign("hook-binding.activate", registration)
        assert (await client.post(f"/v1/apps/hook-bindings/{registration.binding_id}/activate",
                                  json=_body(signing, signature))).status_code == 200

        listed = await client.get("/v1/apps/hook-bindings", params={"team_id": TEAM, "app_id": "logs"})

    assert listed.status_code == 200, listed.text
    body = listed.json()
    assert body["team_id"] == TEAM
    rows = {row["binding_id"]: row for row in body["bindings"]}
    active = rows[str(registration.binding_id)]
    assert active["state"] == "active"
    assert active["scopes"] == ["logs:append", "logs:write"]
    assert active["activated_at"].endswith("Z") and len(active["activated_at"]) == len("2026-10-20T12:00:00.000Z")
    pending = rows[str(production.binding_id)]
    assert (pending["state"], pending["tool"], pending["reads"], pending["activated_at"]) == (
        "pending", None, ["search"], None,
    )


@pytest.mark.asyncio
async def test_another_teams_bindings_are_not_listed(env, monkeypatch):
    await _install(env.db)
    await _bindings(env)
    async with await _client(env, monkeypatch, team_id=OTHER_TEAM) as client:
        response = await client.get("/v1/apps/hook-bindings", params={"team_id": TEAM, "app_id": "logs"})
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_the_owner_activates_and_revokes_over_http(env, monkeypatch):
    await _install(env.db)
    await _hook_keys(env.db)
    _, production = await _bindings(env)
    async with await _client(env, monkeypatch) as client:
        signing, signature = env.owner.sign("hook-binding.activate", production)
        activated = await client.post(f"/v1/apps/hook-bindings/{production.binding_id}/activate",
                                      json=_body(signing, signature))
        signing, signature = env.owner.sign("hook-binding.revoke", production)
        revoked = await client.post(f"/v1/apps/hook-bindings/{production.binding_id}/revoke",
                                    json=_body(signing, signature))

    assert activated.status_code == 200, activated.text
    assert activated.json()["state"] == "active"
    assert revoked.status_code == 200, revoked.text
    assert (revoked.json()["state"], revoked.json()["ended_by"]) == ("revoked", "owner_act")


@pytest.mark.asyncio
async def test_refusals_carry_their_status_and_code(env, monkeypatch):
    await _install(env.db)
    registration, _ = await _bindings(env)
    from nacl.signing import SigningKey

    async with await _client(env, monkeypatch) as client:
        url = f"/v1/apps/hook-bindings/{registration.binding_id}/activate"
        stranger = Owner(SigningKey.generate()).sign("hook-binding.activate", registration)
        forbidden = await client.post(url, json=_body(*stranger))
        mismatched = await client.post(url, json=_body(*env.owner.sign(
            "hook-binding.activate", registration, path="/hooks/other")))
        malformed = await client.post(url, json={"act": "not base64!", "signature": "x"})
        extra = await client.post(url, json={**_body(b"x", "y"), "note": "z"})
        unknown = await client.post(
            "/v1/apps/hook-bindings/00000000-0000-0000-0000-000000000000/activate", json=_body(b"x", "y"),
        )

    assert (forbidden.status_code, forbidden.json()["detail"].split(":")[0]) == (403, "owner_required")
    assert (mismatched.status_code, mismatched.json()["detail"].split(":")[0]) == (409, "subject_mismatch")
    assert malformed.status_code == 422
    assert extra.status_code == 422
    assert unknown.status_code == 404


def test_the_server_mounts_the_hook_binding_routes():
    from aweb.api import create_app

    paths = {(route.path, tuple(sorted(route.methods))) for route in create_app().routes if hasattr(route, "methods")}
    assert ("/v1/apps/hook-bindings", ("GET",)) in paths
    assert ("/v1/apps/hook-bindings/{binding_id}/activate", ("POST",)) in paths
    assert ("/v1/apps/hook-bindings/{binding_id}/revoke", ("POST",)) in paths
