"""The hook-binding routes: a member reads the team's bindings, and the team
owner's act activates or revokes one.

The caller's team identity is the routes' existing team-auth seam (tested in
its own suites). Everything the routes decide on, the owner act, the team's
current key in a real AWID registry and the bindings in PostgreSQL, is real.
"""

from __future__ import annotations

import base64
from contextlib import aclosing
from dataclasses import replace
from datetime import datetime

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


@pytest.mark.asyncio
async def test_an_unreachable_registry_is_a_classified_503_and_changes_nothing(env, monkeypatch):
    from awid.registry import RegistryClient

    await _install(env.db)
    registration, _ = await _bindings(env)
    monkeypatch.setattr(hook_routes, "get_team_identity", _identity(TEAM))
    # A real registry address nothing listens on: the read fails at the network.
    unreachable = RegistryClient(registry_url="http://127.0.0.1:9", timeout_seconds=1.0)
    app = _app(env, unreachable)
    signing, signature = env.owner.sign("hook-binding.activate", registration)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                f"/v1/apps/hook-bindings/{registration.binding_id}/activate", json=_body(signing, signature),
            )
    finally:
        await unreachable.aclose()

    assert response.status_code == 503, response.text
    assert "AWID owner-act team key" in response.json()["detail"]
    rows = await env.db.fetch_all("SELECT state FROM {{tables.app_hook_bindings}} WHERE binding_id = $1",
                                  registration.binding_id)
    assert [row["state"] for row in rows] == ["pending"]
    assert await env.db.fetch_value("SELECT COUNT(*) FROM {{tables.owner_act_nonces}}") == 0

    # AWID back: the same act now succeeds, because nothing was consumed.
    async with await _client(env, monkeypatch) as client:
        retried = await client.post(
            f"/v1/apps/hook-bindings/{registration.binding_id}/activate", json=_body(signing, signature),
        )
    assert retried.status_code == 200, retried.text


@pytest.mark.asyncio
async def test_a_server_without_a_registry_client_refuses_without_changing_anything(env, monkeypatch):
    await _install(env.db)
    registration, _ = await _bindings(env)
    monkeypatch.setattr(hook_routes, "get_team_identity", _identity(TEAM))
    app = _app(env, None)
    signing, signature = env.owner.sign("hook-binding.activate", registration)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            f"/v1/apps/hook-bindings/{registration.binding_id}/activate", json=_body(signing, signature),
        )
    assert response.status_code == 500
    assert "registry client not configured" in response.json()["detail"]
    assert await env.db.fetch_value("SELECT COUNT(*) FROM {{tables.owner_act_nonces}}") == 0


@pytest.mark.asyncio
async def test_a_stalled_registry_is_a_classified_503_and_the_same_act_can_retry(env, monkeypatch, caplog):
    from awid.registry import RegistryClient
    from tests.awid_stall_support import stalled_registry_url

    await _install(env.db)
    registration, _ = await _bindings(env)
    monkeypatch.setattr(hook_routes, "get_team_identity", _identity(TEAM))
    signing, signature = env.owner.sign("hook-binding.activate", registration)
    url = f"/v1/apps/hook-bindings/{registration.binding_id}/activate"
    async with stalled_registry_url() as registry_url:
        async with aclosing(RegistryClient(registry_url=registry_url, timeout_seconds=0.3)) as registry:
            app = _app(env, registry)
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                response = await client.post(url, json=_body(signing, signature))

    assert response.status_code == 503, response.text
    assert response.json()["detail"] == "AWID owner-act team key upstream unavailable (TimeoutError)"
    assert "AWID registry dependency failed reading the owner-act team key" in caplog.text
    assert "TimeoutError" in caplog.text
    assert await env.db.fetch_value(
        "SELECT state FROM {{tables.app_hook_bindings}} WHERE binding_id = $1", registration.binding_id,
    ) == "pending"
    assert await env.db.fetch_value("SELECT COUNT(*) FROM {{tables.owner_act_nonces}}") == 0
    async with await _client(env, monkeypatch) as client:
        retried = await client.post(url, json=_body(signing, signature))
    assert retried.status_code == 200, retried.text


@pytest.mark.asyncio
async def test_a_database_timeout_is_not_reported_as_an_awid_failure(env, monkeypatch, caplog):
    await _install(env.db)
    registration, _ = await _bindings(env)
    signing, signature = env.owner.sign("hook-binding.activate", registration)
    # A real PostgreSQL query exceeds asyncpg's client deadline at the binding
    # read. The route must not mistake that builtin TimeoutError for AWID's.
    original_fetch_one = env.db.fetch_one

    async def stalled_read(query, *args, **kwargs):
        return await original_fetch_one("SELECT pg_sleep(1)", timeout=0.01)

    monkeypatch.setattr(env.db, "fetch_one", stalled_read)
    async with await _client(env, monkeypatch) as client:
        with pytest.raises(TimeoutError):
            await client.post(
                f"/v1/apps/hook-bindings/{registration.binding_id}/activate", json=_body(signing, signature),
            )
    assert "AWID registry dependency failed" not in caplog.text
    assert await env.db.fetch_value("SELECT COUNT(*) FROM {{tables.owner_act_nonces}}") == 0


@pytest.mark.asyncio
async def test_a_misconfigured_verifier_is_logged_and_changes_nothing(env, monkeypatch, caplog):
    await _install(env.db)
    registration, _ = await _bindings(env)
    signing, signature = env.owner.sign("hook-binding.activate", registration)
    monkeypatch.setattr(hook_routes, "get_team_identity", _identity(TEAM))
    app = _app(env, env.registry)
    app.state.public_origin = ""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            f"/v1/apps/hook-bindings/{registration.binding_id}/activate", json=_body(signing, signature),
        )
    assert response.status_code == 500, response.text
    assert response.json()["detail"].startswith("verifier_misconfigured:")
    errors = [record for record in caplog.records if record.name == hook_routes.__name__ and record.levelname == "ERROR"]
    assert len(errors) == 1
    assert "verifier_misconfigured" in errors[0].getMessage()
    assert errors[0].exc_info is not None
    assert await env.db.fetch_value(
        "SELECT state FROM {{tables.app_hook_bindings}} WHERE binding_id = $1", registration.binding_id,
    ) == "pending"
    assert await env.db.fetch_value("SELECT COUNT(*) FROM {{tables.owner_act_nonces}}") == 0


@pytest.mark.asyncio
async def test_owner_and_app_binding_views_share_utc_times_and_safe_activation_rounding(env):
    from aweb.routes.app_hooks import _binding_fields

    await _install(env.db)
    registration, _ = await _bindings(env)
    binding = replace(
        registration,
        activated_at=datetime.fromisoformat("2026-10-20T16:59:59.123456-07:00"),
        active_from=datetime.fromisoformat("2026-10-20T16:59:59.999999-07:00"),
    )
    owner_view = hook_routes._as_response(binding)
    app_view = _binding_fields(binding)
    assert owner_view.activated_at == "2026-10-20T23:59:59.123Z"
    assert owner_view.active_from == app_view["active_from"] == "2026-10-21T00:00:00.000Z"
    assert owner_view.revoked_at is None
