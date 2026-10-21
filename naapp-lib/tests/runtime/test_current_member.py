"""Recorded creator evidence is rechecked against real AWID on PostgreSQL."""

from __future__ import annotations

import asyncio
import socket
import time
from dataclasses import replace

import httpx
import pytest
import uvicorn
from aweb_naapp_testing import REGISTRY_URL, SERVICE_TOKEN, Member, did_key
from fastapi import FastAPI, HTTPException, Request
from nacl.signing import SigningKey

from aweb_naapp.manifest import write_manifest_file
from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.settings import NaappSettings
from aweb_naapp.runtime.team_auth import AWIDTeamCache

TEAM = "backend:example.com"
ORIGIN = "https://example.test"


@pytest.fixture(params=[None, SERVICE_TOKEN], ids=["certificate-status", "history"])
def cache(registry, request):
    return AWIDTeamCache(
        registry_url=REGISTRY_URL, ttl_seconds=0,
        service_token=request.param, transport=registry.transport,
    )


@pytest.fixture(params=["public", "private"])
async def member(registry, request):
    member = Member(team_id=TEAM)
    await registry.add_team(TEAM, member.team_did_key, visibility=request.param)
    await registry.add_certificate(member.certificate())
    return member


async def require(cache, member, **overrides):
    evidence = {"certificate_id": member.certificate_id, "team_did_key": member.team_did_key}
    evidence.update(overrides)
    return await cache.require_current_member(TEAM, **evidence)


async def test_current_member_passes_without_observed_principal_rows(cache, member):
    assert await require(cache, member) is None


@pytest.mark.parametrize("change", ["revoke", "remove", "rotate"])
async def test_lost_authority_refuses_on_refresh(registry, cache, member, change):
    await require(cache, member)
    if change == "revoke":
        await registry.revoke(member.certificate_id)
    elif change == "remove":
        await registry.db.execute(
            "DELETE FROM {{tables.team_certificates}} WHERE certificate_id = $1", member.certificate_id
        )
    else:
        await registry.rotate_team_key(TEAM, did_key(SigningKey.generate()))
    with pytest.raises(HTTPException) as refused:
        await require(cache, member)
    assert refused.value.status_code == 403
    assert refused.value.detail["code"] == "current_member_required"


async def test_another_teams_evidence_is_not_authority(registry, cache, member):
    other = Member(team_id="other:example.com", certificate_id=member.certificate_id)
    await registry.add_team(other.team_id, other.team_did_key)
    await registry.add_certificate(other.certificate())
    with pytest.raises(HTTPException) as refused:
        await require(cache, other)
    assert refused.value.status_code == 403


async def test_unreadable_private_team_facts_are_retryable(registry, member):
    cache = AWIDTeamCache(
        registry_url=REGISTRY_URL, ttl_seconds=0, service_token="wrong-service-token",
        transport=registry.transport,
    )
    visibility = await registry.db.fetch_value("SELECT visibility FROM {{tables.teams}}")
    if visibility == "public":
        await require(cache, member)
    else:
        with pytest.raises(HTTPException) as refused:
            await require(cache, member)
        assert refused.value.status_code == 503
        assert refused.value.detail["code"] == "current_membership_unavailable"


@pytest.mark.parametrize("evidence", [
    {"certificate_id": ""}, {"certificate_id": None},
    {"team_did_key": ""}, {"team_did_key": None},
])
async def test_incomplete_mint_evidence_refuses_before_lookup(registry, cache, member, evidence):
    with pytest.raises(HTTPException) as refused:
        await require(cache, member, **evidence)
    assert refused.value.status_code == 403
    assert registry.transport.calls == []


async def test_runtime_uses_the_request_verifiers_bounded_cache(registry, member, test_db_factory, tmp_path):
    db = await test_db_factory.create_db()
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    manifest = tmp_path / "aweb-app.json"
    write_manifest_file(manifest, {
        "manifest_version": 1, "app": {"id": "example", "origin": ORIGIN}, "tools": [],
    })
    runtime = NaappRuntime(
        NaappSettings(
            _env_file=None, database_url=db.config.get_dsn(), db_schema=db.schema,
            app_id="example", public_origin=ORIGIN, awid_registry_url=REGISTRY_URL,
        ),
        module_name="example", migrations_path=migrations, manifest_path=manifest,
        awid_transport=registry.transport,
    )
    app = FastAPI()

    @app.get("/mint")
    async def mint(request: Request):
        principal = await runtime.principal(request)
        return {"team_id": principal.team_id, "certificate_id": principal.certificate_id,
                "team_did_key": principal.team_did_key}

    async with runtime.lifespan(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=ORIGIN) as client:
            response = await client.get("/mint", headers=member.headers(aud=ORIGIN, method="GET", path="/mint"))
        assert response.status_code == 200, response.text
        evidence = response.json()
        calls = len(registry.transport.calls)
        await runtime.require_current_member(**evidence)
        assert len(registry.transport.calls) == calls
        assert await runtime.db().fetch_value("SELECT count(*) FROM {{tables.agents}}") == 0
        cache = runtime.team_cache()
        key = (TEAM, member.certificate_id)
        cached = cache._certificate_cache[key]
        assert 0 < cached.expires_at - time.monotonic() <= 60
        await registry.revoke(member.certificate_id)
        await runtime.require_current_member(**evidence)
        cache._certificate_cache[key] = replace(cached, expires_at=-1)
        with pytest.raises(HTTPException) as refused:
            await runtime.require_current_member(**evidence)
        assert refused.value.status_code == 403


async def test_stopped_awid_is_retryable_not_authority_loss(registry, member):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
    server = uvicorn.Server(uvicorn.Config(registry.transport._inner.app, log_level="error", lifespan="off"))
    serving = asyncio.create_task(server.serve(sockets=[listener]))
    try:
        async with asyncio.timeout(5):
            while not server.started:
                if serving.done():
                    await serving
                await asyncio.sleep(0.01)
        cache = AWIDTeamCache(registry_url=origin, ttl_seconds=0)
        await require(cache, member)
    finally:
        server.should_exit = True
        await serving
        listener.close()
    with pytest.raises(HTTPException) as refused:
        await require(cache, member)
    assert refused.value.status_code == 503
    assert refused.value.detail["code"] == "current_membership_unavailable"
