"""Mounted and direct HTTP confirmation with real origin TLS and PostgreSQL."""

from __future__ import annotations

from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI

import test_verified_installations as store_fixture
from aweb.internal_auth import build_internal_auth_header_value
from aweb.routes.apps import router
from test_app_manifest_fetch import digest

origin = store_fixture.origin
db = store_fixture.db
TEAM = store_fixture.TEAM
PRINCIPAL = str(uuid4())
ACTOR = str(uuid4())
SECRET = "test-installation-http-secret"
pytestmark = pytest.mark.asyncio


def headers():
    return {
        "X-Team-ID": TEAM, "X-User-ID": PRINCIPAL, "X-AWEB-Actor-ID": ACTOR,
        "X-AWEB-Auth": build_internal_auth_header_value(
            secret=SECRET, team_id=TEAM, principal_type="u", principal_id=PRINCIPAL, actor_id=ACTOR,
        ),
    }


@pytest_asyncio.fixture
async def client(db, origin, monkeypatch):
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", SECRET)
    await db.execute("CREATE TABLE test_install_admins (team_id TEXT, subject_id TEXT)")

    class Managers:
        def get_manager(self, name="aweb"):
            return db

    async def policy(tx, subject, *, action, app_id):
        return bool(await tx.fetch_value(
            "SELECT EXISTS(SELECT 1 FROM test_install_admins WHERE team_id=$1 AND subject_id=$2)",
            subject.team_id, subject.principal_id,
        ))

    inner = FastAPI()
    inner.state.db = Managers()
    inner.state.install_admin_policy = policy
    inner.state.manifest_fetcher = origin.fetcher
    inner.include_router(router)
    outer = FastAPI()
    outer.mount("/api", inner)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=outer), base_url="http://test") as caller:
        yield caller


async def admin(db):
    await db.execute("INSERT INTO test_install_admins VALUES ($1,$2)", TEAM, PRINCIPAL)


def confirmation(origin):
    data = origin.manifest()
    origin.publish(data)
    return {"app_id":"fixture", "origin":origin.url, "digest":digest(data), "granted_scopes":["fixture:read"]}


async def post(client, body, path="install"):
    return await client.post(f"/api/v1/apps/{path}?team_id={TEAM}", json=body, headers=headers())


async def test_member_refusal_precedes_origin_fetch_and_grants_nothing(client, db, origin):
    response = await post(client, confirmation(origin))
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "admin_required"
    assert not origin.tls.seen
    assert await store_fixture.current(db) is None


async def test_admin_confirmation_installs_fetched_bytes_and_returns_identity(client, db, origin):
    await admin(db)
    response = await post(client, confirmation(origin))
    assert response.status_code == 200, response.text
    record = response.json()
    assert record["installation_id"]
    assert record["generation"] == 1
    assert record["state"] == "active" and record["origin_verified"] is True
    assert record["granted_scopes"] == ["fixture:read"]
    assert (await store_fixture.current(db))["digest"] == record["digest"]


async def test_planted_keys_and_submitted_bytes_are_not_a_second_install_path(client, db, origin):
    await admin(db)
    payload = confirmation(origin)
    payload["event_emitters"] = [{"kid":"planted", "did_key":"did:key:planted"}]
    payload["manifest"] = "installer-supplied"
    response = await post(client, payload)
    assert response.status_code == 422
    assert not origin.tls.seen
    assert await store_fixture.current(db) is None


async def test_admin_policy_is_rechecked_after_the_origin_fetch(client, db, origin):
    await admin(db)
    payload = confirmation(origin)
    respond = origin.tls.respond

    async def revoke_during_fetch(seen):
        await db.execute("DELETE FROM test_install_admins")
        return await respond(seen)

    origin.tls.respond = revoke_during_fetch
    response = await post(client, payload)
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "admin_required"
    assert origin.tls.seen
    assert await store_fixture.current(db) is None


async def test_conditional_update_never_synthesizes_the_generation(client, db, origin):
    await admin(db)
    payload = confirmation(origin)
    assert (await post(client, payload)).status_code == 200
    refused = await post(client, payload)
    assert refused.status_code == 422
    assert refused.json()["detail"]["code"] == "generation_required"
    payload["expected_generation"] = 1
    updated = await post(client, payload)
    assert updated.status_code == 200, updated.text
    assert updated.json()["generation"] == 2
    conflict = await post(client, payload)
    assert conflict.status_code == 409
    assert conflict.json()["detail"]["code"] == "generation_conflict"


async def test_member_preview_is_read_only_and_confirmation_is_digest_pinned(client, db, origin):
    payload = confirmation(origin)
    response = await post(client, {"origin":origin.url}, "preview")
    assert response.status_code == 200, response.text
    preview = response.json()
    assert preview["digest"] == payload["digest"]
    assert preview["resolved"]["manifest_version"] == 2
    assert preview["current"] is None
    assert await store_fixture.current(db) is None
    await admin(db)
    origin.publish(origin.manifest() + b" ")
    refused = await post(client, payload)
    assert refused.status_code == 409
    assert refused.json()["detail"]["code"] == "manifest_changed"
    assert await store_fixture.current(db) is None
