"""Mounted and direct HTTP confirmation with real origin TLS and PostgreSQL."""

from __future__ import annotations

from contextlib import asynccontextmanager
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
import test_verified_installations as store_fixture
from fastapi import FastAPI
from test_app_manifest_fetch import digest

from aweb.internal_auth import ProxyVerificationConfig
from aweb.internal_auth import build_internal_auth_header_value
from aweb.routes.app_hooks import router as hooks_router
from aweb.routes.apps import router

origin = store_fixture.origin
db = store_fixture.db
TEAM = store_fixture.TEAM
PRINCIPAL = str(uuid4())
ACTOR = str(uuid4())
SECRET = "test-installation-http-secret"
pytestmark = pytest.mark.asyncio


def headers():
    return {
        "X-Team-ID": TEAM,
        "X-User-ID": PRINCIPAL,
        "X-AWEB-Actor-ID": ACTOR,
        "X-AWEB-Auth": build_internal_auth_header_value(
            secret=SECRET,
            team_id=TEAM,
            principal_type="u",
            principal_id=PRINCIPAL,
            actor_id=ACTOR,
        ),
    }


@asynccontextmanager
async def mounted(db, monkeypatch, fetcher):
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", SECRET)
    await db.execute(
        "CREATE TABLE aweb.test_install_admins (team_id TEXT, subject_id TEXT)"
    )

    class Managers:
        def get_manager(self, name="aweb"):
            return db

    async def policy(tx, subject, *, action, app_id, verified_origin=None):
        return bool(
            await tx.fetch_value(
                "SELECT EXISTS(SELECT 1 FROM aweb.test_install_admins WHERE team_id=$1 AND subject_id=$2)",
                subject.team_id,
                subject.principal_id,
            )
        )

    inner = FastAPI()
    ProxyVerificationConfig.capture().install(inner)
    inner.state.db = Managers()
    inner.state.public_origin = "http://test"
    inner.state.install_admin_policy = policy
    inner.state.manifest_fetcher = fetcher
    inner.include_router(router)
    inner.include_router(hooks_router)
    outer = FastAPI()
    outer.mount("/api", inner)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=outer), base_url="http://test"
    ) as caller:
        yield caller


@pytest_asyncio.fixture
async def client(db, origin, monkeypatch):
    async with mounted(db, monkeypatch, origin.fetcher) as caller:
        yield caller


@pytest_asyncio.fixture
async def public_client(db, origin, monkeypatch):
    """The production address policy, resolving names through the test DNS."""
    async with mounted(db, monkeypatch, origin.public_fetcher) as caller:
        yield caller


async def admin(db):
    await db.execute(
        "INSERT INTO aweb.test_install_admins VALUES ($1,$2)", TEAM, PRINCIPAL
    )


def confirmation(origin):
    data = origin.manifest()
    origin.publish(data)
    return {
        "app_id": "fixture",
        "origin": origin.url,
        "digest": digest(data),
        "granted_scopes": ["fixture:read"],
    }


async def post(client, body, path="install"):
    return await client.post(
        f"/api/v1/apps/{path}?team_id={TEAM}", json=body, headers=headers()
    )


async def test_member_refusal_precedes_origin_fetch_and_grants_nothing(
    client, db, origin
):
    response = await post(client, confirmation(origin))
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "admin_required"
    assert not origin.tls.seen
    assert await store_fixture.current(db) is None


async def test_admin_confirmation_installs_fetched_bytes_and_returns_identity(
    client, db, origin
):
    await admin(db)
    response = await post(client, confirmation(origin))
    assert response.status_code == 200, response.text
    record = response.json()
    assert record["installation_id"]
    assert record["generation"] == 1
    assert record["state"] == "active" and record["origin_verified"] is True
    assert record["granted_scopes"] == ["fixture:read"]
    assert (await store_fixture.current(db))["digest"] == record["digest"]


async def test_planted_keys_and_submitted_bytes_are_not_a_second_install_path(
    client, db, origin
):
    await admin(db)
    payload = confirmation(origin)
    payload["event_emitters"] = [{"kid": "planted", "did_key": "did:key:planted"}]
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
        await db.execute("DELETE FROM aweb.test_install_admins")
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


async def test_member_preview_is_read_only_and_confirmation_is_digest_pinned(
    client, db, origin
):
    payload = confirmation(origin)
    response = await post(client, {"origin": origin.url}, "preview")
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


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("https://localhost", "origin_refused"),
        ("https://10.0.0.1", "origin_refused"),
        ("https://nothing-here.invalid", "origin_unresolvable"),
    ],
)
async def test_preview_of_an_origin_never_reached_is_unprocessable(
    public_client, origin, url, code
):
    origin.dns.records[("localhost", "A")] = ["127.0.0.1"]
    response = await post(public_client, {"origin": url}, "preview")
    assert response.status_code == 422, response.text
    assert response.json()["detail"]["code"] == code
    assert not origin.tls.seen


async def test_preview_of_an_origin_that_answers_500_is_a_bad_gateway(client, origin):
    origin.routes["/.well-known/aweb-app-versions.json"] = (500, b"", [])
    response = await post(client, {"origin": origin.url}, "preview")
    assert response.status_code == 502, response.text
    assert response.json()["detail"]["code"] == "catalog_unavailable"
    assert len(origin.tls.seen) == 1


async def test_member_request_has_a_separate_current_admin_approval_path(
    client, db, origin
):
    payload = confirmation(origin)
    payload["requested_scopes"] = payload.pop("granted_scopes")
    created = await post(client, payload, "requests")
    assert created.status_code == 201, created.text
    request_id = created.json()["request_id"]
    assert await store_fixture.current(db) is None
    body = {"granted_scopes": ["fixture:read"]}
    assert (
        await post(client, body, f"requests/{request_id}/approve")
    ).status_code == 403
    await admin(db)
    approved = await post(client, body, f"requests/{request_id}/approve")
    assert approved.status_code == 200, approved.text
    mine = await client.get(f"/api/v1/apps/requests?team_id={TEAM}", headers=headers())
    assert mine.status_code == 200, mine.text
    assert mine.json()["requests"][0]["state"] == "approved"
    assert (
        mine.json()["requests"][0]["installation_id"]
        == approved.json()["installation_id"]
    )
    assert mine.json()["requests"][0]["requested_by"]["user_id"] == PRINCIPAL
    origin.tls.seen.clear()
    origin.publish(origin.manifest(version="2.0.0"))
    again = await post(client, body, f"requests/{request_id}/approve")
    assert again.status_code == 409
    assert again.json()["detail"]["code"] == "installation_request_resolved"
    assert not origin.tls.seen


async def test_admin_reverify_only_queues_and_management_exposes_pending_reason(
    client, db, origin
):
    await admin(db)
    assert (await post(client, confirmation(origin))).status_code == 200
    await store_fixture.make_pending(db)
    origin.tls.seen.clear()
    queued = await post(client, {"expected_generation": 1}, "fixture/reverify")
    assert queued.status_code == 202, queued.text
    assert queued.json()["state"] == "queued"
    assert not origin.tls.seen
    read = await client.get(
        f"/api/v1/apps/fixture/installation?team_id={TEAM}", headers=headers()
    )
    assert read.status_code == 200, read.text
    assert read.json()["state"] == "pending_origin_verification"
    assert read.json()["lifecycle"]["report"] == {"available": False}


async def forwarded_agent(db, *, status="active", removed=False, team=TEAM):
    """The agent row the forwarded actor id names, in `team`."""
    namespace = team.split(":", 1)[1]
    await db.execute(
        "INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key) "
        "VALUES ($1, $2, $3, 'did:key:z6MkkopcdRMf2qPVBdcugyhrVQorfEfz2uUigTwZDvZ15poA' /* z6MkTeam */) ON CONFLICT DO NOTHING",
        team,
        namespace,
        team.split(":", 1)[0],
    )
    await db.execute(
        "INSERT INTO {{tables.agents}} (agent_id, team_id, did_key, alias, identity_scope, status, deleted_at, inbound_mode) "
        "VALUES ($1, $2, 'did:key:z6MkggGwZHMkBygNAy7tZGtCZxrkWBHQ5fpEm6fSAxfkuvqE' /* z6MkAlice */, 'alice', 'local', $3, "
        "CASE WHEN $4 THEN NOW() END, 'open')",
        ACTOR,
        team,
        status,
        removed,
    )


async def test_a_forwarded_actor_that_names_an_active_member_or_no_agent_reads_installations(
    client, db
):
    # The proxy's placeholder for a caller with no agent names no agent row.
    assert (
        await client.get(f"/api/v1/apps/installed?team_id={TEAM}", headers=headers())
    ).status_code == 200
    await forwarded_agent(db)
    assert (
        await client.get(f"/api/v1/apps/installed?team_id={TEAM}", headers=headers())
    ).status_code == 200


@pytest.mark.parametrize(
    "state", ["retired", "archived", "deleted", "removed", "other-team"]
)
async def test_a_forwarded_actor_that_names_an_agent_that_is_not_an_active_member_is_refused(
    client, db, origin, state
):
    if state == "removed":
        await forwarded_agent(db, removed=True)
    elif state == "other-team":
        await forwarded_agent(db, team="elsewhere:example.com")
    else:
        await forwarded_agent(db, status=state)
    await admin(db)

    listed = await client.get(
        f"/api/v1/apps/installed?team_id={TEAM}", headers=headers()
    )
    assert listed.status_code == 403, listed.text
    # An installation by this person's admin authority is refused the same way, and nothing is installed.
    installed = await post(client, confirmation(origin))
    assert installed.status_code == 403, installed.text
    assert await store_fixture.current(db) is None
