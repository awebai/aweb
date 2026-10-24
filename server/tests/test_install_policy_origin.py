"""Host admission and final authorization through real TLS, routes and PostgreSQL."""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio
import test_installation_http as http_fixture
from aweb.routes.apps import router
from fastapi import FastAPI

db = http_fixture.db
origin = http_fixture.origin
TEAM = http_fixture.TEAM
pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def host(db, origin, monkeypatch):
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", http_fixture.SECRET)

    class Managers:
        def get_manager(self, name="aweb"):
            return db

    admitted, authorized = [], []

    async def admission(tx, subject, *, action, app_id, unverified_origin):
        admitted.append((subject, action, app_id, unverified_origin))
        return True

    async def policy(tx, subject, *, action, app_id, verified_origin=None):
        authorized.append((subject, action, app_id, verified_origin))
        return verified_origin == origin.url

    app = FastAPI()
    app.state.db = Managers()
    app.state.manifest_fetcher = origin.fetcher
    app.state.install_admission_policy = admission
    app.state.install_admin_policy = policy
    app.include_router(router)
    outer = FastAPI()
    outer.mount("/api", app)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=outer), base_url="http://test") as client:
        yield SimpleNamespace(app=app, client=client, admitted=admitted, authorized=authorized)


async def successes(db):
    return await db.fetch_value("SELECT count(*) FROM {{tables.audit_log}} WHERE outcome='success'")


async def test_final_authorization_receives_canonical_fetched_origin_not_payload(host, db, origin):
    payload = http_fixture.confirmation(origin)
    payload["origin"] = origin.url.replace("manifest.fetch.test", "MANIFEST.FETCH.TEST") + "/"
    response = await http_fixture.post(host.client, payload)
    assert response.status_code == 200, response.text
    assert origin.tls.seen
    assert len(host.admitted) == len(host.authorized) == 1
    subject, action, app_id, hint = host.admitted[0]
    assert (action, app_id, hint) == ("apps.install", "fixture", payload["origin"])
    assert host.authorized == [(subject, "apps.install", "fixture", origin.url)]
    assert hint != origin.url
    assert (await http_fixture.store_fixture.current(db))["origin"] == origin.url
    assert await successes(db) == 1


async def test_manifest_claiming_another_origin_never_reaches_final_authorization(host, db, origin):
    payload = http_fixture.confirmation(origin)
    data = origin.manifest(origin="https://claimed.example")
    origin.publish(data)
    payload["digest"] = http_fixture.digest(data)
    response = await http_fixture.post(host.client, payload)
    assert response.status_code == 422, response.text
    assert response.json()["detail"]["code"] == "manifest_origin_mismatch"
    assert host.admitted and not host.authorized
    assert await http_fixture.store_fixture.current(db) is None
    assert await successes(db) == 0


@pytest.mark.parametrize("operation", ["install", "update", "approve"])
async def test_final_denial_after_admission_writes_no_installation_or_success_audit(host, db, origin, operation):
    payload = http_fixture.confirmation(origin)
    path = "install"
    if operation == "update":
        assert (await http_fixture.post(host.client, payload)).status_code == 200
        payload["expected_generation"] = 1
    elif operation == "approve":
        payload["requested_scopes"] = payload.pop("granted_scopes")
        created = await http_fixture.post(host.client, payload, "requests")
        assert created.status_code == 201, created.text
        path = f"requests/{created.json()['request_id']}/approve"
        payload = {"granted_scopes": ["fixture:read"]}
    before = await http_fixture.store_fixture.current(db)
    audit_before = await successes(db)
    host.admitted.clear()
    origin.tls.seen.clear()

    async def deny(tx, subject, *, action, app_id, verified_origin=None):
        assert verified_origin == origin.url
        return False

    host.app.state.install_admin_policy = deny
    response = await http_fixture.post(host.client, payload, path)
    assert response.status_code == 403, response.text
    assert response.json()["detail"]["code"] == "admin_required"
    assert host.admitted and origin.tls.seen
    assert await http_fixture.store_fixture.current(db) == before
    assert await successes(db) == audit_before
    if operation == "approve":
        assert await db.fetch_value("SELECT state FROM {{tables.app_installation_requests}}") == "pending"


async def test_update_rechecks_verified_origin_in_final_policy(host, db, origin):
    payload = http_fixture.confirmation(origin)
    assert (await http_fixture.post(host.client, payload)).status_code == 200
    before = await http_fixture.store_fixture.current(db)
    data = origin.manifest(version="2.0.0")
    origin.publish(data)
    payload.update(digest=http_fixture.digest(data), expected_generation=before["generation"])
    response = await http_fixture.post(host.client, payload)
    assert response.status_code == 200, response.text
    assert response.json()["generation"] > before["generation"]
    assert len(host.authorized) == 2
    assert [call[3] for call in host.authorized] == [origin.url, origin.url]
    assert await successes(db) == 2


async def test_request_approval_passes_both_policy_phases(host, db, origin):
    payload = http_fixture.confirmation(origin)
    payload["requested_scopes"] = payload.pop("granted_scopes")
    created = await http_fixture.post(host.client, payload, "requests")
    assert created.status_code == 201, created.text
    response = await http_fixture.post(
        host.client, {"granted_scopes": ["fixture:read"]}, f"requests/{created.json()['request_id']}/approve",
    )
    assert response.status_code == 200, response.text
    assert len(host.admitted) == len(host.authorized) == 1
    subject, action, app_id, hint = host.admitted[0]
    assert (action, app_id, hint) == ("apps.requests.approve", "fixture", origin.url)
    assert host.authorized == [(subject, action, app_id, origin.url)]
    assert await successes(db) == 1


@pytest.mark.parametrize("phase", ["admission", "authorization"])
@pytest.mark.parametrize("result", ["raises", 1, None])
async def test_policy_errors_and_non_true_results_are_stable_refusals(host, db, origin, phase, result):
    seen = []

    async def refuse(tx, subject, **kwargs):
        seen.append(kwargs)
        if result == "raises":
            raise RuntimeError("private host policy failure")
        return result

    attribute = "install_admission_policy" if phase == "admission" else "install_admin_policy"
    setattr(host.app.state, attribute, refuse)
    response = await http_fixture.post(host.client, http_fixture.confirmation(origin))
    assert response.status_code == (503 if result == "raises" else 403), response.text
    assert response.json()["detail"]["code"] == (
        "install_policy_unavailable" if result == "raises" else "admin_required"
    )
    assert "private host policy failure" not in response.text
    assert len(seen) == 1
    assert bool(origin.tls.seen) == (phase == "authorization")
    assert await http_fixture.store_fixture.current(db) is None
    assert await successes(db) == 0
