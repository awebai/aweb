"""Real AWID routes/PostgreSQL and app authentication; no fake registry responses."""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from awid.did import did_from_public_key
from awid.pagination import decode_cursor, encode_cursor
from awid.ratelimit import NoOpRateLimiter
from awid.signing import canonical_json_bytes, sign_message
from awid_service.db import AwidDatabaseInfra
from awid_service.routes.teams import router
from fastapi import FastAPI, Request
from nacl.signing import SigningKey
from pgdbm import AsyncMigrationManager

from library import auth
from library.config import Settings

pytest_plugins = ("pgdbm.fixtures.conftest",)
TEAM_ID = "backend:example.com"
ORIGIN = "https://app.example.com"


def signed_headers():
    team_key, member_key = SigningKey.generate(), SigningKey.generate()
    team_did = did_from_public_key(bytes(team_key.verify_key))
    member_did = did_from_public_key(bytes(member_key.verify_key))
    timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    cert = {
        "version": 1, "certificate_id": "target", "team_id": TEAM_ID,
        "team_did_key": team_did, "member_did_key": member_did,
        "alias": "target", "issued_at": timestamp,
    }
    cert["signature"] = sign_message(bytes(team_key), canonical_json_bytes(cert))
    payload = canonical_json_bytes({
        "v": 2, "aud": ORIGIN, "method": "GET", "path": "/protected",
        "team_id": TEAM_ID, "timestamp": timestamp,
        "body_sha256": hashlib.sha256(b"").hexdigest(),
    })
    return team_did, member_did, {
        "Authorization": f"DIDKey {member_did} {sign_message(bytes(member_key), payload)}",
        "X-AWEB-Timestamp": timestamp,
        "X-AWID-Team-Certificate": base64.b64encode(json.dumps(cert).encode()).decode(),
        "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(payload).rstrip(b"=").decode(),
    }


@pytest_asyncio.fixture
async def real_registry(test_db_factory, monkeypatch, request):
    registry_db = await test_db_factory.create_db(suffix="pagination_registry")
    infra = AwidDatabaseInfra(schema="awid")
    monkeypatch.setenv("AWID_DATABASE_URL", registry_db.config.get_dsn())
    await infra.initialize(run_migrations=True)
    registry = FastAPI()
    registry.state.db = infra
    registry.state.rate_limiter = NoOpRateLimiter()
    token = "pagination-test-service-token-32-bytes"
    registry.state.awid_service_token = token
    registry.include_router(router)
    db = infra.get_manager("aweb")
    team_did, member_did, headers = signed_headers()
    visibility = getattr(request, "param", "public")
    team = await db.fetch_one(
        "INSERT INTO {{tables.teams}} (domain, name, team_did_key, visibility) "
        "VALUES ('example.com', 'backend', $1, $2) RETURNING team_uuid", team_did, visibility,
    )
    # 201 real rows: target is beyond both AWID's default 50 and the client's 200.
    await db.execute(
        "INSERT INTO {{tables.team_certificates}} "
        "(team_uuid, certificate_id, member_did_key, alias, issued_at) "
        "SELECT $1, 'filler-' || n, $2, 'filler-' || n, "
        "'2026-01-01'::timestamptz + n * interval '1 second' "
        "FROM generate_series(1, 200) AS n", team["team_uuid"], member_did,
    )
    await db.execute(
        "INSERT INTO {{tables.team_certificates}} "
        "(team_uuid, certificate_id, member_did_key, alias, issued_at) "
        "VALUES ($1, 'target', $2, 'target', '2026-01-02')", team["team_uuid"], member_did,
    )
    app_db = await test_db_factory.create_db(suffix="pagination_app")
    await AsyncMigrationManager(
        app_db, migrations_path=str(Path(auth.__file__).parent / "migrations"),
        module_name="library",
    ).apply_pending_migrations()
    calls = []
    faults = {}
    client_type = httpx.AsyncClient

    async def record(request):
        calls.append(request)

    async def inject_fault(response):
        # Faults are injected AFTER real AWID has handled the HTTP request.
        # Cache/authentication code, database queries and pagination stay real.
        if not response.request.url.path.endswith("/certificates"):
            return
        await response.aread()
        payload = response.json()
        if not response.request.url.params.get("cursor"):
            faults["first_cursor"] = payload.get("next_cursor")
            return
        fault = faults.get("kind")
        if fault is None:
            return
        if fault == "transport":
            raise httpx.ReadTimeout("injected later-page timeout", request=response.request)
        if fault == "http":
            response.status_code = 503
            return
        if fault == "json":
            response._content = b"{"
            return
        if fault == "payload":
            payload = []
        elif fault == "missing_has_more":
            payload.pop("has_more")
        elif fault == "has_more":
            payload["has_more"] = "false"
        elif fault == "certificates":
            payload["certificates"] = {}
        elif fault == "row":
            payload["certificates"] = [None]
        elif fault == "missing_revoked_at":
            payload["certificates"][0].pop("revoked_at")
        elif fault == "missing_certificate_id":
            payload["certificates"][0].pop("certificate_id")
        elif fault in ("missing_cursor", "blank_cursor", "invalid_cursor", "repeated_cursor", "cycling_cursor"):
            payload["has_more"] = True
            if fault == "cycling_cursor" and response.request.url.params["cursor"] == faults["first_cursor"]:
                prior = decode_cursor(faults["first_cursor"])
                prior["issued_at"] = "2025-12-31T00:00:00+00:00"
                payload["next_cursor"] = encode_cursor(prior)
            else:
                payload["next_cursor"] = {
                    "missing_cursor": None, "blank_cursor": " ", "invalid_cursor": 1,
                }.get(fault, faults["first_cursor"])
        elif fault == "private":
            response.status_code = 403
            payload = {"detail": {"code": "team_private"}}
        response._content = json.dumps(payload).encode()

    # Only replace transport selection: every request reaches real AWID handlers.
    monkeypatch.setattr(auth.httpx, "AsyncClient", lambda **kw: client_type(
        transport=httpx.ASGITransport(app=registry), event_hooks={"request": [record], "response": [inject_fault]}, **kw,
    ))
    cache = auth.AWIDTeamCache(registry_url="https://registry.example", ttl_seconds=60, service_token=token)
    app = FastAPI()

    @app.get("/protected")
    async def protected(request: Request):
        principal = await auth.authenticate_request(
            request, settings=Settings(public_origin=ORIGIN), team_cache=cache, db=app_db,
        )
        return {"certificate_id": principal.certificate_id}

    async with client_type(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as client:
        yield client, headers, cache, db, calls, faults
    await infra.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("real_registry", ["public", "private"], indirect=True)
@pytest.mark.parametrize("revoked", [False, True])
async def test_certificate_beyond_first_page(real_registry, revoked):
    client, headers, cache, db, calls, _faults = real_registry
    if revoked:
        await db.execute(
            "UPDATE {{tables.team_certificates}} SET revoked_at = now() WHERE certificate_id = 'target'"
        )
    response = await client.get("/protected", headers=headers)
    assert response.status_code == (401 if revoked else 200), response.text
    if revoked:
        assert response.json()["detail"] == "Team certificate has been revoked"
    pages = [r for r in calls if r.url.path.endswith("/certificates")]
    assert len(pages) == 2
    assert pages[1].url.params["cursor"]
    assert all(r.headers.get("X-AWID-Service-Token") == "pagination-test-service-token-32-bytes" for r in calls)
    assert cache._cache[TEAM_ID].revoked_certificate_ids == (frozenset({"target"}) if revoked else frozenset())


@pytest.mark.asyncio
async def test_page_bound_fails_closed_without_caching_partial_facts(real_registry):
    client, headers, cache, db, calls, _faults = real_registry
    await exceed_page_bound(db)
    response = await client.get("/protected", headers=headers)
    assert response.status_code == 503, response.text
    assert response.json()["detail"] == "AWID certificate pagination limit exceeded"
    assert not cache._cache
    assert len([r for r in calls if r.url.path.endswith("/certificates")]) == 100
    # The last permitted page is allowed when it actually completes the history.
    await db.execute("DELETE FROM {{tables.team_certificates}} WHERE certificate_id = 'filler-1'")
    response = await client.get("/protected", headers=headers)
    assert response.status_code == 200, response.text
    assert TEAM_ID in cache._cache


@pytest.mark.asyncio
async def test_failed_refresh_does_not_reuse_expired_facts(real_registry, caplog):
    client, headers, cache, db, _calls, _faults = real_registry
    assert (await client.get("/protected", headers=headers)).status_code == 200
    old = cache._cache[TEAM_ID]
    cache._cache[TEAM_ID] = replace(old, expires_at=-1)
    await exceed_page_bound(db)
    response = await client.get("/protected", headers=headers)
    assert response.status_code == 503
    assert cache._cache[TEAM_ID].expires_at == -1
    assert "AWID certificate pagination limit exceeded" in caplog.text


async def exceed_page_bound(db):
    # Together with the original 201 rows, cross the actual 20,000-record bound.
    await db.execute(
        "INSERT INTO {{tables.team_certificates}} "
        "(team_uuid, certificate_id, member_did_key, alias, issued_at) "
        "SELECT target.team_uuid, 'filler-' || n, target.member_did_key, 'filler-' || n, "
        "'2026-01-01'::timestamptz + n * interval '1 second' "
        "FROM {{tables.team_certificates}} target CROSS JOIN generate_series(201, 20000) AS n "
        "WHERE target.certificate_id = 'target'"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("fault,detail", [
    ("payload", "AWID registry unavailable"),
    ("json", "AWID registry unavailable"),
    ("missing_has_more", "AWID certificate revocation response is incomplete"),
    ("has_more", "AWID certificate revocation response is incomplete"),
    ("certificates", "AWID certificate revocation response is incomplete"),
    ("row", "AWID certificate revocation response is incomplete"),
    ("missing_revoked_at", "AWID certificate revocation response is incomplete"),
    ("missing_certificate_id", "AWID certificate revocation response is incomplete"),
    ("missing_cursor", "AWID certificate pagination did not advance"),
    ("repeated_cursor", "AWID certificate pagination did not advance"),
    ("blank_cursor", "AWID certificate pagination did not advance"),
    ("invalid_cursor", "AWID certificate pagination did not advance"),
    ("cycling_cursor", "AWID certificate pagination did not advance"),
    ("http", "AWID certificate revocation lookup unavailable"),
    ("transport", "AWID registry unavailable"),
])
async def test_later_page_fault_fails_closed(real_registry, fault, detail, caplog):
    client, headers, cache, _db, calls, faults = real_registry
    faults["kind"] = fault
    response = await client.get("/protected", headers=headers)
    assert response.status_code == 503, response.text
    assert response.json()["detail"] == detail
    assert not cache._cache
    pages = [r for r in calls if r.url.path.endswith("/certificates")]
    assert len(pages) == (3 if fault == "cycling_cursor" else 2)
    assert pages[1].url.params["cursor"] == faults["first_cursor"]
    assert "AWID team facts refresh failed" in caplog.text
    if fault == "transport":
        assert "injected later-page timeout" in caplog.text
    # Complete data from the same server still works after the fault is removed.
    faults.pop("kind")
    response = await client.get("/protected", headers=headers)
    assert response.status_code == 200, response.text
    assert TEAM_ID in cache._cache


@pytest.mark.asyncio
async def test_later_page_timeout_does_not_use_expired_cache(real_registry):
    client, headers, cache, _db, _calls, faults = real_registry
    assert (await client.get("/protected", headers=headers)).status_code == 200
    expired = replace(cache._cache[TEAM_ID], expires_at=-1)
    cache._cache[TEAM_ID] = expired
    faults["kind"] = "transport"
    response = await client.get("/protected", headers=headers)
    assert response.status_code == 503
    assert cache._cache[TEAM_ID] is expired


@pytest.mark.asyncio
async def test_later_page_private_denial_keeps_classified_403(real_registry):
    client, headers, cache, _db, calls, faults = real_registry
    faults["kind"] = "private"
    response = await client.get("/protected", headers=headers)
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "team_private_unreadable"
    assert not cache._cache
    assert len([r for r in calls if r.url.path.endswith("/certificates")]) == 2
