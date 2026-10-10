"""Real AWID routes/PostgreSQL and app authentication, with HTTP-boundary fault controls."""
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
    registry_db = await test_db_factory.create_db(suffix="status_registry")
    infra = AwidDatabaseInfra(schema="awid")
    monkeypatch.setenv("AWID_DATABASE_URL", registry_db.config.get_dsn())
    await infra.initialize(run_migrations=True)
    registry = FastAPI()
    registry.state.db = infra
    registry.state.rate_limiter = NoOpRateLimiter()
    registry.state.awid_service_token = None
    registry.include_router(router)
    db = infra.get_manager("aweb")
    team_did, member_did, headers = signed_headers()
    team = await db.fetch_one(
        "INSERT INTO {{tables.teams}} (domain, name, team_did_key, visibility) "
        "VALUES ('example.com', 'backend', $1, $2) RETURNING team_uuid",
        team_did, getattr(request, "param", "private"),
    )
    await db.execute(
        "INSERT INTO {{tables.team_certificates}} "
        "(team_uuid, certificate_id, member_did_key, alias, issued_at) "
        "VALUES ($1, 'target', $2, 'target', now())", team["team_uuid"], member_did,
    )
    app_db = await test_db_factory.create_db(suffix="status_app")
    await AsyncMigrationManager(
        app_db, migrations_path=str(Path(auth.__file__).parent / "migrations"),
        module_name="library",
    ).apply_pending_migrations()
    calls, faults = [], {}
    client_type = httpx.AsyncClient

    async def record(request):
        calls.append(request)

    async def inject_fault(response):
        # Real route first; inject only HTTP response/transport failures.
        await response.aread()
        fault = faults.get("kind")
        if fault == "timeout":
            raise httpx.ReadTimeout("injected status timeout", request=response.request)
        if fault in (404, 429, 503):
            response.status_code = fault
        elif fault == "json":
            response._content = b"{"
        elif fault == "payload":
            response._content = json.dumps(faults["payload"]).encode()

    monkeypatch.setattr(auth.httpx, "AsyncClient", lambda **kw: client_type(
        transport=httpx.ASGITransport(app=registry),
        event_hooks={"request": [record], "response": [inject_fault]}, **kw,
    ))
    cache = auth.AWIDTeamCache(registry_url="https://registry.example", ttl_seconds=600)
    app = FastAPI()

    @app.get("/protected")
    async def protected(request: Request):
        principal = await auth.authenticate_request(
            request, settings=Settings(public_origin=ORIGIN), team_cache=cache, db=app_db,
        )
        return {"certificate_id": principal.certificate_id}

    try:
        async with client_type(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as client:
            yield client, headers, cache, db, calls, faults
    finally:
        await infra.close()


@pytest.mark.parametrize("real_registry", ["public", "private"], indirect=True)
async def test_status_verifies_published_certificate_and_rejects_revoked(real_registry):
    client, headers, cache, db, calls, _ = real_registry
    assert (await client.get("/protected", headers=headers)).status_code == 200
    assert len(calls) == 1
    assert calls[0].url.path.endswith("/certificates/target/status")
    assert "X-AWID-Service-Token" not in calls[0].headers
    old = cache._certificate_cache[(TEAM_ID, "target")]
    assert 0 < old.expires_at - auth.time.monotonic() <= 60
    await db.execute("UPDATE {{tables.team_certificates}} SET revoked_at = now()")
    # Within TTL we retain facts; expiry forces revocation lookup.
    assert (await client.get("/protected", headers=headers)).status_code == 200
    cache._certificate_cache[(TEAM_ID, "target")] = replace(old, expires_at=-1)
    response = await client.get("/protected", headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "Team certificate has been revoked"


async def test_unknown_certificate_does_not_reuse_other_certificate_cache(real_registry):
    client, headers, cache, db, calls, _ = real_registry
    assert (await client.get("/protected", headers=headers)).status_code == 200
    with pytest.raises(auth.HTTPException) as exc:
        await cache.get(TEAM_ID, "unpublished")
    assert exc.value.status_code == 401
    assert (TEAM_ID, "unpublished") not in cache._certificate_cache
    assert len(calls) == 2


async def test_rotation_active_is_not_authentication(real_registry):
    client, headers, cache, db, calls, _ = real_registry
    new_did = did_from_public_key(bytes(SigningKey.generate().verify_key))
    await db.execute("UPDATE {{tables.teams}} SET team_did_key = $1", new_did)
    response = await client.get("/protected", headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "Team certificate signature verification failed"


@pytest.mark.parametrize("fault", [404, 429, 503, "timeout", "json"])
async def test_failed_refresh_has_no_stale_fallback(real_registry, fault):
    client, headers, cache, db, calls, faults = real_registry
    assert (await client.get("/protected", headers=headers)).status_code == 200
    old = cache._certificate_cache[(TEAM_ID, "target")]
    expired = replace(old, expires_at=-1)
    cache._certificate_cache[(TEAM_ID, "target")] = expired
    faults["kind"] = fault
    response = await client.get("/protected", headers=headers)
    assert response.status_code == (401 if fault == 404 else 503)
    assert cache._certificate_cache[(TEAM_ID, "target")] is expired
    faults.clear()
    assert (await client.get("/protected", headers=headers)).status_code == 200


@pytest.mark.parametrize("change", ["nonobject", "missing_key", "invalid_key", "wrong_team",
                                  "missing_status", "bad_status", "missing_revoked_at",
                                  "active_with_revocation", "revoked_without_time", "bad_time", "extra"])
async def test_malformed_status_is_not_cached(real_registry, change):
    client, headers, cache, db, calls, faults = real_registry
    row = await db.fetch_one("SELECT team_did_key FROM {{tables.teams}}")
    payload = {"team_id": TEAM_ID, "team_did_key": row["team_did_key"],
               "status": "active", "revoked_at": None}
    if change == "nonobject":
        payload = []
    elif change.startswith("missing_"):
        payload.pop({"missing_key": "team_did_key"}.get(change, change[8:]))
    elif change == "invalid_key":
        payload["team_did_key"] = "garbage"
    elif change == "wrong_team":
        payload["team_id"] = "other:example.com"
    elif change == "bad_status":
        payload["status"] = "unknown"
    elif change == "active_with_revocation":
        payload["revoked_at"] = "2026-01-01T00:00:00Z"
    elif change in ("revoked_without_time", "bad_time"):
        payload["status"] = "revoked"
        payload["revoked_at"] = None if change == "revoked_without_time" else "yesterday"
    else:
        payload["alias"] = "private-member"
    faults.update(kind="payload", payload=payload)
    assert (await client.get("/protected", headers=headers)).status_code == 503
    assert not cache._certificate_cache


async def test_valid_but_unpublished_certificate_is_refused(real_registry):
    client, headers, cache, db, calls, _ = real_registry
    await db.execute("DELETE FROM {{tables.team_certificates}}")
    response = await client.get("/protected", headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "Unknown AWID certificate"
    assert not cache._certificate_cache


async def test_private_team_on_registry_without_status_fails_closed(real_registry):
    # Default fixture team is private. An older registry returns 404 for /status.
    client, headers, cache, db, calls, faults = real_registry
    faults["kind"] = 404
    response = await client.get("/protected", headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "Unknown AWID certificate"
    assert not cache._certificate_cache
    assert len(calls) == 1
    assert calls[0].url.path.endswith("/certificates/target/status")
    assert "X-AWID-Service-Token" not in calls[0].headers
