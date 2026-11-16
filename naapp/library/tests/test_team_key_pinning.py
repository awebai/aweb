"""A team key library admitted is not replaced by an unsigned registry answer.

Library's own app and request authentication on real PostgreSQL, against the
real AWID team routes. The registry operator is modelled by writing the
registry's own tables, exactly the power the threat gives it; rotation goes
through the real route. DNS is the one answer the test supplies.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime

import httpx
import pytest_asyncio
from awid.did import did_from_public_key
from awid.ratelimit import NoOpRateLimiter
from awid.signing import canonical_json_bytes, sign_message
from awid_service.attestation_rotation import DEFAULT_ROTATE_MAX_BODY_BYTES
from awid_service.db import AwidDatabaseInfra
from awid_service.routes.teams import router
from awid_service.testing import dns_naming
from fastapi import FastAPI
from nacl.signing import SigningKey

from library import api as library_api
from library import auth
from library.config import Settings

pytest_plugins = ("pgdbm.fixtures.conftest",)
TEAM_ID = "backend:example.com"
ORIGIN = "https://library.example.com"
REGISTRY = "https://registry.example"
NAMESPACE_KEY = SigningKey.generate()


def _did(key: SigningKey) -> str:
    return did_from_public_key(bytes(key.verify_key))


def _member_headers(team_key: SigningKey, alias: str) -> dict[str, str]:
    member_key = SigningKey.generate()
    timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    cert = {
        "version": 1, "certificate_id": f"{alias}-cert", "team_id": TEAM_ID,
        "team_did_key": _did(team_key), "member_did_key": _did(member_key),
        "alias": alias, "issued_at": timestamp,
    }
    cert["signature"] = sign_message(bytes(team_key), canonical_json_bytes(cert))
    payload = canonical_json_bytes({
        "v": 2, "aud": ORIGIN, "method": "GET", "path": "/v1/shelf",
        "team_id": TEAM_ID, "timestamp": timestamp,
        "body_sha256": hashlib.sha256(b"").hexdigest(),
    })
    return {
        "Authorization": f"DIDKey {_did(member_key)} {sign_message(bytes(member_key), payload)}",
        "X-AWEB-Timestamp": timestamp,
        "X-AWID-Team-Certificate": base64.b64encode(json.dumps(cert).encode()).decode(),
        "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(payload).rstrip(b"=").decode(),
    }


@pytest_asyncio.fixture
async def world(test_db_factory, monkeypatch):
    registry_db = await test_db_factory.create_db(suffix="pin_registry")
    infra = AwidDatabaseInfra(schema="awid")
    monkeypatch.setenv("AWID_DATABASE_URL", registry_db.config.get_dsn())
    await infra.initialize(run_migrations=True)
    registry = FastAPI()
    registry.state.db = infra
    registry.state.rate_limiter = NoOpRateLimiter()
    registry.state.awid_service_token = None
    registry.state.rotate_max_body_bytes = DEFAULT_ROTATE_MAX_BODY_BYTES
    registry.include_router(router)
    db = infra.get_manager("aweb")
    team_key = SigningKey.generate()
    await db.execute(
        "INSERT INTO {{tables.dns_namespaces}} (domain, controller_did, verification_status) "
        "VALUES ('example.com', $1, 'verified')", _did(NAMESPACE_KEY),
    )
    await db.execute(
        "INSERT INTO {{tables.teams}} (domain, name, team_did_key, visibility) "
        "VALUES ('example.com', 'backend', $1, 'public')", _did(team_key),
    )
    client_type = httpx.AsyncClient
    monkeypatch.setattr(auth.httpx, "AsyncClient", lambda **kw: client_type(
        transport=httpx.ASGITransport(app=registry), **kw,
    ))
    monkeypatch.setenv("AWEB_ENFORCE_TEAM_KEY_PINS", "true")
    app_db = await test_db_factory.create_db(suffix="pin_library")
    app = library_api.create_app(
        Settings(database_url=app_db.config.get_dsn(), awid_registry_url=REGISTRY, public_origin=ORIGIN),
        awid_txt_resolver=dns_naming("example.com", NAMESPACE_KEY),
    )

    async def certify(key: SigningKey, alias: str) -> dict[str, str]:
        headers = _member_headers(key, alias)
        cert = json.loads(base64.b64decode(headers["X-AWID-Team-Certificate"]))
        await db.execute(
            "INSERT INTO {{tables.team_certificates}} (team_uuid, certificate_id, member_did_key, alias, issued_at) "
            "SELECT team_uuid, $1, $2, $3, now() FROM {{tables.teams}} WHERE name = 'backend'",
            cert["certificate_id"], cert["member_did_key"], alias,
        )
        return headers

    async def rotate(new_key: SigningKey) -> None:
        timestamp = datetime.now(UTC).isoformat()
        claims = {"domain": "example.com", "operation": "rotate_team_key", "name": "backend",
                  "new_team_did_key": _did(new_key)}
        signature = sign_message(bytes(NAMESPACE_KEY), canonical_json_bytes({**claims, "timestamp": timestamp}))
        async with client_type(transport=httpx.ASGITransport(app=registry), base_url=REGISTRY) as http:
            response = await http.post(
                "/v1/namespaces/example.com/teams/backend/rotate", json={"new_team_did_key": _did(new_key)},
                headers={"Authorization": f"DIDKey {_did(NAMESPACE_KEY)} {signature}", "X-AWEB-Timestamp": timestamp},
            )
        assert response.status_code == 200, response.text

    try:
        async with app.router.lifespan_context(app):
            async with client_type(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as client:
                yield client, db, app_db, team_key, certify, rotate
    finally:
        await infra.close()


async def _pinned_key(app_db) -> str | None:
    # Library connects by its DSN alone, so its tables are in the default schema.
    return await app_db.fetch_value("SELECT team_did_key FROM public.team_key_pins WHERE team_id = $1", TEAM_ID)


async def _shelf(client, headers):
    return await client.get("/v1/shelf", headers=headers)


async def test_substituted_registry_team_key_does_not_admit_a_forged_member(world):
    client, db, app_db, team_key, certify, _ = world
    assert (await _shelf(client, await certify(team_key, "alice"))).status_code == 200
    forger_team_key = SigningKey.generate()
    await db.execute("UPDATE {{tables.teams}} SET team_did_key = $1 WHERE name = 'backend'", _did(forger_team_key))

    forged = await _shelf(client, await certify(forger_team_key, "mallory"))

    assert forged.status_code == 401, forged.text
    assert forged.json()["detail"] == "team_key_unverified"
    assert await _pinned_key(app_db) == _did(team_key)


async def test_rotation_signed_by_the_dns_controller_moves_the_pin(world):
    client, _, app_db, team_key, certify, rotate = world
    assert (await _shelf(client, await certify(team_key, "alice"))).status_code == 200
    next_key = SigningKey.generate()
    await rotate(next_key)

    accepted = await _shelf(client, await certify(next_key, "dave"))

    assert accepted.status_code == 200, accepted.text
    assert await _pinned_key(app_db) == _did(next_key)
