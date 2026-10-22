"""Public code exchange uses the real registration store; no request echo."""

import json
from datetime import UTC, datetime

import httpx
import pytest
from aweb_naapp.hooks.strictjson import encode_base64url
from awid.did import did_from_public_key
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi import FastAPI
from nacl.signing import SigningKey

from aweb_secrets.runner_routes import runner_registration_router
from aweb_secrets.runners import (
    RunnerRecord,
    apply_runner_migrations,
    create_runner,
    mint_runner_id,
)


@pytest.fixture
async def db(test_db_factory):
    database = await test_db_factory.create_db(suffix="runner_registration")
    await apply_runner_migrations(database)
    return database


async def test_registration_returns_only_public_pins_and_never_replays_code(db):
    key = SigningKey.generate()
    app = FastAPI()
    app.include_router(
        runner_registration_router(db=lambda: db, origin="https://secrets.example", service_key=key)
    )
    record = RunnerRecord.from_after(
        {"v": 1, "runner_id": mint_runner_id(), "label": "Runner", "allowed_jobs": []}
    )
    async with db.transaction() as tx:
        code = await create_runner(
            tx, "install-one", "team:acme.test", record, now=datetime.now(UTC)
        )
    signing = did_from_public_key(bytes(SigningKey.generate().verify_key))
    body = {
        "code": code,
        "signing_key": signing,
        "encryption_key": encode_base64url(
            X25519PrivateKey.generate().public_key().public_bytes_raw()
        ),
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://secrets.example"
    ) as client:
        response = await client.post("/runner/v1/register", json=body)
        assert response.status_code == 200
        assert response.json() == {
            "runner_id": record.runner_id,
            "origin": "https://secrets.example",
            "service_kid": did_from_public_key(bytes(key.verify_key)),
        }
        assert response.headers["cache-control"] == "no-store"
        replay = await client.post("/runner/v1/register", json=body)
        assert replay.status_code == 401
        assert replay.json()["detail"]["code"] == "registration_code_invalid"
        assert code not in response.text + replay.text
        duplicate = json.dumps(body)[:-1] + ',"code":"duplicate"}'
        malformed = await client.post("/runner/v1/register", content=duplicate)
        assert malformed.status_code == 400
        assert code not in malformed.text


async def test_malformed_code_is_constant_refusal_and_does_not_burn_valid_code(db):
    key = SigningKey.generate()
    app = FastAPI()
    app.include_router(
        runner_registration_router(db=lambda: db, origin="https://secrets.example", service_key=key)
    )
    record = RunnerRecord.from_after(
        {"v": 1, "runner_id": mint_runner_id(), "label": "Runner", "allowed_jobs": []}
    )
    async with db.transaction() as tx:
        code = await create_runner(
            tx, "install-one", "team:acme.test", record, now=datetime.now(UTC)
        )
    body = {
        "code": code,
        "signing_key": did_from_public_key(bytes(SigningKey.generate().verify_key)),
        "encryption_key": encode_base64url(
            X25519PrivateKey.generate().public_key().public_bytes_raw()
        ),
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://secrets.example"
    ) as client:
        for invalid in [
            "\ud800",
            "not-a-registration-code",
            code + "=",
            "",
            encode_base64url(bytes(31)),
        ]:
            malformed = await client.post(
                "/runner/v1/register", content=json.dumps({**body, "code": invalid})
            )
            assert malformed.status_code == 401
            assert malformed.json() == {"detail": {"code": "registration_code_invalid"}}
            assert malformed.headers["cache-control"] == "no-store"
        accepted = await client.post("/runner/v1/register", json=body)
        assert accepted.status_code == 200
        assert code not in accepted.text
