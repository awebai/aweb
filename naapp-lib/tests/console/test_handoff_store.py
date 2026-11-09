"""Unauthenticated handoff creation grants nothing, on owned PostgreSQL."""

import hashlib
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key
from fastapi import FastAPI

from aweb_naapp.console import ClientIdentity, LoginLimiter, apply_console_migrations
from aweb_naapp.console.handoff_store import HandoffStore, handoff_start_router
from aweb_naapp.runtime.origins import split_origins

ORIGIN = "https://console.example"


def start_body(**changes):
    _, public = generate_keypair()
    key = did_from_public_key(public)
    return {
        "v": 1,
        "purpose": "session",
        "client_key": key,
        "return": "loopback",
        "redirect_uri": "http://127.0.0.1:54321/callback",
        "verifier_sha256": hashlib.sha256(b"ephemeral verifier text").hexdigest(),
        "scope": {
            "installation_id": "00000000-0000-4000-8000-000000000001",
            "role": "example.owner",
            "principal": stable_id_from_did_key(key),
        },
        **changes,
    }


@pytest.fixture
async def handoff_db(test_db_factory):
    db = await test_db_factory.create_db(suffix="handoffs", schema="app")
    await apply_console_migrations(db)
    return db


def app(db, *, limit=20):
    human = FastAPI()
    human.include_router(
        handoff_start_router(
            store=HandoffStore(db),
            limiter=LoginLimiter(
                db, client_identity=ClientIdentity(), limit=limit, window=timedelta(minutes=1)
            ),
        )
    )
    return split_origins(FastAPI(), human, agent_origin="https://api.example", human_origin=ORIGIN)


async def test_create_returns_only_a_bounded_handoff_reference(handoff_db):
    before = datetime.now(UTC)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app(handoff_db)), base_url=ORIGIN
    ) as client:
        body = start_body()
        response = await client.post("/handoffs", json=body)
    assert response.status_code == 201
    result = response.json()
    assert set(result) == {"handoff_id", "expires_at"}
    expires = datetime.fromisoformat(result["expires_at"].replace("Z", "+00:00"))
    assert before < expires <= datetime.now(UTC) + timedelta(minutes=10)
    row = await handoff_db.fetch_one(
        "SELECT * FROM {{tables.console_handoffs}} WHERE handoff_id=$1::uuid", result["handoff_id"]
    )
    assert bytes(row["verifier_sha256"]).hex() == body["verifier_sha256"]
    assert row["redirect_uri"] == body["redirect_uri"]
    assert row["completed_at"] is None and row["released_at"] is None
    assert await handoff_db.fetch_value("SELECT COUNT(*) FROM {{tables.console_sessions}}") == 0


@pytest.mark.parametrize(
    "change,detail",
    [
        ({"redirect_uri": "https://attacker.example/callback"}, "redirect_uri_refused"),
        ({"return": "user_code"}, "handoff_invalid"),
        ({"extra": "unknown"}, "handoff_invalid"),
        ({"verifier_sha256": "not-a-digest"}, "handoff_invalid"),
    ],
)
async def test_refused_creation_never_leaves_a_handoff(handoff_db, change, detail):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app(handoff_db)), base_url=ORIGIN
    ) as client:
        response = await client.post("/handoffs", json=start_body(**change))
    assert response.status_code == 400
    assert response.json() == {"detail": detail}
    assert await handoff_db.fetch_value("SELECT COUNT(*) FROM {{tables.console_handoffs}}") == 0


async def test_creation_throttle_uses_the_handoff_wire_refusal(handoff_db):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app(handoff_db, limit=1)), base_url=ORIGIN
    ) as client:
        assert (await client.post("/handoffs", json=start_body())).status_code == 201
        response = await client.post("/handoffs", json=start_body())
    assert response.status_code == 429
    assert response.json() == {"detail": "handoff_rate_limited"}
    assert "Retry-After" in response.headers
    assert await handoff_db.fetch_value("SELECT COUNT(*) FROM {{tables.console_handoffs}}") == 1
