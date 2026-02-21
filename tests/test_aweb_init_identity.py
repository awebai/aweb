"""Tests for identity fields on /v1/init (aweb-fj2.7)."""

from __future__ import annotations

import secrets
import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app
from aweb.custody import decrypt_signing_key
from aweb.db import DatabaseInfra
from aweb.did import did_from_public_key, generate_keypair


@pytest.mark.asyncio
async def test_legacy_init_no_did_fields(aweb_db_infra):
    """Legacy init (no DID fields) works exactly as before — no identity columns set."""
    aweb_db_infra: DatabaseInfra
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/init",
                json={
                    "project_slug": "test/init-legacy",
                    "alias": "legacy-agent",
                },
            )
            assert resp.status_code == 200, resp.text
            data = resp.json()
            assert data["did"] is None
            assert data["custody"] is None
            assert data["lifetime"] == "persistent"
            assert data["created"] is True


@pytest.mark.asyncio
async def test_self_custodial_init(aweb_db_infra):
    """Self-custodial init: client provides DID+public_key, server validates and stores."""
    aweb_db_infra: DatabaseInfra
    seed, pub = generate_keypair()
    did = did_from_public_key(pub)
    pub_hex = pub.hex()

    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/init",
                json={
                    "project_slug": "test/init-self",
                    "alias": "self-agent",
                    "custody": "self",
                    "did": did,
                    "public_key": pub_hex,
                },
            )
            assert resp.status_code == 200, resp.text
            data = resp.json()
            assert data["did"] == did
            assert data["custody"] == "self"
            assert data["lifetime"] == "persistent"

            # Verify agent row in DB
            aweb_db = aweb_db_infra.get_manager("aweb")
            row = await aweb_db.fetch_one(
                "SELECT did, public_key, custody, signing_key_enc, lifetime "
                "FROM {{tables.agents}} WHERE agent_id = $1",
                uuid.UUID(data["agent_id"]),
            )
            assert row["did"] == did
            assert row["public_key"] == pub_hex
            assert row["custody"] == "self"
            assert row["signing_key_enc"] is None  # self-custodial — no server-side key
            assert row["lifetime"] == "persistent"


@pytest.mark.asyncio
async def test_self_custodial_mismatched_did_rejected(aweb_db_infra):
    """Self-custodial with DID that doesn't match public_key → 422."""
    aweb_db_infra: DatabaseInfra
    _, pub = generate_keypair()
    _, other_pub = generate_keypair()
    wrong_did = did_from_public_key(other_pub)
    pub_hex = pub.hex()

    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/init",
                json={
                    "project_slug": "test/init-mismatch",
                    "alias": "mismatch-agent",
                    "custody": "self",
                    "did": wrong_did,
                    "public_key": pub_hex,
                },
            )
            assert resp.status_code == 422, resp.text


@pytest.mark.asyncio
async def test_self_custodial_missing_public_key_rejected(aweb_db_infra):
    """Self-custodial with DID but no public_key → 422."""
    aweb_db_infra: DatabaseInfra
    _, pub = generate_keypair()
    did = did_from_public_key(pub)

    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/init",
                json={
                    "project_slug": "test/init-no-pk",
                    "alias": "no-pk-agent",
                    "custody": "self",
                    "did": did,
                },
            )
            assert resp.status_code == 422, resp.text


@pytest.mark.asyncio
async def test_custodial_init(aweb_db_infra, monkeypatch):
    """Custodial init: server generates keypair and returns DID."""
    aweb_db_infra: DatabaseInfra
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())

    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/init",
                json={
                    "project_slug": "test/init-custodial",
                    "alias": "cust-agent",
                    "custody": "custodial",
                },
            )
            assert resp.status_code == 200, resp.text
            data = resp.json()
            assert data["did"] is not None
            assert data["did"].startswith("did:key:z")
            assert data["custody"] == "custodial"

            # Verify encrypted key is stored and can be decrypted
            aweb_db = aweb_db_infra.get_manager("aweb")
            row = await aweb_db.fetch_one(
                "SELECT did, public_key, custody, signing_key_enc "
                "FROM {{tables.agents}} WHERE agent_id = $1",
                uuid.UUID(data["agent_id"]),
            )
            assert row["signing_key_enc"] is not None
            seed = decrypt_signing_key(bytes(row["signing_key_enc"]), master_key)
            assert len(seed) == 32

            # Verify the DID matches the stored public key
            pub_bytes = bytes.fromhex(row["public_key"])
            assert did_from_public_key(pub_bytes) == row["did"]


@pytest.mark.asyncio
async def test_custodial_init_without_custody_key(aweb_db_infra, monkeypatch):
    """Custodial init without AWEB_CUSTODY_KEY — DID generated but no encrypted key."""
    aweb_db_infra: DatabaseInfra
    monkeypatch.delenv("AWEB_CUSTODY_KEY", raising=False)

    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/init",
                json={
                    "project_slug": "test/init-cust-nokey",
                    "alias": "cust-nokey",
                    "custody": "custodial",
                },
            )
            assert resp.status_code == 200, resp.text
            data = resp.json()
            assert data["did"] is not None
            assert data["custody"] == "custodial"

            # No encrypted key stored
            aweb_db = aweb_db_infra.get_manager("aweb")
            row = await aweb_db.fetch_one(
                "SELECT signing_key_enc FROM {{tables.agents}} WHERE agent_id = $1",
                uuid.UUID(data["agent_id"]),
            )
            assert row["signing_key_enc"] is None


@pytest.mark.asyncio
async def test_ephemeral_custodial_init(aweb_db_infra, monkeypatch):
    """Ephemeral custodial init — lifetime should be 'ephemeral'."""
    aweb_db_infra: DatabaseInfra
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())

    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/init",
                json={
                    "project_slug": "test/init-ephemeral",
                    "alias": "eph-agent",
                    "custody": "custodial",
                    "lifetime": "ephemeral",
                },
            )
            assert resp.status_code == 200, resp.text
            data = resp.json()
            assert data["lifetime"] == "ephemeral"

            aweb_db = aweb_db_infra.get_manager("aweb")
            row = await aweb_db.fetch_one(
                "SELECT lifetime FROM {{tables.agents}} WHERE agent_id = $1",
                uuid.UUID(data["agent_id"]),
            )
            assert row["lifetime"] == "ephemeral"


@pytest.mark.asyncio
async def test_idempotent_reinit_returns_same_agent(aweb_db_infra):
    """Re-init with same alias returns existing agent (identity not overwritten)."""
    aweb_db_infra: DatabaseInfra
    seed, pub = generate_keypair()
    did = did_from_public_key(pub)

    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp1 = await c.post(
                "/v1/init",
                json={
                    "project_slug": "test/init-idemp",
                    "alias": "idemp-agent",
                    "custody": "self",
                    "did": did,
                    "public_key": pub.hex(),
                },
            )
            assert resp1.status_code == 200
            d1 = resp1.json()
            assert d1["created"] is True

            # Re-init same alias — should return existing agent
            resp2 = await c.post(
                "/v1/init",
                json={
                    "project_slug": "test/init-idemp",
                    "alias": "idemp-agent",
                },
            )
            assert resp2.status_code == 200
            d2 = resp2.json()
            assert d2["agent_id"] == d1["agent_id"]
            assert d2["created"] is False
            assert d2["did"] == did  # should still have the DID


@pytest.mark.asyncio
async def test_agent_log_entry_created(aweb_db_infra):
    """New agent creation writes an agent_log 'create' entry."""
    aweb_db_infra: DatabaseInfra
    seed, pub = generate_keypair()
    did = did_from_public_key(pub)

    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/init",
                json={
                    "project_slug": "test/init-log",
                    "alias": "log-agent",
                    "custody": "self",
                    "did": did,
                    "public_key": pub.hex(),
                },
            )
            assert resp.status_code == 200
            data = resp.json()

            aweb_db = aweb_db_infra.get_manager("aweb")
            logs = await aweb_db.fetch_all(
                "SELECT operation, new_did FROM {{tables.agent_log}} WHERE agent_id = $1",
                uuid.UUID(data["agent_id"]),
            )
            assert len(logs) == 1
            assert logs[0]["operation"] == "create"
            assert logs[0]["new_did"] == did


@pytest.mark.asyncio
async def test_invalid_custody_value_rejected(aweb_db_infra):
    """Invalid custody value → 422."""
    aweb_db_infra: DatabaseInfra
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/init",
                json={
                    "project_slug": "test/init-invalid-custody",
                    "alias": "invalid-cust",
                    "custody": "magic",
                },
            )
            assert resp.status_code == 422


@pytest.mark.asyncio
async def test_invalid_lifetime_value_rejected(aweb_db_infra):
    """Invalid lifetime value → 422."""
    aweb_db_infra: DatabaseInfra
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/init",
                json={
                    "project_slug": "test/init-invalid-lifetime",
                    "alias": "invalid-lt",
                    "lifetime": "forever",
                },
            )
            assert resp.status_code == 422
