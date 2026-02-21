"""Tests for PUT /v1/agents/{agent_id}/rotate — key rotation endpoint (aweb-fj2.13)."""

from __future__ import annotations

import base64
import json
import secrets
import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey

from aweb.api import create_app
from aweb.auth import hash_api_key
from aweb.custody import encrypt_signing_key
from aweb.did import did_from_public_key, generate_keypair


def _auth(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


def _make_rotation_proof(old_private_key: bytes, old_did: str, new_did: str, timestamp: str) -> str:
    """Sign the canonical rotation payload with the old key."""
    payload = json.dumps(
        {"new_did": new_did, "old_did": old_did, "operation": "rotate", "timestamp": timestamp},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    signing_key = SigningKey(old_private_key)
    signed = signing_key.sign(payload)
    return base64.b64encode(signed.signature).rstrip(b"=").decode("ascii")


async def _seed_persistent_self_custodial(aweb_db, *, slug: str = "rotate-proj", alias: str = "agent"):
    """Create a persistent self-custodial agent."""
    private_key, public_key = generate_keypair()
    did = did_from_public_key(public_key)
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()

    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_id,
        slug,
        f"Project {slug}",
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, project_id, alias, human_name, agent_type,
             did, public_key, custody, lifetime, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        """,
        agent_id,
        project_id,
        alias,
        f"Human {alias}",
        "agent",
        did,
        public_key.hex(),
        "self",
        "persistent",
        "active",
    )

    api_key = f"aw_sk_{uuid.uuid4().hex}"
    await aweb_db.execute(
        "INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active) "
        "VALUES ($1, $2, $3, $4, $5)",
        project_id,
        agent_id,
        api_key[:12],
        hash_api_key(api_key),
        True,
    )

    return {
        "project_id": str(project_id),
        "agent_id": str(agent_id),
        "private_key": private_key,
        "public_key": public_key,
        "did": did,
        "api_key": api_key,
    }


async def _seed_persistent_custodial(aweb_db, *, slug: str, alias: str, master_key: bytes):
    """Create a persistent custodial agent with encrypted signing key."""
    private_key, public_key = generate_keypair()
    did = did_from_public_key(public_key)
    encrypted_key = encrypt_signing_key(private_key, master_key)
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()

    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_id,
        slug,
        f"Project {slug}",
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, project_id, alias, human_name, agent_type,
             did, public_key, custody, signing_key_enc, lifetime, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        """,
        agent_id,
        project_id,
        alias,
        f"Human {alias}",
        "agent",
        did,
        public_key.hex(),
        "custodial",
        encrypted_key,
        "persistent",
        "active",
    )

    api_key = f"aw_sk_{uuid.uuid4().hex}"
    await aweb_db.execute(
        "INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active) "
        "VALUES ($1, $2, $3, $4, $5)",
        project_id,
        agent_id,
        api_key[:12],
        hash_api_key(api_key),
        True,
    )

    return {
        "project_id": str(project_id),
        "agent_id": str(agent_id),
        "private_key": private_key,
        "public_key": public_key,
        "did": did,
        "api_key": api_key,
    }


@pytest.mark.asyncio
async def test_rotate_self_custodial(aweb_db_infra):
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_persistent_self_custodial(aweb_db)

    # Generate new key
    new_private, new_public = generate_keypair()
    new_did = did_from_public_key(new_public)
    timestamp = "2026-02-21T12:00:00Z"
    proof = _make_rotation_proof(seed["private_key"], seed["did"], new_did, timestamp)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.put(
                f"/v1/agents/{seed['agent_id']}/rotate",
                headers=_auth(seed["api_key"]),
                json={
                    "new_did": new_did,
                    "new_public_key": new_public.hex(),
                    "custody": "self",
                    "rotation_proof": proof,
                    "timestamp": timestamp,
                },
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["status"] == "rotated"
            assert body["old_did"] == seed["did"]
            assert body["new_did"] == new_did
            assert body["custody"] == "self"

    # Verify DB was updated
    row = await aweb_db.fetch_one(
        "SELECT did, public_key, custody FROM {{tables.agents}} WHERE agent_id = $1",
        uuid.UUID(seed["agent_id"]),
    )
    assert row["did"] == new_did
    assert row["public_key"] == new_public.hex()
    assert row["custody"] == "self"


@pytest.mark.asyncio
async def test_rotate_creates_log_entry(aweb_db_infra):
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_persistent_self_custodial(aweb_db, slug="rotate-log")

    new_private, new_public = generate_keypair()
    new_did = did_from_public_key(new_public)
    timestamp = "2026-02-21T12:00:00Z"
    proof = _make_rotation_proof(seed["private_key"], seed["did"], new_did, timestamp)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.put(
                f"/v1/agents/{seed['agent_id']}/rotate",
                headers=_auth(seed["api_key"]),
                json={
                    "new_did": new_did,
                    "new_public_key": new_public.hex(),
                    "custody": "self",
                    "rotation_proof": proof,
                    "timestamp": timestamp,
                },
            )

    log = await aweb_db.fetch_one(
        "SELECT operation, old_did, new_did, signed_by FROM {{tables.agent_log}} WHERE agent_id = $1",
        uuid.UUID(seed["agent_id"]),
    )
    assert log["operation"] == "rotate"
    assert log["old_did"] == seed["did"]
    assert log["new_did"] == new_did
    assert log["signed_by"] == seed["did"]


@pytest.mark.asyncio
async def test_rotate_rejects_ephemeral_agent(aweb_db_infra, monkeypatch):
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())
    aweb_db = aweb_db_infra.get_manager("aweb")

    # Create an ephemeral agent
    private_key, public_key = generate_keypair()
    did = did_from_public_key(public_key)
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_id,
        "ephemeral-rotate",
        "Ephemeral",
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, project_id, alias, human_name, agent_type,
             did, public_key, custody, lifetime, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        """,
        agent_id,
        project_id,
        "temp",
        "Temp",
        "agent",
        did,
        public_key.hex(),
        "custodial",
        "ephemeral",
        "active",
    )
    api_key = f"aw_sk_{uuid.uuid4().hex}"
    await aweb_db.execute(
        "INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active) "
        "VALUES ($1, $2, $3, $4, $5)",
        project_id,
        agent_id,
        api_key[:12],
        hash_api_key(api_key),
        True,
    )

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.put(
                f"/v1/agents/{agent_id}/rotate",
                headers=_auth(api_key),
                json={
                    "new_did": "did:key:zFake",
                    "new_public_key": "aa" * 32,
                    "custody": "self",
                    "rotation_proof": "fake",
                    "timestamp": "2026-02-21T12:00:00Z",
                },
            )
            assert resp.status_code == 400
            assert "ephemeral" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_rotate_rejects_bad_proof(aweb_db_infra):
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_persistent_self_custodial(aweb_db, slug="bad-proof")

    new_private, new_public = generate_keypair()
    new_did = did_from_public_key(new_public)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.put(
                f"/v1/agents/{seed['agent_id']}/rotate",
                headers=_auth(seed["api_key"]),
                json={
                    "new_did": new_did,
                    "new_public_key": new_public.hex(),
                    "custody": "self",
                    "rotation_proof": "invalid-proof",
                    "timestamp": "2026-02-21T12:00:00Z",
                },
            )
            assert resp.status_code == 403


@pytest.mark.asyncio
async def test_rotate_graduation_custodial_to_self(aweb_db_infra, monkeypatch):
    """Graduating from custodial to self-custodial should destroy the encrypted key."""
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_persistent_custodial(aweb_db, slug="grad-test", alias="grad", master_key=master_key)

    new_private, new_public = generate_keypair()
    new_did = did_from_public_key(new_public)
    timestamp = "2026-02-21T12:00:00Z"

    # For custodial agents, the server signs the proof on behalf
    # The rotation_proof is signed by the old key (server holds it)
    proof = _make_rotation_proof(seed["private_key"], seed["did"], new_did, timestamp)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.put(
                f"/v1/agents/{seed['agent_id']}/rotate",
                headers=_auth(seed["api_key"]),
                json={
                    "new_did": new_did,
                    "new_public_key": new_public.hex(),
                    "custody": "self",
                    "rotation_proof": proof,
                    "timestamp": timestamp,
                },
            )
            assert resp.status_code == 200
            assert resp.json()["custody"] == "self"

    # Verify encrypted key was destroyed
    row = await aweb_db.fetch_one(
        "SELECT signing_key_enc, custody FROM {{tables.agents}} WHERE agent_id = $1",
        uuid.UUID(seed["agent_id"]),
    )
    assert row["signing_key_enc"] is None
    assert row["custody"] == "self"


@pytest.mark.asyncio
async def test_rotate_404_unknown_agent(aweb_db_infra):
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_persistent_self_custodial(aweb_db, slug="unknown-rotate")

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.put(
                f"/v1/agents/{uuid.uuid4()}/rotate",
                headers=_auth(seed["api_key"]),
                json={
                    "new_did": "did:key:zFake",
                    "new_public_key": "aa" * 32,
                    "custody": "self",
                    "rotation_proof": "fake",
                    "timestamp": "2026-02-21T12:00:00Z",
                },
            )
            assert resp.status_code == 404
