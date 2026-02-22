"""Tests for PUT /v1/agents/me/retire — retirement with successor (aweb-fj2.14)."""

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
from aweb.db import DatabaseInfra
from aweb.did import did_from_public_key, generate_keypair


def _auth(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


def _sign_retirement_proof(private_key: bytes, successor_agent_id: str, timestamp: str) -> str:
    """Build and sign the canonical retirement proof."""
    canonical = json.dumps(
        {
            "operation": "retire",
            "successor_agent_id": successor_agent_id,
            "timestamp": timestamp,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    signing_key = SigningKey(private_key)
    signed = signing_key.sign(canonical)
    return base64.b64encode(signed.signature).rstrip(b"=").decode("ascii")


async def _seed_project_with_agents(aweb_db, *, custody: str = "self", master_key=None):
    """Create a project with a persistent agent (self or custodial) and a successor agent."""
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    successor_id = uuid.uuid4()

    seed, pub = generate_keypair()
    did = did_from_public_key(pub)
    succ_seed, succ_pub = generate_keypair()
    succ_did = did_from_public_key(succ_pub)

    slug = f"retire-{uuid.uuid4().hex[:8]}"
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_id,
        slug,
        "Retirement Test",
    )

    signing_key_enc = None
    if custody == "custodial" and master_key:
        signing_key_enc = encrypt_signing_key(seed, master_key)

    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} "
        "(agent_id, project_id, alias, human_name, agent_type, did, public_key, custody, signing_key_enc, lifetime) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        agent_id,
        project_id,
        "retiring-agent",
        "Retiring Agent",
        "agent",
        did,
        pub.hex(),
        custody,
        signing_key_enc,
        "persistent",
    )

    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} "
        "(agent_id, project_id, alias, human_name, agent_type, did, public_key, custody, lifetime) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        successor_id,
        project_id,
        "successor-agent",
        "Successor Agent",
        "agent",
        succ_did,
        succ_pub.hex(),
        "self",
        "persistent",
    )

    key = f"aw_sk_{uuid.uuid4().hex}"
    await aweb_db.execute(
        "INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active) "
        "VALUES ($1, $2, $3, $4, $5)",
        project_id,
        agent_id,
        key[:12],
        hash_api_key(key),
        True,
    )

    return {
        "project_id": project_id,
        "agent_id": str(agent_id),
        "successor_id": str(successor_id),
        "api_key": key,
        "seed": seed,
        "pub": pub,
        "did": did,
        "succ_did": succ_did,
    }


@pytest.mark.asyncio
async def test_retire_self_custodial_agent(aweb_db_infra):
    """Self-custodial agent retires with valid proof → status='retired', successor set."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")
    data = await _seed_project_with_agents(aweb_db, custody="self")

    timestamp = "2026-02-21T12:00:00Z"
    proof = _sign_retirement_proof(data["seed"], data["successor_id"], timestamp)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.put(
                "/v1/agents/me/retire",
                headers=_auth(data["api_key"]),
                json={
                    "successor_agent_id": data["successor_id"],
                    "retirement_proof": proof,
                    "timestamp": timestamp,
                },
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["status"] == "retired"
            assert body["successor_agent_id"] == data["successor_id"]

    # Verify DB state
    row = await aweb_db.fetch_one(
        "SELECT status, successor_agent_id FROM {{tables.agents}} WHERE agent_id = $1",
        uuid.UUID(data["agent_id"]),
    )
    assert row["status"] == "retired"
    assert str(row["successor_agent_id"]) == data["successor_id"]


@pytest.mark.asyncio
async def test_retire_agent_creates_log_entry(aweb_db_infra):
    """Retirement appends a 'retire' entry to agent_log."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")
    data = await _seed_project_with_agents(aweb_db, custody="self")

    timestamp = "2026-02-21T12:00:00Z"
    proof = _sign_retirement_proof(data["seed"], data["successor_id"], timestamp)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.put(
                "/v1/agents/me/retire",
                headers=_auth(data["api_key"]),
                json={
                    "successor_agent_id": data["successor_id"],
                    "retirement_proof": proof,
                    "timestamp": timestamp,
                },
            )
            assert resp.status_code == 200

    log = await aweb_db.fetch_one(
        "SELECT operation, old_did, metadata FROM {{tables.agent_log}} WHERE agent_id = $1 AND operation = $2",
        uuid.UUID(data["agent_id"]),
        "retire",
    )
    assert log is not None
    assert log["old_did"] == data["did"]
    metadata = json.loads(log["metadata"]) if isinstance(log["metadata"], str) else log["metadata"]
    assert metadata["successor_agent_id"] == data["successor_id"]


@pytest.mark.asyncio
async def test_retire_custodial_agent_server_signs(aweb_db_infra, monkeypatch):
    """Custodial agent retires → server signs the proof on behalf."""
    aweb_db_infra: DatabaseInfra
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())

    aweb_db = aweb_db_infra.get_manager("aweb")
    data = await _seed_project_with_agents(aweb_db, custody="custodial", master_key=master_key)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Custodial agent: no proof needed, server signs on behalf.
            resp = await client.put(
                "/v1/agents/me/retire",
                headers=_auth(data["api_key"]),
                json={
                    "successor_agent_id": data["successor_id"],
                },
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["status"] == "retired"

    row = await aweb_db.fetch_one(
        "SELECT status, successor_agent_id FROM {{tables.agents}} WHERE agent_id = $1",
        uuid.UUID(data["agent_id"]),
    )
    assert row["status"] == "retired"


@pytest.mark.asyncio
async def test_retire_rejects_ephemeral_agent(aweb_db_infra):
    """Ephemeral agents cannot retire — use deregister instead."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")

    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    seed, pub = generate_keypair()
    did = did_from_public_key(pub)

    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_id,
        f"eph-{uuid.uuid4().hex[:8]}",
        "Ephemeral Test",
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} "
        "(agent_id, project_id, alias, human_name, agent_type, did, public_key, custody, lifetime) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        agent_id,
        project_id,
        "eph-agent",
        "Ephemeral Agent",
        "agent",
        did,
        pub.hex(),
        "self",
        "ephemeral",
    )
    key = f"aw_sk_{uuid.uuid4().hex}"
    await aweb_db.execute(
        "INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active) "
        "VALUES ($1, $2, $3, $4, $5)",
        project_id,
        agent_id,
        key[:12],
        hash_api_key(key),
        True,
    )

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.put(
                "/v1/agents/me/retire",
                headers=_auth(key),
                json={"successor_agent_id": str(uuid.uuid4())},
            )
            assert resp.status_code == 400
            assert "ephemeral" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_retire_rejects_invalid_proof(aweb_db_infra):
    """Invalid retirement proof → 403."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")
    data = await _seed_project_with_agents(aweb_db, custody="self")

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.put(
                "/v1/agents/me/retire",
                headers=_auth(data["api_key"]),
                json={
                    "successor_agent_id": data["successor_id"],
                    "retirement_proof": "bad-proof",
                    "timestamp": "2026-02-21T12:00:00Z",
                },
            )
            assert resp.status_code == 403


@pytest.mark.asyncio
async def test_retire_rejects_unknown_successor(aweb_db_infra):
    """Successor agent must exist in the same project."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")
    data = await _seed_project_with_agents(aweb_db, custody="self")

    fake_successor = str(uuid.uuid4())
    timestamp = "2026-02-21T12:00:00Z"
    proof = _sign_retirement_proof(data["seed"], fake_successor, timestamp)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.put(
                "/v1/agents/me/retire",
                headers=_auth(data["api_key"]),
                json={
                    "successor_agent_id": fake_successor,
                    "retirement_proof": proof,
                    "timestamp": timestamp,
                },
            )
            assert resp.status_code == 404
            assert "successor" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_retire_rejects_self_succession(aweb_db_infra):
    """An agent cannot name itself as its own successor."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")
    data = await _seed_project_with_agents(aweb_db, custody="self")

    timestamp = "2026-02-21T12:00:00Z"
    # Sign a proof with self as successor
    proof = _sign_retirement_proof(data["seed"], data["agent_id"], timestamp)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.put(
                "/v1/agents/me/retire",
                headers=_auth(data["api_key"]),
                json={
                    "successor_agent_id": data["agent_id"],
                    "retirement_proof": proof,
                    "timestamp": timestamp,
                },
            )
            assert resp.status_code == 400
            assert "itself" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_retire_log_includes_signed_by(aweb_db_infra):
    """Retirement log entry includes signed_by and entry_signature."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")
    data = await _seed_project_with_agents(aweb_db, custody="self")

    timestamp = "2026-02-21T12:00:00Z"
    proof = _sign_retirement_proof(data["seed"], data["successor_id"], timestamp)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.put(
                "/v1/agents/me/retire",
                headers=_auth(data["api_key"]),
                json={
                    "successor_agent_id": data["successor_id"],
                    "retirement_proof": proof,
                    "timestamp": timestamp,
                },
            )
            assert resp.status_code == 200

    log = await aweb_db.fetch_one(
        "SELECT signed_by, entry_signature FROM {{tables.agent_log}} WHERE agent_id = $1 AND operation = $2",
        uuid.UUID(data["agent_id"]),
        "retire",
    )
    assert log is not None
    assert log["signed_by"] == data["did"]
    assert log["entry_signature"] == proof


@pytest.mark.asyncio
async def test_retire_already_retired_agent(aweb_db_infra):
    """Cannot retire an agent that is already retired."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")
    data = await _seed_project_with_agents(aweb_db, custody="self")

    # Manually set status to retired
    await aweb_db.execute(
        "UPDATE {{tables.agents}} SET status = 'retired' WHERE agent_id = $1",
        uuid.UUID(data["agent_id"]),
    )

    timestamp = "2026-02-21T12:00:00Z"
    proof = _sign_retirement_proof(data["seed"], data["successor_id"], timestamp)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.put(
                "/v1/agents/me/retire",
                headers=_auth(data["api_key"]),
                json={
                    "successor_agent_id": data["successor_id"],
                    "retirement_proof": proof,
                    "timestamp": timestamp,
                },
            )
            assert resp.status_code == 400
            assert "already" in resp.json()["detail"].lower()
