"""Tests for /v1/agents/me/* — self-operation endpoints.

The /me/ pattern uses the bearer token to identify the agent.
No UUID or DID in API paths for self-operations.
"""

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
from aweb.auth import hash_api_key, validate_agent_alias
from aweb.custody import encrypt_signing_key
from aweb.did import did_from_public_key, generate_keypair


def _auth(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


async def _seed_persistent_self_custodial(aweb_db, *, slug: str = "me-proj", alias: str = "agent"):
    """Create a persistent self-custodial agent with API key."""
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


async def _seed_ephemeral_custodial(aweb_db, *, slug: str, alias: str, master_key: bytes):
    """Create an ephemeral custodial agent with encrypted signing key."""
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

    return {
        "project_id": str(project_id),
        "agent_id": str(agent_id),
        "did": did,
        "api_key": api_key,
    }


# --- 'me' alias reservation ---


def test_me_alias_reserved():
    """The alias 'me' must be rejected to avoid path collisions with /v1/agents/me/*."""
    with pytest.raises(ValueError, match="reserved"):
        validate_agent_alias("me")


def test_me_alias_case_variants_reserved():
    """Case variants of 'me' must also be rejected."""
    for variant in ("Me", "ME", "mE"):
        with pytest.raises(ValueError, match="reserved"):
            validate_agent_alias(variant)


# --- /me/rotate ---


def _make_rotation_signature(
    old_private_key: bytes, old_did: str, new_did: str, timestamp: str
) -> str:
    payload = json.dumps(
        {"new_did": new_did, "old_did": old_did, "timestamp": timestamp},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    signing_key = SigningKey(old_private_key)
    signed = signing_key.sign(payload)
    return base64.b64encode(signed.signature).rstrip(b"=").decode("ascii")


@pytest.mark.asyncio
async def test_me_rotate(aweb_db_infra):
    """PUT /v1/agents/me/rotate — rotate caller's own key."""
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_persistent_self_custodial(aweb_db, slug="me-rotate")

    new_private, new_public = generate_keypair()
    new_did = did_from_public_key(new_public)
    timestamp = "2026-02-22T12:00:00Z"
    proof = _make_rotation_signature(seed["private_key"], seed["did"], new_did, timestamp)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.put(
                "/v1/agents/me/rotate",
                headers=_auth(seed["api_key"]),
                json={
                    "new_did": new_did,
                    "new_public_key": new_public.hex(),
                    "custody": "self",
                    "rotation_signature": proof,
                    "timestamp": timestamp,
                },
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["status"] == "rotated"
            assert body["old_did"] == seed["did"]
            assert body["new_did"] == new_did


# --- /me/retire ---


def _sign_retirement_proof(private_key: bytes, successor_agent_id: str, timestamp: str) -> str:
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


@pytest.mark.asyncio
async def test_me_retire(aweb_db_infra):
    """PUT /v1/agents/me/retire — retire caller's own agent."""
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_persistent_self_custodial(aweb_db, slug="me-retire")

    # Create successor in same project
    successor_id = uuid.uuid4()
    s_priv, s_pub = generate_keypair()
    s_did = did_from_public_key(s_pub)
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, project_id, alias, human_name, agent_type,
             did, public_key, custody, lifetime, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        """,
        successor_id,
        uuid.UUID(seed["project_id"]),
        "successor",
        "Successor",
        "agent",
        s_did,
        s_pub.hex(),
        "self",
        "persistent",
        "active",
    )

    timestamp = "2026-02-22T12:00:00Z"
    proof = _sign_retirement_proof(seed["private_key"], str(successor_id), timestamp)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.put(
                "/v1/agents/me/retire",
                headers=_auth(seed["api_key"]),
                json={
                    "successor_agent_id": str(successor_id),
                    "retirement_proof": proof,
                    "timestamp": timestamp,
                },
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["status"] == "retired"
            assert body["successor_agent_id"] == str(successor_id)


# --- DELETE /me ---


@pytest.mark.asyncio
async def test_me_deregister(aweb_db_infra, monkeypatch):
    """DELETE /v1/agents/me — self-deregister ephemeral agent."""
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_ephemeral_custodial(
        aweb_db, slug="me-dereg", alias="temp", master_key=master_key
    )

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.delete(
                "/v1/agents/me",
                headers=_auth(seed["api_key"]),
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["agent_id"] == seed["agent_id"]
            assert body["status"] == "deregistered"


# --- GET /me/log ---


@pytest.mark.asyncio
async def test_me_log(aweb_db_infra):
    """GET /v1/agents/me/log — view caller's own lifecycle log."""
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_persistent_self_custodial(aweb_db, slug="me-log")

    # Insert a log entry
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agent_log}} (agent_id, project_id, operation, old_did)
        VALUES ($1, $2, $3, $4)
        """,
        uuid.UUID(seed["agent_id"]),
        uuid.UUID(seed["project_id"]),
        "create",
        seed["did"],
    )

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(
                "/v1/agents/me/log",
                headers=_auth(seed["api_key"]),
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["agent_id"] == seed["agent_id"]
            assert len(body["log"]) == 1
            assert body["log"][0]["operation"] == "create"


# --- PATCH /me ---


@pytest.mark.asyncio
async def test_me_patch(aweb_db_infra):
    """PATCH /v1/agents/me — update caller's own access_mode."""
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_persistent_self_custodial(aweb_db, slug="me-patch")

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.patch(
                "/v1/agents/me",
                headers=_auth(seed["api_key"]),
                json={"access_mode": "contacts_only"},
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["agent_id"] == seed["agent_id"]
            assert body["access_mode"] == "contacts_only"


# --- Auth required ---


@pytest.mark.asyncio
async def test_me_endpoints_require_auth(aweb_db_infra):
    """All /me/ endpoints require authentication."""
    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            for method, path in [
                ("PUT", "/v1/agents/me/rotate"),
                ("PUT", "/v1/agents/me/retire"),
                ("DELETE", "/v1/agents/me"),
                ("GET", "/v1/agents/me/log"),
                ("PATCH", "/v1/agents/me"),
            ]:
                resp = await c.request(method, path)
                assert resp.status_code in (401, 403, 422), f"{method} {path}: {resp.status_code}"
