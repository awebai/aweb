"""Tests for PUT /v1/agents/me/identity — one-time identity claim (aweb-0bj)."""

from __future__ import annotations

from uuid import UUID

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app
from aweb.bootstrap import bootstrap_identity
from aweb.db import DatabaseInfra
from aweb.did import did_from_public_key, encode_public_key, generate_keypair
from aweb.stable_id import stable_id_from_did_key


async def _create_unclaimed_agent(client: AsyncClient, aweb_db) -> dict:
    """Create an agent via /v1/init, then NULL out its DID to simulate
    dashboard-first provisioning (agent exists, no keypair yet)."""
    resp = await client.post(
        "/v1/init",
        json={
            "project_slug": "test/identity-claim",
            "alias": "unclaimed-agent",
        },
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    # Clear DID/public_key/stable_id/custody/signing_key_enc to simulate dashboard-first
    await aweb_db.execute(
        """
        UPDATE {{tables.agents}}
        SET did = NULL, public_key = NULL, stable_id = NULL,
            custody = NULL, signing_key_enc = NULL
        WHERE agent_id = $1
        """,
        UUID(data["agent_id"]),
    )
    return data


async def _create_self_custody_agent(client: AsyncClient, alias: str) -> dict:
    """Create a self-custodial agent via /v1/init (DID already bound)."""
    seed, pub = generate_keypair()
    did = did_from_public_key(pub)
    pub_b64 = encode_public_key(pub)
    resp = await client.post(
        "/v1/init",
        json={
            "project_slug": "test/identity-claim",
            "alias": alias,
            "did": did,
            "public_key": pub_b64,
            "custody": "self",
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.mark.asyncio
async def test_claim_identity_success(aweb_db_infra):
    """Unclaimed agent (did IS NULL) can bind did:key + public_key via PUT /me/identity."""
    aweb_db_infra: DatabaseInfra
    app = create_app(db_infra=aweb_db_infra, redis=None)
    aweb_db = aweb_db_infra.get_manager("aweb")
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            init_data = await _create_unclaimed_agent(c, aweb_db)
            api_key = init_data["api_key"]

            seed, pub = generate_keypair()
            did = did_from_public_key(pub)
            pub_b64 = encode_public_key(pub)
            expected_stable_id = stable_id_from_did_key(did)

            resp = await c.put(
                "/v1/agents/me/identity",
                json={
                    "did": did,
                    "public_key": pub_b64,
                    "custody": "self",
                    "lifetime": "persistent",
                },
                headers={"Authorization": f"Bearer {api_key}"},
            )
            assert resp.status_code == 200, resp.text
            data = resp.json()
            assert data["agent_id"] == init_data["agent_id"]
            assert data["alias"] == "unclaimed-agent"
            assert data["did"] == did
            assert data["public_key"] == pub_b64
            assert data["custody"] == "self"
            assert data["lifetime"] == "persistent"
            assert data["stable_id"] == expected_stable_id


@pytest.mark.asyncio
async def test_claim_identity_idempotent(aweb_db_infra):
    """Claiming with the same DID twice is idempotent (200, no change)."""
    aweb_db_infra: DatabaseInfra
    app = create_app(db_infra=aweb_db_infra, redis=None)
    aweb_db = aweb_db_infra.get_manager("aweb")
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            init_data = await _create_unclaimed_agent(c, aweb_db)
            api_key = init_data["api_key"]

            seed, pub = generate_keypair()
            did = did_from_public_key(pub)
            pub_b64 = encode_public_key(pub)

            headers = {"Authorization": f"Bearer {api_key}"}
            body = {
                "did": did,
                "public_key": pub_b64,
                "custody": "self",
                "lifetime": "persistent",
            }

            resp1 = await c.put("/v1/agents/me/identity", json=body, headers=headers)
            assert resp1.status_code == 200

            resp2 = await c.put("/v1/agents/me/identity", json=body, headers=headers)
            assert resp2.status_code == 200
            assert resp2.json()["did"] == did


@pytest.mark.asyncio
async def test_claim_identity_conflict_different_did(aweb_db_infra):
    """Claiming with a different DID when one is already bound returns 409."""
    aweb_db_infra: DatabaseInfra
    app = create_app(db_infra=aweb_db_infra, redis=None)
    aweb_db = aweb_db_infra.get_manager("aweb")
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            init_data = await _create_unclaimed_agent(c, aweb_db)
            api_key = init_data["api_key"]
            headers = {"Authorization": f"Bearer {api_key}"}

            seed1, pub1 = generate_keypair()
            did1 = did_from_public_key(pub1)
            pub1_b64 = encode_public_key(pub1)
            resp1 = await c.put(
                "/v1/agents/me/identity",
                json={
                    "did": did1,
                    "public_key": pub1_b64,
                    "custody": "self",
                    "lifetime": "persistent",
                },
                headers=headers,
            )
            assert resp1.status_code == 200

            seed2, pub2 = generate_keypair()
            did2 = did_from_public_key(pub2)
            pub2_b64 = encode_public_key(pub2)
            resp2 = await c.put(
                "/v1/agents/me/identity",
                json={
                    "did": did2,
                    "public_key": pub2_b64,
                    "custody": "self",
                    "lifetime": "persistent",
                },
                headers=headers,
            )
            assert resp2.status_code == 409
            assert "already claimed" in resp2.json()["detail"].lower()


@pytest.mark.asyncio
async def test_claim_identity_did_public_key_mismatch(aweb_db_infra):
    """DID must embed the exact public_key bytes — reject mismatches."""
    aweb_db_infra: DatabaseInfra
    app = create_app(db_infra=aweb_db_infra, redis=None)
    aweb_db = aweb_db_infra.get_manager("aweb")
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            init_data = await _create_unclaimed_agent(c, aweb_db)
            api_key = init_data["api_key"]

            seed1, pub1 = generate_keypair()
            seed2, pub2 = generate_keypair()
            did1 = did_from_public_key(pub1)
            pub2_b64 = encode_public_key(pub2)

            resp = await c.put(
                "/v1/agents/me/identity",
                json={
                    "did": did1,
                    "public_key": pub2_b64,
                    "custody": "self",
                    "lifetime": "persistent",
                },
                headers={"Authorization": f"Bearer {api_key}"},
            )
            assert resp.status_code == 400
            assert "does not match" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_claim_identity_invalid_did(aweb_db_infra):
    """Invalid did:key format is rejected."""
    aweb_db_infra: DatabaseInfra
    app = create_app(db_infra=aweb_db_infra, redis=None)
    aweb_db = aweb_db_infra.get_manager("aweb")
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            init_data = await _create_unclaimed_agent(c, aweb_db)
            api_key = init_data["api_key"]

            seed, pub = generate_keypair()
            pub_b64 = encode_public_key(pub)

            resp = await c.put(
                "/v1/agents/me/identity",
                json={
                    "did": "not-a-valid-did",
                    "public_key": pub_b64,
                    "custody": "self",
                    "lifetime": "persistent",
                },
                headers={"Authorization": f"Bearer {api_key}"},
            )
            assert resp.status_code == 400


@pytest.mark.asyncio
async def test_claim_identity_writes_agent_log(aweb_db_infra):
    """Identity claim appends a claim_identity entry to agent_log."""
    aweb_db_infra: DatabaseInfra
    app = create_app(db_infra=aweb_db_infra, redis=None)
    aweb_db = aweb_db_infra.get_manager("aweb")
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            init_data = await _create_unclaimed_agent(c, aweb_db)
            api_key = init_data["api_key"]

            seed, pub = generate_keypair()
            did = did_from_public_key(pub)
            pub_b64 = encode_public_key(pub)

            resp = await c.put(
                "/v1/agents/me/identity",
                json={
                    "did": did,
                    "public_key": pub_b64,
                    "custody": "self",
                    "lifetime": "persistent",
                },
                headers={"Authorization": f"Bearer {api_key}"},
            )
            assert resp.status_code == 200

            log_resp = await c.get(
                "/v1/agents/me/log",
                headers={"Authorization": f"Bearer {api_key}"},
            )
            assert log_resp.status_code == 200
            log_entries = log_resp.json()["log"]
            ops = [e["operation"] for e in log_entries]
            assert "claim_identity" in ops
            claim_entry = [e for e in log_entries if e["operation"] == "claim_identity"][0]
            assert claim_entry["new_did"] == did
            assert claim_entry["old_did"] is None


@pytest.mark.asyncio
async def test_claim_identity_already_self_custody_rejects(aweb_db_infra):
    """An agent created with self-custody (DID already bound at init) rejects claim
    with a different DID."""
    aweb_db_infra: DatabaseInfra
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            init_data = await _create_self_custody_agent(c, "self-agent")
            api_key = init_data["api_key"]

            seed, pub = generate_keypair()
            did = did_from_public_key(pub)
            pub_b64 = encode_public_key(pub)

            resp = await c.put(
                "/v1/agents/me/identity",
                json={
                    "did": did,
                    "public_key": pub_b64,
                    "custody": "self",
                    "lifetime": "persistent",
                },
                headers={"Authorization": f"Bearer {api_key}"},
            )
            assert resp.status_code == 409


@pytest.mark.asyncio
async def test_claim_identity_requires_auth(aweb_db_infra):
    """PUT /me/identity without auth returns 401."""
    aweb_db_infra: DatabaseInfra
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            seed, pub = generate_keypair()
            did = did_from_public_key(pub)
            pub_b64 = encode_public_key(pub)

            resp = await c.put(
                "/v1/agents/me/identity",
                json={
                    "did": did,
                    "public_key": pub_b64,
                    "custody": "self",
                    "lifetime": "persistent",
                },
            )
            assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_bootstrap_self_custody_unclaimed_then_claim(aweb_db_infra):
    """bootstrap_identity(custody='self', did=None) creates an unclaimed agent.
    PUT /me/identity then binds the identity successfully."""
    aweb_db_infra: DatabaseInfra
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        # Create unclaimed self-custodial agent via bootstrap
        result = await bootstrap_identity(
            aweb_db_infra,
            project_slug="test/unclaimed-bootstrap",
            alias=None,
            custody="self",
            lifetime="persistent",
        )
        assert result.created is True
        assert result.did is None
        assert result.stable_id is None
        assert result.custody == "self"
        assert result.lifetime == "persistent"

        # Claim identity
        _, pub = generate_keypair()
        did = did_from_public_key(pub)
        pub_b64 = encode_public_key(pub)
        expected_stable_id = stable_id_from_did_key(did)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.put(
                "/v1/agents/me/identity",
                json={
                    "did": did,
                    "public_key": pub_b64,
                    "custody": "self",
                    "lifetime": "persistent",
                },
                headers={"Authorization": f"Bearer {result.api_key}"},
            )
            assert resp.status_code == 200, resp.text
            data = resp.json()
            assert data["did"] == did
            assert data["stable_id"] == expected_stable_id
            assert data["custody"] == "self"
