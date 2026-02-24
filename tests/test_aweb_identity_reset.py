"""Tests for POST /v1/agents/me/identity/reset — self-service identity reset (aweb-cwb)."""

from __future__ import annotations

from uuid import UUID

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app
from aweb.db import DatabaseInfra
from aweb.did import did_from_public_key, encode_public_key, generate_keypair
from aweb.stable_id import stable_id_from_did_key


async def _create_and_claim(client: AsyncClient, aweb_db, alias: str = "reset-agent"):
    """Create an agent, NULL its identity, then claim via PUT /me/identity.
    Returns (init_data, api_key, did, pub_b64)."""
    resp = await client.post(
        "/v1/init",
        json={"project_slug": "test/identity-reset", "alias": alias},
    )
    assert resp.status_code == 200, resp.text
    init_data = resp.json()
    api_key = init_data["api_key"]

    # NULL out identity to simulate dashboard-first provisioning
    await aweb_db.execute(
        """
        UPDATE {{tables.agents}}
        SET did = NULL, public_key = NULL, stable_id = NULL,
            custody = NULL, signing_key_enc = NULL
        WHERE agent_id = $1
        """,
        UUID(init_data["agent_id"]),
    )

    # Claim identity
    _, pub = generate_keypair()
    did = did_from_public_key(pub)
    pub_b64 = encode_public_key(pub)
    resp = await client.put(
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
    return init_data, api_key, did, pub_b64


@pytest.mark.asyncio
async def test_reset_identity_success(aweb_db_infra):
    """Reset clears did/public_key/stable_id and returns empty identity state."""
    aweb_db_infra: DatabaseInfra
    app = create_app(db_infra=aweb_db_infra, redis=None)
    aweb_db = aweb_db_infra.get_manager("aweb")
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            init_data, api_key, did, _ = await _create_and_claim(c, aweb_db)
            headers = {"Authorization": f"Bearer {api_key}"}

            resp = await c.post(
                "/v1/agents/me/identity/reset",
                json={"confirm": True},
                headers=headers,
            )
            assert resp.status_code == 200, resp.text
            data = resp.json()
            assert data["agent_id"] == init_data["agent_id"]
            assert data["did"] is None
            assert data["public_key"] is None
            assert data["stable_id"] is None
            assert data["alias"] == "reset-agent"


@pytest.mark.asyncio
async def test_reset_identity_requires_confirm(aweb_db_infra):
    """Reset without confirm=true returns 400."""
    aweb_db_infra: DatabaseInfra
    app = create_app(db_infra=aweb_db_infra, redis=None)
    aweb_db = aweb_db_infra.get_manager("aweb")
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            _, api_key, _, _ = await _create_and_claim(c, aweb_db)
            headers = {"Authorization": f"Bearer {api_key}"}

            # confirm=false
            resp = await c.post(
                "/v1/agents/me/identity/reset",
                json={"confirm": False},
                headers=headers,
            )
            assert resp.status_code == 400

            # missing confirm
            resp2 = await c.post(
                "/v1/agents/me/identity/reset",
                json={},
                headers=headers,
            )
            assert resp2.status_code == 422


@pytest.mark.asyncio
async def test_reset_then_reclaim(aweb_db_infra):
    """After reset, PUT /me/identity succeeds again with a new keypair."""
    aweb_db_infra: DatabaseInfra
    app = create_app(db_infra=aweb_db_infra, redis=None)
    aweb_db = aweb_db_infra.get_manager("aweb")
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            _, api_key, old_did, _ = await _create_and_claim(c, aweb_db)
            headers = {"Authorization": f"Bearer {api_key}"}

            # Reset
            resp = await c.post(
                "/v1/agents/me/identity/reset",
                json={"confirm": True},
                headers=headers,
            )
            assert resp.status_code == 200

            # Reclaim with new keypair
            _, new_pub = generate_keypair()
            new_did = did_from_public_key(new_pub)
            new_pub_b64 = encode_public_key(new_pub)

            resp2 = await c.put(
                "/v1/agents/me/identity",
                json={
                    "did": new_did,
                    "public_key": new_pub_b64,
                    "custody": "self",
                    "lifetime": "persistent",
                },
                headers=headers,
            )
            assert resp2.status_code == 200, resp2.text
            assert resp2.json()["did"] == new_did
            assert resp2.json()["did"] != old_did


@pytest.mark.asyncio
async def test_reset_writes_agent_log(aweb_db_infra):
    """Reset appends a reset_identity entry to agent_log with old DID."""
    aweb_db_infra: DatabaseInfra
    app = create_app(db_infra=aweb_db_infra, redis=None)
    aweb_db = aweb_db_infra.get_manager("aweb")
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            _, api_key, did, _ = await _create_and_claim(c, aweb_db)
            headers = {"Authorization": f"Bearer {api_key}"}

            await c.post(
                "/v1/agents/me/identity/reset",
                json={"confirm": True},
                headers=headers,
            )

            log_resp = await c.get("/v1/agents/me/log", headers=headers)
            assert log_resp.status_code == 200
            entries = log_resp.json()["log"]
            ops = [e["operation"] for e in entries]
            assert "reset_identity" in ops
            reset_entry = [e for e in entries if e["operation"] == "reset_identity"][0]
            assert reset_entry["old_did"] == did
            assert reset_entry["new_did"] is None


@pytest.mark.asyncio
async def test_reset_unclaimed_agent_is_noop(aweb_db_infra):
    """Resetting an agent with no identity is a no-op (200, already empty)."""
    aweb_db_infra: DatabaseInfra
    app = create_app(db_infra=aweb_db_infra, redis=None)
    aweb_db = aweb_db_infra.get_manager("aweb")
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/init",
                json={"project_slug": "test/identity-reset", "alias": "empty-agent"},
            )
            assert resp.status_code == 200
            api_key = resp.json()["api_key"]
            agent_id = resp.json()["agent_id"]

            # NULL out identity
            await aweb_db.execute(
                """
                UPDATE {{tables.agents}}
                SET did = NULL, public_key = NULL, stable_id = NULL,
                    custody = NULL, signing_key_enc = NULL
                WHERE agent_id = $1
                """,
                UUID(agent_id),
            )

            resp2 = await c.post(
                "/v1/agents/me/identity/reset",
                json={"confirm": True},
                headers={"Authorization": f"Bearer {api_key}"},
            )
            assert resp2.status_code == 200
            data = resp2.json()
            assert data["did"] is None


@pytest.mark.asyncio
async def test_reset_requires_auth(aweb_db_infra):
    """POST /me/identity/reset without auth returns 401."""
    aweb_db_infra: DatabaseInfra
    app = create_app(db_infra=aweb_db_infra, redis=None)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/agents/me/identity/reset",
                json={"confirm": True},
            )
            assert resp.status_code in (401, 403)
