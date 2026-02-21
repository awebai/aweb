"""Tests for transparent server-side signing of custodial agent messages (aweb-fj2.11)."""

from __future__ import annotations

import secrets
import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app
from aweb.auth import hash_api_key
from aweb.db import DatabaseInfra
from aweb.did import did_from_public_key, generate_keypair
from aweb.signing import VerifyResult, canonical_payload, verify_signature


def _auth(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


async def _seed_custodial_project(aweb_db, master_key: bytes):
    """Create a project with a custodial agent and a plain agent. Returns IDs and keys."""
    from aweb.custody import encrypt_signing_key

    project_id = uuid.uuid4()
    cust_id = uuid.uuid4()
    plain_id = uuid.uuid4()

    seed, pub = generate_keypair()
    did = did_from_public_key(pub)
    signing_key_enc = encrypt_signing_key(seed, master_key)

    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_id,
        f"proj-{uuid.uuid4().hex[:8]}",
        "Custodial Test",
    )

    # Custodial agent with encrypted key
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} "
        "(agent_id, project_id, alias, human_name, agent_type, did, public_key, custody, signing_key_enc, lifetime) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        cust_id,
        project_id,
        "custodial-alice",
        "Custodial Alice",
        "agent",
        did,
        pub.hex(),
        "custodial",
        signing_key_enc,
        "persistent",
    )

    # Plain agent (no identity)
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type) "
        "VALUES ($1, $2, $3, $4, $5)",
        plain_id,
        project_id,
        "plain-bob",
        "Plain Bob",
        "agent",
    )

    key_cust = f"aw_sk_{uuid.uuid4().hex}"
    key_plain = f"aw_sk_{uuid.uuid4().hex}"
    for aid, key in [(cust_id, key_cust), (plain_id, key_plain)]:
        await aweb_db.execute(
            "INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active) "
            "VALUES ($1, $2, $3, $4, $5)",
            project_id,
            aid,
            key[:12],
            hash_api_key(key),
            True,
        )

    # Read back the project slug for address reconstruction in tests.
    proj_row = await aweb_db.fetch_one(
        "SELECT slug FROM {{tables.projects}} WHERE project_id = $1",
        project_id,
    )

    return {
        "project_id": project_id,
        "project_slug": proj_row["slug"],
        "cust_id": str(cust_id),
        "plain_id": str(plain_id),
        "key_cust": key_cust,
        "key_plain": key_plain,
        "did": did,
        "seed": seed,
        "pub": pub,
    }


@pytest.mark.asyncio
async def test_mail_custodial_signing(aweb_db_infra, monkeypatch):
    """Custodial agent sends mail → server signs automatically, signature verifiable."""
    aweb_db_infra: DatabaseInfra
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())

    aweb_db = aweb_db_infra.get_manager("aweb")
    seed_data = await _seed_custodial_project(aweb_db, master_key)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Custodial agent sends mail without providing signature
            resp = await client.post(
                "/v1/messages",
                headers=_auth(seed_data["key_cust"]),
                json={
                    "to_alias": "plain-bob",
                    "subject": "auto-signed",
                    "body": "hello from custodial",
                },
            )
            assert resp.status_code == 200, resp.text

            # Check inbox — message should have server-signed fields
            resp = await client.get("/v1/messages/inbox", headers=_auth(seed_data["key_plain"]))
            assert resp.status_code == 200
            msgs = resp.json()["messages"]
            assert len(msgs) == 1
            msg = msgs[0]
            assert msg["from_did"] == seed_data["did"]
            assert msg["signature"] is not None
            assert msg["signing_key_id"] == seed_data["did"]


@pytest.mark.asyncio
async def test_mail_no_signing_without_custody_key(aweb_db_infra, monkeypatch):
    """Without AWEB_CUSTODY_KEY, custodial agent messages are stored unsigned."""
    aweb_db_infra: DatabaseInfra
    master_key = secrets.token_bytes(32)

    # Seed with a custody key (to create the encrypted key), then remove it
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed_data = await _seed_custodial_project(aweb_db, master_key)
    monkeypatch.delenv("AWEB_CUSTODY_KEY")

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/v1/messages",
                headers=_auth(seed_data["key_cust"]),
                json={
                    "to_alias": "plain-bob",
                    "subject": "unsigned",
                    "body": "no custody key",
                },
            )
            assert resp.status_code == 200

            resp = await client.get("/v1/messages/inbox", headers=_auth(seed_data["key_plain"]))
            msgs = resp.json()["messages"]
            assert len(msgs) == 1
            assert msgs[0]["signature"] is None
            assert msgs[0]["from_did"] is None


@pytest.mark.asyncio
async def test_chat_custodial_signing(aweb_db_infra, monkeypatch):
    """Custodial agent sends chat → server signs automatically."""
    aweb_db_infra: DatabaseInfra
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())

    aweb_db = aweb_db_infra.get_manager("aweb")
    seed_data = await _seed_custodial_project(aweb_db, master_key)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Create chat session
            resp = await client.post(
                "/v1/chat/sessions",
                headers=_auth(seed_data["key_cust"]),
                json={
                    "to_aliases": ["plain-bob"],
                    "message": "hello chat",
                },
            )
            assert resp.status_code == 200, resp.text
            session_id = resp.json()["session_id"]

            # Check history — should be signed
            resp = await client.get(
                f"/v1/chat/sessions/{session_id}/messages",
                headers=_auth(seed_data["key_plain"]),
            )
            assert resp.status_code == 200
            msgs = resp.json()["messages"]
            assert len(msgs) == 1
            assert msgs[0]["from_did"] == seed_data["did"]
            assert msgs[0]["signature"] is not None
            assert msgs[0]["signing_key_id"] == seed_data["did"]


@pytest.mark.asyncio
async def test_plain_agent_not_signed(aweb_db_infra, monkeypatch):
    """Non-custodial agent messages are NOT signed by server."""
    aweb_db_infra: DatabaseInfra
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())

    aweb_db = aweb_db_infra.get_manager("aweb")
    seed_data = await _seed_custodial_project(aweb_db, master_key)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/v1/messages",
                headers=_auth(seed_data["key_plain"]),
                json={
                    "to_alias": "custodial-alice",
                    "subject": "from plain",
                    "body": "unsigned message",
                },
            )
            assert resp.status_code == 200

            resp = await client.get("/v1/messages/inbox", headers=_auth(seed_data["key_cust"]))
            msgs = resp.json()["messages"]
            assert len(msgs) == 1
            assert msgs[0]["signature"] is None
            assert msgs[0]["from_did"] is None


@pytest.mark.asyncio
async def test_caller_provided_signature_not_overwritten(aweb_db_infra, monkeypatch):
    """If caller already provides signature fields, server does not overwrite them."""
    aweb_db_infra: DatabaseInfra
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())

    aweb_db = aweb_db_infra.get_manager("aweb")
    seed_data = await _seed_custodial_project(aweb_db, master_key)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/v1/messages",
                headers=_auth(seed_data["key_cust"]),
                json={
                    "to_alias": "plain-bob",
                    "subject": "pre-signed",
                    "body": "already signed",
                    "from_did": "did:key:zCallerProvided",
                    "signature": "caller-sig",
                    "signing_key_id": "did:key:zCallerKey",
                },
            )
            assert resp.status_code == 200

            resp = await client.get("/v1/messages/inbox", headers=_auth(seed_data["key_plain"]))
            msgs = resp.json()["messages"]
            assert len(msgs) == 1
            # Caller's values should be preserved, not overwritten
            assert msgs[0]["from_did"] == "did:key:zCallerProvided"
            assert msgs[0]["signature"] == "caller-sig"
            assert msgs[0]["signing_key_id"] == "did:key:zCallerKey"


@pytest.mark.asyncio
async def test_chat_send_message_custodial_signing(aweb_db_infra, monkeypatch):
    """Custodial agent sends follow-up chat message → server signs automatically."""
    aweb_db_infra: DatabaseInfra
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())

    aweb_db = aweb_db_infra.get_manager("aweb")
    seed_data = await _seed_custodial_project(aweb_db, master_key)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Create session first
            resp = await client.post(
                "/v1/chat/sessions",
                headers=_auth(seed_data["key_cust"]),
                json={"to_aliases": ["plain-bob"], "message": "start"},
            )
            assert resp.status_code == 200, resp.text
            session_id = resp.json()["session_id"]

            # Send follow-up message in existing session
            resp = await client.post(
                f"/v1/chat/sessions/{session_id}/messages",
                headers=_auth(seed_data["key_cust"]),
                json={"body": "follow-up message"},
            )
            assert resp.status_code == 200, resp.text

            # Check history — both messages should be signed
            resp = await client.get(
                f"/v1/chat/sessions/{session_id}/messages",
                headers=_auth(seed_data["key_plain"]),
            )
            assert resp.status_code == 200
            msgs = resp.json()["messages"]
            assert len(msgs) == 2
            for msg in msgs:
                assert msg["from_did"] == seed_data["did"]
                assert msg["signature"] is not None
                assert msg["signing_key_id"] == seed_data["did"]


@pytest.mark.asyncio
async def test_custodial_signature_verifies_end_to_end(aweb_db_infra, monkeypatch):
    """Signature produced by server-side custodial signing verifies against the canonical payload."""
    aweb_db_infra: DatabaseInfra
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())

    aweb_db = aweb_db_infra.get_manager("aweb")
    seed_data = await _seed_custodial_project(aweb_db, master_key)
    slug = seed_data["project_slug"]

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/v1/messages",
                headers=_auth(seed_data["key_cust"]),
                json={
                    "to_alias": "plain-bob",
                    "subject": "verify-me",
                    "body": "end-to-end verification",
                },
            )
            assert resp.status_code == 200, resp.text

            resp = await client.get("/v1/messages/inbox", headers=_auth(seed_data["key_plain"]))
            msgs = resp.json()["messages"]
            assert len(msgs) == 1
            msg = msgs[0]

            # Reconstruct the canonical payload that the server should have signed.
            payload = canonical_payload(
                {
                    "from": f"{slug}/custodial-alice",
                    "from_did": seed_data["did"],
                    "to": f"{slug}/plain-bob",
                    "to_did": "",
                    "type": "mail",
                    "subject": "verify-me",
                    "body": "end-to-end verification",
                    "timestamp": msg["created_at"],
                }
            )

            result = verify_signature(msg["from_did"], payload, msg["signature"])
            assert result == VerifyResult.VERIFIED
