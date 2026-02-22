"""Tests for sending messages to retired agents (aweb-sqt)."""

from __future__ import annotations

import base64
import json
import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey

from aweb.api import create_app
from aweb.auth import hash_api_key
from aweb.db import DatabaseInfra
from aweb.did import did_from_public_key, encode_public_key, generate_keypair


def _auth(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


def _sign_retirement_proof(private_key: bytes, successor_agent_id: str, timestamp: str) -> str:
    canonical = json.dumps(
        {"operation": "retire", "successor_agent_id": successor_agent_id, "timestamp": timestamp},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    signing_key = SigningKey(private_key)
    signed = signing_key.sign(canonical)
    return base64.b64encode(signed.signature).rstrip(b"=").decode("ascii")


async def _seed_with_retired_agent(aweb_db):
    """Create a project with a retired agent and an active successor."""
    project_id = uuid.uuid4()
    retired_id = uuid.uuid4()
    successor_id = uuid.uuid4()
    sender_id = uuid.uuid4()

    seed, pub = generate_keypair()
    did = did_from_public_key(pub)
    succ_seed, succ_pub = generate_keypair()
    succ_did = did_from_public_key(succ_pub)

    slug = f"retired-{uuid.uuid4().hex[:8]}"
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_id,
        slug,
        "Retired Delivery Test",
    )

    # Successor agent (must exist before retired agent due to FK on successor_agent_id)
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
        encode_public_key(succ_pub),
        "self",
        "persistent",
    )

    # Retired agent (status='retired', points to successor)
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} "
        "(agent_id, project_id, alias, human_name, agent_type, did, public_key, custody, lifetime, status, successor_agent_id) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        retired_id,
        project_id,
        "retired-agent",
        "Retired Agent",
        "agent",
        did,
        encode_public_key(pub),
        "self",
        "persistent",
        "retired",
        successor_id,
    )

    # Sender agent
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type) "
        "VALUES ($1, $2, $3, $4, $5)",
        sender_id,
        project_id,
        "sender",
        "Sender",
        "agent",
    )

    sender_key = f"aw_sk_{uuid.uuid4().hex}"
    await aweb_db.execute(
        "INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active) "
        "VALUES ($1, $2, $3, $4, $5)",
        project_id,
        sender_id,
        sender_key[:12],
        hash_api_key(sender_key),
        True,
    )

    return {
        "project_id": project_id,
        "retired_id": str(retired_id),
        "successor_id": str(successor_id),
        "sender_id": str(sender_id),
        "sender_key": sender_key,
        "successor_alias": "successor-agent",
    }


@pytest.mark.asyncio
async def test_send_mail_to_retired_agent_returns_notice(aweb_db_infra):
    """Sending a message to a retired agent should return a retirement notice with successor info."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")
    data = await _seed_with_retired_agent(aweb_db)

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/v1/messages",
                headers=_auth(data["sender_key"]),
                json={
                    "to_alias": "retired-agent",
                    "subject": "hello",
                    "body": "are you there?",
                },
            )
            # Should indicate retirement, not silently deliver
            assert (
                resp.status_code == 410
            ), f"Expected 410 Gone, got {resp.status_code}: {resp.text}"
            body = resp.json()
            assert "retired" in body.get("detail", "").lower()
            assert body.get("successor_alias") == "successor-agent"
