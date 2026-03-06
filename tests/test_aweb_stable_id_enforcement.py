"""Tests for stable_id envelope enforcement (anti-spoof/DoS checks)."""

from __future__ import annotations

import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app
from aweb.auth import hash_api_key
from aweb.did import did_from_public_key, encode_public_key, generate_keypair
from aweb.stable_id import stable_id_from_did_key


def _auth(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


async def _seed_two_self_custody_agents(aweb_db):
    namespace_id = uuid.uuid4()
    project_id = uuid.uuid4()
    alice_id = uuid.uuid4()
    bob_id = uuid.uuid4()
    proj_slug = f"proj-{uuid.uuid4().hex[:8]}"

    alice_seed, alice_pub = generate_keypair()
    bob_seed, bob_pub = generate_keypair()
    alice_did = did_from_public_key(alice_pub)
    bob_did = did_from_public_key(bob_pub)

    await aweb_db.execute(
        "INSERT INTO {{tables.namespaces}} (namespace_id, slug) VALUES ($1, $2)",
        namespace_id,
        proj_slug,
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name, namespace_id) VALUES ($1, $2, $3, $4)",
        project_id,
        proj_slug,
        "Stable ID Test",
        namespace_id,
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} "
        "(agent_id, project_id, alias, human_name, agent_type, did, public_key, custody, lifetime, namespace_id) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        alice_id,
        project_id,
        "alice",
        "Alice",
        "agent",
        alice_did,
        encode_public_key(alice_pub),
        "self",
        "persistent",
        namespace_id,
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.agents}} "
        "(agent_id, project_id, alias, human_name, agent_type, did, public_key, custody, lifetime, namespace_id) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        bob_id,
        project_id,
        "bob",
        "Bob",
        "agent",
        bob_did,
        encode_public_key(bob_pub),
        "self",
        "persistent",
        namespace_id,
    )

    key_alice = f"aw_sk_{uuid.uuid4().hex}"
    key_bob = f"aw_sk_{uuid.uuid4().hex}"
    for aid, key in [(alice_id, key_alice), (bob_id, key_bob)]:
        await aweb_db.execute(
            "INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active) "
            "VALUES ($1, $2, $3, $4, $5)",
            project_id,
            aid,
            key[:12],
            hash_api_key(key),
            True,
        )

    return {
        "project_id": str(project_id),
        "alice_id": str(alice_id),
        "bob_id": str(bob_id),
        "alice_did": alice_did,
        "bob_did": bob_did,
        "key_alice": key_alice,
        "key_bob": key_bob,
        "alice_seed": alice_seed,
        "bob_seed": bob_seed,
    }


@pytest.mark.asyncio
async def test_mail_rejects_mismatched_from_stable_id(aweb_db_infra):
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_two_self_custody_agents(aweb_db)

    good_from_stable = stable_id_from_did_key(seed["alice_did"])
    bad_from_stable = good_from_stable[:-1] + ("1" if good_from_stable[-1] != "1" else "2")

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/v1/messages",
                headers=_auth(seed["key_alice"]),
                json={
                    "to_alias": "bob",
                    "subject": "signed",
                    "body": "hello",
                    "message_id": str(uuid.uuid4()),
                    "timestamp": "2026-02-21T12:00:00Z",
                    "from_did": seed["alice_did"],
                    "to_did": seed["bob_did"],
                    "from_stable_id": bad_from_stable,
                    "signature": "sig",
                    "signing_key_id": seed["alice_did"],
                },
            )
            assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
async def test_mail_rejects_mismatched_to_stable_id(aweb_db_infra):
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_two_self_custody_agents(aweb_db)

    good_to_stable = stable_id_from_did_key(seed["bob_did"])
    bad_to_stable = good_to_stable[:-1] + ("1" if good_to_stable[-1] != "1" else "2")

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/v1/messages",
                headers=_auth(seed["key_alice"]),
                json={
                    "to_alias": "bob",
                    "subject": "signed",
                    "body": "hello",
                    "message_id": str(uuid.uuid4()),
                    "timestamp": "2026-02-21T12:00:00Z",
                    "from_did": seed["alice_did"],
                    "to_did": seed["bob_did"],
                    "to_stable_id": bad_to_stable,
                    "signature": "sig",
                    "signing_key_id": seed["alice_did"],
                },
            )
            assert resp.status_code == 403, resp.text
