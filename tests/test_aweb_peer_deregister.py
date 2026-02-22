"""Tests for DELETE /v1/agents/{namespace}/{alias} — peer deregistration (aweb-jzb)."""

from __future__ import annotations

import secrets
import uuid

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app
from aweb.auth import hash_api_key
from aweb.custody import encrypt_signing_key
from aweb.did import did_from_public_key, generate_keypair


def _auth(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


async def _seed_project_with_agents(
    aweb_db,
    *,
    project_slug: str,
    ephemeral_alias: str = "eph-agent",
    peer_alias: str = "peer-agent",
    master_key: bytes,
):
    """Create a project with an ephemeral agent and a persistent peer agent."""
    project_id = uuid.uuid4()
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
        project_id,
        project_slug,
        f"Project {project_slug}",
    )

    # Ephemeral custodial agent (target)
    eph_private, eph_public = generate_keypair()
    eph_did = did_from_public_key(eph_public)
    eph_enc = encrypt_signing_key(eph_private, master_key)
    eph_id = uuid.uuid4()
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, project_id, alias, human_name, agent_type,
             did, public_key, custody, signing_key_enc, lifetime, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        """,
        eph_id,
        project_id,
        ephemeral_alias,
        f"Human {ephemeral_alias}",
        "agent",
        eph_did,
        eph_public.hex(),
        "custodial",
        eph_enc,
        "ephemeral",
        "active",
    )
    eph_key = f"aw_sk_{uuid.uuid4().hex}"
    await aweb_db.execute(
        "INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active) "
        "VALUES ($1, $2, $3, $4, $5)",
        project_id,
        eph_id,
        eph_key[:12],
        hash_api_key(eph_key),
        True,
    )

    # Persistent peer agent (caller)
    peer_private, peer_public = generate_keypair()
    peer_did = did_from_public_key(peer_public)
    peer_id = uuid.uuid4()
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, project_id, alias, human_name, agent_type,
             did, public_key, custody, lifetime, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        """,
        peer_id,
        project_id,
        peer_alias,
        f"Human {peer_alias}",
        "agent",
        peer_did,
        peer_public.hex(),
        "self",
        "persistent",
        "active",
    )
    peer_key = f"aw_sk_{uuid.uuid4().hex}"
    await aweb_db.execute(
        "INSERT INTO {{tables.api_keys}} (project_id, agent_id, key_prefix, key_hash, is_active) "
        "VALUES ($1, $2, $3, $4, $5)",
        project_id,
        peer_id,
        peer_key[:12],
        hash_api_key(peer_key),
        True,
    )

    return {
        "project_id": str(project_id),
        "project_slug": project_slug,
        "ephemeral": {
            "agent_id": str(eph_id),
            "alias": ephemeral_alias,
            "did": eph_did,
            "api_key": eph_key,
        },
        "peer": {
            "agent_id": str(peer_id),
            "alias": peer_alias,
            "api_key": peer_key,
        },
    }


@pytest.mark.asyncio
async def test_peer_deregister_ephemeral_agent(aweb_db_infra, monkeypatch):
    """A project peer can deregister an ephemeral agent by namespace/alias."""
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_project_with_agents(
        aweb_db, project_slug="peer-dereg/basic", master_key=master_key
    )

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.delete(
                f"/v1/agents/{seed['project_slug']}/{seed['ephemeral']['alias']}",
                headers=_auth(seed["peer"]["api_key"]),
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["agent_id"] == seed["ephemeral"]["agent_id"]
            assert body["status"] == "deregistered"


@pytest.mark.asyncio
async def test_peer_deregister_clears_signing_key(aweb_db_infra, monkeypatch):
    """Peer deregistration destroys the signing key and soft-deletes."""
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_project_with_agents(
        aweb_db, project_slug="peer-dereg/key-clear", master_key=master_key
    )

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.delete(
                f"/v1/agents/{seed['project_slug']}/{seed['ephemeral']['alias']}",
                headers=_auth(seed["peer"]["api_key"]),
            )
            assert resp.status_code == 200

    row = await aweb_db.fetch_one(
        "SELECT signing_key_enc, status, deleted_at FROM {{tables.agents}} WHERE agent_id = $1",
        uuid.UUID(seed["ephemeral"]["agent_id"]),
    )
    assert row["signing_key_enc"] is None
    assert row["status"] == "deregistered"
    assert row["deleted_at"] is not None


@pytest.mark.asyncio
async def test_peer_deregister_creates_log_entry(aweb_db_infra, monkeypatch):
    """Peer deregistration appends a 'deregister' entry to agent_log."""
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_project_with_agents(
        aweb_db, project_slug="peer-dereg/log", master_key=master_key
    )

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.delete(
                f"/v1/agents/{seed['project_slug']}/{seed['ephemeral']['alias']}",
                headers=_auth(seed["peer"]["api_key"]),
            )

    log = await aweb_db.fetch_one(
        "SELECT operation, old_did FROM {{tables.agent_log}} WHERE agent_id = $1",
        uuid.UUID(seed["ephemeral"]["agent_id"]),
    )
    assert log is not None
    assert log["operation"] == "deregister"
    assert log["old_did"] == seed["ephemeral"]["did"]


@pytest.mark.asyncio
async def test_peer_deregister_rejects_persistent_agent(aweb_db_infra, monkeypatch):
    """Peer deregistration of a persistent agent returns 400."""
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_project_with_agents(
        aweb_db, project_slug="peer-dereg/persistent", master_key=master_key
    )

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # Try to deregister the persistent peer agent (should fail)
            resp = await c.delete(
                f"/v1/agents/{seed['project_slug']}/{seed['peer']['alias']}",
                headers=_auth(seed["ephemeral"]["api_key"]),
            )
            assert resp.status_code == 400
            assert (
                "persistent" in resp.json()["detail"].lower()
                or "retire" in resp.json()["detail"].lower()
            )


@pytest.mark.asyncio
async def test_peer_deregister_cross_project_forbidden(aweb_db_infra, monkeypatch):
    """An agent from a different project cannot deregister another project's agent."""
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())
    aweb_db = aweb_db_infra.get_manager("aweb")

    seed_a = await _seed_project_with_agents(
        aweb_db, project_slug="peer-dereg/proj-a", master_key=master_key
    )
    seed_b = await _seed_project_with_agents(
        aweb_db, project_slug="peer-dereg/proj-b", master_key=master_key
    )

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # Agent from project B tries to deregister agent in project A
            resp = await c.delete(
                f"/v1/agents/{seed_a['project_slug']}/{seed_a['ephemeral']['alias']}",
                headers=_auth(seed_b["peer"]["api_key"]),
            )
            assert resp.status_code == 403


@pytest.mark.asyncio
async def test_peer_deregister_404_unknown_alias(aweb_db_infra, monkeypatch):
    """Deregistering a nonexistent alias returns 404."""
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_project_with_agents(
        aweb_db, project_slug="peer-dereg/not-found", master_key=master_key
    )

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.delete(
                f"/v1/agents/{seed['project_slug']}/nonexistent",
                headers=_auth(seed["peer"]["api_key"]),
            )
            assert resp.status_code == 404


@pytest.mark.asyncio
async def test_peer_deregister_404_unknown_namespace(aweb_db_infra, monkeypatch):
    """Deregistering in a nonexistent namespace returns 404."""
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_project_with_agents(
        aweb_db, project_slug="peer-dereg/ns-check", master_key=master_key
    )

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.delete(
                f"/v1/agents/nonexistent-project/{seed['ephemeral']['alias']}",
                headers=_auth(seed["peer"]["api_key"]),
            )
            assert resp.status_code == 404


@pytest.mark.asyncio
async def test_peer_deregister_twice_returns_404(aweb_db_infra, monkeypatch):
    """Deregistering the same agent twice via peer endpoint returns 404."""
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_project_with_agents(
        aweb_db, project_slug="peer-dereg/double", master_key=master_key
    )

    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            url = f"/v1/agents/{seed['project_slug']}/{seed['ephemeral']['alias']}"
            headers = _auth(seed["peer"]["api_key"])

            resp1 = await c.delete(url, headers=headers)
            assert resp1.status_code == 200

            resp2 = await c.delete(url, headers=headers)
            assert resp2.status_code == 404


@pytest.mark.asyncio
async def test_peer_deregister_requires_auth(aweb_db_infra):
    """Peer deregistration without auth returns 401."""
    app = create_app(db_infra=aweb_db_infra)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.delete("/v1/agents/some-project/some-agent")
            assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_peer_deregister_fires_mutation_hook(aweb_db_infra, monkeypatch):
    """Peer deregistration fires an agent.deregistered mutation hook."""
    master_key = secrets.token_bytes(32)
    monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())
    aweb_db = aweb_db_infra.get_manager("aweb")
    seed = await _seed_project_with_agents(
        aweb_db, project_slug="peer-dereg/hook", master_key=master_key
    )

    hook_calls = []

    app = create_app(db_infra=aweb_db_infra)

    # Patch fire_mutation_hook to capture calls
    import aweb.routes.agents as agents_mod

    original_fire = agents_mod.fire_mutation_hook

    async def capture_hook(request, event_type, context):
        hook_calls.append({"event_type": event_type, "context": context})
        return await original_fire(request, event_type, context)

    monkeypatch.setattr(agents_mod, "fire_mutation_hook", capture_hook)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.delete(
                f"/v1/agents/{seed['project_slug']}/{seed['ephemeral']['alias']}",
                headers=_auth(seed["peer"]["api_key"]),
            )
            assert resp.status_code == 200

    dereg_hooks = [h for h in hook_calls if h["event_type"] == "agent.deregistered"]
    assert len(dereg_hooks) == 1
    assert dereg_hooks[0]["context"]["agent_id"] == seed["ephemeral"]["agent_id"]
