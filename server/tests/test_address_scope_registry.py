from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
import os

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from aweb.address_scope import _sender_contact_addresses, resolve_local_recipient
from aweb.awid.custody import encrypt_signing_key, reset_custody_key_cache
from aweb.awid.did import did_from_public_key, encode_public_key, generate_keypair, stable_id_from_did_key
from aweb.awid.replacement import get_sender_delivery_metadata
from aweb.awid.registry import RegistryError
from aweb.db import get_db_infra
from aweb.mcp.auth import AuthContext, _auth_context
from aweb.mcp.tools.identity import whoami
from aweb.mcp.tools.mail import check_inbox
from aweb.messaging.messages import deliver_message
from aweb.redis_client import get_redis
from aweb.routes.agents import router as agents_router
from aweb.routes.init import bootstrap_router, router as init_router


class _DbInfra:
    is_initialized = True

    def __init__(self, *, aweb_db, server_db=None):
        self._aweb_db = aweb_db
        self._server_db = server_db

    def get_manager(self, name: str = "aweb"):
        if name == "aweb":
            return self._aweb_db
        if name == "server" and self._server_db is not None:
            return self._server_db
        raise KeyError(name)


@dataclass(frozen=True)
class _FakeAddress:
    domain: str
    name: str
    did_aw: str
    reachability: str = "public"


class _FakeRegistryClient:
    def __init__(
        self,
        *,
        resolved_address: _FakeAddress | None = None,
        did_addresses=None,
        did_addresses_by_did: dict[str, list[_FakeAddress]] | None = None,
        fail_list: bool = False,
    ):
        self._resolved_address = resolved_address
        self._did_addresses = list(did_addresses or [])
        self._did_addresses_by_did = dict(did_addresses_by_did or {})
        self._fail_list = fail_list
        self.resolve_calls: list[tuple[str, str]] = []
        self.did_calls: list[str] = []

    async def resolve_address(self, domain: str, name: str):
        self.resolve_calls.append((domain, name))
        return self._resolved_address

    async def list_did_addresses(self, did_aw: str):
        self.did_calls.append(did_aw)
        if self._fail_list:
            raise RegistryError("registry unavailable", status_code=503, detail="registry unavailable")
        if did_aw in self._did_addresses_by_did:
            return list(self._did_addresses_by_did[did_aw])
        return list(self._did_addresses)

    async def get_namespace(self, domain: str):
        return _FakeNamespace(domain=domain, controller_did="did:key:z-controller")


@dataclass(frozen=True)
class _FakeNamespace:
    domain: str
    controller_did: str


class _FakeRedis:
    def __init__(self) -> None:
        self._counts: dict[str, int] = {}
        self._ttl: dict[str, int] = {}

    async def eval(self, _script: str, _num_keys: int, key: str, window_seconds: int) -> int:
        current = self._counts.get(key, 0) + 1
        self._counts[key] = current
        self._ttl[key] = int(window_seconds)
        return current

    async def ttl(self, key: str) -> int:
        return self._ttl.get(key, -1)

    async def delete(self, key: str) -> int:
        self._counts.pop(key, None)
        self._ttl.pop(key, None)
        return 1


def _build_app(*, aweb_db, server_db, registry_client) -> FastAPI:
    app = FastAPI(title="address scope registry test")
    app.include_router(bootstrap_router)
    app.include_router(init_router)
    app.include_router(agents_router)
    app.state.awid_registry_client = registry_client
    app.dependency_overrides[get_db_infra] = lambda: _DbInfra(aweb_db=aweb_db, server_db=server_db)
    app.dependency_overrides[get_redis] = lambda: _FakeRedis()
    return app


def _auth_headers(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


async def _create_project(aweb_db, *, slug: str):
    project_id = uuid.uuid4()
    await aweb_db.execute(
        """
        INSERT INTO {{tables.projects}} (project_id, slug, name)
        VALUES ($1, $2, $3)
        """,
        project_id,
        slug,
        slug,
    )
    return str(project_id)


async def _create_agent(aweb_db, *, project_id: str, alias: str, stable_id: str | None = None):
    signing_key, public_key = generate_keypair()
    agent_id = uuid.uuid4()
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, project_id, alias, human_name, agent_type, custody, did, public_key,
             signing_key_enc, lifetime, stable_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        """,
        agent_id,
        uuid.UUID(project_id),
        alias,
        alias.title(),
        "agent",
        "self",
        did_from_public_key(public_key),
        encode_public_key(public_key),
        None,
        "persistent",
        stable_id,
    )
    return str(agent_id)


@pytest.fixture(autouse=True)
def _reset_custody_env():
    original = os.environ.get("AWEB_CUSTODY_KEY")
    reset_custody_key_cache()
    yield
    if original is None:
        os.environ.pop("AWEB_CUSTODY_KEY", None)
    else:
        os.environ["AWEB_CUSTODY_KEY"] = original
    reset_custody_key_cache()


@pytest.mark.asyncio
async def test_resolve_local_recipient_uses_registry_lookup(aweb_cloud_db):
    db = _DbInfra(aweb_db=aweb_cloud_db.aweb_db)
    sender_project_id = await _create_project(aweb_cloud_db.aweb_db, slug=f"sender-{uuid.uuid4().hex[:8]}")
    recipient_project_id = await _create_project(
        aweb_cloud_db.aweb_db,
        slug=f"recipient-{uuid.uuid4().hex[:8]}",
    )
    sender_agent_id = await _create_agent(
        aweb_cloud_db.aweb_db,
        project_id=sender_project_id,
        alias="alice",
        stable_id=f"did:aw:{uuid.uuid4().hex}",
    )
    recipient_stable_id = f"did:aw:{uuid.uuid4().hex}"
    recipient_agent_id = await _create_agent(
        aweb_cloud_db.aweb_db,
        project_id=recipient_project_id,
        alias="bob",
        stable_id=recipient_stable_id,
    )
    registry_client = _FakeRegistryClient(
        resolved_address=_FakeAddress(
            domain="acme.com",
            name="bob",
            did_aw=recipient_stable_id,
            reachability="public",
        )
    )

    resolved = await resolve_local_recipient(
        db,
        sender_project_id=sender_project_id,
        sender_agent_id=sender_agent_id,
        ref="acme.com/bob",
        registry_client=registry_client,
    )

    assert resolved.agent_id == recipient_agent_id
    assert resolved.agent_alias == "bob"
    assert resolved.project_id == recipient_project_id
    assert registry_client.resolve_calls == [("acme.com", "bob")]


@pytest.mark.asyncio
async def test_sender_contact_addresses_use_registry_reverse_lookup(aweb_cloud_db):
    db = _DbInfra(aweb_db=aweb_cloud_db.aweb_db)
    project_slug = f"contacts-{uuid.uuid4().hex[:8]}"
    project_id = await _create_project(aweb_cloud_db.aweb_db, slug=project_slug)
    sender_stable_id = f"did:aw:{uuid.uuid4().hex}"
    sender_agent_id = await _create_agent(
        aweb_cloud_db.aweb_db,
        project_id=project_id,
        alias="alice",
        stable_id=sender_stable_id,
    )
    registry_client = _FakeRegistryClient(
        did_addresses=[
            _FakeAddress(domain="team.example", name="alice", did_aw=sender_stable_id),
        ]
    )

    addresses = await _sender_contact_addresses(
        db,
        sender_project_id=project_id,
        sender_agent_id=sender_agent_id,
        registry_client=registry_client,
    )

    assert project_slug in addresses
    assert "alice" in addresses
    assert f"{project_slug}~alice" in addresses
    assert "team.example/alice" in addresses
    assert registry_client.did_calls == [sender_stable_id]


@pytest.mark.asyncio
async def test_sender_delivery_metadata_uses_registry_addresses(aweb_cloud_db):
    aweb_db = aweb_cloud_db.aweb_db
    project_id = await _create_project(aweb_db, slug=f"delivery-{uuid.uuid4().hex[:8]}")
    stable_id = f"did:aw:{uuid.uuid4().hex}"
    agent_id = await _create_agent(
        aweb_db,
        project_id=project_id,
        alias="alice",
        stable_id=stable_id,
    )
    registry_client = _FakeRegistryClient(
        did_addresses=[
            _FakeAddress(domain="team.example", name="alice", did_aw=stable_id),
        ]
    )

    metadata = await get_sender_delivery_metadata(
        aweb_db,
        sender_ids=[uuid.UUID(agent_id)],
        registry_client=registry_client,
    )

    assert metadata[agent_id]["from_address"] == "team.example/alice"
    assert metadata[agent_id]["replacement_announcement"] is None
    assert registry_client.did_calls == [stable_id]


@pytest.mark.asyncio
async def test_sender_delivery_metadata_degrades_when_registry_unavailable(aweb_cloud_db):
    aweb_db = aweb_cloud_db.aweb_db
    project_id = await _create_project(aweb_db, slug=f"delivery-fallback-{uuid.uuid4().hex[:8]}")
    stable_id = f"did:aw:{uuid.uuid4().hex}"
    agent_id = await _create_agent(
        aweb_db,
        project_id=project_id,
        alias="alice",
        stable_id=stable_id,
    )
    registry_client = _FakeRegistryClient(fail_list=True)

    metadata = await get_sender_delivery_metadata(
        aweb_db,
        sender_ids=[uuid.UUID(agent_id)],
        registry_client=registry_client,
    )

    assert metadata[agent_id]["from_address"] is None
    assert metadata[agent_id]["replacement_announcement"] is None
    assert registry_client.did_calls == [stable_id]


@pytest.mark.asyncio
async def test_whoami_uses_registry_for_assigned_addresses(aweb_cloud_db):
    db = _DbInfra(aweb_db=aweb_cloud_db.aweb_db)
    project_id = await _create_project(aweb_cloud_db.aweb_db, slug=f"whoami-{uuid.uuid4().hex[:8]}")
    stable_id = f"did:aw:{uuid.uuid4().hex}"
    agent_id = await _create_agent(
        aweb_cloud_db.aweb_db,
        project_id=project_id,
        alias="alice",
        stable_id=stable_id,
    )
    registry_client = _FakeRegistryClient(
        did_addresses=[
            _FakeAddress(domain="team.example", name="alice", did_aw=stable_id),
            _FakeAddress(domain="team.example", name="ops", did_aw=stable_id),
        ]
    )

    token = _auth_context.set(AuthContext(project_id=project_id, agent_id=agent_id))
    try:
        result = json.loads(await whoami(db, registry_client=registry_client))
    finally:
        _auth_context.reset(token)

    assert result["agent_id"] == agent_id
    assert result["stable_id"] == stable_id
    assert result["addresses"] == ["team.example/alice", "team.example/ops"]
    assert registry_client.did_calls == [stable_id]


@pytest.mark.asyncio
async def test_whoami_falls_back_to_empty_addresses_on_registry_error(aweb_cloud_db):
    db = _DbInfra(aweb_db=aweb_cloud_db.aweb_db)
    project_id = await _create_project(aweb_cloud_db.aweb_db, slug=f"whoami-fallback-{uuid.uuid4().hex[:8]}")
    stable_id = f"did:aw:{uuid.uuid4().hex}"
    agent_id = await _create_agent(
        aweb_cloud_db.aweb_db,
        project_id=project_id,
        alias="alice",
        stable_id=stable_id,
    )
    registry_client = _FakeRegistryClient(fail_list=True)

    token = _auth_context.set(AuthContext(project_id=project_id, agent_id=agent_id))
    try:
        result = json.loads(await whoami(db, registry_client=registry_client))
    finally:
        _auth_context.reset(token)

    assert result["agent_id"] == agent_id
    assert result["addresses"] == []
    assert registry_client.did_calls == [stable_id]


@pytest.mark.asyncio
async def test_mcp_check_inbox_uses_registry_client_with_messages(aweb_cloud_db):
    db = _DbInfra(aweb_db=aweb_cloud_db.aweb_db)
    project_id = await _create_project(aweb_cloud_db.aweb_db, slug=f"inbox-{uuid.uuid4().hex[:8]}")
    sender_stable_id = f"did:aw:{uuid.uuid4().hex}"
    recipient_stable_id = f"did:aw:{uuid.uuid4().hex}"
    sender_agent_id = await _create_agent(
        aweb_cloud_db.aweb_db,
        project_id=project_id,
        alias="alice",
        stable_id=sender_stable_id,
    )
    recipient_agent_id = await _create_agent(
        aweb_cloud_db.aweb_db,
        project_id=project_id,
        alias="bob",
        stable_id=recipient_stable_id,
    )
    registry_client = _FakeRegistryClient(
        did_addresses_by_did={
            sender_stable_id: [
                _FakeAddress(domain="team.example", name="alice", did_aw=sender_stable_id),
            ]
        }
    )

    await deliver_message(
        db,
        project_id=project_id,
        from_agent_id=sender_agent_id,
        from_alias="alice",
        to_agent_id=recipient_agent_id,
        subject="hello",
        body="world",
        priority="normal",
        thread_id=None,
        from_stable_id=sender_stable_id,
        to_stable_id=recipient_stable_id,
    )

    token = _auth_context.set(
        AuthContext(project_id=project_id, agent_id=recipient_agent_id),
    )
    try:
        result = json.loads(await check_inbox(db, registry_client=registry_client))
    finally:
        _auth_context.reset(token)

    assert result["messages"][0]["from_address"] == "team.example/alice"
    assert result["messages"][0]["subject"] == "hello"
    assert registry_client.did_calls == [sender_stable_id]


@pytest.mark.asyncio
async def test_resolve_agent_route_uses_registry_lookup(aweb_cloud_db):
    recipient_stable_id = f"did:aw:{uuid.uuid4().hex}"
    registry_client = _FakeRegistryClient(
        resolved_address=_FakeAddress(
            domain="team.example",
            name="bob",
            did_aw=recipient_stable_id,
            reachability="public",
        )
    )
    app = _build_app(
        aweb_db=aweb_cloud_db.aweb_db,
        server_db=aweb_cloud_db.oss_db,
        registry_client=registry_client,
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        bootstrap = await client.post(
            "/api/v1/create-project",
            json={
                "project_slug": f"resolve-{uuid.uuid4().hex[:8]}",
                "namespace_slug": f"resolve-{uuid.uuid4().hex[:8]}",
                "alias": "alice",
            },
        )
        assert bootstrap.status_code == 200, bootstrap.text
        creator = bootstrap.json()
        await aweb_cloud_db.aweb_db.execute(
            """
            UPDATE {{tables.agents}}
            SET stable_id = $2
            WHERE agent_id = $1
            """,
            uuid.UUID(creator["agent_id"]),
            f"did:aw:{uuid.uuid4().hex}",
        )

        second = await client.post(
            "/v1/workspaces/init",
            headers=_auth_headers(creator["api_key"]),
            json={"alias": "bob"},
        )
        assert second.status_code == 200, second.text
        recipient = second.json()
        await aweb_cloud_db.aweb_db.execute(
            """
            UPDATE {{tables.agents}}
            SET stable_id = $2
            WHERE agent_id = $1
            """,
            uuid.UUID(recipient["agent_id"]),
            recipient_stable_id,
        )

        response = await client.get(
            "/v1/agents/resolve/team.example/bob",
            headers=_auth_headers(creator["api_key"]),
        )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["agent_id"] == recipient["agent_id"]
    assert payload["stable_id"] == recipient_stable_id
    assert payload["address"] == "team.example/bob"
    assert payload["controller_did"] == "did:key:z-controller"
    assert registry_client.resolve_calls == [("team.example", "bob")]


@pytest.mark.asyncio
async def test_retire_agent_uses_registry_successor_address(aweb_cloud_db):
    creator_stable_id = f"did:aw:{uuid.uuid4().hex}"
    successor_stable_id = ""
    registry_client = _FakeRegistryClient(
        did_addresses_by_did={
            successor_stable_id: [
                _FakeAddress(domain="team.example", name="bob", did_aw=successor_stable_id),
            ],
        }
    )
    app = _build_app(
        aweb_db=aweb_cloud_db.aweb_db,
        server_db=aweb_cloud_db.oss_db,
        registry_client=registry_client,
    )
    master_key = bytes.fromhex("77" * 32)
    os.environ["AWEB_CUSTODY_KEY"] = master_key.hex()
    reset_custody_key_cache()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        bootstrap = await client.post(
            "/api/v1/create-project",
            json={
                "project_slug": f"retire-{uuid.uuid4().hex[:8]}",
                "namespace_slug": f"retire-{uuid.uuid4().hex[:8]}",
                "alias": "alice",
            },
        )
        assert bootstrap.status_code == 200, bootstrap.text
        creator = bootstrap.json()

        second = await client.post(
            "/v1/workspaces/init",
            headers=_auth_headers(creator["api_key"]),
            json={"alias": "bob"},
        )
        assert second.status_code == 200, second.text
        successor = second.json()
        successor_row = await aweb_cloud_db.aweb_db.fetch_one(
            """
            SELECT did
            FROM {{tables.agents}}
            WHERE agent_id = $1
            """,
            uuid.UUID(successor["agent_id"]),
        )
        assert successor_row is not None
        successor_stable_id = stable_id_from_did_key(successor_row["did"])
        registry_client._did_addresses_by_did = {
            successor_stable_id: [
                _FakeAddress(domain="team.example", name="bob", did_aw=successor_stable_id),
            ],
        }

        encrypted = encrypt_signing_key(generate_keypair()[0], master_key)
        await aweb_cloud_db.aweb_db.execute(
            """
            UPDATE {{tables.agents}}
            SET stable_id = $2,
                custody = 'custodial',
                signing_key_enc = $3,
                lifetime = 'persistent'
            WHERE agent_id = $1
            """,
            uuid.UUID(creator["agent_id"]),
            creator_stable_id,
            encrypted,
        )
        await aweb_cloud_db.aweb_db.execute(
            """
            UPDATE {{tables.agents}}
            SET stable_id = $2
            WHERE agent_id = $1
            """,
            uuid.UUID(successor["agent_id"]),
            successor_stable_id,
        )

        response = await client.put(
            "/v1/agents/me/retire",
            headers=_auth_headers(creator["api_key"]),
            json={
                "successor_agent_id": successor["agent_id"],
                "timestamp": "2026-04-05T00:00:00Z",
            },
        )

    assert response.status_code == 200, response.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT metadata
        FROM {{tables.agent_log}}
        WHERE agent_id = $1 AND operation = 'retire'
        ORDER BY created_at DESC
        LIMIT 1
        """,
        uuid.UUID(creator["agent_id"]),
    )
    assert row is not None
    metadata = row["metadata"]
    if isinstance(metadata, str):
        metadata = json.loads(metadata)
    assert metadata["successor_address"] == "team.example/bob"
    assert registry_client.did_calls == [successor_stable_id]
