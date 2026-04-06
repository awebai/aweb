from __future__ import annotations
import pytest; pytest.skip("Tests reference removed schema — to be deleted in aaez.5", allow_module_level=True)

import uuid
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from aweb.auth import hash_api_key
from aweb.awid.custody import reset_custody_key_cache
from aweb.awid.did import did_from_public_key, encode_public_key, generate_keypair
from aweb.db import get_db_infra
from aweb.redis_client import get_redis
from aweb.routes.auth import router as auth_router
from aweb.routes.init import bootstrap_router, router as init_router
from aweb.routes.spawn import router as spawn_router


@pytest.fixture(autouse=True)
def _reset_signing_key_cache():
    reset_custody_key_cache()
    yield
    reset_custody_key_cache()


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


class _FakeRegistryClient:
    def __init__(self) -> None:
        self._namespaces: dict[str, SimpleNamespace] = {}

    async def get_namespace(self, domain: str):
        return self._namespaces.get(domain)

    async def register_namespace(
        self,
        *,
        domain: str,
        controller_did: str,
        controller_signing_key: bytes,
        parent_signing_key: bytes | None,
    ):
        del controller_signing_key, parent_signing_key

        ns = SimpleNamespace(
            namespace_id="ns-1",
            domain=domain,
            controller_did=controller_did,
            verification_status="verified",
            last_verified_at=None,
            created_at="2026-04-06T00:00:00Z",
        )
        self._namespaces[domain] = ns
        return ns


def _build_spawn_test_app(*, aweb_db, server_db, registry_client=None) -> FastAPI:
    class _DbInfra:
        is_initialized = True

        def get_manager(self, name: str = "aweb"):
            if name == "aweb":
                return aweb_db
            if name == "server":
                return server_db
            raise KeyError(name)

    app = FastAPI(title="aweb spawn test")
    app.include_router(bootstrap_router)
    app.include_router(init_router)
    app.include_router(spawn_router)
    app.include_router(auth_router)
    if registry_client is not None:
        app.state.awid_registry_client = registry_client
    app.dependency_overrides[get_db_infra] = lambda: _DbInfra()
    app.dependency_overrides[get_redis] = lambda: _FakeRedis()
    return app


def _auth_headers(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


async def _assert_api_key_maps_to_identity(*, aweb_db, api_key: str, project_id: str, identity_id: str) -> None:
    key_hash = hash_api_key(api_key)
    row = await aweb_db.fetch_one(
        """
        SELECT project_id, agent_id
        FROM {{tables.api_keys}}
        WHERE key_hash = $1
        """,
        key_hash,
    )
    assert row is not None
    assert str(row["project_id"]) == project_id
    assert str(row["agent_id"]) == identity_id


@pytest.mark.asyncio
async def test_create_project_uses_owner_ref_for_managed_namespace(aweb_cloud_db, monkeypatch):
    monkeypatch.setenv("AWEB_MANAGED_DOMAIN", "aweb.ai")
    app = _build_spawn_test_app(aweb_db=aweb_cloud_db.aweb_db, server_db=aweb_cloud_db.oss_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = await client.post(
            "/api/v1/create-project",
            json={
                "project_slug": "acme-billing",
                "owner_type": "organization",
                "owner_ref": "acme",
                "alias": "alice",
            },
        )

    assert created.status_code == 200, created.text
    data = created.json()
    assert data["project_slug"] == "acme-billing"
    assert data["namespace_slug"] == "acme"
    assert data["namespace"] == "acme.aweb.ai"
    assert data["address"] == "acme.aweb.ai/alice"


@pytest.mark.asyncio
async def test_projects_under_same_owner_share_namespace_domain(aweb_cloud_db, monkeypatch):
    monkeypatch.setenv("AWEB_MANAGED_DOMAIN", "aweb.ai")
    app = _build_spawn_test_app(aweb_db=aweb_cloud_db.aweb_db, server_db=aweb_cloud_db.oss_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        billing = await client.post(
            "/api/v1/create-project",
            json={
                "project_slug": "acme-billing",
                "owner_type": "organization",
                "owner_ref": "acme",
                "alias": "alice",
            },
        )
        support = await client.post(
            "/api/v1/create-project",
            json={
                "project_slug": "acme-support",
                "owner_type": "organization",
                "owner_ref": "acme",
                "alias": "bob",
            },
        )

    assert billing.status_code == 200, billing.text
    assert support.status_code == 200, support.text
    billing_data = billing.json()
    support_data = support.json()
    assert billing_data["namespace_slug"] == "acme"
    assert support_data["namespace_slug"] == "acme"
    assert billing_data["namespace"] == "acme.aweb.ai"
    assert support_data["namespace"] == "acme.aweb.ai"


@pytest.mark.asyncio
async def test_spawn_invite_lifecycle_in_oss(aweb_cloud_db):
    app = _build_spawn_test_app(aweb_db=aweb_cloud_db.aweb_db, server_db=aweb_cloud_db.oss_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        bootstrap = await client.post(
            "/api/v1/create-project",
            json={
                "project_slug": "oss-spawn-project",
                "alias": "parent-bot",
            },
        )
        assert bootstrap.status_code == 200, bootstrap.text
        bootstrap_data = bootstrap.json()

        created = await client.post(
            "/api/v1/spawn/create-invite",
            headers=_auth_headers(bootstrap_data["api_key"]),
            json={
                "alias_hint": "reviewer",
                "access_mode": "contacts_only",
                "max_uses": 2,
            },
        )
        assert created.status_code == 201, created.text
        created_data = created.json()
        assert created_data["token"].startswith("aw_inv_")
        assert created_data["namespace_slug"] == "oss-spawn-project"
        assert created_data["namespace"] == "oss-spawn-project"
        assert created_data["server_url"] == "http://test"

        listed = await client.get(
            "/api/v1/spawn/invites",
            headers=_auth_headers(bootstrap_data["api_key"]),
        )
        assert listed.status_code == 200, listed.text
        invites = listed.json()["invites"]
        assert len(invites) == 1
        assert invites[0]["token_prefix"] == created_data["token_prefix"]
        assert invites[0]["current_uses"] == 0

        accepted = await client.post(
            "/api/v1/spawn/accept-invite",
            json={"token": created_data["token"]},
        )
        assert accepted.status_code == 200, accepted.text
        accepted_data = accepted.json()
        assert accepted_data["project_id"] == bootstrap_data["project_id"]
        assert accepted_data["project_slug"] == "oss-spawn-project"
        assert accepted_data["namespace_slug"] == "oss-spawn-project"
        assert accepted_data["namespace"] == "oss-spawn-project"
        assert accepted_data["alias"] == "reviewer"
        assert accepted_data["name"] is None
        assert accepted_data["address"] == "oss-spawn-project/reviewer"
        assert accepted_data["access_mode"] == "contacts_only"
        await _assert_api_key_maps_to_identity(
            aweb_db=aweb_cloud_db.aweb_db,
            api_key=accepted_data["api_key"],
            project_id=bootstrap_data["project_id"],
            identity_id=accepted_data["identity_id"],
        )

        second = await client.post(
            "/api/v1/spawn/accept-invite",
            json={"token": created_data["token"], "alias": "reviewer-two"},
        )
        assert second.status_code == 200, second.text
        third = await client.post(
            "/api/v1/spawn/accept-invite",
            json={"token": created_data["token"], "alias": "reviewer-three"},
        )
        assert third.status_code == 409, third.text
        assert third.json()["detail"] == "Invite token use limit reached"


@pytest.mark.asyncio
async def test_spawn_invite_revoke_is_creator_only(aweb_cloud_db):
    app = _build_spawn_test_app(aweb_db=aweb_cloud_db.aweb_db, server_db=aweb_cloud_db.oss_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        bootstrap = await client.post(
            "/api/v1/create-project",
            json={
                "project_slug": "oss-spawn-revoke-project",
                "alias": "parent-bot",
            },
        )
        assert bootstrap.status_code == 200, bootstrap.text
        parent_key = bootstrap.json()["api_key"]

        second_identity = await client.post(
            "/v1/workspaces/init",
            headers=_auth_headers(parent_key),
            json={"alias": "peer-bot"},
        )
        assert second_identity.status_code == 200, second_identity.text
        peer_key = second_identity.json()["api_key"]

        created = await client.post(
            "/api/v1/spawn/create-invite",
            headers=_auth_headers(parent_key),
            json={"alias_hint": "helper"},
        )
        assert created.status_code == 201, created.text
        invite_id = created.json()["invite_id"]
        token = created.json()["token"]

        forbidden = await client.delete(
            f"/api/v1/spawn/invites/{invite_id}",
            headers=_auth_headers(peer_key),
        )
        assert forbidden.status_code == 403, forbidden.text

        revoked = await client.delete(
            f"/api/v1/spawn/invites/{invite_id}",
            headers=_auth_headers(parent_key),
        )
        assert revoked.status_code == 204, revoked.text

        expired = await client.post(
            "/api/v1/spawn/accept-invite",
            json={"token": token, "alias": "helper-two"},
        )
        assert expired.status_code == 410, expired.text
        assert expired.json()["detail"] == "Invite token expired or revoked"


@pytest.mark.asyncio
async def test_spawn_accept_allows_explicit_permanent_self_custodial_identity(aweb_cloud_db, monkeypatch):
    monkeypatch.setenv("AWEB_MANAGED_DOMAIN", "aweb.ai")
    monkeypatch.setenv("AWID_REGISTRY_URL", "https://api.awid.ai")
    monkeypatch.setenv("AWEB_NAMESPACE_CONTROLLER_KEY", "33" * 32)
    app = _build_spawn_test_app(
        aweb_db=aweb_cloud_db.aweb_db,
        server_db=aweb_cloud_db.oss_db,
        registry_client=_FakeRegistryClient(),
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        bootstrap = await client.post(
            "/api/v1/create-project",
            json={
                "project_slug": "oss-spawn-permanent",
                "alias": "parent-bot",
            },
        )
        assert bootstrap.status_code == 200, bootstrap.text

        created = await client.post(
            "/api/v1/spawn/create-invite",
            headers=_auth_headers(bootstrap.json()["api_key"]),
            json={"alias_hint": "durable-child"},
        )
        assert created.status_code == 201, created.text

        seed, public_key = generate_keypair()
        del seed
        did = did_from_public_key(public_key)
        public_key_b64 = encode_public_key(public_key)

        accepted = await client.post(
            "/api/v1/spawn/accept-invite",
            json={
                "token": created.json()["token"],
                "name": "durable-child",
                "lifetime": "persistent",
                "custody": "self",
                "did": did,
                "public_key": public_key_b64,
                "address_reachability": "public",
            },
        )
        assert accepted.status_code == 200, accepted.text
        data = accepted.json()
        assert data["alias"] is None
        assert data["name"] == "durable-child"
        assert data["namespace_slug"] == "oss-spawn-permanent"
        assert data["namespace"] == "oss-spawn-permanent.aweb.ai"
        assert data["address"] == "oss-spawn-permanent.aweb.ai/durable-child"
        assert data["lifetime"] == "persistent"
        assert data["custody"] == "self"
        assert data["did"] == did
        assert data["address_reachability"] == "public"


@pytest.mark.asyncio
async def test_spawn_accept_persistent_identity_requires_namespace_controller_key_for_external_registry(
    aweb_cloud_db, monkeypatch
):
    monkeypatch.setenv("AWEB_MANAGED_DOMAIN", "aweb.ai")
    monkeypatch.setenv("AWID_REGISTRY_URL", "https://api.awid.ai")
    monkeypatch.delenv("AWEB_NAMESPACE_CONTROLLER_KEY", raising=False)
    app = _build_spawn_test_app(aweb_db=aweb_cloud_db.aweb_db, server_db=aweb_cloud_db.oss_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        bootstrap = await client.post(
            "/api/v1/create-project",
            json={
                "project_slug": "oss-spawn-controller-key",
                "alias": "parent-bot",
            },
        )
        assert bootstrap.status_code == 200, bootstrap.text

        created = await client.post(
            "/api/v1/spawn/create-invite",
            headers=_auth_headers(bootstrap.json()["api_key"]),
            json={"alias_hint": "durable-child"},
        )
        assert created.status_code == 201, created.text

        seed, public_key = generate_keypair()
        del seed
        did = did_from_public_key(public_key)
        public_key_b64 = encode_public_key(public_key)

        accepted = await client.post(
            "/api/v1/spawn/accept-invite",
            json={
                "token": created.json()["token"],
                "name": "durable-child",
                "lifetime": "persistent",
                "custody": "self",
                "did": did,
                "public_key": public_key_b64,
            },
        )

    assert accepted.status_code == 422, accepted.text
    assert accepted.json()["detail"] == (
        "AWEB_NAMESPACE_CONTROLLER_KEY not set — cannot register managed namespace with external awid registry"
    )


@pytest.mark.asyncio
async def test_spawn_accept_persistent_identity_requires_managed_domain(aweb_cloud_db, monkeypatch):
    monkeypatch.delenv("AWEB_MANAGED_DOMAIN", raising=False)
    app = _build_spawn_test_app(aweb_db=aweb_cloud_db.aweb_db, server_db=aweb_cloud_db.oss_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        bootstrap = await client.post(
            "/api/v1/create-project",
            json={
                "project_slug": "oss-spawn-unavailable",
                "alias": "parent-bot",
            },
        )
        assert bootstrap.status_code == 200, bootstrap.text

        created = await client.post(
            "/api/v1/spawn/create-invite",
            headers=_auth_headers(bootstrap.json()["api_key"]),
            json={"alias_hint": "durable-child"},
        )
        assert created.status_code == 201, created.text

        seed, public_key = generate_keypair()
        del seed
        did = did_from_public_key(public_key)
        public_key_b64 = encode_public_key(public_key)

        accepted = await client.post(
            "/api/v1/spawn/accept-invite",
            json={
                "token": created.json()["token"],
                "name": "durable-child",
                "lifetime": "persistent",
                "custody": "self",
                "did": did,
                "public_key": public_key_b64,
            },
        )

    assert accepted.status_code == 503, accepted.text
    assert accepted.json()["detail"] == "Permanent identity bootstrap is unavailable on this server"


@pytest.mark.asyncio
async def test_init_rejects_malformed_stored_owner_ref(aweb_cloud_db):
    app = _build_spawn_test_app(aweb_db=aweb_cloud_db.aweb_db, server_db=aweb_cloud_db.oss_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = await client.post(
            "/api/v1/create-project",
            json={
                "project_slug": "owner-ref-bad-init",
                "alias": "alice",
            },
        )
        assert created.status_code == 200, created.text
        created_data = created.json()

        await aweb_cloud_db.aweb_db.execute(
            """
            UPDATE {{tables.projects}}
            SET owner_type = 'organization',
                owner_ref = 'bad owner ref'
            WHERE project_id = $1
            """,
            uuid.UUID(created_data["project_id"]),
        )

        response = await client.post(
            "/v1/workspaces/init",
            headers=_auth_headers(created_data["api_key"]),
            json={"alias": "bob"},
        )

    assert response.status_code == 422, response.text
    assert "Subnamespace label" in response.json()["detail"]


@pytest.mark.asyncio
async def test_spawn_accept_rejects_malformed_stored_owner_ref(aweb_cloud_db):
    app = _build_spawn_test_app(aweb_db=aweb_cloud_db.aweb_db, server_db=aweb_cloud_db.oss_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = await client.post(
            "/api/v1/create-project",
            json={
                "project_slug": "owner-ref-bad-spawn",
                "alias": "alice",
            },
        )
        assert created.status_code == 200, created.text
        created_data = created.json()

        invite = await client.post(
            "/api/v1/spawn/create-invite",
            headers=_auth_headers(created_data["api_key"]),
            json={"alias_hint": "helper"},
        )
        assert invite.status_code == 201, invite.text

        await aweb_cloud_db.aweb_db.execute(
            """
            UPDATE {{tables.projects}}
            SET owner_type = 'organization',
                owner_ref = 'bad owner ref'
            WHERE project_id = $1
            """,
            uuid.UUID(created_data["project_id"]),
        )

        accepted = await client.post(
            "/api/v1/spawn/accept-invite",
            json={"token": invite.json()["token"], "alias": "helper-two"},
        )

    assert accepted.status_code == 422, accepted.text
    assert "Subnamespace label" in accepted.json()["detail"]


@pytest.mark.asyncio
async def test_spawn_create_invite_requires_identity_authority(aweb_cloud_db):
    app = _build_spawn_test_app(aweb_db=aweb_cloud_db.aweb_db, server_db=aweb_cloud_db.oss_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/spawn/create-invite",
            json={"alias_hint": "helper"},
        )

    assert response.status_code == 401, response.text
    assert response.json()["detail"] == "Authentication required"
