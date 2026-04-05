from __future__ import annotations

from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient

from aweb.awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key
from aweb.awid.signing import canonical_json_bytes
from aweb.awid import sign_message

from awid_service.main import create_app


def test_create_app_requires_complete_library_dependencies(awid_db_infra, fake_redis):
    with pytest.raises(ValueError):
        create_app(db_infra=awid_db_infra)

    with pytest.raises(ValueError):
        create_app(redis=fake_redis)


def test_get_manager_accepts_any_name(awid_db_infra):
    assert awid_db_infra.get_manager("aweb") is awid_db_infra.get_manager("server")
    assert awid_db_infra.get_manager("anything") is awid_db_infra.get_manager("aweb")


@pytest.mark.asyncio
async def test_health_and_ops_health_expose_registry_state(client):
    health = await client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert health.json()["checks"]["schema"] == "awid"

    ops = await client.get("/ops/health")
    assert ops.status_code == 200
    assert ops.json() == health.json()


@pytest.mark.asyncio
async def test_health_hides_backend_exception_details(awid_db_infra, fake_redis):
    class BrokenRedis:
        async def ping(self) -> bool:
            raise RuntimeError("redis failure at redis://secret-host:6379/0")

    class BrokenDbManager:
        async def fetch_value(self, _query: str):
            raise RuntimeError("postgres failure at postgresql://secret-host/db")

    class BrokenDbInfra:
        is_initialized = True
        schema = "awid"

        def get_manager(self, _name: str = "aweb"):
            return BrokenDbManager()

    app = create_app(db_infra=BrokenDbInfra(), redis=BrokenRedis())
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as test_client:
            response = await test_client.get("/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "unhealthy"
    assert payload["checks"]["redis"] == "error"
    assert payload["checks"]["database"] == "error"
    assert "secret-host" not in response.text


@pytest.mark.asyncio
async def test_openapi_only_mounts_registry_routes(client):
    resp = await client.get("/openapi.json")
    assert resp.status_code == 200
    paths = resp.json()["paths"]
    assert "/v1/did/{did_aw}/key" in paths
    assert "/v1/namespaces/{domain}" in paths
    assert "/v1/namespaces/{domain}/addresses/{name}" in paths
    assert "/v1/status" not in paths


@pytest.mark.asyncio
async def test_did_routes_use_redis_rate_limiter(client, fake_redis):
    _, public_key = generate_keypair()
    missing_did_aw = stable_id_from_did_key(did_from_public_key(public_key))
    resp = await client.get(f"/v1/did/{missing_did_aw}/key")
    assert resp.status_code == 404
    assert fake_redis.eval_calls


@pytest.mark.asyncio
async def test_namespace_and_address_read_routes_use_redis_rate_limiter(client, fake_redis):
    fake_redis.eval_calls.clear()

    namespace_resp = await client.get("/v1/namespaces")
    address_list_resp = await client.get("/v1/namespaces/example.com/addresses")
    address_get_resp = await client.get("/v1/namespaces/example.com/addresses/alice")

    assert namespace_resp.status_code == 200
    assert address_list_resp.status_code == 404
    assert address_get_resp.status_code == 404
    assert len(fake_redis.eval_calls) >= 3


@pytest.mark.asyncio
async def test_namespace_mutation_routes_use_overridden_domain_verifier(client, controller_identity):
    signing_key, controller_did = controller_identity
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    payload = canonical_json_bytes(
        {
            "domain": "example.com",
            "operation": "register",
            "timestamp": timestamp,
        }
    )
    signature = sign_message(signing_key, payload)

    response = await client.post(
        "/v1/namespaces",
        json={"domain": "example.com"},
        headers={
            "Authorization": f"DIDKey {controller_did} {signature}",
            "X-AWEB-Timestamp": timestamp,
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["domain"] == "example.com"
