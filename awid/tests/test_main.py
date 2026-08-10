from __future__ import annotations

from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient

import awid.ratelimit as ratelimit_module
from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key
from awid.signing import canonical_json_bytes
from awid.signing import sign_message
from awid.ratelimit import normalize_service_token

from awid_service.deps import get_domain_verifier
from awid_service.main import create_app


def test_service_token_requires_at_least_32_bytes():
    assert normalize_service_token(None) is None
    assert normalize_service_token(" " * 40) is None
    with pytest.raises(ValueError, match="at least 32 bytes"):
        normalize_service_token("too-short")


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
async def test_trusted_service_token_bypasses_only_identity_auth_read_limits(
    awid_db_infra, fake_redis, fake_domain_verifier, monkeypatch
):
    token = "trusted-service-token-with-at-least-32-bytes"
    monkeypatch.setenv("AWID_SERVICE_TOKEN", token)
    compared: list[tuple[bytes, bytes]] = []

    def constant_time_compare(expected: bytes, presented: bytes) -> bool:
        compared.append((expected, presented))
        return expected == presented

    monkeypatch.setattr(ratelimit_module.secrets, "compare_digest", constant_time_compare)
    app = create_app(db_infra=awid_db_infra, redis=fake_redis)
    app.dependency_overrides[get_domain_verifier] = lambda: fake_domain_verifier

    _, public_key = generate_keypair()
    missing_did_aw = stable_id_from_did_key(did_from_public_key(public_key))
    headers = {"X-AWID-Service-Token": token}

    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as test_client:
            key_response = await test_client.get(f"/v1/did/{missing_did_aw}/key", headers=headers)
            addresses_response = await test_client.get(
                f"/v1/did/{missing_did_aw}/addresses", headers=headers
            )
            namespace_response = await test_client.get("/v1/namespaces", headers=headers)
            write_response = await test_client.post("/v1/did", json={}, headers=headers)

    assert key_response.status_code == 404
    assert addresses_response.status_code == 200
    assert namespace_response.status_code == 200
    assert write_response.status_code == 422
    assert len(fake_redis.eval_calls) == 2
    rate_keys = [call[0][2] for call in fake_redis.eval_calls]
    assert any(":namespace_list:" in key for key in rate_keys)
    assert any(":did_register:" in key for key in rate_keys)
    assert compared == [(token.encode(), token.encode()), (token.encode(), token.encode())]


@pytest.mark.asyncio
async def test_wrong_trusted_service_token_falls_back_and_emits_metric_signal(
    awid_db_infra, fake_redis, fake_domain_verifier, monkeypatch, capsys
):
    monkeypatch.setenv("AWID_SERVICE_TOKEN", "trusted-service-token-with-at-least-32-bytes")
    app = create_app(db_infra=awid_db_infra, redis=fake_redis)
    app.dependency_overrides[get_domain_verifier] = lambda: fake_domain_verifier

    _, public_key = generate_keypair()
    missing_did_aw = stable_id_from_did_key(did_from_public_key(public_key))

    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as test_client:
            response = await test_client.get(
                f"/v1/did/{missing_did_aw}/key",
                headers={"X-AWID-Service-Token": "wrong-service-token-with-at-least-32-bytes"},
            )

    assert response.status_code == 404
    assert len(fake_redis.eval_calls) == 1
    assert "event=awid_service_credential_rejected" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_awid_rate_limit_disabled_uses_noop_limiter(
    awid_db_infra, fake_redis, fake_domain_verifier, monkeypatch
):
    monkeypatch.setenv("AWID_RATE_LIMIT_DISABLED", "1")
    app = create_app(db_infra=awid_db_infra, redis=fake_redis)
    app.dependency_overrides[get_domain_verifier] = lambda: fake_domain_verifier

    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as test_client:
            health = await test_client.get("/health")
            namespace = await test_client.get("/v1/namespaces")
            address = await test_client.get("/v1/namespaces/example.com/addresses/alice")

    assert health.status_code == 200
    assert health.json()["checks"]["rate_limiter"] == "NoOpRateLimiter"
    assert namespace.status_code == 200
    assert address.status_code == 404
    assert fake_redis.eval_calls == []


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
