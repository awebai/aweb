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
async def test_trusted_service_token_uses_constant_time_comparison_for_reads(
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
    assert len(fake_redis.eval_calls) == 1
    rate_keys = [call[0][2] for call in fake_redis.eval_calls]
    assert any(":did_register:" in key for key in rate_keys)
    assert compared == [(token.encode(), token.encode())] * 3


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


@pytest.mark.asyncio
async def test_trusted_service_token_bypasses_revocation_list_limit(
    awid_db_infra, fake_redis, fake_domain_verifier, monkeypatch
):
    """aweb-abfp: aweb backends poll revocations per team per 60s as the input
    to membership enforcement, and a 429 here becomes a fail-closed 503 on the
    requests they serve. A trusted service token bypasses the per-IP bucket;
    anonymous callers keep it."""
    token = "trusted-service-token-with-at-least-32-bytes"
    monkeypatch.setenv("AWID_SERVICE_TOKEN", token)
    app = create_app(db_infra=awid_db_infra, redis=fake_redis)
    app.dependency_overrides[get_domain_verifier] = lambda: fake_domain_verifier
    headers = {"X-AWID-Service-Token": token}

    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as test_client:
            fake_redis.eval_calls.clear()
            with_token = await test_client.get(
                "/v1/namespaces/acme.com/teams/ops/revocations", headers=headers
            )
            assert with_token.status_code == 404  # team absent; the route ran
            assert fake_redis.eval_calls == []

            anonymous = await test_client.get("/v1/namespaces/acme.com/teams/ops/revocations")
            assert anonymous.status_code == 404
            rate_keys = [call[0][2] for call in fake_redis.eval_calls]
            assert any(":revocation_list:" in key for key in rate_keys)


# All rate-limited registry reads, including those which still require a path
# signature after a service credential has exempted the per-IP rate limit.
_READ_LIMIT_ROUTES = [
    ("did_key", "/v1/did/{did}/key", 404),
    ("did_addresses", "/v1/did/{did}/addresses", 200),
    ("did_head", "/v1/did/{did}/head", 404),
    ("did_full", "/v1/did/{did}/full", 401),
    ("did_log", "/v1/did/{did}/log", 200),
    ("namespace_get", "/v1/namespaces/example.com", 404),
    ("namespace_list", "/v1/namespaces", 200),
    ("address_get", "/v1/namespaces/example.com/addresses/alice", 404),
    ("address_list", "/v1/namespaces/example.com/addresses", 404),
    ("a2a_publication_get", "/v1/namespaces/example.com/addresses/alice/a2a", 404),
    ("team_list", "/v1/namespaces/example.com/teams", 200),
    ("team_get", "/v1/namespaces/example.com/teams/ops", 404),
    ("certificate_list", "/v1/namespaces/example.com/teams/ops/certificates", 404),
    ("team_member_get", "/v1/namespaces/example.com/teams/ops/members/alice", 404),
    ("certificate_fetch", "/v1/namespaces/example.com/teams/ops/certificates/missing", 401),
    ("certificate_status", "/v1/namespaces/example.com/teams/ops/certificates/missing/status", 404),
    ("revocation_list", "/v1/namespaces/example.com/teams/ops/revocations", 404),
]

_WRITE_LIMIT_ROUTES = [
    ("did_register", "POST", "/v1/did"),
    ("did_update", "PUT", "/v1/did/{did}"),
    ("did_encryption_key_publish", "POST", "/v1/did/{did}/encryption-key"),
    ("namespace_register", "POST", "/v1/namespaces"),
    ("namespace_reverify", "POST", "/v1/namespaces/example.com/reverify"),
    ("namespace_update", "PATCH", "/v1/namespaces/example.com"),
    ("namespace_rotate", "PUT", "/v1/namespaces/example.com"),
    ("namespace_delete", "DELETE", "/v1/namespaces/example.com"),
    ("address_register", "POST", "/v1/namespaces/example.com/addresses"),
    ("address_atomic_claim", "POST", "/v1/namespaces/example.com/addresses/claims"),
    ("address_update", "PUT", "/v1/namespaces/example.com/addresses/alice"),
    ("address_delete", "DELETE", "/v1/namespaces/example.com/addresses/alice"),
    ("address_reassign", "POST", "/v1/namespaces/example.com/addresses/alice/reassign"),
    ("a2a_delegation_publish", "POST", "/v1/a2a/delegations"),
    ("a2a_publication_publish", "POST", "/v1/a2a/publications"),
    ("team_create", "POST", "/v1/namespaces/example.com/teams"),
    ("team_delete", "DELETE", "/v1/namespaces/example.com/teams/ops"),
    ("team_rotate", "POST", "/v1/namespaces/example.com/teams/ops/rotate"),
    ("team_update", "POST", "/v1/namespaces/example.com/teams/ops/visibility"),
    ("certificate_register", "POST", "/v1/namespaces/example.com/teams/ops/certificates"),
    ("certificate_revoke", "POST", "/v1/namespaces/example.com/teams/ops/certificates/revoke"),
]


def _missing_did_path(path):
    _, public_key = generate_keypair()
    return path.format(did=stable_id_from_did_key(did_from_public_key(public_key)))


def _assert_limited(response):
    assert response.status_code == 429, response.text
    assert response.json()["detail"] == "rate limit exceeded"
    assert response.headers["X-RateLimit-Remaining"] == "0"
    assert "Retry-After" in response.headers


@pytest.mark.asyncio
@pytest.mark.parametrize("bucket,path,status", _READ_LIMIT_ROUTES, ids=[r[0] for r in _READ_LIMIT_ROUTES])
async def test_every_read_bucket_trusted_exemption(
    client, fake_redis, monkeypatch, caplog, bucket, path, status
):
    token = "trusted-service-token-with-at-least-32-bytes"
    wrong = "wrong-service-token-with-at-least-32-bytes"
    app = client._transport.app
    monkeypatch.setattr(app.state, "awid_service_token", token)
    # Short budget, long fixed window: test exhaustion without hundreds of
    # requests or minute-boundary flakes. The actual Redis limiter still runs.
    monkeypatch.setitem(ratelimit_module._BUCKET_DEFAULTS, bucket, (2, 2**31))
    path = _missing_did_path(path)
    for remaining in (1, 0):
        response = await client.get(path)
        assert response.status_code == status, response.text
        # HTTPExceptions replace response headers, so the limiter's Redis
        # calls below establish that those endpoints consumed the budget too.
        if status == 200:
            assert response.headers["X-RateLimit-Remaining"] == str(remaining)
    _assert_limited(await client.get(path))
    assert len(fake_redis.eval_calls) == 3
    assert all(f":{bucket}:" in call[0][2] for call in fake_redis.eval_calls)

    response = await client.get(path, headers={"X-AWID-Service-Token": token})
    assert response.status_code == status, response.text
    assert "X-RateLimit-Limit" not in response.headers
    assert len(fake_redis.eval_calls) == 3  # exemption never hits the limiter
    assert f"value=1 bucket={bucket}" in caplog.text
    caplog.clear()

    _assert_limited(await client.get(path))
    assert "awid_service_credential_rejected" not in caplog.text
    _assert_limited(await client.get(path, headers={"X-AWID-Service-Token": wrong}))
    rejected = caplog.text
    assert f"event=awid_service_credential_rejected metric=awid_service_credential_rejected value=1 bucket={bucket}" in rejected
    assert token not in rejected and wrong not in rejected
    caplog.clear()

    # Even an otherwise valid token cannot exempt an unconfigured deployment.
    monkeypatch.setattr(app.state, "awid_service_token", None)
    _assert_limited(await client.get(path, headers={"X-AWID-Service-Token": token}))
    rejected = caplog.text
    assert "event=awid_service_credential_rejected" in rejected
    assert "event=awid_service_exempt" not in rejected
    assert token not in rejected
    assert len(fake_redis.eval_calls) == 6


@pytest.mark.asyncio
@pytest.mark.parametrize("bucket,method,path", _WRITE_LIMIT_ROUTES, ids=[r[0] for r in _WRITE_LIMIT_ROUTES])
async def test_service_token_never_exempts_write_buckets(
    client, fake_redis, monkeypatch, caplog, bucket, method, path
):
    token = "trusted-service-token-with-at-least-32-bytes"
    monkeypatch.setattr(client._transport.app.state, "awid_service_token", token)
    monkeypatch.setitem(ratelimit_module._BUCKET_DEFAULTS, bucket, (2, 2**31))
    path = _missing_did_path(path)
    for attempt in range(3):
        response = await client.request(method, path, json={}, headers={"X-AWID-Service-Token": token})
        if attempt < 2:
            assert response.status_code in (401, 404, 422), response.text
        else:
            _assert_limited(response)
    assert len(fake_redis.eval_calls) == 3
    assert all(f":{bucket}:" in call[0][2] for call in fake_redis.eval_calls)
    assert "event=awid_service_exempt" not in caplog.text


@pytest.mark.asyncio
async def test_service_exemption_telemetry_is_aggregated_per_bucket(client, fake_redis, monkeypatch, caplog):
    token = "trusted-service-token-with-at-least-32-bytes"
    monkeypatch.setattr(client._transport.app.state, "awid_service_token", token)
    path = _missing_did_path("/v1/did/{did}")
    caplog.clear()
    for bucket, suffix, count, status in (("did_key", "key", 9, 404), ("did_addresses", "addresses", 3, 200)):
        for n in range(1, count + 1):
            response = await client.get(f"{path}/{suffix}", headers={"X-AWID-Service-Token": token})
            assert response.status_code == status
            events = [
                record.getMessage()
                for record in caplog.records
                if record.name == "awid.ratelimit"
            ]
            caplog.clear()
            expected = (
                [f"event=awid_service_exempt metric=awid_service_exempt value={n} bucket={bucket}"]
                if n in (1, 2, 4, 8) else []
            )
            assert events == expected
            assert all(token not in event and "testserver" not in event and path not in event for event in events)
    assert fake_redis.eval_calls == []
