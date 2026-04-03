from __future__ import annotations

import pytest

from aweb.awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key

from awid_service.main import create_app


def test_create_app_requires_complete_library_dependencies(awid_db_infra, fake_redis):
    with pytest.raises(ValueError):
        create_app(db_infra=awid_db_infra)

    with pytest.raises(ValueError):
        create_app(redis=fake_redis)


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
