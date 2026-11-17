"""Real signed server requests select exact status IDs, even with long history."""

import base64
import json

import httpx
import pytest

from awid.registry import CachedRegistryClient
from test_dashboard_privacy import TEAM, TEAM_NAME, privacy_app  # noqa: F401
from test_messages_http import _signed_team_headers


@pytest.mark.asyncio
@pytest.mark.parametrize("history,strict", [(0, False), (100001, False), (100001, True)])
async def test_signed_server_auth_is_history_independent_and_warm_is_zero_http(privacy_app, monkeypatch, history, strict):  # noqa: F811
    env = privacy_app
    monkeypatch.setenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", str(strict).lower())
    actor = env.actors["alice"]
    await env.registry_db.execute("""
        INSERT INTO {{tables.team_certificates}} (team_uuid, certificate_id, member_did_key, alias)
        SELECT team_uuid, 'privacy-alice', $2, 'alice' FROM {{tables.teams}} WHERE name = $1
    """, TEAM_NAME, actor.did)
    await env.registry_db.execute("""
        INSERT INTO {{tables.team_certificates}} (team_uuid, certificate_id, member_did_key, alias, revoked_at)
        SELECT t.team_uuid, 'old-' || n, $2, 'old-' || n, now()
        FROM {{tables.teams}} t CROSS JOIN generate_series(1, $3::int) n WHERE t.name = $1
    """, TEAM_NAME, actor.did, history)
    requests, redis_gets = [], []

    class CountedTransport(httpx.ASGITransport):
        async def handle_async_request(self, request):
            requests.append((request.method, request.url.path, request.content))
            return await super().handle_async_request(request)

    class CountedRedis:
        def __getattr__(self, name):
            return getattr(env.redis, name)

        async def get(self, key):
            value = await env.redis.get(key)
            redis_gets.append({"status": ":certificate_status:" in key,
                               "bytes": len(value) if value is not None else 0})
            return value

    original = env.app.state.awid_registry_client
    cached = CachedRegistryClient("http://registry.test", CountedRedis(),
                                  transport=CountedTransport(app=env.registry_app),
                                  service_token=original.service_token)
    env.app.state.awid_registry_client = cached
    try:
        await cached.invalidate_team_certificate_cache("example.test", TEAM_NAME)
        response = await env.client.get("/v1/agents", headers=_signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate))
        assert response.status_code == 200, response.text
        batches = [json.loads(body) for method, path, body in requests if method == "POST" and path.endswith("/certificates/status")]
        assert batches == [{"certificate_ids": ["privacy-alice"]}]
        assert not any(path.endswith("/revocations") or path.endswith("/certificates") for _, path, _ in requests)
        requests.clear()
        redis_gets.clear()
        response = await env.client.get("/v1/agents", headers=_signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate))
        assert response.status_code == 200, response.text
        assert requests == []
        assert sum(row["bytes"] for row in redis_gets if row["status"]) < 512
        print("R8_SERVER_COST " + json.dumps({"history": history, "registration_required": strict,
              "warm_http": len(requests), "redis_gets_including_generation": len(redis_gets),
              "status_bytes": sum(row["bytes"] for row in redis_gets if row["status"])}, sort_keys=True), flush=True)

        # A member may sign the request but cannot invent a new certificate ID
        # and make it spend a status refresh before certificate verification.
        forged = json.loads(base64.b64decode(actor.certificate))
        forged["certificate_id"] = "forged-certificate-id"
        encoded = base64.b64encode(json.dumps(forged).encode()).decode()
        response = await env.client.post("/v1/messages", content=b"{}",
            headers=_signed_team_headers(actor.sk, actor.did, TEAM, encoded, b"{}"))
        assert response.status_code == 401, response.text
        assert not any(path.endswith("/certificates/status") for _, path, _ in requests)
        assert await env.db.fetch_value("SELECT count(*) FROM {{tables.messages}}") == 0
        assert env.dispatched == []
    finally:
        env.app.state.awid_registry_client = original
        await cached.aclose()
