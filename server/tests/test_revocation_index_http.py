"""Signed HTTP authentication uses the derived index of the complete real CRL."""

import json

import httpx
import pytest

from awid.registry import CachedRegistryClient, RegistryError
from awid.team_certificate import decode_team_certificate
from test_dashboard_privacy import TEAM, TEAM_NAME, registered_privacy_app  # noqa: F401
from test_messages_http import _signed_team_headers

__all__ = ["registered_privacy_app"]


@pytest.mark.asyncio
@pytest.mark.parametrize("history,strict", [(0, False), (1000, True), (100000, False)])
async def test_warm_signed_auth_reads_no_full_crl_and_no_registry(registered_privacy_app, monkeypatch, history, strict):  # noqa: F811
    env = registered_privacy_app
    monkeypatch.setenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", str(strict).lower())
    actor = env.actors["alice"]
    certificate_id = decode_team_certificate(actor.certificate)["certificate_id"]
    # Bulk-load historical revocations to exercise pagination at its ceiling.
    # The live certificate and its revocation use the registry and connect APIs.
    await env.registry_db.execute("""
        INSERT INTO {{tables.team_certificates}} (team_uuid, certificate_id, member_did_key, alias, revoked_at)
        SELECT t.team_uuid, 'old-' || n, $2, 'old-' || n, now()
        FROM {{tables.teams}} t CROSS JOIN generate_series(1, $3::int) n WHERE t.name = $1
    """, TEAM_NAME, actor.did, history)
    requests, redis_reads = [], []

    class CountedTransport(httpx.ASGITransport):
        async def handle_async_request(self, request):
            requests.append((request.method, request.url.path))
            return await super().handle_async_request(request)

    class CountedRedis:
        def __getattr__(self, name):
            return getattr(env.redis, name)

        async def get(self, key):
            value = await env.redis.get(key)
            redis_reads.append({"command": "GET", "full_crl": key == crl_key,
                                "generation": key.startswith("awid:cache_generation:"),
                                "bytes": len(value) if value is not None else 0})
            return value

        async def eval(self, script, count, *args):
            value = await env.redis.eval(script, count, *args)
            redis_reads.append({"command": "EVAL", "full_crl": False, "generation": False,
                                "bytes": sum(len(item) for item in value if isinstance(item, (str, bytes)))
                                if isinstance(value, list) else 0})
            return value

    original = env.app.state.awid_registry_client
    cached = CachedRegistryClient("http://registry.test", CountedRedis(),
                                  transport=CountedTransport(app=env.registry_app),
                                  service_token=original.service_token)
    crl_key = cached._team_revocations_cache_key("example.test", TEAM_NAME)
    env.app.state.awid_registry_client = cached
    try:
        await cached.invalidate_team_certificate_cache("example.test", TEAM_NAME)
        # Populate using the real COMPLETE paginated registry read, outside
        # the HTTP client's deadline. No direct cache fixture substitutes it.
        assert len(await cached.get_team_revocations("example.test", TEAM_NAME)) == history
        response = await env.client.get("/v1/agents", headers=_signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate))
        assert response.status_code == 200, response.text
        assert all(method == "GET" for method, _ in requests)
        requests.clear()
        redis_reads.clear()
        response = await env.client.get("/v1/agents", headers=_signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate))
        assert response.status_code == 200, response.text
        assert requests == []
        assert not any(row["full_crl"] for row in redis_reads)
        assert any(row["command"] == "EVAL" for row in redis_reads)
        print("R8_CRL_HTTP_COST " + json.dumps({"history": history, "registration_required": strict,
              "warm_http": len(requests), "redis_commands": len(redis_reads),
              "generation_gets": sum(row["generation"] for row in redis_reads),
              "returned_payload_bytes": sum(row["bytes"] for row in redis_reads)}, sort_keys=True), flush=True)

        await cached.revoke_team_certificate(
            "example.test", TEAM_NAME,
            team_controller_signing_key=env.team_sk, certificate_id=certificate_id,
        )
        assert requests == [
            ("POST", f"/v1/namespaces/example.test/teams/{TEAM_NAME}/certificates/revoke")
        ]
        crl_keys = (crl_key, crl_key + ":membership", crl_key + ":membership-meta")
        assert await env.redis.exists(*crl_keys) == 0
        if history == 100000:
            # One more revocation crosses the documented ceiling. A partial
            # list/index must never be installed, even with a service token.
            with pytest.raises(RegistryError, match="pagination exceeded 500 pages") as error:
                await cached.get_team_revocations("example.test", TEAM_NAME)
            assert error.value.status_code == 502
            assert await env.redis.exists(*crl_keys) == 0
        else:
            response = await env.client.get("/v1/agents", headers=_signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate))
            assert response.status_code == 401, response.text
            assert response.json()["detail"]["code"] == "certificate_revoked"
            assert certificate_id in await cached.get_team_revocations("example.test", TEAM_NAME)
    finally:
        env.app.state.awid_registry_client = original
        await cached.aclose()
