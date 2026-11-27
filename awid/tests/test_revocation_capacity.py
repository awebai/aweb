"""The complete-list cache serves serial local members at the real public quota."""

import json
import os

import httpx
import pytest
from redis.asyncio import Redis

from awid.ratelimit import RedisFixedWindowRateLimiter
from awid.registry import CachedRegistryClient
from test_team_visibility_enforcement import _create_team, _setup_namespace


@pytest.mark.asyncio
@pytest.mark.parametrize("active", [1, 128, 512])
async def test_default_public_quota_does_not_regress_serial_members(
    client,
    controller_identity,
    awid_db_infra,
    active,
):
    key, did = controller_identity
    domain = "serial-status.example"
    await _setup_namespace(client, key, did, domain)
    _, team_did, _ = await _create_team(
        client, key, did, domain, "ops", visibility="public"
    )
    await awid_db_infra.get_manager("aweb").execute(
        """
        INSERT INTO {{tables.team_certificates}} (team_uuid, certificate_id, member_did_key, alias)
        SELECT team_uuid, 'member-' || n, $2, 'member-' || n
        FROM {{tables.teams}} CROSS JOIN generate_series(1, $3::int) n WHERE domain = $1
    """,
        domain,
        team_did,
        active,
    )
    redis = Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
    app = client._transport.app
    app.state.rate_limiter = RedisFixedWindowRateLimiter(redis=redis)
    ip = "127." + ".".join(str(n) for n in os.urandom(3))
    requests = []

    class Counted(httpx.ASGITransport):
        async def handle_async_request(self, request):
            requests.append((request.method, request.url.path))
            return await super().handle_async_request(request)

    registry = CachedRegistryClient(
        "http://testserver", redis, transport=Counted(app=app, client=(ip, 12345))
    )
    try:
        await registry.invalidate_team_certificate_cache(domain, "ops")
        ids = [f"member-{n}" for n in range(1, active + 1)]
        for cid in ids:
            assert cid not in await registry.get_team_revocations(domain, "ops")
        before = len(requests)
        requests.clear()
        await registry.invalidate_team_certificate_cache(domain, "ops")
        completed = 0
        try:
            for cid in ids:
                assert (
                    await registry.get_team_revocations_for_certificates(
                        domain, "ops", [cid]
                    )
                    == set()
                )
                completed += 1
        finally:
            print(
                "R8_SERIAL_COST "
                + json.dumps(
                    {
                        "active": active,
                        "before_requests": before,
                        "after_requests": len(requests),
                        "completed": completed,
                        "default_public_limit": 60,
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
        assert completed == active
        assert before == len(requests) == 1
        assert all(
            method == "GET" and path.endswith("/revocations")
            for method, path in requests
        )
        requests.clear()
        for cid in ids:
            assert (
                await registry.get_team_revocations_for_certificates(
                    domain, "ops", [cid]
                )
                == set()
            )
        assert requests == []
    finally:
        await registry.aclose()
        await redis.aclose()
