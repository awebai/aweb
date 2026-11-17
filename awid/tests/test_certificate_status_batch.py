"""Exact-ID authorization reads must not materialize lifetime team history."""

import json
import os
import time
from uuid import uuid4

import httpx
import pytest
from redis.asyncio import Redis

from awid.ratelimit import RedisFixedWindowRateLimiter
from awid.registry import RegistryClient, RegistryError
from test_team_visibility_enforcement import (
    _create_team, _register_member, _revoke_member, _setup_namespace,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("visibility", ["public", "private"])
async def test_batch_returns_only_requested_public_status_facts(client, controller_identity, visibility):
    key, did = controller_identity
    domain = "batch.example"
    await _setup_namespace(client, key, did, domain)
    team_key, team_did, _ = await _create_team(client, key, did, domain, "ops", visibility=visibility)
    _, _, active = await _register_member(client, team_key, team_did, domain, "ops", "alice")
    _, _, revoked = await _register_member(client, team_key, team_did, domain, "ops", "bob")
    _, _, unasked = await _register_member(client, team_key, team_did, domain, "ops", "carol")
    await _revoke_member(client, team_key, team_did, domain, "ops", revoked)
    missing = str(uuid4())
    base = f"/v1/namespaces/{domain}/teams/ops/certificates"
    response = await client.post(base + "/status", json={"certificate_ids": [revoked, active, missing]})
    assert response.status_code == 200, response.text
    entries = response.json()["certificates"]
    assert [entry["certificate_id"] for entry in entries] == [revoked, active, missing]
    for entry in entries[:2]:
        exact = await client.get(base + f"/{entry['certificate_id']}/status")
        assert entry == {"certificate_id": entry["certificate_id"], **exact.json()}
    assert entries[2] == {"certificate_id": missing, "status": "missing"}
    assert unasked not in response.text
    assert "alice" not in response.text and "bob" not in response.text and "carol" not in response.text


@pytest.mark.asyncio
async def test_batch_missing_private_team_and_wrong_team_are_indistinguishable(client, controller_identity):
    key, did = controller_identity
    domain = "batch-private.example"
    await _setup_namespace(client, key, did, domain)
    team_key, team_did, _ = await _create_team(client, key, did, domain, "ops", visibility="private")
    _, _, cert = await _register_member(client, team_key, team_did, domain, "ops", "alice")
    await _create_team(client, key, did, domain, "other", visibility="private")
    responses = [await client.post(f"/v1/namespaces/{d}/teams/{name}/certificates/status",
                                  json={"certificate_ids": [cert]})
                 for d, name in [(domain, "missing"), (domain, "other"), ("unknown.example", "ops")]]
    assert [r.status_code for r in responses] == [200, 200, 200]
    assert len({r.content for r in responses}) == 1
    assert responses[0].json() == {"certificates": [{"certificate_id": cert, "status": "missing"}]}


@pytest.mark.asyncio
@pytest.mark.parametrize("ids", [[], ["id"] * 129, [""], ["x" * 257]])
async def test_batch_refuses_out_of_bound_requests(client, ids):
    response = await client.post("/v1/namespaces/example.com/teams/ops/certificates/status",
                                 json={"certificate_ids": ids})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_old_registry_fallback_is_complete_or_refused_never_partial():
    requests = []

    def old(request):
        requests.append(request)
        if request.method == "POST":
            return httpx.Response(404)
        page = len(requests) - 1
        return httpx.Response(200, json={"revocations": [{"certificate_id": f"revoked-{page}"}],
                                        "has_more": True, "next_cursor": str(page)})

    registry = RegistryClient("http://registry.test", transport=httpx.MockTransport(old))
    try:
        with pytest.raises(RegistryError, match="pagination exceeded 500 pages") as error:
            await registry.get_team_revocations_for_certificates("example.com", "ops", ["not-revoked"])
        assert error.value.status_code == 502
        assert len(requests) == 501
    finally:
        await registry.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("history", [0, 1000, 100001])
async def test_real_history_cost_depends_only_on_requested_ids(
    client, controller_identity, awid_db_infra, history,
):
    key, did = controller_identity
    domain = "batch-cost.example"
    await _setup_namespace(client, key, did, domain)
    team_key, team_did, _ = await _create_team(client, key, did, domain, "ops", visibility="public")
    _, _, active = await _register_member(client, team_key, team_did, domain, "ops", "alice")
    db = awid_db_infra.get_manager("aweb")
    await db.execute("""
        INSERT INTO {{tables.team_certificates}}
            (team_uuid, certificate_id, member_did_key, alias, revoked_at)
        SELECT t.team_uuid, 'old-' || n, $3, 'old-' || n, now()
        FROM {{tables.teams}} t CROSS JOIN generate_series(1, $4::int) n
        WHERE t.domain = $1 AND t.name = $2
    """, domain, "ops", team_did, history)
    redis = Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
    app = client._transport.app
    app.state.rate_limiter = RedisFixedWindowRateLimiter(redis=redis)
    # A private source-IP bucket, with the real default limiter still enabled.
    ip = "127." + ".".join(str(n) for n in os.urandom(3))
    upstream = httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=(ip, 12345)),
                                base_url="http://testserver")
    requests = []

    class CountedApp(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            response = await upstream.send(request)
            await response.aread()
            requests.append({"method": request.method, "bytes": len(response.content)})
            return response

    registry = RegistryClient("http://testserver", transport=CountedApp())
    try:
        started = time.perf_counter()
        if history > 100000:
            # Default public quota may refuse before the 500-page ceiling;
            # either refusal is safe, neither may return a partial set.
            with pytest.raises(RegistryError) as old_failure:
                await registry.get_team_revocations(domain, "ops")
            assert old_failure.value.status_code in (429, 502)
        else:
            assert len(await registry.get_team_revocations(domain, "ops")) == history
        before = {"requests": len(requests), "bytes": sum(r["bytes"] for r in requests),
                  "seconds": time.perf_counter() - started}
        requests.clear()
        wanted = [active, "old-1", f"old-{history}"]
        started = time.perf_counter()
        result = await registry.get_team_revocations_for_certificates(domain, "ops", wanted)
        assert result == ({"old-1", f"old-{history}"} if history else set())
        assert len(requests) == 1 and requests[0]["method"] == "POST"
        print("R8_COST " + json.dumps({"history": history, "before": before,
              "after": {"requests": len(requests), "bytes": requests[0]["bytes"],
                        "seconds": time.perf_counter() - started}}, sort_keys=True), flush=True)
    finally:
        await registry.aclose()
        await upstream.aclose()
        await redis.aclose()
