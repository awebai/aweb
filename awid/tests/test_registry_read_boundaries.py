"""Real PostgreSQL/Redis registry read concurrency, cost and refusal controls."""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from awid.protected_receipts import PATH
from awid.protected_effect import HEADER, artifact_digest, encode_proofs, http_consumer, issue_proof
from awid.signing import canonical_json_bytes, sign_message
from awid.team_server_record import record_signing_bytes
from awid_service.protected_teams import _lock_key, provision_team_protection
from test_controller_request_v2_http import ORIGIN, controller_app as controller_app, keypair, send

TEAM_PATH = "/v1/namespaces/local/teams/base"


async def team_lock_rows(tx):
    value = _lock_key("team", "base:local") & ((1 << 64) - 1)
    return await tx.fetch_all(
        "SELECT mode,granted FROM pg_locks WHERE locktype='advisory' "
        "AND classid=$1::oid AND objid=$2::oid",
        value >> 32, value & ((1 << 32) - 1),
    )


async def wait_locks(tx, count):
    async with asyncio.timeout(10):
        while True:
            rows = await team_lock_rows(tx)
            if len(rows) >= count:
                return rows
            await asyncio.sleep(0.01)


@pytest.mark.asyncio
async def test_actual_get_readers_share_team_guard_and_exclude_writer(controller_app):
    env = controller_app
    tasks = []
    try:
        # Hold the binding table: readers acquire their guards and read the
        # team, then wait on their real protection SELECT. The HTTP writer's
        # controller preflight can still run before it waits on that guard.
        async with env.db.transaction() as blocker:
            await blocker.execute("LOCK TABLE {{tables.team_protection}} IN ACCESS EXCLUSIVE MODE")
            tasks.extend(asyncio.create_task(env.client.get(TEAM_PATH)) for _ in range(2))
            rows = await wait_locks(blocker, 2)
            assert all(r["granted"] and r["mode"] == "ShareLock" for r in rows), rows
            tasks.append(asyncio.create_task(send(
                env, "POST", TEAM_PATH + "/visibility",
                {"domain": "local", "operation": "set_team_visibility", "team_name": "base", "visibility": "private"},
                {"visibility": "private"}, signer=env.team,
            )))
            rows = await wait_locks(blocker, 3)
            assert sum(r["granted"] and r["mode"] == "ShareLock" for r in rows) == 2
            assert sum(not r["granted"] and r["mode"] == "ExclusiveLock" for r in rows) == 1
            assert not any(task.done() for task in tasks)
        responses = await asyncio.wait_for(asyncio.gather(*tasks), 10)
        assert [r.status_code for r in responses] == [200, 200, 200]
        assert all(r.json()["visibility"] == "public" for r in responses[:2])
        assert await env.db.fetch_value("SELECT visibility FROM {{tables.teams}} WHERE name='base'") == "private"
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


@asynccontextmanager
async def actual_queries(db):
    """Observe executed asyncpg queries; leave all real database calls intact."""
    pool = db._pool
    queries = []

    def record(query):
        if query.query.lstrip().startswith("SELECT ") and "pg_advisory_unlock_all" not in query.query:
            queries.append(query.query)

    connections = [await pool.acquire() for _ in range(pool.get_max_size())]
    for connection in connections:
        connection.add_query_logger(record)
    for connection in connections:
        await pool.release(connection)
    try:
        yield queries
        await asyncio.sleep(0)  # asyncpg schedules the actual query observations.
    finally:
        connections = [await pool.acquire() for _ in range(pool.get_max_size())]
        for connection in connections:
            connection.remove_query_logger(record)
        for connection in connections:
            await pool.release(connection)


async def add_teams(env, count):
    await env.db.execute(
        "INSERT INTO {{tables.teams}} (domain,name,display_name,team_did_key,visibility,created_by) "
        "SELECT 'local','page-'||lpad(i::text,3,'0'),'Page '||i,$1,'public',$2 "
        "FROM generate_series(1,$3::int) i",
        env.team[1], env.controller[1], count,
    )
    await env.db.execute(
        "INSERT INTO {{tables.team_protection}} (domain,name,service_id,service_did_key,generation) "
        "SELECT domain,name,'test-signer',$1,1 FROM {{tables.teams}} "
        "WHERE name LIKE 'page-%' AND right(name,1) IN ('0','2','4','6','8')",
        keypair()[1],
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1, 200])
async def test_paginated_team_projection_is_one_actual_select_per_page(controller_app, count):
    env = controller_app
    await add_teams(env, count - 1)
    found = []
    cursor = None
    while True:
        async with actual_queries(env.db) as queries:
            response = await env.client.get("/v1/namespaces/local/teams", params={"limit": 100, **({"cursor": cursor} if cursor else {})})
        assert response.status_code == 200, response.text
        assert len(queries) == 1, queries
        data = response.json()
        found.extend(data["teams"])
        if not data["has_more"]:
            assert data["next_cursor"] is None
            break
        cursor = data["next_cursor"]
        assert cursor
    assert len(found) == count and len({t["team_id"] for t in found}) == count
    for team in found:
        protected = team["name"].startswith("page-") and int(team["name"][-1]) % 2 == 0
        assert team["protection"]["mode"] == ("protected" if protected else "legacy")


@pytest.mark.asyncio
async def test_bad_binding_refuses_entire_list_without_inventing_legacy(controller_app):
    env = controller_app
    await env.db.execute(
        "INSERT INTO {{tables.team_protection}} (domain,name,service_id,service_did_key,generation) "
        "VALUES ('local','base','not a valid service id',$1,1)", keypair()[1],
    )
    response = await env.client.get("/v1/namespaces/local/teams")
    assert response.status_code == 503, response.text
    assert response.json()["detail"]["code"] == "protected_state_unavailable"
    assert "teams" not in response.json()


@pytest.mark.asyncio
async def test_unavailable_projection_store_refuses_the_whole_page(controller_app):
    env = controller_app
    await env.db.execute("ALTER TABLE {{tables.team_protection}} RENAME TO unavailable_protection")
    try:
        env.client._transport.raise_app_exceptions = False
        response = await env.client.get("/v1/namespaces/local/teams")
        assert response.status_code == 503, response.text
        assert response.json()["detail"]["code"] == "protected_state_unavailable"
    finally:
        await env.db.execute('ALTER TABLE "awid".unavailable_protection RENAME TO team_protection')


@pytest.mark.asyncio
@pytest.mark.parametrize("domain", ["%2E", "%2E%2E"])
async def test_empty_canonical_domain_is_a_client_error(controller_app, domain):
    env = controller_app
    # Percent encoding preserves the actual dot segment through HTTPX's URL
    # parser; ASGI decodes it to the same domain supplied by an HTTP caller.
    env.client._transport.raise_app_exceptions = False
    response = await env.client.get(f"/v1/namespaces/{domain}/teams/base")
    assert response.status_code == 400, response.text
    assert response.json()["detail"] == "Invalid namespace domain"
    assert (await env.client.get(TEAM_PATH)).status_code == 200


@pytest.mark.asyncio
async def test_historical_receipt_route_uses_real_rate_limiter(controller_app):
    env = controller_app
    assert type(env.app.state.rate_limiter).__name__ == "RedisFixedWindowRateLimiter"
    path = PATH + "/11111111-1111-4111-8111-111111111111"
    allowed, window = 0, None
    for _ in range(122):
        response = await env.client.get(path)
        assert response.headers.get("X-RateLimit-Limit") == "60"
        reset = response.headers["X-RateLimit-Reset"]
        if reset != window:
            window, allowed = reset, 0
        if response.status_code == 429:
            assert allowed == 60
            break
        assert response.status_code == 404
        assert response.headers["cache-control"] == "no-store"
        allowed += 1
    else:
        pytest.fail("receipt reads never reached their real rate limit")
    assert response.status_code == 429, response.text
    assert int(response.headers["Retry-After"]) >= 0
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
@pytest.mark.parametrize("protected", [False, True])
@pytest.mark.parametrize("configured", [False, True])
async def test_registry_artifact_origin_configuration_has_no_request_fallback(controller_app, protected, configured):
    """Real registry+codec proof: no claim about signer/UV execution."""
    env = controller_app
    env.app.state.awid_public_origins = (ORIGIN,) if configured else ()
    service_key, service_did = keypair()
    if protected:
        async with env.db.transaction() as tx:
            binding = await provision_team_protection(tx, domain="local", name="base",
                service_id="test-service", service_did_key=service_did,
                expected_generation=0, approval_ref="native-origin-control")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    record = {"v": 1, "type": "aweb.team-server", "team_id": "base:local",
              "team_did_key": env.team[1], "server_url": "https://coord.example",
              "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ")}
    signing = record_signing_bytes(record)
    signature = sign_message(env.team[0], signing)
    body = canonical_json_bytes({"record": record, "signature": signature})
    path = TEAM_PATH + "/server"
    request_headers = {"Content-Type": "application/json"}
    if protected:
        proof = issue_proof({"v": 1, "type": "aweb.protected-effect", "service_id": "test-service",
            "team_id": "base:local", "history_id": binding["history_id"], "generation": binding["generation"],
            "controller_did_key": env.team[1], "operation": "team.server-record.publish", "variant": "default",
            "operation_id": str(uuid4()), "artifact_type": "team-server-record",
            "artifact_sha256": artifact_digest(signing, signature),
            "consumer": http_consumer(audience=ORIGIN, method="PUT", path=path, body=body),
            "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (now + timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%SZ")}, service_key)
        request_headers[HEADER] = encode_proofs([proof])
    response = await env.client.put(path, content=body, headers=request_headers)
    accepted = not protected or configured
    assert response.status_code == (200 if accepted else 403), response.text
    if not accepted:
        assert response.json()["detail"]["code"] == "protected_controller_required"
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.team_server_records}}") == int(accepted)
