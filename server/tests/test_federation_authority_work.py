from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest

from awid.db_config import build_database_config
from pgdbm import AsyncDatabaseManager

from aweb.federation.authority_work import AuthorityWorkRepository
from awid.federation_errors import FederationAuthorityError


@pytest.mark.asyncio
async def test_lease_takeover_increments_persistent_fence_and_stale_owner_cannot_publish(
    aweb_cloud_db,
) -> None:
    repository = AuthorityWorkRepository(aweb_cloud_db.aweb_db)
    scope = "origin:https://registry.example"
    owner1 = uuid4()
    owner2 = uuid4()
    first = await repository.acquire_lease(scope, owner_id=owner1, ttl_seconds=5)
    assert first.fence == 1
    waiting = await repository.acquire_lease(scope, owner_id=owner2, ttl_seconds=5)
    assert waiting.acquired is False
    assert waiting.fence == 1

    await aweb_cloud_db.aweb_db.execute(
        "UPDATE {{tables.federation_authority_leases}} SET acquired_at = clock_timestamp() - interval '2 seconds', expires_at = clock_timestamp() - interval '1 second' WHERE scope_key = $1",
        scope,
    )
    second = await repository.acquire_lease(scope, owner_id=owner2, ttl_seconds=5)
    assert second.acquired is True
    assert second.fence == 2

    with pytest.raises(FederationAuthorityError) as stale:
        await repository.publish_result(
            first, status="ok", evidence={"generation": 1}, ttl_seconds=5
        )
    assert stale.value.reason == "federation_authority_cas_conflict"
    await repository.publish_result(
        second, status="ok", evidence={"generation": 2}, ttl_seconds=5
    )
    result = await repository.get_result(scope)
    assert result is not None
    assert result.fence == 2
    assert result.evidence == {"generation": 2}

    counter = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT last_fence FROM {{tables.federation_authority_fences}} WHERE scope_key = $1",
        scope,
    )
    assert counter == 2


@pytest.mark.asyncio
async def test_lease_release_requires_the_current_owner_and_fence(
    aweb_cloud_db,
) -> None:
    repository = AuthorityWorkRepository(aweb_cloud_db.aweb_db)
    scope = "evidence:release"
    owner1 = uuid4()
    owner2 = uuid4()
    first = await repository.acquire_lease(scope, owner_id=owner1, ttl_seconds=10)

    await repository.release_lease(
        type(first)(first.scope_key, first.owner_id, first.fence + 1, first.expires_at)
    )
    blocked = await repository.acquire_lease(scope, owner_id=owner2, ttl_seconds=10)
    assert blocked.acquired is False

    await repository.release_lease(first)
    replacement = await repository.acquire_lease(scope, owner_id=owner2, ttl_seconds=10)
    assert replacement.acquired is True
    assert replacement.fence == first.fence + 1


@pytest.mark.asyncio
async def test_permits_are_deployment_wide_and_ignore_expired_rows(
    aweb_cloud_db,
) -> None:
    repository = AuthorityWorkRepository(aweb_cloud_db.aweb_db)
    first = await repository.acquire_permits(
        owner_id=uuid4(),
        scopes=(("origin", "https://registry.example", 1),),
        ttl_seconds=5,
    )
    assert len(first) == 1
    with pytest.raises(FederationAuthorityError) as busy:
        await repository.acquire_permits(
            owner_id=uuid4(),
            scopes=(("origin", "https://registry.example", 1),),
            ttl_seconds=5,
        )
    assert busy.value.reason == "federation_resolver_busy"

    await aweb_cloud_db.aweb_db.execute(
        "UPDATE {{tables.federation_authority_permits}} SET acquired_at = clock_timestamp() - interval '2 seconds', expires_at = clock_timestamp() - interval '1 second'"
    )
    replacement = await repository.acquire_permits(
        owner_id=uuid4(),
        scopes=(("origin", "https://registry.example", 1),),
        ttl_seconds=5,
    )
    assert len(replacement) == 1


@pytest.mark.asyncio
async def test_token_bucket_uses_shared_database_state(aweb_cloud_db) -> None:
    repository_a = AuthorityWorkRepository(aweb_cloud_db.aweb_db)
    repository_b = AuthorityWorkRepository(aweb_cloud_db.aweb_db)
    for _ in range(5):
        await repository_a.consume_token(
            bucket_kind="domain",
            bucket_key="example.com",
            burst=5,
            refill_per_minute=30,
        )
    with pytest.raises(FederationAuthorityError) as limited:
        await repository_b.consume_token(
            bucket_kind="domain",
            bucket_key="example.com",
            burst=5,
            refill_per_minute=30,
        )
    assert limited.value.reason == "federation_rate_limited"


@pytest.mark.asyncio
async def test_fence_overflow_and_database_failure_fail_closed(aweb_cloud_db) -> None:
    repository = AuthorityWorkRepository(aweb_cloud_db.aweb_db)
    scope = "did:did:aw:fixture"
    await aweb_cloud_db.aweb_db.execute(
        "INSERT INTO {{tables.federation_authority_fences}} (scope_key, last_fence) VALUES ($1, 9223372036854775807)",
        scope,
    )
    with pytest.raises(FederationAuthorityError) as overflow:
        await repository.acquire_lease(scope, owner_id=uuid4(), ttl_seconds=5)
    assert overflow.value.reason == "federation_authority_coordination_unavailable"

    class FailedDB:
        def transaction(self):
            raise RuntimeError("postgres unavailable")

    with pytest.raises(FederationAuthorityError) as outage:
        await AuthorityWorkRepository(FailedDB()).acquire_lease(
            "discovery:example.com", owner_id=uuid4(), ttl_seconds=5
        )
    assert outage.value.reason == "federation_authority_coordination_unavailable"


@pytest.mark.asyncio
async def test_a_published_result_lives_exactly_its_ttl_when_the_clock_advances(
    aweb_cloud_db, shared_test_database
) -> None:
    # A connection whose clock_timestamp() advances 10 ms on every read: a
    # result stamped from two reads would live longer than its TTL.
    await aweb_cloud_db.aweb_db.execute("CREATE SCHEMA IF NOT EXISTS clock_fault")
    await aweb_cloud_db.aweb_db.execute(
        """
        CREATE OR REPLACE FUNCTION clock_fault.clock_timestamp()
        RETURNS timestamptz LANGUAGE plpgsql VOLATILE AS $$
        BEGIN
            PERFORM pg_catalog.pg_sleep(0.01);
            RETURN pg_catalog.clock_timestamp();
        END $$
        """
    )
    pool = await AsyncDatabaseManager.create_shared_pool(
        build_database_config(
            connection_string=shared_test_database.config.get_dsn(),
            min_connections=1,
            max_connections=1,
            shared_pool_search_path="clock_fault, pg_catalog",
        )
    )
    try:
        repository = AuthorityWorkRepository(
            AsyncDatabaseManager(pool=pool, schema="aweb")
        )
        scope = "discovery:exact-ttl"
        lease = await repository.acquire_lease(scope, owner_id=uuid4(), ttl_seconds=10)

        await repository.publish_result(
            lease, status="failed", evidence={"reason": "x"}, ttl_seconds=5
        )
    finally:
        await pool.close()

    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT created_at, expires_at FROM {{tables.federation_authority_results}} "
        "WHERE scope_key = $1",
        scope,
    )
    assert row["expires_at"] - row["created_at"] == timedelta(seconds=5)
