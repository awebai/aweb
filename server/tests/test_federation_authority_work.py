from __future__ import annotations

from uuid import uuid4

import pytest

from aweb.federation.authority_work import AuthorityWorkRepository
from awid.federation_errors import FederationAuthorityError


@pytest.mark.asyncio
async def test_lease_takeover_increments_persistent_fence_and_stale_owner_cannot_publish(aweb_cloud_db) -> None:
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
        await repository.publish_result(first, status="ok", evidence={"generation": 1}, ttl_seconds=5)
    assert stale.value.reason == "federation_authority_cas_conflict"
    await repository.publish_result(second, status="ok", evidence={"generation": 2}, ttl_seconds=5)
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
async def test_permits_are_deployment_wide_and_ignore_expired_rows(aweb_cloud_db) -> None:
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
