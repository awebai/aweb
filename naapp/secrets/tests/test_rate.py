"""Rate buckets charged inside the admission transaction (§4.4), on real PostgreSQL."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import asyncpg
import pytest
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager

from aweb_secrets.app import MIGRATIONS_PATH, MODULE_NAME
from aweb_secrets.rate import RateLimited, charge, lock_buckets

INSTALLATION = "inst_5d2a9c31"
SECRET = "sec_19ab42"
ALICE = "did:aw:alice"
BOB = "did:aw:bob"
POLICY_A = "a" * 64
POLICY_B = "b" * 64
T0 = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)
PER_PRINCIPAL = [{"per": "principal_secret", "capacity": 2, "window_s": 3600}]
BOTH = [
    {"per": "principal_secret", "capacity": 2, "window_s": 3600},
    {"per": "secret", "capacity": 3, "window_s": 3600},
]


@pytest.fixture
async def db(test_db_factory) -> AsyncIterator[AsyncDatabaseManager]:
    database = await test_db_factory.create_db(suffix="secrets_rate")
    await AsyncMigrationManager(
        database, migrations_path=str(MIGRATIONS_PATH), module_name=MODULE_NAME
    ).apply_pending_migrations()
    yield database


async def _charge(db, buckets, principal=ALICE, now=T0, policy=POLICY_A) -> None:
    async with db.transaction() as tx:
        await charge(tx, INSTALLATION, SECRET, principal, policy, buckets, now=now)


async def test_requests_within_capacity_are_admitted_and_the_next_is_refused(db) -> None:
    await _charge(db, PER_PRINCIPAL)
    await _charge(db, PER_PRINCIPAL)
    with pytest.raises(RateLimited) as refused:
        await _charge(db, PER_PRINCIPAL)
    assert refused.value.code == "policy_rate_limited"


async def test_a_bucket_refills_at_its_rate(db) -> None:
    await _charge(db, PER_PRINCIPAL)
    await _charge(db, PER_PRINCIPAL)
    with pytest.raises(RateLimited):
        await _charge(db, PER_PRINCIPAL, now=T0 + timedelta(minutes=29))
    await _charge(db, PER_PRINCIPAL, now=T0 + timedelta(minutes=30))


async def test_the_per_secret_bucket_is_shared_by_every_principal(db) -> None:
    await _charge(db, BOTH, ALICE)
    await _charge(db, BOTH, ALICE)
    await _charge(db, BOTH, BOB)
    with pytest.raises(RateLimited):
        await _charge(db, BOTH, BOB)


async def test_a_refused_request_charges_no_bucket(db) -> None:
    await _charge(db, BOTH, ALICE)
    await _charge(db, BOTH, ALICE)
    with pytest.raises(RateLimited):
        await _charge(db, BOTH, ALICE)
    # Alice's refusal took nothing from the secret's bucket: Bob still has one.
    await _charge(db, BOTH, BOB)


async def test_a_charge_rolls_back_with_the_callers_transaction(db) -> None:
    for _ in range(2):
        with pytest.raises(RuntimeError):
            async with db.transaction() as tx:
                await charge(tx, INSTALLATION, SECRET, ALICE, POLICY_A, PER_PRINCIPAL, now=T0)
                raise RuntimeError("admission failed later")
    await _charge(db, PER_PRINCIPAL)
    await _charge(db, PER_PRINCIPAL)


async def test_no_buckets_means_no_limit(db) -> None:
    for _ in range(5):
        await _charge(db, [])


async def test_concurrent_charges_never_exceed_capacity(db) -> None:
    buckets = [{"per": "secret", "capacity": 3, "window_s": 3600}]

    async def attempt(index: int) -> bool:
        try:
            await _charge(db, buckets, principal=f"did:aw:p{index}")
        except RateLimited:
            return False
        return True

    outcomes = await asyncio.gather(*(attempt(i) for i in range(8)))
    assert outcomes.count(True) == 3


async def test_each_policy_charges_its_own_buckets(db) -> None:
    roomy = [{"per": "principal_secret", "capacity": 100, "window_s": 3600}]
    await _charge(db, PER_PRINCIPAL, policy=POLICY_A)
    await _charge(db, PER_PRINCIPAL, policy=POLICY_A)
    # Charging the same secret and principal under another policy leaves A's bucket empty.
    await _charge(db, roomy, policy=POLICY_B)
    with pytest.raises(RateLimited):
        await _charge(db, PER_PRINCIPAL, policy=POLICY_A)


async def test_locking_the_candidates_buckets_holds_every_one_of_them(db) -> None:
    async with db.transaction() as locking:
        await lock_buckets(
            locking, INSTALLATION, SECRET, ALICE, [(POLICY_B, BOTH), (POLICY_A, BOTH)], now=T0
        )
        for policy in (POLICY_A, POLICY_B):
            with pytest.raises(asyncpg.LockNotAvailableError):
                async with db.transaction() as tx:
                    await tx.execute("SET LOCAL lock_timeout = '100ms'")
                    await charge(tx, INSTALLATION, SECRET, BOB, policy, BOTH, now=T0)
        # The holder charges its own buckets without waiting.
        await charge(locking, INSTALLATION, SECRET, ALICE, POLICY_A, BOTH, now=T0)
