"""The shared token-bucket rate limits on real PostgreSQL."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from pgdbm import AsyncDatabaseManager

from aweb_naapp.ratelimit import (
    Charge,
    Decision,
    apply_ratelimit_migrations,
    peek,
    sweep,
    take,
)

T0 = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def charge(
    key: str = "client-1", capacity: int = 3, window_s: int = 60, bucket: str = "test.bucket"
):
    return Charge(bucket=bucket, key=key, capacity=capacity, window_s=window_s)


@pytest.fixture
async def db(test_db_factory) -> AsyncIterator[AsyncDatabaseManager]:
    database = await test_db_factory.create_db(suffix="naapp_ratelimit")
    await apply_ratelimit_migrations(database)
    yield database


async def _take(db: AsyncDatabaseManager, *charges: Charge, now: datetime) -> Decision:
    async with db.transaction() as tx:
        return await take(tx, charges, now=now)


async def _peek(db: AsyncDatabaseManager, *charges: Charge, now: datetime) -> Decision:
    async with db.transaction() as tx:
        return await peek(tx, charges, now=now)


async def _admitted(
    db: AsyncDatabaseManager, *charges: Charge, now: datetime, tries: int = 20
) -> int:
    count = 0
    for _ in range(tries):
        if (await _take(db, *charges, now=now)).allowed:
            count += 1
    return count


async def _rows(db: AsyncDatabaseManager) -> int:
    return int(await db.fetch_value("SELECT count(*) FROM {{tables.rate_buckets}}"))


async def test_a_fresh_bucket_admits_its_capacity_then_refuses(db: AsyncDatabaseManager) -> None:
    for _ in range(3):
        decision = await _take(db, charge(), now=T0)
        assert decision == Decision(allowed=True, retry_after_s=0, refused=())
        assert decision.throttled is False
    refused = await _take(db, charge(), now=T0)
    assert refused.allowed is False and refused.throttled is True
    assert refused.refused == (charge(),)
    assert refused.retry_after_s == 20  # one token per 60/3 seconds


async def test_tokens_refill_continuously(db: AsyncDatabaseManager) -> None:
    await _admitted(db, charge(), now=T0, tries=3)
    almost = await _take(db, charge(), now=at(19))
    assert almost.allowed is False and almost.retry_after_s == 1
    assert (await _take(db, charge(), now=at(20))).allowed is True
    assert (await _take(db, charge(), now=at(20))).allowed is False


async def test_a_bucket_is_full_again_after_its_window(db: AsyncDatabaseManager) -> None:
    await _admitted(db, charge(), now=T0, tries=3)
    assert await _admitted(db, charge(), now=at(600)) == 3


async def test_retry_after_is_whole_seconds_and_at_least_one(db: AsyncDatabaseManager) -> None:
    slow = charge(capacity=7, window_s=10)
    await _admitted(db, slow, now=T0, tries=7)
    refused = await _take(db, slow, now=at(1.4))
    assert refused.allowed is False
    assert refused.retry_after_s == 1  # ceil((1 - 0.98) * 10 / 7)
    assert (await _take(db, slow, now=at(0))).retry_after_s == 2  # ceil(10 / 7)


async def test_a_shrunk_capacity_caps_immediately(db: AsyncDatabaseManager) -> None:
    assert (await _take(db, charge(capacity=10), now=T0)).allowed is True
    assert await _admitted(db, charge(capacity=2), now=T0) == 2


async def test_a_grown_capacity_refills_toward_the_new_limit(db: AsyncDatabaseManager) -> None:
    await _admitted(db, charge(capacity=2), now=T0, tries=2)
    assert (await _take(db, charge(capacity=4), now=T0)).allowed is False
    assert await _admitted(db, charge(capacity=4), now=at(60)) == 4


async def test_time_running_backwards_adds_no_tokens(db: AsyncDatabaseManager) -> None:
    await _admitted(db, charge(), now=at(100), tries=3)
    assert (await _take(db, charge(), now=at(0))).allowed is False


async def test_a_multi_bucket_take_is_all_or_none(db: AsyncDatabaseManager) -> None:
    shared = charge(key="secret", capacity=5, bucket="test.shared")
    alice = charge(key="alice", capacity=1, bucket="test.principal")
    assert (await _take(db, alice, shared, now=T0)).allowed is True
    refused = await _take(db, shared, alice, now=T0)
    assert refused.allowed is False and refused.refused == (alice,)
    # Refusing alice drained nothing from the shared bucket: it still holds 4.
    assert await _admitted(db, shared, now=T0) == 4


async def test_a_refusal_names_every_empty_bucket(db: AsyncDatabaseManager) -> None:
    fast = charge(key="a", capacity=1, window_s=10)
    slow = charge(key="b", capacity=1, window_s=100)
    await _take(db, fast, slow, now=T0)
    refused = await _take(db, slow, fast, now=T0)
    assert set(refused.refused) == {fast, slow}
    assert refused.retry_after_s == 100


async def test_a_rolled_back_take_charges_nothing(db: AsyncDatabaseManager) -> None:
    class Abort(Exception):
        pass

    with pytest.raises(Abort):
        async with db.transaction() as tx:
            assert (await take(tx, [charge(capacity=1)], now=T0)).allowed is True
            raise Abort
    assert (await _take(db, charge(capacity=1), now=T0)).allowed is True


async def test_peek_charges_nothing(db: AsyncDatabaseManager) -> None:
    for _ in range(10):
        assert (await _peek(db, charge(), now=T0)).allowed is True
    assert await _admitted(db, charge(), now=T0) == 3
    refused = await _peek(db, charge(), now=T0)
    assert refused.allowed is False and refused.retry_after_s == 20
    assert await _rows(db) == 1


async def test_peek_then_take_on_success_keeps_wrong_guesses_from_locking_the_holder_out(
    db: AsyncDatabaseManager,
) -> None:
    """C4's exchange: failures spend the client's bucket, successes the link's."""
    link = charge(key="link-1", capacity=10, bucket="link.exchange")

    async def exchange(client: str, *, secret_ok: bool) -> bool:
        client_bucket = charge(key=client, capacity=30, bucket="link.exchange.client")
        async with db.transaction() as tx:
            if not (await peek(tx, [link], now=T0)).allowed:
                return False
            if not (await take(tx, [client_bucket], now=T0)).allowed:
                return False
            if not secret_ok:
                return False
            return (await take(tx, [link], now=T0)).allowed

    results = [await exchange("attacker", secret_ok=False) for _ in range(50)]
    assert not any(results)
    assert await exchange("holder", secret_ok=True) is True


async def test_parallel_takes_on_one_bucket_admit_exactly_its_capacity(
    db: AsyncDatabaseManager,
) -> None:
    async def contender() -> bool:
        async with db.transaction() as tx:
            decision = await take(tx, [charge(capacity=4)], now=T0)
            await asyncio.sleep(0.05)
            return decision.allowed

    results = await asyncio.gather(*(contender() for _ in range(12)))
    assert sum(results) == 4


async def test_overlapping_bucket_sets_never_deadlock(db: AsyncDatabaseManager) -> None:
    a = charge(key="a", capacity=100)
    b = charge(key="b", capacity=100)

    async def contender(charges: list[Charge]) -> bool:
        async with db.transaction() as tx:
            decision = await take(tx, charges, now=T0)
            await asyncio.sleep(0.01)
            return decision.allowed

    results = await asyncio.gather(*(contender([a, b] if n % 2 else [b, a]) for n in range(20)))
    assert all(results)


async def test_take_in_a_caller_transaction_cannot_deadlock_with_a_take_on_an_idle_key(
    db: AsyncDatabaseManager,
) -> None:
    """T1 charges A and then needs R; T2 holds R and charges an idle key X.

    A take that deleted idle rows inside its transaction would lock X for T1,
    and T2's charge of X would then close a cycle with T1's wait on R.
    """
    idle = charge(key="x")
    await _take(db, idle, now=T0)
    now = at(3600)  # X is full again: an idle row
    t1_charged, t2_holds_r = asyncio.Event(), asyncio.Event()

    async def t1() -> bool:
        async with db.transaction() as tx:
            await take(tx, [charge(key="a")], now=now)
            t1_charged.set()
            await t2_holds_r.wait()
            return (await take(tx, [charge(key="r")], now=now)).allowed

    async def t2() -> bool:
        async with db.transaction() as tx:
            await take(tx, [charge(key="r")], now=now)
            t2_holds_r.set()
            await t1_charged.wait()
            decision = await take(tx, [idle], now=now)
            await asyncio.sleep(0.1)
            return decision.allowed

    assert await asyncio.wait_for(asyncio.gather(t1(), t2()), timeout=10) == [True, True]


async def test_sweep_deletes_only_full_rows(db: AsyncDatabaseManager) -> None:
    await _take(db, charge(key="idle"), now=T0)
    await _take(db, charge(key="busy"), now=at(50))
    assert await sweep(db, now=at(60)) == 1  # idle is full at 20 s, busy only at 70 s
    assert await _rows(db) == 1
    assert await sweep(db, now=at(60)) == 0


async def test_sweep_is_bounded_by_its_limit(db: AsyncDatabaseManager) -> None:
    for n in range(40):
        await _take(db, charge(key=f"client-{n}"), now=T0)
    assert await sweep(db, now=at(3600), limit=16) == 16
    assert await _rows(db) == 24


async def test_sweep_never_waits_on_a_bucket_a_transaction_holds(db: AsyncDatabaseManager) -> None:
    held = asyncio.Event()
    release = asyncio.Event()

    async def holder() -> None:
        async with db.transaction() as tx:
            await take(tx, [charge(key="held")], now=T0)
            held.set()
            await release.wait()

    task = asyncio.create_task(holder())
    await held.wait()
    swept = await asyncio.wait_for(sweep(db, now=at(3600)), timeout=2)
    release.set()
    await task
    assert swept == 0
    assert await sweep(db, now=at(3600)) == 1


async def test_a_swept_bucket_reads_as_full(db: AsyncDatabaseManager) -> None:
    await _admitted(db, charge(), now=T0, tries=3)
    await sweep(db, now=at(60))
    assert await _admitted(db, charge(), now=at(60)) == 3


@pytest.mark.parametrize(
    "bad",
    [
        dict(bucket="Upper"),
        dict(bucket=""),
        dict(bucket="a" * 65),
        dict(key=""),
        dict(key="k" * 513),
        dict(capacity=0),
        dict(window_s=0),
        dict(capacity=True),
        dict(window_s=1.5),
    ],
)
def test_a_malformed_charge_is_refused(bad: dict) -> None:
    fields = dict(bucket="test.bucket", key="client-1", capacity=3, window_s=60)
    fields.update(bad)
    with pytest.raises(ValueError):
        Charge(**fields)


async def test_a_call_needs_distinct_charges_and_an_aware_now(db: AsyncDatabaseManager) -> None:
    async with db.transaction() as tx:
        with pytest.raises(ValueError):
            await take(tx, [charge(), charge()], now=T0)
        with pytest.raises(ValueError):
            await take(tx, [], now=T0)
        with pytest.raises(ValueError):
            await take(tx, [charge()], now=datetime(2026, 10, 20, 12, 0))
        with pytest.raises(ValueError):
            await peek(tx, [charge()], now=datetime(2026, 10, 20, 12, 0))
    with pytest.raises(ValueError):
        await sweep(db, now=T0, limit=0)
