"""The shared idempotency store on real PostgreSQL."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import AsyncIterator
from datetime import timedelta

import pytest
from pgdbm import AsyncDatabaseManager

from aweb_naapp.idempotency import (
    IdempotencyConflict,
    IdempotencyExpired,
    apply_idempotency_migrations,
    claim,
    expire_keys,
)

KEY = ("installation-1", "did:aw:member", "request-1")
RETENTION = timedelta(days=30)


def _hash(body: bytes) -> bytes:
    return hashlib.sha256(body).digest()


@pytest.fixture
async def db(test_db_factory) -> AsyncIterator[AsyncDatabaseManager]:
    database = await test_db_factory.create_db(suffix="naapp_idempotency")
    await apply_idempotency_migrations(database)
    yield database


async def _claim(db: AsyncDatabaseManager, ref: str, body: bytes = b"a", **changes):
    arguments = dict(key=KEY, request_hash=_hash(body), receipt_ref=ref, retention=RETENTION)
    arguments.update(changes)
    async with db.transaction() as tx:
        return await claim(tx, **arguments)


async def _rows(db: AsyncDatabaseManager) -> int:
    return int(await db.fetch_value("SELECT count(*) FROM {{tables.idempotency_keys}}"))


async def test_a_new_key_is_claimed_for_the_given_receipt(db: AsyncDatabaseManager) -> None:
    receipt = await _claim(db, "dispatch-1")
    assert (receipt.receipt_ref, receipt.created) == ("dispatch-1", True)


async def test_same_key_and_bytes_return_the_stored_receipt(db: AsyncDatabaseManager) -> None:
    await _claim(db, "dispatch-1")
    again = await _claim(db, "dispatch-2")
    assert (again.receipt_ref, again.created) == ("dispatch-1", False)
    assert await _rows(db) == 1


async def test_same_key_with_different_bytes_is_a_conflict(db: AsyncDatabaseManager) -> None:
    await _claim(db, "dispatch-1", body=b"a")
    with pytest.raises(IdempotencyConflict) as conflict:
        await _claim(db, "dispatch-2", body=b"b")
    assert (conflict.value.code, conflict.value.status) == ("idempotency_conflict", 409)


SHORT = timedelta(milliseconds=100)


async def test_an_expired_key_is_gone_and_never_re_executes(db: AsyncDatabaseManager) -> None:
    await _claim(db, "dispatch-1", retention=SHORT)
    await asyncio.sleep(0.2)
    for body in (b"a", b"b"):
        with pytest.raises(IdempotencyExpired) as expired:
            await _claim(db, "dispatch-2", body=body)
        assert (expired.value.code, expired.value.status) == ("idempotency_expired", 410)
    assert await _rows(db) == 1


async def test_a_key_within_retention_is_not_expired(db: AsyncDatabaseManager) -> None:
    await _claim(db, "dispatch-1", retention=timedelta(minutes=5))
    assert (await _claim(db, "dispatch-2")).receipt_ref == "dispatch-1"


async def test_keys_are_the_whole_tuple(db: AsyncDatabaseManager) -> None:
    first = await _claim(db, "dispatch-1", key=("ab", "c"))
    second = await _claim(db, "dispatch-2", key=("a", "bc"))
    third = await _claim(db, "dispatch-3", key=("ab", "c", ""))
    assert [r.created for r in (first, second, third)] == [True, True, True]


async def test_the_claim_rolls_back_with_the_callers_transaction(
    db: AsyncDatabaseManager,
) -> None:
    class Abort(Exception):
        pass

    with pytest.raises(Abort):
        async with db.transaction() as tx:
            await claim(
                tx, key=KEY, request_hash=_hash(b"a"), receipt_ref="dispatch-1", retention=RETENTION
            )
            raise Abort
    assert await _rows(db) == 0
    assert (await _claim(db, "dispatch-2")).created is True


async def test_parallel_claims_of_one_key_yield_one_winner(db: AsyncDatabaseManager) -> None:
    first_inserted = asyncio.Event()

    async def slow_winner() -> object:
        async with db.transaction() as tx:
            receipt = await claim(
                tx, key=KEY, request_hash=_hash(b"a"), receipt_ref="dispatch-1", retention=RETENTION
            )
            first_inserted.set()
            await asyncio.sleep(0.3)
            return receipt

    async def contender() -> object:
        await first_inserted.wait()
        return await _claim(db, "dispatch-2")

    winner, other = await asyncio.gather(slow_winner(), contender())
    assert (winner.receipt_ref, winner.created) == ("dispatch-1", True)  # type: ignore[attr-defined]
    assert (other.receipt_ref, other.created) == ("dispatch-1", False)  # type: ignore[attr-defined]
    assert await _rows(db) == 1


async def test_a_contender_wins_when_the_first_claim_rolls_back(db: AsyncDatabaseManager) -> None:
    first_inserted = asyncio.Event()

    class Abort(Exception):
        pass

    async def loser() -> None:
        async with db.transaction() as tx:
            await claim(
                tx, key=KEY, request_hash=_hash(b"a"), receipt_ref="dispatch-1", retention=RETENTION
            )
            first_inserted.set()
            await asyncio.sleep(0.3)
            raise Abort

    async def contender() -> object:
        await first_inserted.wait()
        return await _claim(db, "dispatch-2")

    results = await asyncio.gather(loser(), contender(), return_exceptions=True)
    assert isinstance(results[0], Abort)
    assert (results[1].receipt_ref, results[1].created) == ("dispatch-2", True)  # type: ignore[union-attr]


async def test_expiring_keys_leaves_content_free_tombstones(db: AsyncDatabaseManager) -> None:
    await _claim(db, "dispatch-1", retention=SHORT)
    await _claim(db, "dispatch-2", key=("live",))
    await asyncio.sleep(0.2)
    assert await expire_keys(db) == 1
    assert await expire_keys(db) == 0
    expired = await db.fetch_one(
        "SELECT request_hash, receipt_ref FROM {{tables.idempotency_keys}} WHERE key = $1",
        list(KEY),
    )
    assert expired is not None
    assert (expired["request_hash"], expired["receipt_ref"]) == (None, None)
    with pytest.raises(IdempotencyExpired):
        await _claim(db, "dispatch-3")
    assert (await _claim(db, "dispatch-4", key=("live",))).receipt_ref == "dispatch-2"
    assert await _rows(db) == 2


@pytest.mark.parametrize(
    "changes",
    [
        {"key": ()},
        {"request_hash": b""},
        {"receipt_ref": ""},
        {"retention": timedelta(seconds=-1)},
        {"retention": timedelta(0)},
    ],
)
async def test_malformed_claims_are_refused(db: AsyncDatabaseManager, changes: dict) -> None:
    with pytest.raises(ValueError):
        await _claim(db, "dispatch-1", **changes)
