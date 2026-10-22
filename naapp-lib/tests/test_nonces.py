"""Durable single-use nonces, atomic with effects, on real PostgreSQL."""

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from aweb_naapp.nonces import apply_nonce_migrations, consume_nonce, prune_nonces

NOW = datetime(2026, 10, 21, tzinfo=UTC)


@pytest.fixture
async def db(test_db_factory):
    database = await test_db_factory.create_db(suffix="nonces")
    await apply_nonce_migrations(database)
    return database


async def test_concurrent_consume_has_one_winner_and_scopes_are_independent(db):
    async def consume(scope):
        async with db.transaction() as tx:
            return await consume_nonce(tx, scope=scope, nonce="one", expires_at=NOW)

    results = await asyncio.gather(*(consume("scope-a") for _ in range(4)))
    assert results.count(True) == 1
    assert await consume("scope-b")


async def test_rollback_and_expiry_boundary(db):
    with pytest.raises(RuntimeError):
        async with db.transaction() as tx:
            assert await consume_nonce(tx, scope="scope", nonce="one", expires_at=NOW)
            raise RuntimeError("rollback")
    async with db.transaction() as tx:
        assert await consume_nonce(tx, scope="scope", nonce="one", expires_at=NOW)
        assert await prune_nonces(tx, now=NOW) == 0
        assert not await consume_nonce(tx, scope="scope", nonce="one", expires_at=NOW)
        assert await prune_nonces(tx, now=NOW + timedelta(microseconds=1)) == 1
