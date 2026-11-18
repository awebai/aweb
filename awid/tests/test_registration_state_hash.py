"""Initial registration must store the state that the holder actually signed."""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from redis.asyncio import Redis

from awid.did import did_from_public_key, generate_keypair
from awid.log import initial_registration_entry, log_entry_payload
from awid.ratelimit import MemoryFixedWindowRateLimiter
from awid.signing import sign_message
from awid_service.main import create_app


@pytest_asyncio.fixture
async def registration_client(awid_db_infra):
    # This route needs no DNS. Use the real app, database and bounded memory
    # limiter without conftest's FakeRedis or domain-verifier overrides.
    async with Redis.from_url(
        os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    ) as redis:
        app = create_app(
            db_infra=awid_db_infra,
            redis=redis,
            rate_limiter=MemoryFixedWindowRateLimiter(),
        )
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://registry.test",
            ) as client:
                yield client


def signed_registration(*, state_hash: str | None = None):
    seed, public_key = generate_keypair()
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    entry = initial_registration_entry(
        did_from_public_key(public_key), timestamp=timestamp
    )
    if state_hash is not None:
        entry["state_hash"] = state_hash
    return {**entry, "proof": sign_message(seed, log_entry_payload(**entry))}


@pytest.mark.asyncio
@pytest.mark.parametrize("wrong_hash", ["0" * 64, ""])
async def test_signed_wrong_initial_state_is_refused_before_any_write(
    registration_client,
    awid_db_infra,
    wrong_hash,
):
    body = signed_registration(state_hash=wrong_hash)
    response = await registration_client.post("/v1/did", json=body)
    assert response.status_code == 400, response.text
    assert response.json() == {
        "detail": (
            "state_hash mismatch. Rebuild and sign the request with its canonical identity state hash."
        )
    }
    db = awid_db_infra.get_manager("aweb")
    for table in ("did_aw_mappings", "did_aw_log"):
        assert (
            await db.fetch_value(
                f"SELECT count(*) FROM {{{{tables.{table}}}}} WHERE did_aw=$1",
                body["did_aw"],
            )
            == 0
        )


@pytest.mark.asyncio
async def test_correct_initial_state_and_exact_retry_keep_one_self_consistent_log(
    registration_client,
    awid_db_infra,
):
    body = signed_registration()
    first = await registration_client.post("/v1/did", json=body)
    assert first.status_code == 200, first.text
    retry = await registration_client.post("/v1/did", json=body)
    assert retry.status_code == 200, retry.text
    assert retry.json() == first.json()
    rows = await awid_db_infra.get_manager("aweb").fetch_all(
        "SELECT entry_hash,state_hash,signature FROM {{tables.did_aw_log}} WHERE did_aw=$1",
        body["did_aw"],
    )
    assert len(rows) == 1
    assert rows[0]["state_hash"] == body["state_hash"]
    assert rows[0]["signature"] == body["proof"]
    entry = {name: value for name, value in body.items() if name != "proof"}
    assert (
        rows[0]["entry_hash"] == hashlib.sha256(log_entry_payload(**entry)).hexdigest()
    )


@pytest.mark.asyncio
async def test_unsigned_state_tampering_still_fails_signature_verification(
    registration_client,
):
    body = signed_registration()
    body["state_hash"] = "0" * 64
    response = await registration_client.post("/v1/did", json=body)
    assert response.status_code == 401, response.text
    assert response.json() == {"detail": "invalid proof"}


@pytest.mark.asyncio
async def test_read_only_census_matches_service_canonicalisation_and_detects_one_corrupt_entry(
    registration_client,
    awid_db_infra,
    shared_test_pool,
):
    # Execute exactly the SELECT supplied for production, with its own read-only
    # transaction. Never normalize/rewrite JSON or hashes inside the test.
    script = (
        Path(__file__).resolve().parents[1] / "ops" / "first-registration-census.sql"
    ).read_text()
    _before, separator, tail = script.partition("BEGIN READ ONLY;")
    query, rollback, after = tail.rpartition("ROLLBACK;")
    assert separator and rollback and not after.strip()

    async def census():
        async with shared_test_pool.acquire() as conn:
            await conn.execute(separator)
            try:
                assert await conn.fetchval("SHOW transaction_read_only") == "on"
                result = dict(await conn.fetchrow(query))
                assert await conn.fetchval("SHOW transaction_read_only") == "on"
                return result
            finally:
                await conn.execute(rollback)

    bodies = [signed_registration() for _ in range(3)]
    for body in bodies:
        created = await registration_client.post("/v1/did", json=body)
        assert created.status_code == 200, created.text
    assert await census() == {
        "first_registration_entries": 3,
        "stored_state_hash_mismatch": 0,
        "stored_fields_entry_hash_mismatch": 0,
        "computed_state_but_signed_entry_inconsistent_candidates": 0,
    }

    # Recreate the retained-hash shape of11.17: the hash commits another state
    # while the row retains the computed state. This deliberately corrupts only
    # the private test database; it is not a repair or a production operation.
    corrupt = {name: value for name, value in bodies[0].items() if name != "proof"}
    corrupt["state_hash"] = "0" * 64
    await awid_db_infra.get_manager("aweb").execute(
        "UPDATE {{tables.did_aw_log}} SET entry_hash=$2 WHERE did_aw=$1 AND seq=1",
        bodies[0]["did_aw"],
        hashlib.sha256(log_entry_payload(**corrupt)).hexdigest(),
    )
    assert await census() == {
        "first_registration_entries": 3,
        "stored_state_hash_mismatch": 0,
        "stored_fields_entry_hash_mismatch": 1,
        "computed_state_but_signed_entry_inconsistent_candidates": 1,
    }
