"""The owner-act verifier with its nonce table on real PostgreSQL, reading the
team's current key from real AWID routes.

Single use is a unique insert in the effect's transaction, so two concurrent
requests carrying one act produce exactly one effect, and a failed effect lets
the owner retry the same act. A rotated team key stops verifying as soon as
the verifier's view of the team refreshes.
"""

from __future__ import annotations

import asyncio
import base64
import secrets
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from aweb_naapp_testing import did_key
from awid_service.testing import REGISTRY_URL, SERVICE_TOKEN
from nacl.signing import SigningKey
from pgdbm import AsyncDatabaseManager

from aweb_naapp.hooks.owner_act import CORE_ACTS, PREFIX, Refused, VerifiedOwnerAct
from aweb_naapp.hooks.owner_act_nonces import (
    OwnerActVerifier,
    PreparedOwnerAct,
    apply_owner_act_migrations,
    prune_owner_act_nonces,
)
from aweb_naapp.hooks.strictjson import canonical
from aweb_naapp.runtime.team_auth import AWIDTeamCache

TEAM_ID = "demo:example.com"
AUDIENCE = "https://aweb.example.com"
SUBJECT = {
    "binding_id": "6f9619ff-8b86-4011-b42d-00c04fc964ff",
    "installation_id": "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b",
    "generation": 2,
    "app_id": "logs",
    "origin": "https://logs.example.com",
    "digest": "sha256:" + "9f" * 32,
    "kind": "registration",
    "catalog_id": "aweb.hooks",
    "catalog_version": 1,
    "hook": "post-secret-use-hook",
    "tool": "ingest",
    "method": "POST",
    "path": "/hooks/ingest",
    "scopes": ["logs:ingest"],
}


def owner_act(team_key: SigningKey, *, issued: datetime) -> tuple[bytes, str]:
    act = {
        "v": 1,
        "type": "aweb.owner-act",
        "act": "hook-binding.activate",
        "team_id": TEAM_ID,
        "aud": AUDIENCE,
        "team_key_did": did_key(team_key),
        "subject": SUBJECT,
        "issued_at": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (issued + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "nonce": secrets.token_hex(16),
    }
    signing = PREFIX + canonical(act)
    signature = base64.b64encode(team_key.sign(signing).signature).decode().rstrip("=")
    return signing, signature


@pytest_asyncio.fixture
async def db(test_db_factory) -> AsyncIterator[AsyncDatabaseManager]:
    database = await test_db_factory.create_db(suffix="naapp_owner_act")
    await apply_owner_act_migrations(database)
    await database.execute("CREATE TABLE effects (id SERIAL PRIMARY KEY, nonce TEXT NOT NULL)")
    yield database


@pytest_asyncio.fixture
async def team_key(registry) -> SigningKey:
    key = SigningKey.generate()
    await registry.add_team(TEAM_ID, did_key(key))
    return key


def verifier(registry, *, clock=None) -> OwnerActVerifier:
    cache = AWIDTeamCache(
        registry_url=REGISTRY_URL,
        ttl_seconds=0,
        service_token=SERVICE_TOKEN,
        transport=registry.transport,
    )

    async def current_team_key(team_id: str) -> str:
        return (await cache.get(team_id)).team_did_key

    verify = OwnerActVerifier(
        scope="core",
        audience=AUDIENCE,
        acts=CORE_ACTS,
        team_key_for=current_team_key,
        clock=clock or (lambda: datetime.now(UTC)),
    )
    verify.key_reads = 0  # type: ignore[attr-defined]

    async def counted(team_id: str) -> str:
        verify.key_reads += 1  # type: ignore[attr-defined]
        return await current_team_key(team_id)

    verify._team_key_for = counted
    return verify


async def apply_effect(
    db, verify: OwnerActVerifier, signing: bytes, signature: str, *, fail: bool = False
):
    prepared = await verify.prepare(signing, signature, team_id=TEAM_ID)
    async with db.transaction() as tx:
        act = await verify.consume_in(tx, prepared, expected_subject=SUBJECT)
        await tx.execute("INSERT INTO effects (nonce) VALUES ($1)", act.nonce)
        if fail:
            raise RuntimeError("the effect failed")
    return act


async def effects(db) -> int:
    return await db.fetch_value("SELECT count(*) FROM effects")


async def test_an_act_takes_effect_once(db, registry, team_key) -> None:
    verify = verifier(registry)
    signing, signature = owner_act(team_key, issued=datetime.now(UTC))
    await apply_effect(db, verify, signing, signature)
    with pytest.raises(Refused) as refused:
        await apply_effect(db, verify, signing, signature)
    assert refused.value.code == "nonce_reused"
    assert await effects(db) == 1


async def test_a_verified_act_names_the_transaction_that_consumed_it(
    db, registry, team_key
) -> None:
    signing, signature = owner_act(team_key, issued=datetime.now(UTC))
    verify = verifier(registry)
    prepared = await verify.prepare(signing, signature, team_id=TEAM_ID)
    async with db.transaction() as tx:
        act = await verify.consume_in(tx, prepared, expected_subject=SUBJECT)
        assert act.transaction_id == await tx.fetch_value("SELECT txid_current()")


async def test_concurrent_uses_of_one_act_produce_exactly_one_effect(
    db, registry, team_key
) -> None:
    verify = verifier(registry)
    signing, signature = owner_act(team_key, issued=datetime.now(UTC))
    first_inserted = asyncio.Event()
    release_first = asyncio.Event()

    async def first() -> None:
        prepared = await verify.prepare(signing, signature, team_id=TEAM_ID)
        async with db.transaction() as tx:
            act = await verify.consume_in(tx, prepared, expected_subject=SUBJECT)
            await tx.execute("INSERT INTO effects (nonce) VALUES ($1)", act.nonce)
            first_inserted.set()
            await release_first.wait()

    async def second() -> str:
        await first_inserted.wait()
        try:
            await apply_effect(db, verify, signing, signature)
        except Refused as refused:
            return refused.code
        return "committed"

    first_task = asyncio.create_task(first())
    second_task = asyncio.create_task(second())
    await first_inserted.wait()
    await asyncio.sleep(0.2)
    assert not second_task.done(), "the second use must wait on the first's nonce row"
    release_first.set()
    await first_task
    assert await second_task == "nonce_reused"
    assert await effects(db) == 1


async def test_a_failed_effect_releases_the_nonce_for_a_retry(db, registry, team_key) -> None:
    verify = verifier(registry)
    signing, signature = owner_act(team_key, issued=datetime.now(UTC))
    with pytest.raises(RuntimeError):
        await apply_effect(db, verify, signing, signature, fail=True)
    assert await effects(db) == 0
    await apply_effect(db, verify, signing, signature)
    assert await effects(db) == 1


async def test_a_rotated_team_key_stops_verifying(db, registry, team_key) -> None:
    verify = verifier(registry)
    await apply_effect(db, verify, *owner_act(team_key, issued=datetime.now(UTC)))
    new_key = SigningKey.generate()
    await registry.rotate_team_key(TEAM_ID, did_key(new_key))
    with pytest.raises(Refused) as refused:
        await apply_effect(db, verify, *owner_act(team_key, issued=datetime.now(UTC)))
    assert refused.value.code == "owner_required"
    await apply_effect(db, verify, *owner_act(new_key, issued=datetime.now(UTC)))
    assert await effects(db) == 2


async def test_nonce_rows_outlive_the_act_and_are_then_pruned(db, registry, team_key) -> None:
    issued = datetime.now(UTC)
    await apply_effect(db, verifier(registry), *owner_act(team_key, issued=issued))
    expires = issued.replace(microsecond=0) + timedelta(minutes=5)
    assert await prune_owner_act_nonces(db, now=expires + timedelta(seconds=60)) == 0
    assert await prune_owner_act_nonces(db, now=expires + timedelta(seconds=61)) == 1


async def test_consuming_reads_no_team_key(db, registry, team_key) -> None:
    verify = verifier(registry)
    signing, signature = owner_act(team_key, issued=datetime.now(UTC))
    prepared = await verify.prepare(signing, signature, team_id=TEAM_ID)
    assert verify.key_reads == 1
    async with db.transaction() as tx:
        act = await verify.consume_in(tx, prepared, expected_subject=SUBJECT)
    assert verify.key_reads == 1
    assert isinstance(act, VerifiedOwnerAct)


async def test_a_prepared_act_is_not_authority(registry, team_key) -> None:
    verify = verifier(registry)
    signing, signature = owner_act(team_key, issued=datetime.now(UTC))
    prepared = await verify.prepare(signing, signature, team_id=TEAM_ID)
    assert isinstance(prepared, PreparedOwnerAct)
    assert not isinstance(prepared, VerifiedOwnerAct)
    assert prepared.act_name == "hook-binding.activate"
    for name in ("subject", "nonce", "team_id", "fields", "audience"):
        assert not hasattr(prepared, name)


async def test_an_act_prepared_by_another_verifier_is_refused(db, registry, team_key) -> None:
    signing, signature = owner_act(team_key, issued=datetime.now(UTC))
    prepared = await verifier(registry).prepare(signing, signature, team_id=TEAM_ID)
    async with db.transaction() as tx:
        with pytest.raises(Refused) as refused:
            await verifier(registry).consume_in(tx, prepared, expected_subject=SUBJECT)
    assert refused.value.code == "verifier_misconfigured"


async def test_a_prepared_act_past_its_expiry_is_not_consumed(db, registry, team_key) -> None:
    issued = datetime.now(UTC).replace(microsecond=0)
    expires = issued + timedelta(minutes=5)
    moment = [expires - timedelta(seconds=30)]
    verify = verifier(registry, clock=lambda: moment[0])
    signing, signature = owner_act(team_key, issued=issued)
    prepared = await verify.prepare(signing, signature, team_id=TEAM_ID)
    moment[0] = expires + timedelta(seconds=1)
    async with db.transaction() as tx:
        with pytest.raises(Refused) as refused:
            await verify.consume_in(tx, prepared, expected_subject=SUBJECT)
    assert refused.value.code == "expired"
    assert await effects(db) == 0


async def test_a_pruned_act_cannot_be_consumed_again(db, registry, team_key) -> None:
    issued = datetime.now(UTC).replace(microsecond=0)
    moment = [issued]
    verify = verifier(registry, clock=lambda: moment[0])
    signing, signature = owner_act(team_key, issued=issued)
    prepared = await verify.prepare(signing, signature, team_id=TEAM_ID)
    async with db.transaction() as tx:
        await verify.consume_in(tx, prepared, expected_subject=SUBJECT)
    moment[0] = issued + timedelta(minutes=5, seconds=61)
    assert await prune_owner_act_nonces(db, now=moment[0]) == 1
    # Held minutes after prepare, the act no longer proves the current team
    # key, and it has expired too: the first of those refusals applies.
    async with db.transaction() as tx:
        with pytest.raises(Refused) as refused:
            await verify.consume_in(tx, prepared, expected_subject=SUBJECT)
    assert refused.value.code == "owner_required"


async def test_a_prepared_act_older_than_the_key_bound_is_refused(db, registry, team_key) -> None:
    issued = datetime.now(UTC)
    moment = [issued]
    verify = verifier(registry, clock=lambda: moment[0])
    signing, signature = owner_act(team_key, issued=issued)
    prepared = await verify.prepare(signing, signature, team_id=TEAM_ID)
    moment[0] = issued + timedelta(seconds=61)
    async with db.transaction() as tx:
        with pytest.raises(Refused) as refused:
            await verify.consume_in(tx, prepared, expected_subject=SUBJECT)
    assert refused.value.code == "owner_required"
    assert await effects(db) == 0
    moment[0] = issued + timedelta(seconds=60)
    async with db.transaction() as tx:
        await verify.consume_in(tx, prepared, expected_subject=SUBJECT)
