"""Human-role holdings keyed by (installation, role, principal), on real PostgreSQL.

A holding is the principal's role assignment in the team together with the
installation's record of it: its B3 scope and the exact certificate retained
for it (human-role-holders.md, Reading a holding).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest
from pgdbm import AsyncDatabaseManager

from aweb_naapp.roles import (
    HoldingRecord,
    PrincipalKey,
    apply_roles_migrations,
    assign,
    begin_holding,
    end_holding,
    hold_holding,
    holding_record_of_scope,
    holding_scope,
    is_holding_scope,
    lock_holding,
    purge_team,
    read_holding,
    read_holding_of_scope,
    refresh_holding_certificate,
)

INSTALLATION = "9d7f1c2e-4b1a-4c55-8f0e-2a6b3c4d5e6f"
OTHER_INSTALLATION = "6f9619ff-8b86-4011-b42d-00c04fc964ff"
TEAM = "aweb:example.com"
PRINCIPAL = "did:aw:2Wq7mXn4kP9rT1vY5zA8bC3dE6"
READER = "logs.reader"
CERTIFICATE = b'{"certificate_id":"cert-1"}'
RENEWED = b'{"certificate_id":"cert-2"}'
KEY = dict(installation_id=INSTALLATION, team_id=TEAM, role=READER, principal=PRINCIPAL)


@pytest.fixture
async def db(test_db_factory) -> AsyncIterator[AsyncDatabaseManager]:
    database = await test_db_factory.create_db(suffix="naapp_holdings")
    await apply_roles_migrations(database)
    yield database


async def _begin(db: AsyncDatabaseManager, certificate: bytes | None = CERTIFICATE):
    async with db.transaction() as tx:
        return await begin_holding(tx, **KEY, certificate=certificate)


async def _end(db: AsyncDatabaseManager) -> bool:
    async with db.transaction() as tx:
        return await end_holding(tx, **KEY)


async def test_a_begun_holding_reads_with_its_scope_certificate_and_version(
    db: AsyncDatabaseManager,
) -> None:
    begun = await _begin(db)
    assert begun is not None
    async with db.transaction() as tx:
        held = await read_holding(tx, **KEY)
    assert held == begun
    assert held.b3_scope == holding_scope(INSTALLATION, TEAM, READER, PRINCIPAL)
    assert held.certificate == CERTIFICATE


async def test_a_held_role_cannot_be_begun_again(db: AsyncDatabaseManager) -> None:
    first = await _begin(db)
    assert await _begin(db, RENEWED) is None
    async with db.transaction() as tx:
        assert await read_holding(tx, **KEY) == first


async def test_an_ended_holding_reads_as_none_and_ends_once(db: AsyncDatabaseManager) -> None:
    await _begin(db)
    assert await _end(db)
    assert not await _end(db)
    async with db.transaction() as tx:
        assert await read_holding(tx, **KEY) is None


async def test_holding_again_after_an_end_is_a_new_version_of_the_same_scope(
    db: AsyncDatabaseManager,
) -> None:
    first = await _begin(db)
    await _end(db)
    second = await _begin(db, RENEWED)
    assert first is not None and second is not None
    assert second.b3_scope == first.b3_scope
    assert second.held_since > first.held_since
    assert second.certificate == RENEWED


async def test_ending_and_holding_again_in_one_transaction_changes_the_version(
    db: AsyncDatabaseManager,
) -> None:
    first = await _begin(db)
    async with db.transaction() as tx:
        assert await end_holding(tx, **KEY)
        second = await begin_holding(tx, **KEY, certificate=RENEWED)
    assert first is not None and second is not None
    assert second.held_since != first.held_since


async def test_a_holding_belongs_to_its_installation(db: AsyncDatabaseManager) -> None:
    await _begin(db)
    async with db.transaction() as tx:
        assert await read_holding(tx, **{**KEY, "installation_id": OTHER_INSTALLATION}) is None


async def test_a_bare_role_assignment_is_not_a_holding(db: AsyncDatabaseManager) -> None:
    async with db.transaction() as tx:
        await assign(tx, PrincipalKey(TEAM, PRINCIPAL), READER)
        assert await read_holding(tx, **KEY) is None
        assert await hold_holding(tx, **KEY) is None


async def test_a_holding_without_a_retained_certificate_is_still_a_holding(
    db: AsyncDatabaseManager,
) -> None:
    begun = await _begin(db, None)
    assert begun is not None and begun.certificate is None


async def test_locking_a_holding_keeps_its_version(db: AsyncDatabaseManager) -> None:
    begun = await _begin(db)
    async with db.transaction() as tx:
        assert await lock_holding(tx, **KEY) == begun


async def test_a_purged_team_holds_nothing(db: AsyncDatabaseManager) -> None:
    await _begin(db)
    async with db.transaction() as tx:
        await purge_team(tx, TEAM)
        assert await read_holding(tx, **KEY) is None


async def test_a_held_holding_blocks_its_writers_until_the_holder_commits(
    db: AsyncDatabaseManager,
) -> None:
    await _begin(db)
    started: asyncio.Future[int] = asyncio.get_running_loop().create_future()

    async def writer() -> bool:
        async with db.transaction() as tx:
            started.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
            return await end_holding(tx, **KEY)

    ending = None
    try:
        async with db.transaction() as tx:
            assert await hold_holding(tx, **KEY) is not None
            holder = await tx.fetch_value("SELECT pg_backend_pid()")
            ending = asyncio.create_task(writer())
            pid = await asyncio.wait_for(started, 5)
            async with asyncio.timeout(5):
                while holder not in await db.fetch_value("SELECT pg_blocking_pids($1)", pid):
                    assert not ending.done(), "the writer ended a held holding"
                    await asyncio.sleep(0.01)
        assert await asyncio.wait_for(ending, 5)
    finally:
        if ending is not None and not ending.done():
            ending.cancel()
            await asyncio.gather(ending, return_exceptions=True)


@pytest.mark.parametrize("principal", ["did:key:z6MkfirstKey", "did:aw:"])
async def test_only_a_did_aw_principal_holds_a_human_role(
    db: AsyncDatabaseManager, principal: str
) -> None:
    async with db.transaction() as tx:
        with pytest.raises(ValueError):
            await begin_holding(tx, **{**KEY, "principal": principal}, certificate=CERTIFICATE)


async def _refresh(db: AsyncDatabaseManager, held_since, certificate: bytes) -> bool:
    async with db.transaction() as tx:
        return await refresh_holding_certificate(
            tx, **KEY, held_since=held_since, certificate=certificate
        )


async def test_a_refresh_replaces_the_retained_certificate_of_the_same_holding(
    db: AsyncDatabaseManager,
) -> None:
    begun = await _begin(db)
    assert begun is not None
    assert await _refresh(db, begun.held_since, RENEWED)
    async with db.transaction() as tx:
        held = await read_holding(tx, **KEY)
    assert held is not None
    assert (held.certificate, held.held_since) == (RENEWED, begun.held_since)


async def test_a_refresh_for_an_earlier_holding_writes_nothing(db: AsyncDatabaseManager) -> None:
    first = await _begin(db)
    await _end(db)
    second = await _begin(db)
    assert first is not None and second is not None
    assert not await _refresh(db, first.held_since, RENEWED)
    async with db.transaction() as tx:
        held = await read_holding(tx, **KEY)
    assert held is not None and held.certificate == CERTIFICATE


async def test_a_refresh_of_an_ended_holding_writes_nothing(db: AsyncDatabaseManager) -> None:
    begun = await _begin(db)
    await _end(db)
    assert begun is not None
    assert not await _refresh(db, begun.held_since, RENEWED)


async def test_concurrent_refreshes_of_one_holding_both_apply_in_turn(
    db: AsyncDatabaseManager,
) -> None:
    begun = await _begin(db)
    assert begun is not None
    other = b'{"certificate_id":"cert-3"}'
    results = await asyncio.gather(
        _refresh(db, begun.held_since, RENEWED), _refresh(db, begun.held_since, other)
    )
    assert results == [True, True]
    async with db.transaction() as tx:
        held = await read_holding(tx, **KEY)
    assert held is not None and held.certificate in (RENEWED, other)


async def test_a_scope_that_was_ever_held_stays_a_holding_scope(db: AsyncDatabaseManager) -> None:
    scope = holding_scope(INSTALLATION, TEAM, READER, PRINCIPAL)
    other = holding_scope(OTHER_INSTALLATION, TEAM, READER, PRINCIPAL)
    assert not await is_holding_scope(db, scope)
    await _begin(db)
    await _end(db)
    assert await is_holding_scope(db, scope)
    assert not await is_holding_scope(db, other)


async def test_a_current_holding_reads_by_its_scope(db: AsyncDatabaseManager) -> None:
    begun = await _begin(db)
    assert begun is not None
    async with db.transaction() as tx:
        assert await read_holding_of_scope(tx, begun.b3_scope) == begun


async def test_a_scope_reads_its_current_version_and_nothing_once_ended(
    db: AsyncDatabaseManager,
) -> None:
    scope = holding_scope(INSTALLATION, TEAM, READER, PRINCIPAL)
    await _begin(db)
    await _end(db)
    async with db.transaction() as tx:
        assert await read_holding_of_scope(tx, scope) is None
    again = await _begin(db, RENEWED)
    async with db.transaction() as tx:
        assert await read_holding_of_scope(tx, scope) == again


async def test_a_scope_reads_only_its_own_holding(db: AsyncDatabaseManager) -> None:
    await _begin(db)
    async with db.transaction() as tx:
        await assign(tx, PrincipalKey(TEAM, "did:aw:9Zx8yW7vU6tS5rQ4pO3nM2lK1j"), READER)
        assert await read_holding_of_scope(tx, "unknown") is None
        assert (
            await read_holding_of_scope(
                tx, holding_scope(OTHER_INSTALLATION, TEAM, READER, PRINCIPAL)
            )
            is None
        )
        assert (
            await read_holding_of_scope(
                tx, holding_scope(INSTALLATION, TEAM, READER, "did:aw:9Zx8yW7vU6tS5rQ4pO3nM2lK1j")
            )
            is None
        )


async def test_a_purged_team_holds_nothing_by_scope(db: AsyncDatabaseManager) -> None:
    begun = await _begin(db)
    assert begun is not None
    async with db.transaction() as tx:
        await purge_team(tx, TEAM)
        assert await read_holding_of_scope(tx, begun.b3_scope) is None


async def test_a_scope_names_its_record_while_held_and_after_it_ends(
    db: AsyncDatabaseManager,
) -> None:
    scope = holding_scope(INSTALLATION, TEAM, READER, PRINCIPAL)
    record = HoldingRecord(**KEY, b3_scope=scope)
    async with db.transaction() as tx:
        assert await holding_record_of_scope(tx, scope) is None
    await _begin(db)
    async with db.transaction() as tx:
        assert await holding_record_of_scope(tx, scope) == record
        assert await end_holding(tx, **KEY)
        assert await holding_record_of_scope(tx, scope) == record
    async with db.transaction() as tx:
        assert await holding_record_of_scope(tx, scope) == record
        assert (
            await holding_record_of_scope(
                tx, holding_scope(OTHER_INSTALLATION, TEAM, READER, PRINCIPAL)
            )
            is None
        )
        await purge_team(tx, TEAM)
        assert await holding_record_of_scope(tx, scope) is None
