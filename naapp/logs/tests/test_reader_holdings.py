"""The readers of a team's log are the current holders of ``logs.reader``
(human-role-holders.md): a principal the owner names by a human-role act, whose
bound credential can sign in. A console session holds only the holding's B3
scope, and the directory answers from the holding store on every request, on
real PostgreSQL with real owner acts."""

from __future__ import annotations

from aweb_naapp.roles import holding_scope
from aweb_naapp_testing.owner_acts import INSTALLATION_ID, TEAM_ID

from aweb_logs.readers import is_reader_scope

from .reader_world import (
    OTHER_READER,
    READER,
    World,
    held_reader,
    reader_scope,
    replaced_reader,
    revoked_reader,
    world_fixture,  # noqa: F401
)


async def test_a_held_reader_reads_its_own_installation_and_team(world: World) -> None:
    scope, _ = await held_reader(world)
    reader = await world.directory.reader(scope)
    assert reader is not None
    assert (reader.scope, reader.installation_id, reader.team_id, reader.principal) == (
        scope,
        INSTALLATION_ID,
        TEAM_ID,
        READER,
    )
    assert await world.directory.is_current_reader(scope)


async def test_a_holding_scope_is_a_reader_scope() -> None:
    assert is_reader_scope(reader_scope())
    assert not is_reader_scope(
        holding_scope(INSTALLATION_ID, TEAM_ID, "secrets.owner", READER)
    )


async def test_a_scope_no_one_holds_is_no_reader(world: World) -> None:
    await held_reader(world)
    never = reader_scope(OTHER_READER)
    assert await world.directory.reader(never) is None
    assert not await world.directory.is_current_reader(never)


async def test_a_revoked_reader_is_no_reader(world: World) -> None:
    scope, _ = await held_reader(world)
    await revoked_reader(world)
    assert await world.directory.reader(scope) is None
    assert not await world.directory.is_current_reader(scope)


async def test_a_reader_held_again_after_revocation_reads_again(world: World) -> None:
    scope, first = await held_reader(world)
    await revoked_reader(world)
    again, second = await held_reader(world)
    assert again == scope and second != first
    assert await world.directory.is_current_reader(scope)


async def test_a_reader_whose_credential_is_being_replaced_cannot_read(world: World) -> None:
    """From a replace until its cooling-off ends, no credential can sign in, so
    the holding admits no session, though it still exists."""
    scope, _ = await held_reader(world)
    await replaced_reader(world)
    assert await world.directory.reader(scope) is None
    assert not await world.directory.is_current_reader(scope)


async def test_a_reader_of_an_inactive_installation_reads_nothing(world: World) -> None:
    scope, _ = await held_reader(world)
    await world.db.execute(
        "UPDATE {{tables.installation_fences}} SET state = 'inactive' WHERE team_id = $1",
        TEAM_ID,
    )
    assert await world.directory.reader(scope) is None
    assert not await world.directory.is_current_reader(scope)


async def test_one_readers_scope_reads_only_that_reader(world: World) -> None:
    scope, _ = await held_reader(world)
    other, _ = await held_reader(world, OTHER_READER)
    assert scope != other
    first, second = await world.directory.reader(scope), await world.directory.reader(other)
    assert first is not None and second is not None
    assert (first.principal, second.principal) == (READER, OTHER_READER)
