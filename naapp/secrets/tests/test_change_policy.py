"""The installation's four-eyes setting for change sets (decision 61), on real PostgreSQL.

Requiring four eyes is applied directly; relaxing it only through a confirmed
change set. While four eyes is required, the installation keeps at least two
enrolled owners, so a change set can always still be confirmed.
"""

from __future__ import annotations

import asyncio

import pytest
from aweb_naapp.roles import has_role, unassign
from aweb_naapp_testing.owner_acts import INSTALLATION_ID

from aweb_secrets.change import ChangeRefused
from aweb_secrets.change_policy import (
    apply_change_policy_migrations,
    four_eyes,
    keep_four_eyes_owners,
    relax_four_eyes,
    require_four_eyes,
)
from aweb_secrets.owners import OWNER_ROLE
from aweb_secrets.revisions import apply_revision_migrations, config_revision
from tests.test_owner_directory import ALICE, BOB, TEAM, World, designate_owner, world  # noqa: F401


@pytest.fixture
async def settings(world: World) -> World:  # noqa: F811
    await apply_revision_migrations(world.db)
    await apply_change_policy_migrations(world.db)
    return world


async def _require(owners: World) -> None:
    async with owners.db.transaction() as tx:
        await require_four_eyes(
            tx, installation_id=INSTALLATION_ID, team_id=TEAM, directory=owners.directory
        )


async def _revoke_owner(owners: World, principal) -> None:
    """An owner's role is revoked, in the order withdrawal locks take: role first."""
    async with owners.db.transaction() as tx:
        await unassign(tx, principal, OWNER_ROLE)
        await keep_four_eyes_owners(
            tx, installation_id=INSTALLATION_ID, team_id=TEAM, directory=owners.directory
        )


async def test_four_eyes_is_off_until_an_owner_requires_it(settings: World) -> None:
    assert await four_eyes(settings.db, INSTALLATION_ID) == "not_required"


async def test_requiring_four_eyes_takes_two_enrolled_owners(settings: World) -> None:
    await designate_owner(settings, ALICE, "alice@acme.com")
    with pytest.raises(ChangeRefused) as refused:
        await _require(settings)
    assert refused.value.code == "four_eyes_needs_two_owners"
    assert await four_eyes(settings.db, INSTALLATION_ID) == "not_required"
    await designate_owner(settings, BOB, "bob@acme.com")
    before = await config_revision(settings.db, INSTALLATION_ID)
    await _require(settings)
    assert await four_eyes(settings.db, INSTALLATION_ID) == "required"
    assert await config_revision(settings.db, INSTALLATION_ID) == before + 1


async def test_relaxing_four_eyes_turns_it_off(settings: World) -> None:
    await designate_owner(settings, ALICE, "alice@acme.com")
    await designate_owner(settings, BOB, "bob@acme.com")
    await _require(settings)
    async with settings.db.transaction() as tx:
        await relax_four_eyes(tx, installation_id=INSTALLATION_ID)
    assert await four_eyes(settings.db, INSTALLATION_ID) == "not_required"


async def test_while_four_eyes_is_required_the_second_last_owner_stays(settings: World) -> None:
    await designate_owner(settings, ALICE, "alice@acme.com")
    await designate_owner(settings, BOB, "bob@acme.com")
    await _require(settings)
    with pytest.raises(ChangeRefused) as refused:
        await _revoke_owner(settings, ALICE)
    assert refused.value.code == "four_eyes_needs_two_owners"
    assert await has_role(settings.db, ALICE, OWNER_ROLE)


async def test_without_four_eyes_an_owner_can_be_revoked(settings: World) -> None:
    await designate_owner(settings, ALICE, "alice@acme.com")
    await designate_owner(settings, BOB, "bob@acme.com")
    await _revoke_owner(settings, ALICE)
    assert not await has_role(settings.db, ALICE, OWNER_ROLE)


async def _revoke_and_hold(owners: World, principal, held: asyncio.Event) -> None:
    """Revoke an owner, keeping the transaction open until ``held`` is set."""
    async with owners.db.transaction() as tx:
        await unassign(tx, principal, OWNER_ROLE)
        await keep_four_eyes_owners(
            tx, installation_id=INSTALLATION_ID, team_id=TEAM, directory=owners.directory
        )
        await held.wait()


async def test_requiring_while_an_owner_is_revoked_waits_and_is_refused(settings: World) -> None:
    await designate_owner(settings, ALICE, "alice@acme.com")
    await designate_owner(settings, BOB, "bob@acme.com")
    # The setting already exists, so only its row lock can serialise the two.
    await _require(settings)
    async with settings.db.transaction() as tx:
        await relax_four_eyes(tx, installation_id=INSTALLATION_ID)
    held = asyncio.Event()
    revoking = asyncio.create_task(_revoke_and_hold(settings, ALICE, held))
    await asyncio.sleep(0.2)
    requiring = asyncio.create_task(_require(settings))
    await asyncio.sleep(0.2)
    held.set()
    await revoking
    with pytest.raises(ChangeRefused) as refused:
        await requiring
    assert refused.value.code == "four_eyes_needs_two_owners"
    assert await four_eyes(settings.db, INSTALLATION_ID) == "not_required"
