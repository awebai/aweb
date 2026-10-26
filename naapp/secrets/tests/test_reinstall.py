"""A retired installation takes its team's role assignments with it (decision 48b),
through the real installation fence and roles.purge_team on real PostgreSQL."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from types import SimpleNamespace

import pytest
from aweb_naapp.roles import (
    PrincipalKey,
    apply_roles_migrations,
    assign,
    has_role,
)
from aweb_naapp.runtime.authorization import Grant
from aweb_naapp.runtime.clock import seconds_to_ns
from aweb_naapp.runtime.installation import InstallationRefused, apply_installation_migrations
from pgdbm import AsyncDatabaseManager

from aweb_secrets.app import installation_fence

TEAM = "backend:acme.com"
OTHER_TEAM = "frontend:acme.com"
APP = "secrets"
OWNER = "secrets.owner"
ALICE = PrincipalKey(team_id=TEAM, principal_did="did:aw:alice")
ELSEWHERE = PrincipalKey(team_id=OTHER_TEAM, principal_did="did:aw:alice")


def _grant(installation_id: str, generation: int, team_id: str = TEAM) -> Grant:
    return Grant(
        team_id=team_id,
        scopes=frozenset({"secrets:use"}),
        fresh_until=time.monotonic_ns() + seconds_to_ns(30),
        installation_id=installation_id,
        generation=generation,
    )


class TeamServer:
    """The team server's answers for one team: its grant and installation state."""

    def __init__(self) -> None:
        self.grant: Grant | None = _grant("inst_old", 1)
        self.state = "active"

    async def grant_for(self, team_id: str, certificate_id: str | None = None) -> Grant | None:
        return self.grant if self.grant is not None and self.grant.team_id == team_id else None

    async def status_for(self, team_id: str):
        grant = await self.grant_for(team_id)
        if grant is None:
            return None
        return SimpleNamespace(
            team_id=grant.team_id,
            app_id=APP,
            state=self.state,
            installation_id=grant.installation_id,
            generation=grant.generation,
            granted_scopes=grant.scopes,
            fresh_until=grant.fresh_until,
        )


@pytest.fixture
async def db(test_db_factory) -> AsyncIterator[AsyncDatabaseManager]:
    database = await test_db_factory.create_db(suffix="secrets_reinstall")
    await apply_installation_migrations(database)
    await apply_roles_migrations(database)
    yield database


@pytest.fixture
def server() -> TeamServer:
    return TeamServer()


@pytest.fixture
async def fence(db, server):
    fence = installation_fence(db, app_id=APP, grants=server)
    async with db.transaction() as tx:
        await fence.admit(tx, _grant("inst_old", 1))
        await assign(tx, ALICE, OWNER)
        await assign(tx, ELSEWHERE, OWNER)
    return fence


async def test_a_reinstall_leaves_none_of_the_old_installations_roles(db, fence) -> None:
    async with db.transaction() as tx:
        await fence.admit(tx, _grant("inst_new", 2))
    assert not await has_role(db, ALICE, OWNER)
    assert await has_role(db, ELSEWHERE, OWNER)


async def test_a_confirmed_uninstall_purges_the_teams_roles(db, fence, server) -> None:
    server.state = "uninstalled"
    await fence.refresh(TEAM)
    assert not await has_role(db, ALICE, OWNER)
    assert await has_role(db, ELSEWHERE, OWNER)


@pytest.mark.parametrize("state", ["pending", "unknown", "disabled"])
async def test_a_status_short_of_uninstalled_purges_nothing(db, fence, server, state) -> None:
    server.state = state
    await fence.refresh(TEAM)
    assert await has_role(db, ALICE, OWNER)


async def test_a_missing_grant_purges_nothing(db, fence, server) -> None:
    server.grant = None
    with pytest.raises(InstallationRefused):
        await fence.refresh(TEAM)
    assert await has_role(db, ALICE, OWNER)


async def test_the_purge_belongs_to_the_retiring_transaction(db, fence) -> None:
    with pytest.raises(RuntimeError):
        async with db.transaction() as tx:
            await fence.admit(tx, _grant("inst_new", 2))
            assert not await has_role(tx, ALICE, OWNER)
            raise RuntimeError("the admission failed later")
    assert await has_role(db, ALICE, OWNER)


async def test_readmitting_the_same_installation_purges_nothing(db, fence) -> None:
    async with db.transaction() as tx:
        await fence.admit(tx, _grant("inst_old", 1))
        await fence.admit(tx, _grant("inst_old", 2))
    assert await has_role(db, ALICE, OWNER)
