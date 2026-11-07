"""The B3 challenge context of one installation, read from the shared F6 record
on real PostgreSQL: the app's binding names the installation, the fence says
whether it is the app's active, fresh and unretired installation of that team."""

from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from aweb_naapp.runtime.authorization import Grant
from aweb_naapp.runtime.clock import seconds_to_ns
from aweb_naapp.runtime.installation import InstallationFence, apply_installation_migrations
from aweb_naapp.runtime.passkeys import (
    PasskeyInstallationContext,
    ProofContextUnavailable,
    installation_context,
)

TEAM = "demo:example.com"
APP = "fixture"
INSTALLATION = "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b"
GENERATION = 3


class Source:
    def __init__(self) -> None:
        self.grant = Grant(
            team_id=TEAM,
            installation_id=INSTALLATION,
            generation=GENERATION,
            scopes=frozenset({"fixture:read"}),
            fresh_until=time.monotonic_ns() + seconds_to_ns(55),
        )

    async def grant_for(self, team_id, certificate_id=None):
        return self.grant if team_id == TEAM else None

    async def status_for(self, team_id):
        if team_id != TEAM:
            return None
        return SimpleNamespace(
            team_id=TEAM,
            app_id=APP,
            state="active",
            installation_id=INSTALLATION,
            generation=GENERATION,
            granted_scopes=self.grant.scopes,
            fresh_until=self.grant.fresh_until,
        )


@pytest.fixture
async def db(test_db_factory):
    database = await test_db_factory.create_db(suffix="installation_context")
    await apply_installation_migrations(database)
    source = Source()
    fence = InstallationFence(database, app_id=APP, grants=source)
    async with database.transaction() as tx:
        await fence.admit(tx, source.grant)
    return database


async def test_the_active_fresh_installation_is_the_context_and_takes_no_authority_locks(db):
    async with db.transaction() as tx:
        context = await installation_context(
            tx, app_id=APP, team_id=TEAM, installation_id=INSTALLATION
        )
        assert context == PasskeyInstallationContext(APP, TEAM, INSTALLATION, GENERATION)
        assert not await tx.fetch_value(
            "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=pg_backend_pid() AND granted "
            "AND locktype IN ('relation','advisory') AND mode<>'AccessShareLock')"
        )


@pytest.mark.parametrize(
    "change", ["stale", "inactive", "retired", "wrong_app", "wrong_team", "wrong_installation"]
)
async def test_an_unusable_installation_is_never_a_context(db, change):
    named = {"app_id": APP, "team_id": TEAM, "installation_id": INSTALLATION}
    async with db.transaction() as tx:
        if change == "stale":
            await tx.execute(
                "UPDATE {{tables.installation_fences}}"
                " SET fresh_until=clock_timestamp()-interval '1 second'"
            )
        elif change == "inactive":
            await tx.execute("UPDATE {{tables.installation_fences}} SET state='inactive'")
        elif change == "retired":
            await tx.execute(
                "INSERT INTO {{tables.retired_installation_fences}}"
                " (app_id,team_id,installation_id) VALUES($1,$2,$3)",
                APP,
                TEAM,
                INSTALLATION,
            )
        elif change == "wrong_app":
            named["app_id"] = "another-app"
        elif change == "wrong_team":
            named["team_id"] = "other:example.com"
        else:
            named["installation_id"] = "6f9619ff-8b86-4011-b42d-00c04fc964ff"
    with pytest.raises(ProofContextUnavailable):
        async with db.transaction() as tx:
            await installation_context(tx, **named)
