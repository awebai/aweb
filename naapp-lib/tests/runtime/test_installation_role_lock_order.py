"""The real installation fence and role hold/withdraw paths share lock order."""

from __future__ import annotations

import asyncio
import time

import pytest

from aweb_naapp import roles
from aweb_naapp.runtime.authorization import Grant
from aweb_naapp.runtime.installation import (
    InstallationFence,
    InstallationRefused,
    apply_installation_migrations,
)

TEAM = "demo:example.com"
ROLE = "fixture.approver"
PRINCIPAL = roles.PrincipalKey(team_id=TEAM, principal_did="did:aw:member")


class AuthorityOutsideTransaction:
    async def grant_for(self, team_id):
        raise AssertionError("authority reads must precede the transaction")

    async def status_for(self, team_id):
        raise AssertionError("authority reads must precede the transaction")


def grant(installation_id, generation):
    return Grant(
        team_id=TEAM, installation_id=installation_id, generation=generation,
        scopes=frozenset({"fixture:write"}), fresh_until=time.monotonic() + 60,
    )


@pytest.mark.parametrize("first", ["staging", "retirement"])
async def test_role_hold_and_installation_retirement_do_not_deadlock(test_db_factory, first):
    db = await test_db_factory.create_db(suffix="installation_role_order")
    await apply_installation_migrations(db)
    await roles.apply_roles_migrations(db)
    await db.execute("CREATE TABLE fixture_stage_evidence (installation_id TEXT NOT NULL)")
    staging_attempting = asyncio.Event()
    staging_holds = asyncio.Event()
    retirement_attempting = asyncio.Event()
    retirement_locked = asyncio.Event()
    retired = asyncio.Event()

    async def on_retire(tx, team_id):
        # F6 already holds the installation UPDATE lock when this runs.
        retirement_locked.set()
        if first == "retirement":
            await staging_attempting.wait()
            await asyncio.sleep(0.05)
        await roles.purge_team(tx, team_id)

    fence = InstallationFence(
        db, app_id="fixture", grants=AuthorityOutsideTransaction(), on_retire=on_retire,
    )
    async with db.transaction() as tx:
        admitted = await fence.admit(tx, grant("old-installation", 1))
        await roles.assign(tx, PRINCIPAL, ROLE)

    async def stage():
        if first == "retirement":
            await retirement_locked.wait()
        staging_attempting.set()
        async with db.transaction() as tx:
            try:
                await fence.check(tx, admitted)
            except InstallationRefused as exc:
                assert first == "retirement"
                assert exc.code == "generation_superseded"
                return "refused"
            assert await roles.hold_role(tx, PRINCIPAL, ROLE)
            staging_holds.set()
            if first == "staging":
                await retirement_attempting.wait()
                await asyncio.sleep(0.05)
                assert not retired.is_set()
            await tx.execute("INSERT INTO fixture_stage_evidence VALUES ($1)", admitted.installation_id)
        return "committed"

    async def retire():
        if first == "staging":
            await staging_holds.wait()
        retirement_attempting.set()
        async with db.transaction() as tx:
            current = await fence.admit(tx, grant("new-installation", 2))
        retired.set()
        return current

    # Either the earlier stage commits while its role remains held, or the
    # earlier withdrawal prevents staging. Neither ordering may deadlock.
    stage_result, current = await asyncio.wait_for(asyncio.gather(stage(), retire()), 5)
    assert current.installation_id == "new-installation"
    assert not await roles.has_role(db, PRINCIPAL, ROLE)
    assert stage_result == ("committed" if first == "staging" else "refused")
    assert await db.fetch_value("SELECT count(*) FROM fixture_stage_evidence") == (first == "staging")
