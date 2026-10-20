"""X9's transactional installation fence on real PostgreSQL.

The source here implements B1's protocol for store tests. The real remote-source
integration belongs to the G1/F6 end-to-end path, once G1-c3 lands.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from aweb_naapp.runtime.authorization import Grant, GrantUnavailable
from aweb_naapp.runtime.installation import (
    InstallationFence,
    InstallationRefused,
    apply_installation_migrations,
)

TEAM = "demo:example.com"
APP = "fixture"


def grant(installation_id="installation-1", generation=1, *, ttl=60.0, team_id=TEAM):
    return Grant(
        team_id=team_id, installation_id=installation_id, generation=generation,
        scopes=frozenset({"fixture:write"}), fresh_until=time.monotonic() + ttl,
    )


class Source:
    def __init__(self, current):
        self.current = current
        self.calls = 0

    async def grant_for(self, team_id):
        self.calls += 1
        if isinstance(self.current, Exception):
            raise self.current
        return self.current


@pytest.fixture
async def db(test_db_factory):
    db = await test_db_factory.create_db(suffix="installation_fence")
    await apply_installation_migrations(db)
    return db


@pytest.fixture
async def setup(db):
    source = Source(grant())
    return InstallationFence(db, app_id=APP, grants=source), source


async def admit(db, fence, current):
    async with db.transaction() as tx:
        return await fence.admit(tx, current)


async def check(db, fence, admitted):
    async with db.transaction() as tx:
        await fence.check(tx, admitted)


async def test_admission_records_identity_and_check_only_uses_sql(db, setup):
    fence, source = setup
    admitted = await admit(db, fence, source.current)
    assert (admitted.team_id, admitted.app_id, admitted.installation_id, admitted.generation) == (
        TEAM, APP, "installation-1", 1,
    )
    source.current = AssertionError("check must never call the source under the dispatch lock")
    await check(db, fence, admitted)
    assert source.calls == 0


async def test_bound_admission_observes_before_its_lock_free_check_phase(db, setup):
    fence, source = setup
    bound = fence.for_admission(source.current)
    async with db.transaction() as tx:
        await bound.prepare(tx)
        await bound.check(tx, object())
    assert bound.admitted.installation_id == "installation-1"
    source.current = AssertionError("dispatch phases must be SQL only")
    dispatch_fence = fence.for_installation(bound.admitted)
    async with db.transaction() as tx:
        await dispatch_fence.prepare(tx)
        await dispatch_fence.check(tx, object())
    assert source.calls == 0


async def test_bound_check_refuses_if_s3_did_not_prepare_its_transaction(db, setup):
    fence, source = setup
    admitted = await admit(db, fence, source.current)
    bound = fence.for_installation(admitted)
    async with db.transaction() as tx:
        with pytest.raises(InstallationRefused) as exc:
            await bound.check(tx, object())
    assert exc.value.code == "authority_unavailable"


@pytest.mark.parametrize("current", [grant(None, 1), grant("installation-1", None)])
async def test_missing_identity_is_never_synthesized(db, setup, current):
    fence, _ = setup
    with pytest.raises(InstallationRefused) as exc:
        await admit(db, fence, current)
    assert (exc.value.code, exc.value.status) == ("installation_identity_required", 403)


async def test_expired_grant_refuses_admission_and_dispatch(db, setup):
    fence, source = setup
    with pytest.raises(InstallationRefused, match="fresh") as exc:
        await admit(db, fence, grant(ttl=-1))
    assert exc.value.code == "authority_unavailable"
    admitted = await admit(db, fence, source.current)
    await db.execute("UPDATE {{tables.installation_fences}} SET fresh_until = clock_timestamp() - interval '1 second'")
    with pytest.raises(InstallationRefused) as exc:
        await check(db, fence, admitted)
    assert exc.value.code == "authority_unavailable"


async def test_dispatch_stops_at_the_source_freshness_bound_before_refresh(db, setup):
    fence, source = setup
    # G1 permits at most 60 seconds plus its bounded refresh (default 5s).
    # After expiry the SQL check refuses
    # even if no refresh or admission has run, rather than using stale authority.
    source.current = grant(ttl=60)
    admitted = await admit(db, fence, source.current)
    remaining = await db.fetch_value(
        "SELECT extract(epoch FROM fresh_until - clock_timestamp()) FROM {{tables.installation_fences}}"
    )
    assert 0 < remaining <= 60
    source.current = None
    await db.execute(
        "UPDATE {{tables.installation_fences}} SET fresh_until = clock_timestamp() - interval '1 second'"
    )
    with pytest.raises(InstallationRefused) as exc:
        await check(db, fence, admitted)
    assert exc.value.code == "authority_unavailable"
    await fence.refresh(TEAM)
    with pytest.raises(InstallationRefused) as exc:
        await check(db, fence, admitted)
    assert exc.value.code == "installation_inactive"


async def test_admission_refuses_a_source_window_over_60_seconds(db, setup):
    fence, _ = setup
    with pytest.raises(InstallationRefused) as exc:
        await admit(db, fence, grant(ttl=61))
    assert exc.value.code == "authority_unavailable"


async def test_observed_generation_stops_old_dispatch_and_stale_admission(db, setup):
    fence, source = setup
    old = await admit(db, fence, source.current)
    source.current = grant(generation=2)
    await fence.refresh(TEAM)
    for operation in (lambda: check(db, fence, old), lambda: admit(db, fence, grant(generation=1))):
        with pytest.raises(InstallationRefused) as exc:
            await operation()
        assert exc.value.code == "generation_superseded"
    current = await admit(db, fence, source.current)
    await check(db, fence, current)


async def test_uninstall_is_observed_without_any_new_admission(db, setup):
    fence, source = setup
    admitted = await admit(db, fence, source.current)
    source.current = None
    await fence.refresh(TEAM)
    with pytest.raises(InstallationRefused) as exc:
        await check(db, fence, admitted)
    assert (exc.value.code, exc.value.status) == ("installation_inactive", 403)
    with pytest.raises(InstallationRefused):
        await admit(db, fence, grant())


async def test_reinstall_cannot_revive_old_identity(db, setup):
    fence, source = setup
    old = await admit(db, fence, source.current)
    source.current = grant("installation-2")
    await fence.refresh(TEAM)
    current = await admit(db, fence, source.current)
    await check(db, fence, current)
    with pytest.raises(InstallationRefused) as exc:
        await check(db, fence, old)
    assert exc.value.code == "generation_superseded"
    with pytest.raises(InstallationRefused) as exc:
        await admit(db, fence, grant("installation-1", generation=99))
    assert exc.value.code == "installation_inactive"


async def test_a_new_generation_can_recover_after_an_old_digest_key_was_denied(db, setup):
    fence, source = setup
    old = await admit(db, fence, source.current)
    # GrantSource's None also means app_key_not_registered: a new manifest's
    # digest-scoped key can replace the old read key without a reinstall.
    source.current = None
    await fence.refresh(TEAM)
    source.current = grant(generation=2)
    await fence.refresh(TEAM)
    current = await admit(db, fence, source.current)
    await check(db, fence, current)
    with pytest.raises(InstallationRefused) as exc:
        await check(db, fence, old)
    assert exc.value.code == "generation_superseded"


async def test_refresh_failure_invalidates_local_authority_and_recovers(db, setup):
    fence, source = setup
    admitted = await admit(db, fence, source.current)
    source.current = GrantUnavailable("unreachable")
    with pytest.raises(InstallationRefused) as exc:
        await fence.refresh(TEAM)
    assert exc.value.code == "authority_unavailable"
    with pytest.raises(InstallationRefused) as exc:
        await check(db, fence, admitted)
    assert exc.value.code == "authority_unavailable"
    source.current = grant()
    await fence.refresh(TEAM)
    await check(db, fence, admitted)


async def test_source_cannot_return_another_teams_grant(db, setup):
    fence, source = setup
    source.current = grant(team_id="other:example.com")
    with pytest.raises(InstallationRefused) as exc:
        await fence.refresh(TEAM)
    assert exc.value.code == "authority_unavailable"


async def test_admission_observation_rolls_back_with_caller(db, setup):
    fence, source = setup
    with pytest.raises(RuntimeError, match="abort"):
        async with db.transaction() as tx:
            await fence.admit(tx, source.current)
            raise RuntimeError("abort")
    assert await db.fetch_value("SELECT count(*) FROM {{tables.installation_fences}}") == 0


async def test_dispatch_share_lock_serializes_with_observed_generation(db, setup):
    fence, source = setup
    admitted = await admit(db, fence, source.current)
    checked = asyncio.Event()
    release = asyncio.Event()
    refreshed = asyncio.Event()

    async def dispatch():
        async with db.transaction() as tx:
            await fence.check(tx, admitted)
            checked.set()
            await release.wait()

    async def update():
        await checked.wait()
        source.current = grant(generation=2)
        await fence.refresh(TEAM)
        refreshed.set()

    dispatch_task = asyncio.create_task(dispatch())
    update_task = asyncio.create_task(update())
    try:
        await asyncio.wait_for(checked.wait(), 2)
        # A server-side change observed while this local commit is admitted
        # waits for its share lock; that earlier commit is reconciled.
        await asyncio.sleep(0.05)
        assert not refreshed.is_set()
    finally:
        release.set()
        await asyncio.wait_for(asyncio.gather(dispatch_task, update_task), 3)
    with pytest.raises(InstallationRefused) as exc:
        await check(db, fence, admitted)
    assert exc.value.code == "generation_superseded"


async def test_expiry_is_rechecked_after_waiting_for_the_fence_lock(db, setup):
    fence, source = setup
    admitted = await admit(db, fence, source.current)
    await db.execute(
        "UPDATE {{tables.installation_fences}} SET fresh_until = clock_timestamp() + interval '200 milliseconds'"
    )
    started = asyncio.Event()

    async def blocked_check():
        started.set()
        await check(db, fence, admitted)

    async with db.transaction() as tx:
        # Lock without changing the tuple: a projection in the locking query
        # can otherwise retain the pre-wait clock result (the review finding).
        await tx.fetch_one("SELECT * FROM {{tables.installation_fences}} FOR UPDATE")
        contender = asyncio.create_task(blocked_check())
        await started.wait()
        await asyncio.sleep(0.35)
        assert not contender.done()
    with pytest.raises(InstallationRefused) as exc:
        await asyncio.wait_for(contender, 2)
    assert exc.value.code == "authority_unavailable"


async def test_app_fences_do_not_share_installations(db, setup):
    fence, source = setup
    admitted = await admit(db, fence, source.current)
    other = InstallationFence(db, app_id="unrelated", grants=source)
    # Isolate app identity: IDs and generations deliberately match.
    await admit(db, other, source.current)
    await check(db, fence, admitted)
    with pytest.raises(InstallationRefused):
        await check(db, other, admitted)
