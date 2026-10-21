"""X9's transactional installation fence on real PostgreSQL.

The source here implements B1's protocol for store tests. The real remote-source
integration belongs to the G1/F6 end-to-end path, once G1-c3 lands.
"""

from __future__ import annotations

import asyncio
import time
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest

from aweb_naapp.dispatch import Dispatches, State, apply_dispatch_migrations
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
        self.state = "active"
        self.app_id = APP

    async def grant_for(self, team_id):
        self.calls += 1
        if isinstance(self.current, Exception):
            raise self.current
        return self.current

    async def status_for(self, team_id):
        current = await self.grant_for(team_id)
        if current is None:
            return None
        return SimpleNamespace(
            team_id=current.team_id, app_id=self.app_id, state=self.state,
            installation_id=current.installation_id, generation=current.generation,
            granted_scopes=current.scopes, fresh_until=current.fresh_until,
        )


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
    source.state = "uninstalled"
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
    source.state = "uninstalled"
    await fence.refresh(TEAM)
    with pytest.raises(InstallationRefused) as exc:
        await check(db, fence, admitted)
    assert (exc.value.code, exc.value.status) == ("installation_inactive", 403)
    with pytest.raises(InstallationRefused):
        await admit(db, fence, grant())


async def test_reinstall_cannot_revive_old_identity(db, setup):
    fence, source = setup
    old = await admit(db, fence, source.current)
    source.current = grant("installation-2", generation=2)
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
    with pytest.raises(InstallationRefused) as exc:
        await fence.refresh(TEAM)
    assert exc.value.code == "installation_inactive"
    source.current = grant(generation=2)
    await fence.refresh(TEAM)
    current = await admit(db, fence, source.current)
    await check(db, fence, current)
    with pytest.raises(InstallationRefused) as exc:
        await check(db, fence, old)
    assert exc.value.code == "generation_superseded"


async def test_an_old_replica_key_denial_cannot_permanently_disable_the_current_generation(db, setup):
    old_fence, old_source = setup
    await admit(db, old_fence, old_source.current)
    current_source = Source(grant(generation=2))
    current_fence = InstallationFence(db, app_id=APP, grants=current_source)
    current = await admit(db, current_fence, current_source.current)
    # During an ordinary rolling update the old digest's key is denied after
    # the new replica already observed generation 2 in the shared database.
    old_source.current = None
    for _ in range(3):
        with pytest.raises(InstallationRefused) as exc:
            await old_fence.refresh(TEAM)
        assert exc.value.code == "installation_inactive"
        # No refresh by the healthy replica is needed to restore shared state.
        await check(db, current_fence, current)
    await check(db, current_fence, current)


async def test_late_cached_observation_of_an_unseen_old_id_cannot_retire_the_new_id(db, setup):
    # The old replica fetched before uninstall/reinstall, but its observation
    # reaches the shared fence after the new installation was first recorded.
    old_source = Source(grant("unseen-old-installation"))
    old_fence = InstallationFence(db, app_id=APP, grants=old_source)
    fence, source = setup
    source.current = grant("current-installation", generation=2)
    await fence.refresh(TEAM)
    admitted = await admit(db, fence, source.current)
    with pytest.raises(InstallationRefused) as exc:
        await old_fence.refresh(TEAM)
    assert exc.value.code == "generation_superseded"
    # Bounded remote staleness must not permanently tombstone the healthy ID.
    await fence.refresh(TEAM)
    await check(db, fence, admitted)


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


@pytest.fixture
async def hooked(db):
    # An app-owned authority hook with real transactional effects. The actual
    # roles.purge_team integration is checked separately once S5 lands.
    await db.execute("CREATE TABLE fixture_authority (team_id TEXT NOT NULL)")
    await db.execute("CREATE TABLE fixture_retirements (old_id TEXT)")

    async def on_retire(tx, team_id):
        old_id = await tx.fetch_value(
            "SELECT active_installation_id FROM {{tables.installation_fences}} WHERE team_id = $1 AND app_id = $2", team_id, APP,
        )
        await tx.execute("INSERT INTO fixture_retirements VALUES ($1)", old_id)
        await tx.execute("DELETE FROM fixture_authority WHERE team_id = $1", team_id)

    source = Source(grant())
    fence = InstallationFence(db, app_id=APP, grants=source, on_retire=on_retire)
    return fence, source, on_retire


async def test_confirmed_uninstall_retires_and_invokes_the_hook_once(db, hooked):
    fence, source, _ = hooked
    await admit(db, fence, source.current)
    await db.execute("INSERT INTO fixture_authority VALUES ($1)", TEAM)
    source.state = "uninstalled"
    await fence.refresh(TEAM)
    await fence.refresh(TEAM)
    assert await db.fetch_value("SELECT count(*) FROM fixture_authority") == 0
    assert await db.fetch_value("SELECT count(*) FROM fixture_retirements") == 1
    for generation in (1, 2, 99):
        source.state = "active"
        source.current = grant(generation=generation)
        with pytest.raises(InstallationRefused) as exc:
            await fence.refresh(TEAM)
        assert exc.value.code == "installation_inactive"


async def test_confirmed_uninstall_purges_authority_even_without_a_local_fence_row(db, hooked):
    fence, source, _ = hooked
    await db.execute("INSERT INTO fixture_authority VALUES ($1)", TEAM)
    source.state = "uninstalled"
    await fence.refresh(TEAM)
    assert await db.fetch_value("SELECT count(*) FROM fixture_authority") == 0
    assert await db.fetch_value("SELECT count(*) FROM fixture_retirements") == 1
    with pytest.raises(InstallationRefused) as exc:
        await admit(db, fence, source.current)
    assert exc.value.code == "installation_inactive"


async def test_a_down_app_retires_old_authority_before_admitting_a_reinstall(db, hooked):
    fence, source, hook = hooked
    await admit(db, fence, source.current)
    await db.execute("INSERT INTO fixture_authority VALUES ($1)", TEAM)
    # A restarted replica never observed the remote uninstall, but shares the
    # durable prior ID. Retirement and hook effects precede the new admission.
    restarted = InstallationFence(db, app_id=APP, grants=source, on_retire=hook)
    new = await admit(db, restarted, grant("installation-2", generation=2))
    assert new.installation_id == "installation-2"
    assert await db.fetch_value("SELECT count(*) FROM fixture_authority") == 0
    assert await db.fetch_value("SELECT old_id FROM fixture_retirements") == "installation-1"


async def test_retirement_hook_failure_rolls_back_both_authority_and_new_identity(db, hooked):
    fence, source, hook = hooked
    await admit(db, fence, source.current)
    await db.execute("INSERT INTO fixture_authority VALUES ($1)", TEAM)

    async def failing_hook(tx, team_id):
        await hook(tx, team_id)
        raise RuntimeError("authority cleanup failed")

    failing = InstallationFence(db, app_id=APP, grants=source, on_retire=failing_hook)
    with pytest.raises(RuntimeError, match="cleanup failed"):
        await admit(db, failing, grant("installation-2", generation=2))
    assert await db.fetch_value("SELECT installation_id FROM {{tables.installation_fences}}") == "installation-1"
    assert await db.fetch_value("SELECT count(*) FROM fixture_authority") == 1
    assert await db.fetch_value("SELECT count(*) FROM fixture_retirements") == 0
    assert await db.fetch_value("SELECT count(*) FROM {{tables.retired_installation_fences}}") == 0


@pytest.mark.parametrize("state", ["pending_origin_verification", "unknown_future_state"])
async def test_nonterminal_inactive_state_keeps_authority_and_recovers_same_generation(db, hooked, state):
    fence, source, _ = hooked
    admitted = await admit(db, fence, source.current)
    await db.execute("INSERT INTO fixture_authority VALUES ($1)", TEAM)
    source.state = state
    await fence.refresh(TEAM)
    with pytest.raises(InstallationRefused) as exc:
        await check(db, fence, admitted)
    assert exc.value.code == "installation_inactive"
    assert await db.fetch_value("SELECT count(*) FROM fixture_authority") == 1
    assert await db.fetch_value("SELECT count(*) FROM fixture_retirements") == 0
    source.state = "active"
    await fence.refresh(TEAM)
    await check(db, fence, admitted)


async def test_denied_replica_key_never_runs_the_retirement_hook_or_accepts_lower_generation(db, hooked):
    fence, source, _ = hooked
    await admit(db, fence, grant(generation=2))
    await db.execute("INSERT INTO fixture_authority VALUES ($1)", TEAM)
    source.current = None
    with pytest.raises(InstallationRefused) as exc:
        await fence.refresh(TEAM)
    assert exc.value.code == "installation_inactive"
    assert await db.fetch_value("SELECT count(*) FROM fixture_authority") == 1
    assert await db.fetch_value("SELECT count(*) FROM fixture_retirements") == 0
    source.current = grant(generation=1)
    with pytest.raises(InstallationRefused) as exc:
        await fence.refresh(TEAM)
    assert exc.value.code == "generation_superseded"


async def test_delayed_uninstall_of_a_retired_id_cannot_purge_the_new_installations_authority(db, hooked):
    fence, source, _ = hooked
    await admit(db, fence, source.current)
    new = await admit(db, fence, grant("installation-2", generation=2))
    await db.execute("INSERT INTO fixture_authority VALUES ($1)", TEAM)
    source.state = "uninstalled"  # A delayed observation of installation-1.
    with pytest.raises(InstallationRefused) as exc:
        await fence.refresh(TEAM)
    assert exc.value.code == "generation_superseded"
    assert await db.fetch_value("SELECT count(*) FROM fixture_authority") == 1
    assert await db.fetch_value("SELECT count(*) FROM fixture_retirements") == 1
    await check(db, fence, new)


@pytest.mark.parametrize("state", ["pending_origin_verification", "unknown_future_state"])
async def test_higher_generation_pending_replacement_keeps_old_authority_until_active(db, hooked, state):
    fence, source, _ = hooked
    await admit(db, fence, source.current)
    await db.execute("INSERT INTO fixture_authority VALUES ($1)", TEAM)
    source.current = grant("installation-2", generation=2)
    source.state = state
    await fence.refresh(TEAM)
    assert await db.fetch_value("SELECT count(*) FROM fixture_authority") == 1
    assert await db.fetch_value("SELECT count(*) FROM fixture_retirements") == 0
    with pytest.raises(InstallationRefused) as exc:
        await admit(db, fence, grant())
    assert exc.value.code == "generation_superseded"
    source.state = "active"
    await fence.refresh(TEAM)
    assert await db.fetch_value("SELECT count(*) FROM fixture_authority") == 0
    assert await db.fetch_value("SELECT old_id FROM fixture_retirements") == "installation-1"
    await check(db, fence, await admit(db, fence, source.current))


async def test_equal_generation_with_a_different_id_is_an_authority_error_without_writes(db, hooked):
    fence, source, _ = hooked
    admitted = await admit(db, fence, source.current)
    before = dict(await db.fetch_one("SELECT * FROM {{tables.installation_fences}}"))
    source.current = grant("inconsistent-id", generation=1)
    for state in ("active", "pending_origin_verification", "uninstalled"):
        source.state = state
        with pytest.raises(InstallationRefused) as exc:
            await fence.refresh(TEAM)
        assert (exc.value.code, exc.value.status) == ("authority_unavailable", 503)
        assert dict(await db.fetch_one("SELECT * FROM {{tables.installation_fences}}")) == before
        assert await db.fetch_value("SELECT count(*) FROM fixture_retirements") == 0
        await check(db, fence, admitted)


@pytest.mark.parametrize("state", ["active", "pending_origin_verification", "unknown_future_state", "uninstalled"])
async def test_lower_generation_observation_has_no_shared_effects(db, hooked, state):
    fence, source, _ = hooked
    admitted = await admit(db, fence, grant("current-installation", generation=2))
    await db.execute("INSERT INTO fixture_authority VALUES ($1)", TEAM)
    before = dict(await db.fetch_one("SELECT * FROM {{tables.installation_fences}}"))
    source.current = grant("unseen-old-installation", generation=1)
    source.state = state
    with pytest.raises(InstallationRefused) as exc:
        await fence.refresh(TEAM)
    assert (exc.value.code, exc.value.status) == ("generation_superseded", 409)
    assert dict(await db.fetch_one("SELECT * FROM {{tables.installation_fences}}")) == before
    assert await db.fetch_value("SELECT count(*) FROM fixture_authority") == 1
    assert await db.fetch_value("SELECT count(*) FROM fixture_retirements") == 0
    await check(db, fence, admitted)


async def test_admission_lock_wait_deducts_freshness_only_once(db, setup):
    fence, source = setup
    await admit(db, fence, source.current)
    async with db.transaction() as holder:
        await holder.fetch_one("SELECT * FROM {{tables.installation_fences}} FOR UPDATE")
        current = grant(generation=2, ttl=1.2)
        admission = asyncio.create_task(admit(db, fence, current))
        # The grant stays fresh, but a clock projected before this wait plus
        # the post-wait remaining lifetime would already be in the past.
        await asyncio.sleep(0.75)
        assert not admission.done()
    admitted = await asyncio.wait_for(admission, 2)
    remaining = current.fresh_until - time.monotonic()
    stored = await db.fetch_value(
        "SELECT extract(epoch FROM fresh_until - clock_timestamp()) FROM {{tables.installation_fences}}"
    )
    assert remaining > 0
    assert stored > 0
    assert abs(float(stored) - remaining) < 0.15
    await check(db, fence, admitted)


async def test_real_s3_admission_and_dispatch_take_the_installation_fence_first(db, setup):
    fence, source = setup
    await apply_dispatch_migrations(db)

    async def on_transition(tx, transition):
        pass

    dispatches = Dispatches(
        on_transition=on_transition,
        max_dispatch=timedelta(seconds=30), sweep_margin=timedelta(seconds=30),
    )
    async def run_round(round_number):
        action = f"fixture:write:{round_number}"
        running, newcomer = uuid4(), uuid4()
        async with db.transaction() as tx:
            for dispatch_id in (running, newcomer):
                await dispatches.create(tx, dispatch_id=dispatch_id, subject=TEAM, action=action)
        admitted_fence = fence.for_admission(source.current)
        async with db.transaction() as tx:
            await dispatches.admit(tx, running, fence=admitted_fence)

        admission_prepared = asyncio.Event()
        new_fence = fence.for_admission(source.current)

        class HoldAdmission:
            async def prepare(self, tx):
                await new_fence.prepare(tx)
                admission_prepared.set()
                # Keep F6's real UPDATE lock before S3 asks for the pair lock.
                # With the reversed order, dispatch holds the pair while it
                # waits for this row, and admission waits for that pair.
                await asyncio.sleep(0.1)

            async def check(self, tx, dispatch):
                await new_fence.check(tx, dispatch)

        async def admission():
            async with db.transaction() as tx:
                await dispatches.admit(tx, newcomer, fence=HoldAdmission())

        async def dispatch():
            await admission_prepared.wait()
            async with db.transaction() as tx:
                await dispatches.begin_dispatch(
                    tx, running, fence=fence.for_installation(admitted_fence.admitted),
                )

        # Unexpected exceptions, including PostgreSQL deadlock_detected, fail
        # the test. Both real operations must commit for every fresh pair.
        await asyncio.wait_for(asyncio.gather(admission(), dispatch()), 5)
        async with db.transaction() as tx:
            assert (await dispatches.get(tx, newcomer)).state is State.ADMITTED
            assert (await dispatches.get(tx, running)).state is State.DISPATCHING
            await fence.check(tx, new_fence.admitted)

    for round_number in range(10):
        await run_round(round_number)
