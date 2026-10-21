"""Containment uses the real ancestry, B2 revocations and custody in one PG transaction."""

import asyncio
import os

import pytest
from aweb_naapp.runtime.approvals import ApprovalState
from aweb_naapp_testing.owner_acts import INSTALLATION_ID

from aweb_secrets import containment, derived_lineage, records
from aweb_secrets.custody import CustodyUnavailable, SealContext, encode_value
from tests.test_change_sets import TEAM, world  # noqa: F401
from tests.test_use_approval_lineage import child, request_child, seed
from tests.test_use_approvals import SECRET_ID, approve, uses  # noqa: F401


async def seal(context, secret_id):
    async with context.world.db.transaction() as tx:
        version = await context.world.custody.sealer.ingest(
            tx,
            installation_id=INSTALLATION_ID,
            team_id=TEAM,
            secret_id=secret_id,
            value=encode_value("bearer", {"value": os.urandom(24).hex()}),
        )
    return SealContext(
        installation_id=INSTALLATION_ID,
        team_id=TEAM,
        secret_id=secret_id,
        version=version,
    )


async def disable(context, tx, secret_id=SECRET_ID):
    await context.world.fence.admit(tx, context.grant)
    return await containment.disable_secret_tree(
        tx,
        context.approvals,
        context.world.custody,
        installation_id=INSTALLATION_ID,
        team_id=TEAM,
        secret_id=secret_id,
        revoked_by="containment-owner",
    )


async def test_disable_cascades_custody_and_pending_and_approved_descendants(uses):  # noqa: F811
    await seed(uses)
    first, _ = await child(uses)
    grandchild, _ = await child(uses, secret_id="sec_grand001", parent=first.secret_id)
    unrelated, _ = await child(uses, secret_id="sec_unrelated1")
    pending = await request_child(uses, first)
    decided = await request_child(uses, grandchild)
    await approve(uses, decided[2], "finance@acme.com")
    untouched = await request_child(uses, unrelated)
    contexts = [await seal(uses, item.secret_id) for item in (first, grandchild, unrelated)]
    async with uses.world.db.transaction() as tx:
        affected = await disable(uses, tx, first.secret_id)
    assert set(affected) == {first.secret_id, grandchild.secret_id}
    for context in contexts[:2]:
        with pytest.raises(CustodyUnavailable):
            await uses.world.custody.opener.open(context)
    assert await uses.world.custody.opener.open(contexts[2]) is not None
    for item in (pending, decided):
        assert (
            await uses.approvals.get(item[2].pending.approval.approval_id)
        ).state == ApprovalState.REVOKED
    assert (
        await uses.approvals.get(untouched[2].pending.approval.approval_id)
    ).state == ApprovalState.PENDING
    async with uses.world.db.transaction() as tx:
        assert (
            await records.secret_by_ref(tx, INSTALLATION_ID, TEAM, unrelated.ref)
        ).state == "active"


async def test_disable_and_approval_revocation_roll_back_together(uses):  # noqa: F811
    await seed(uses)
    first, _ = await child(uses)
    pending = await request_child(uses, first)
    context = await seal(uses, first.secret_id)
    with pytest.raises(RuntimeError):
        async with uses.world.db.transaction() as tx:
            await disable(uses, tx, first.secret_id)
            raise RuntimeError("local commit aborted")
    assert (
        await uses.approvals.get(pending[2].pending.approval.approval_id)
    ).state == ApprovalState.PENDING
    assert await uses.world.custody.opener.open(context) is not None


@pytest.mark.parametrize("insert_first", [True, False])
async def test_concurrent_child_is_selected_or_refused(uses, insert_first):  # noqa: F811
    await seed(uses)
    db = uses.world.db
    if insert_first:
        added, _ = await child(uses)
        async with db.transaction() as tx:
            assert added.secret_id in await disable(uses, tx)
    else:
        task = None
        try:
            async with db.transaction() as tx:
                await uses.world.fence.admit(tx, uses.grant)
                await derived_lineage.lock_ancestry(tx, INSTALLATION_ID, TEAM, SECRET_ID)
                holder = await tx.fetch_value("SELECT pg_backend_pid()")
                task = asyncio.create_task(child(uses))
                async with asyncio.timeout(5):
                    while not await db.fetch_value(
                        "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
                        holder,
                    ):
                        await asyncio.sleep(0.01)
                await disable(uses, tx)
            with pytest.raises(derived_lineage.LineageRefused) as refused:
                await asyncio.wait_for(task, 5)
            assert refused.value.code == "secret_disabled"
            assert (
                await db.fetch_value(
                    "SELECT count(*) FROM {{tables.secrets}} WHERE secret_id='sec_child001'"
                )
                == 0
            )
        finally:
            if task is not None and not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)


async def test_replacement_voids_old_version_approvals_and_disables_children_only(uses):  # noqa: F811
    await seed(uses)
    first, _ = await child(uses)
    pending = await request_child(uses, first)
    async with uses.world.db.transaction() as tx:
        await uses.world.fence.admit(tx, uses.grant)
        affected = await containment.replace_value_consequences(
            tx,
            uses.approvals,
            uses.world.custody,
            installation_id=INSTALLATION_ID,
            team_id=TEAM,
            secret_id=SECRET_ID,
            current_version=5,
            revoked_by="confirming-owner",
        )
        await records.set_active_version(tx, INSTALLATION_ID, TEAM, SECRET_ID, 5)
    assert set(affected) == {SECRET_ID, first.secret_id}
    assert (
        await uses.approvals.get(pending[2].pending.approval.approval_id)
    ).state == ApprovalState.REVOKED
    async with uses.world.db.transaction() as tx:
        root = await records.secret_by_ref(tx, INSTALLATION_ID, TEAM, "staging-api")
    assert (root.state, root.active_version) == ("active", 5)


async def test_kill_switch_is_installation_scoped_and_survives_authority_refresh(uses):  # noqa: F811
    await seed(uses)
    first, _ = await child(uses)
    async with uses.world.db.transaction() as tx:
        await uses.world.fence.admit(tx, uses.grant)
        affected = await containment.disable_installation(
            tx,
            uses.approvals,
            uses.world.custody,
            installation_id=INSTALLATION_ID,
            team_id=TEAM,
            revoked_by="owner",
        )
    assert set(affected) == {SECRET_ID, first.secret_id}
    await uses.world.fence.refresh(TEAM)
    async with uses.world.db.transaction() as tx:
        with pytest.raises(containment.ContainmentRefused) as refused:
            await containment.require_enabled(tx, INSTALLATION_ID, TEAM)
        assert refused.value.code == "installation_disabled"
        await containment.require_enabled(tx, "different-installation", TEAM)


async def test_kill_switch_refuses_new_admission_and_replay(uses):  # noqa: F811
    from aweb_secrets.admission import AdmissionRefused

    await seed(uses)
    first, _ = await child(uses)
    await request_child(uses, first, request_id="before-kill")
    async with uses.world.db.transaction() as tx:
        await uses.world.fence.admit(tx, uses.grant)
        await containment.disable_installation(
            tx,
            uses.approvals,
            uses.world.custody,
            installation_id=INSTALLATION_ID,
            team_id=TEAM,
            revoked_by="owner",
        )
    for request_id in ("before-kill", "after-kill"):
        with pytest.raises(AdmissionRefused) as refused:
            await request_child(uses, first, request_id=request_id)
        assert refused.value.code == "installation_disabled"


async def test_overlapping_replacements_lock_siblings_before_requested_child(uses):  # noqa: F811
    from tests.test_containment_service import service

    await seed(uses)
    sibling, _ = await child(uses, secret_id="sec_000000")
    requested, _ = await child(uses, secret_id="sec_000001")
    svc = await service(uses)
    db = uses.world.db

    async def prepare():
        async with db.transaction() as tx:
            await uses.world.fence.admit(tx, uses.grant)
            await svc.prepare_replacements(
                tx,
                installation_id=INSTALLATION_ID,
                team_id=TEAM,
                secret_ids=(SECRET_ID, requested.secret_id),
            )

    task = None
    try:
        async with db.transaction() as holder:
            await holder.fetch_value(
                "SELECT secret_id FROM {{tables.secrets}} WHERE secret_id=$1 FOR UPDATE",
                sibling.secret_id,
            )
            pid = await holder.fetch_value("SELECT pg_backend_pid()")
            task = asyncio.create_task(prepare())
            async with asyncio.timeout(5):
                while not await db.fetch_value(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
                    pid,
                ):
                    await asyncio.sleep(0.01)
            # Canonical order must reach the earlier sibling before it takes
            # the requested child lock, despite that child being an input root.
            async with db.transaction() as observer:
                assert (
                    await observer.fetch_value(
                        "SELECT secret_id FROM {{tables.secrets}} WHERE secret_id=$1 FOR UPDATE NOWAIT",
                        requested.secret_id,
                    )
                    == requested.secret_id
                )
        await asyncio.wait_for(task, 5)
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
