"""Containment uses the real ancestry, B2 revocations and custody in one PG transaction."""

import asyncio
import os

import pytest
from aweb_naapp.roles import hold_role, principal_key
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


@pytest.mark.parametrize("mode", ["child", "forest", "confirmation"])
async def test_reverse_id_replacement_and_approver_retirement_do_not_deadlock(uses, mode):  # noqa: F811
    """Real B3 retirement holds the lower ID while S10 prepares its whole forest."""
    import json
    import uuid
    from datetime import timedelta

    from aweb_secrets.owners import OWNER_ROLE, approver_scope
    from aweb_secrets.secret import SecretRecord
    from tests.test_containment_service import service
    from tests.test_use_approval_lineage import grant_record
    from tests.test_use_approvals import REQUESTER, SECRET

    source = await seed(uses)
    db = uses.world.db
    first = SecretRecord.from_after(SECRET)
    second = SecretRecord.from_after({**SECRET, "secret_id": "sec_other001", "ref": "other-root"})
    async with db.transaction() as tx:
        digest = await tx.fetch_value(
            "SELECT policy_digest FROM {{tables.grants}} WHERE grant_id=$1", source
        )
        await records.create_secret(tx, INSTALLATION_ID, TEAM, second)
        await records.set_active_version(tx, INSTALLATION_ID, TEAM, second.secret_id, 4)
        await records.create_grant(
            tx, INSTALLATION_ID, TEAM, grant_record("grt_other001", second.secret_id, digest)
        )
        await tx.execute(
            "UPDATE {{tables.approvers}} SET covers=$1 WHERE approver_ref='finance'",
            json.dumps([first.secret_id, second.secret_id]),
        )
    pairs = []
    for secret in (first, second):
        pending = await request_child(uses, secret)
        await approve(uses, pending[2], "finance@acme.com")
        pairs.append((pending[2].pending.approval.approval_id, secret))
    (low_id, low), (high_id, high) = sorted(pairs, key=lambda pair: pair[0])
    # Establish immutable lineage after bootstrap using the generated IDs to
    # choose direction. This guarantees reverse root/child IDs without replacing
    # randomness or mocking either approval/custody implementation.
    if mode == "child":
        async with db.transaction() as tx:
            source_row = await tx.fetch_one(
                "SELECT grant_id,policy_digest FROM {{tables.grants}} WHERE secret_id=$1",
                high.secret_id,
            )
            now = uses.clock()
            await derived_lineage.record_lineage(
                tx,
                installation_id=INSTALLATION_ID,
                team_id=TEAM,
                secret_id=low.secret_id,
                parent_secret_id=high.secret_id,
                parent_version=4,
                source_dispatch_id=str(uuid.uuid4()),
                source_grant_id=source_row["grant_id"],
                issuing_principal=REQUESTER.did_aw,
                policy_digest=source_row["policy_digest"],
                dispatch_started_at=now,
                upstream_expires_at=now + timedelta(hours=1),
                expires_at=now + timedelta(minutes=30),
                clock=uses.clock,
            )
    roots = (high, low) if mode == "forest" else (high,)
    svc = await service(uses)
    scope = approver_scope(INSTALLATION_ID, TEAM, "finance")
    holder = await uses.world.passkeys.designated_approver(scope)
    started = asyncio.get_running_loop().create_future()

    async def replace_values():
        async with db.transaction() as tx:
            started.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
            # S10 confirmation uses the real shared fence check, not a newly
            # exclusive admission lock that would hide the B2 lock inversion.
            await uses.world.fence.check(tx, uses.world.admitted)
            await svc.prepare_replacements(
                tx,
                installation_id=INSTALLATION_ID,
                team_id=TEAM,
                secret_ids=tuple(secret.secret_id for secret in roots),
                approval_ids=(low_id,) if mode == "confirmation" else (),
            )
            for root in roots:
                await svc.replacement_consequences(
                    tx,
                    old=SealContext(
                        installation_id=INSTALLATION_ID,
                        team_id=TEAM,
                        secret_id=root.secret_id,
                        version=4,
                    ),
                    new=SealContext(
                        installation_id=INSTALLATION_ID,
                        team_id=TEAM,
                        secret_id=root.secret_id,
                        version=5,
                    ),
                    revoked_by="confirming-owner",
                )

    task = None
    try:
        async with db.transaction() as retirement:
            blocker = await retirement.fetch_value("SELECT pg_backend_pid()")
            await uses.world.fence.check(retirement, uses.world.admitted)
            assert await hold_role(retirement, principal_key(REQUESTER), OWNER_ROLE)
            prepared = await uses.world.credential_audit.prepare_containment(
                retirement, admitted=uses.world.admitted, principal=REQUESTER
            )
            await retirement.fetch_value(
                "SELECT approval_id FROM {{tables.approvals}} WHERE approval_id=$1 FOR UPDATE",
                low_id,
            )
            task = asyncio.create_task(replace_values())
            pid = await asyncio.wait_for(started, 5)
            async with asyncio.timeout(5):
                while blocker not in await db.fetch_value("SELECT pg_blocking_pids($1)", pid):
                    await asyncio.sleep(0.01)
                with uses.world.credential_audit.prepared(prepared):
                    await uses.world.passkeys.retire_in(
                        retirement,
                        scope=scope,
                        subject=holder.subject,
                        authorized_by=principal_key(REQUESTER).principal_did,
                    )
            await uses.world.fence.check(retirement, uses.world.admitted)
        await asyncio.wait_for(task, 5)
        for approval_id in (low_id, high_id):
            assert (await uses.approvals.get(approval_id)).state == ApprovalState.REVOKED
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


async def test_reenable_locks_parent_before_writing_child(uses):  # noqa: F811
    from tests.test_containment_service import service

    await seed(uses)
    first, _ = await child(uses)
    svc = await service(uses)
    async with uses.world.db.transaction() as tx:
        await disable(uses, tx, first.secret_id)
    db = uses.world.db

    async def enable():
        async with db.transaction() as tx:
            await uses.world.fence.check(tx, uses.world.admitted)
            await svc.reenable(
                tx,
                installation_id=INSTALLATION_ID,
                team_id=TEAM,
                target_kind="secret",
                target_ref=first.ref,
            )

    task = None
    try:
        async with db.transaction() as holder:
            blocker = await holder.fetch_value("SELECT pg_backend_pid()")
            await holder.fetch_value(
                "SELECT secret_id FROM {{tables.secrets}} WHERE secret_id=$1 FOR UPDATE",
                SECRET_ID,
            )
            task = asyncio.create_task(enable())
            async with asyncio.timeout(5):
                while not await db.fetch_value(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
                    blocker,
                ):
                    await asyncio.sleep(0.01)
            async with db.transaction() as observer:
                assert (
                    await observer.fetch_value(
                        "SELECT secret_id FROM {{tables.secrets}} WHERE secret_id=$1 FOR UPDATE NOWAIT",
                        first.secret_id,
                    )
                    == first.secret_id
                )
        await asyncio.wait_for(task, 5)
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


async def test_replacement_keeps_current_root_version_and_revokes_all_descendant_versions(uses):  # noqa: F811
    from aweb_secrets.secret import SecretRecord
    from tests.test_containment_service import service
    from tests.test_use_approvals import SECRET

    await seed(uses)
    root = SecretRecord.from_after(SECRET)
    first, _ = await child(uses)
    old_root = await request_child(uses, root)
    child_v1 = await request_child(uses, first)
    async with uses.world.db.transaction() as tx:
        await records.set_active_version(tx, INSTALLATION_ID, TEAM, first.secret_id, 2)
    child_v2 = await request_child(uses, first)
    async with uses.world.db.transaction() as tx:
        await records.set_active_version(tx, INSTALLATION_ID, TEAM, SECRET_ID, 5)
    current_root = await request_child(uses, root)
    svc = await service(uses)
    async with uses.world.db.transaction() as tx:
        await uses.world.fence.check(tx, uses.world.admitted)
        await svc.prepare_replacements(
            tx,
            installation_id=INSTALLATION_ID,
            team_id=TEAM,
            secret_ids=(SECRET_ID,),
        )
        await svc.replacement_consequences(
            tx,
            old=SealContext(INSTALLATION_ID, TEAM, SECRET_ID, 4),
            new=SealContext(INSTALLATION_ID, TEAM, SECRET_ID, 5),
            revoked_by="owner",
        )
    for item in (old_root, child_v1, child_v2):
        assert (
            await uses.approvals.get(item[2].pending.approval.approval_id)
        ).state == ApprovalState.REVOKED
    assert (
        await uses.approvals.get(current_root[2].pending.approval.approval_id)
    ).state == ApprovalState.PENDING
