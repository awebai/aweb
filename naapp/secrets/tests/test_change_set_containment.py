"""Actual owner confirmations share S14's forest locks and atomic consequences."""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime, timedelta

import asyncpg
import pytest
from aweb_naapp.roles import hold_role
from aweb_naapp.runtime.approvals import ApprovalState
from aweb_naapp_testing.owner_acts import INSTALLATION_ID

from aweb_secrets.change import ChangeRefused
from aweb_secrets.containment import disable_installation, disable_secret_tree
from aweb_secrets.custody import CustodyUnavailable, SealContext, encode_value
from aweb_secrets.owners import OWNER_ROLE, approver_scope, owner_scope
from aweb_secrets.revisions import config_revision
from aweb_secrets.secret import SecretRecord
from aweb_secrets.tokens import TokenKey
from tests.governance import view
from tests.test_change_sets import ALICE, CAROL, TEAM, by_member, change_set, decide, draft
from tests.test_change_sets import world as _world
from tests.test_containment_console import login_session
from tests.test_use_approval_lineage import child, request_child, seed
from tests.test_use_approvals import SECRET
from tests.test_use_approvals import uses as _uses

world = _world
uses = _uses


async def seal(w, record):
    async with w.db.transaction() as tx:
        version = await w.custody.sealer.ingest(
            tx,
            installation_id=INSTALLATION_ID,
            team_id=TEAM,
            secret_id=record.secret_id,
            value=encode_value(record.kind, {"value": os.urandom(24).hex()}),
        )
    return SealContext(INSTALLATION_ID, TEAM, record.secret_id, version)


async def forest(uses):
    await seed(uses)
    root = SecretRecord.from_after(SECRET)
    for _ in range(4):
        old = await seal(uses.world, root)
    descendant, _ = await child(uses)
    await seal(uses.world, descendant)
    return root, descendant, old


def value_item(root, version):
    return {
        "kind": "secret_value",
        "op": "create",
        "ref": root.ref,
        "after": {"v": 1, "secret_ref": root.ref, "version": version},
    }


async def pending_change(w, changes, sealed=()):
    change = change_set(
        drafter=by_member(CAROL),
        changes=changes,
        base_revision=await config_revision(w.db, INSTALLATION_ID),
    )
    approval_id = await draft(w, change, sealed)
    await decide(w, approval_id, "alice@acme.com")
    return change, approval_id


async def confirm(w, tx, change):
    return await w.change_sets.confirm(
        tx,
        change["change_id"],
        operation_id=f"apply-{change['change_id']}",
        fence=w.fence,
        admitted=w.admitted,
        governance_view=view(),
    )


@pytest.mark.parametrize("rollback,rename", [(False, False), (True, False), (False, True)])
async def test_replacement_consequences_commit_with_activation_and_never_evict_early(
    uses, rollback, rename
):
    w = uses.world
    root, descendant, old = await forest(uses)
    use_ids = [
        (await request_child(uses, record))[2].pending.approval.approval_id
        for record in (root, descendant)
    ]
    replacement = await seal(w, root)
    changed = SecretRecord.from_after({**root.after, "ref": "renamed-root"}) if rename else root
    changes = (
        [{"kind": "secret", "op": "update", "ref": changed.ref, "after": dict(changed.after)}]
        if rename
        else []
    )
    changes.append(value_item(changed, replacement.version))
    change, approval_id = await pending_change(w, changes, [replacement])
    key = TokenKey(
        INSTALLATION_ID, TEAM, root.secret_id, old.version, "https://api.example/token", ""
    )
    await w.containment.tokens.put(
        key, os.urandom(24).hex(), datetime.now(UTC) + timedelta(hours=1)
    )

    class Rollback(Exception):
        pass

    try:
        async with w.db.transaction() as tx:
            result = await confirm(w, tx, change)
            assert set(result.affected_secret_ids) == {root.secret_id, descendant.secret_id}
            assert (
                await w.db.fetch_value(
                    "SELECT active_version FROM {{tables.secrets}} WHERE secret_id=$1",
                    root.secret_id,
                )
                == old.version
            )
            assert all(
                [(await uses.approvals.get(a)).state is ApprovalState.PENDING for a in use_ids]
            )
            assert await w.containment.tokens.get(key) is not None
            if rollback:
                raise Rollback
    except Rollback:
        if not rollback:
            raise
    assert await w.db.fetch_value(
        "SELECT active_version FROM {{tables.secrets}} WHERE secret_id=$1",
        root.secret_id,
    ) == (old.version if rollback else replacement.version)
    assert await w.db.fetch_value(
        "SELECT state FROM {{tables.secrets}} WHERE secret_id=$1",
        descendant.secret_id,
    ) == ("active" if rollback else "disabled")
    assert (await w.approvals.get(approval_id)).state is (
        ApprovalState.APPROVED if rollback else ApprovalState.CONSUMED
    )
    for approval in use_ids:
        assert (await uses.approvals.get(approval)).state is (
            ApprovalState.PENDING if rollback else ApprovalState.REVOKED
        )
    # Eviction is caller-owned postcommit cleanup, never a transaction side effect.
    assert await w.containment.tokens.get(key) is not None
    if rollback:
        await w.custody.opener.open(old)
    else:
        with pytest.raises(CustodyUnavailable):
            await w.custody.opener.open(old)
    await w.custody.opener.open(replacement)


async def test_confirmed_reenable_enables_only_selected_display_ref(uses):
    w = uses.world
    root, descendant, old = await forest(uses)
    async with w.db.transaction() as tx:
        await w.fence.check(tx, w.admitted)
        await disable_secret_tree(
            tx,
            w.approvals,
            w.custody,
            installation_id=INSTALLATION_ID,
            team_id=TEAM,
            secret_id=root.secret_id,
            revoked_by="owner",
        )
    after = {"v": 1, "target_kind": "secret", "target_ref": root.ref}
    change, _ = await pending_change(
        w, [{"kind": "reenable", "op": "enable", "ref": root.ref, "after": after}]
    )
    async with w.db.transaction() as tx:
        result = await confirm(w, tx, change)
    assert result.affected_secret_ids == (root.secret_id,)
    await w.custody.opener.open(old)
    assert (
        await w.db.fetch_value(
            "SELECT state FROM {{tables.secrets}} WHERE secret_id=$1",
            descendant.secret_id,
        )
        == "disabled"
    )
    with pytest.raises(CustodyUnavailable):
        await w.custody.opener.open(SealContext(INSTALLATION_ID, TEAM, descendant.secret_id, 1))


async def test_actual_confirmation_prelocks_forest_before_consuming_its_approval(uses):
    w = uses.world
    root, descendant, _ = await forest(uses)
    replacement = await seal(w, root)
    change, confirmation_id = await pending_change(
        w, [value_item(root, replacement.version)], [replacement]
    )
    use_ids = [
        (await request_child(uses, record))[2].pending.approval.approval_id
        for record in (root, descendant)
    ]
    low, *later = sorted([confirmation_id, *use_ids])
    scope = approver_scope(INSTALLATION_ID, TEAM, "finance")
    holder = await w.passkeys.designated_approver(scope)
    session = await login_session(
        w, owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did), w.devices["alice@acme.com"]
    )
    started = asyncio.get_running_loop().create_future()

    async def apply():
        async with w.db.transaction() as tx:
            started.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
            return await confirm(w, tx, change)

    task = None
    try:
        async with w.db.transaction() as retirement:
            await w.fence.check(retirement, w.admitted)
            owner = await w.directory.owner_of(retirement, session.scope)
            assert owner == ALICE and await hold_role(retirement, owner, OWNER_ROLE)
            prepared = await w.credential_audit.prepare_containment(
                retirement, admitted=w.admitted, session=session
            )
            pid = await retirement.fetch_value("SELECT pg_backend_pid()")
            await retirement.fetch_value(
                "SELECT approval_id FROM {{tables.approvals}} WHERE approval_id=$1 FOR UPDATE",
                low,
            )
            task = asyncio.create_task(apply())
            applying = await asyncio.wait_for(started, 5)
            async with asyncio.timeout(5):
                while pid not in await w.db.fetch_value("SELECT pg_blocking_pids($1)", applying):
                    if task.done():
                        await task
                        pytest.fail("confirmation finished before its blocked forest prelock")
                    await asyncio.sleep(0.01)
            # Whichever real ID sorts first blocks before every later approval.
            async with w.db.transaction() as observer:
                unlocked = await observer.fetch_all(
                    "SELECT approval_id FROM {{tables.approvals}}"
                    " WHERE approval_id=ANY($1::text[]) ORDER BY approval_id FOR UPDATE NOWAIT",
                    later,
                )
                assert {row["approval_id"] for row in unlocked} == set(later)
            for record in (root, descendant):
                with pytest.raises(asyncpg.exceptions.LockNotAvailableError):
                    async with w.db.transaction() as observer:
                        await observer.fetch_value(
                            "SELECT secret_id FROM {{tables.secrets}} WHERE secret_id=$1 FOR UPDATE NOWAIT",
                            record.secret_id,
                        )
            with w.credential_audit.prepared(prepared):
                await w.passkeys.retire_in(
                    retirement, scope=scope, subject=holder.subject, authorized_by=session.subject
                )
            await w.fence.check(retirement, w.admitted)
            assert session.expires_at > datetime.now(UTC)
        result = await asyncio.wait_for(task, 10)
        assert set(result.affected_secret_ids) == {root.secret_id, descendant.secret_id}
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


async def test_actual_child_reenable_does_not_lock_child_during_ref_discovery(uses):
    w = uses.world
    root, descendant, _ = await forest(uses)
    async with w.db.transaction() as tx:
        await w.fence.check(tx, w.admitted)
        await disable_secret_tree(
            tx,
            w.approvals,
            w.custody,
            installation_id=INSTALLATION_ID,
            team_id=TEAM,
            secret_id=descendant.secret_id,
            revoked_by="owner",
        )
    after = {"v": 1, "target_kind": "secret", "target_ref": descendant.ref}
    change, _ = await pending_change(
        w,
        [
            {
                "kind": "reenable",
                "op": "enable",
                "ref": descendant.ref,
                "after": after,
            }
        ],
    )
    started = asyncio.get_running_loop().create_future()

    async def apply():
        async with w.db.transaction() as tx:
            started.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
            return await confirm(w, tx, change)

    task = None
    try:
        async with w.db.transaction() as holder:
            pid = await holder.fetch_value("SELECT pg_backend_pid()")
            await holder.fetch_value(
                "SELECT secret_id FROM {{tables.secrets}} WHERE secret_id=$1 FOR UPDATE",
                root.secret_id,
            )
            task = asyncio.create_task(apply())
            applying = await asyncio.wait_for(started, 5)
            async with asyncio.timeout(5):
                while pid not in await w.db.fetch_value("SELECT pg_blocking_pids($1)", applying):
                    if task.done():
                        await task
                        pytest.fail("confirmation did not wait for its ancestor")
                    await asyncio.sleep(0.01)
            async with w.db.transaction() as observer:
                assert (
                    await observer.fetch_value(
                        "SELECT secret_id FROM {{tables.secrets}} WHERE secret_id=$1 FOR UPDATE NOWAIT",
                        descendant.secret_id,
                    )
                    == descendant.secret_id
                )
        result = await asyncio.wait_for(task, 10)
        assert result.affected_secret_ids == (descendant.secret_id,)
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


async def test_later_ancestry_refusal_rolls_back_replacement_and_all_consequences(uses):
    w = uses.world
    root, descendant, old = await forest(uses)
    pending = (await request_child(uses, descendant))[2]
    use_id = pending.pending.approval.approval_id
    replacement = await seal(w, root)
    change, approval_id = await pending_change(
        w,
        [
            value_item(root, replacement.version),
            {
                "kind": "reenable",
                "op": "enable",
                "ref": descendant.ref,
                "after": {"v": 1, "target_kind": "secret", "target_ref": descendant.ref},
            },
        ],
        [replacement],
    )
    revision = await config_revision(w.db, INSTALLATION_ID)
    with pytest.raises(ChangeRefused):
        async with w.db.transaction() as tx:
            await confirm(w, tx, change)
    assert await config_revision(w.db, INSTALLATION_ID) == revision
    assert (await w.approvals.get(approval_id)).state is ApprovalState.APPROVED
    assert (await uses.approvals.get(use_id)).state is ApprovalState.PENDING
    assert (
        await w.db.fetch_value(
            "SELECT active_version FROM {{tables.secrets}} WHERE secret_id=$1",
            root.secret_id,
        )
        == old.version
    )
    assert (
        await w.db.fetch_value(
            "SELECT state FROM {{tables.secrets}} WHERE secret_id=$1",
            descendant.secret_id,
        )
        == "active"
    )
    await w.custody.opener.open(old)
    await w.custody.opener.open(SealContext(INSTALLATION_ID, TEAM, descendant.secret_id, 1))


async def test_installation_reenable_uses_confirmed_path_and_keeps_secret_flags(uses):
    w = uses.world
    root, descendant, old = await forest(uses)
    async with w.db.transaction() as tx:
        await w.fence.check(tx, w.admitted)
        await disable_secret_tree(
            tx,
            w.approvals,
            w.custody,
            installation_id=INSTALLATION_ID,
            team_id=TEAM,
            secret_id=descendant.secret_id,
            revoked_by="owner",
        )
        await disable_installation(
            tx,
            w.approvals,
            w.custody,
            installation_id=INSTALLATION_ID,
            team_id=TEAM,
            revoked_by="owner",
        )
    change, _ = await pending_change(
        w,
        [
            {
                "kind": "reenable",
                "op": "enable",
                "ref": INSTALLATION_ID,
                "after": {"v": 1, "target_kind": "installation", "target_ref": INSTALLATION_ID},
            }
        ],
    )
    async with w.db.transaction() as tx:
        result = await confirm(w, tx, change)
    assert result.affected_secret_ids == ()
    assert not await w.db.fetch_value(
        "SELECT disabled_at IS NOT NULL FROM {{tables.containment_installations}}"
        " WHERE installation_id=$1 AND team_id=$2",
        INSTALLATION_ID,
        TEAM,
    )
    await w.custody.opener.open(old)
    assert (
        await w.db.fetch_value(
            "SELECT state FROM {{tables.secrets}} WHERE secret_id=$1",
            descendant.secret_id,
        )
        == "disabled"
    )
