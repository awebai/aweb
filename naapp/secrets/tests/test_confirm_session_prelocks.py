"""The complete app union precedes B3/session admission and the whole B2 union."""

import asyncio

import pytest
from aweb_naapp.roles import hold_role
from aweb_naapp_testing.owner_acts import INSTALLATION_ID
from fastapi import HTTPException

from aweb_secrets.human_holders import OwnerPublicScope
from aweb_secrets.jobs import JobDefinition, apply_job_migrations, create_job
from aweb_secrets.owners import OWNER_ROLE
from aweb_secrets.revisions import config_revision
from tests.test_change_set_records import wait_blocked
from tests.test_change_sets import (
    ALICE,
    BOB,
    TEAM,
    change_set,
    draft,
    enrol_owner,
    grant_role,
    on_console,
)
from tests.test_change_sets import world as world
from tests.test_console_changes import application
from tests.test_human_holders import authority
from tests.test_jobs import after
from tests.test_use_approval_lineage import seed
from tests.test_use_approvals import SECRET_ID, request
from tests.test_use_approvals import uses as uses


async def prepare_inputs(context):
    w = context.world
    await seed(context)
    _, _, pending = await request(context)
    associated = pending.pending.approval.approval_id
    await enrol_owner(w, BOB, "bob@acme.com")
    await application(w)
    adapter = authority(w)
    targets = [
        await adapter.session_target(OwnerPublicScope(INSTALLATION_ID, OWNER_ROLE, p.principal_did))
        for p in (ALICE, BOB)
    ]
    pairs = sorted((target.b3_scope, target.subject) for target in targets)
    confirming = await draft(
        w,
        change_set(
            drafter=on_console(targets[0].b3_scope),
            changes=[grant_role(ALICE)],
            base_revision=await config_revision(w.db, INSTALLATION_ID),
        ),
    )
    await apply_job_migrations(w.db)
    jobs = [JobDefinition.from_after({**after(), "job_id": name}) for name in ("a-job", "z-job")]
    async with w.db.transaction() as tx:
        for job in jobs:
            await create_job(tx, INSTALLATION_ID, TEAM, job)
    return adapter, targets[0], pairs, jobs, confirming, associated


@pytest.mark.parametrize("blocked_phase", ["upstream", "b3"])
async def test_whole_b2_union_is_free_until_session_preparation_finishes(uses, blocked_phase):  # noqa: F811
    w = uses.world
    adapter, target, pairs, jobs, confirming, associated = await prepare_inputs(uses)
    ready = asyncio.get_running_loop().create_future()
    calls = []

    async def session_prepare(tx):
        calls.append(tx)
        held = await adapter.hold_session_target(tx, target, approver_pairs=pairs)
        assert held.approver_pairs == tuple(pairs)
        assert await adapter.check_session_target(tx, held)

    async def prepare():
        async with w.db.transaction() as tx:
            ready.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
            await w.fence.check(tx, w.admitted)
            for principal in sorted((ALICE, BOB), key=lambda p: p.principal_did):
                assert await hold_role(tx, principal, OWNER_ROLE)
            await w.containment.prepare_replacements(
                tx,
                installation_id=INSTALLATION_ID,
                team_id=TEAM,
                secret_ids=(SECRET_ID,),
                job_ids=tuple(job.job_id for job in jobs),
                approval_ids=(confirming,),
                before_approvals=session_prepare,
            )
            assert calls == [tx]

    task = None
    try:
        async with w.db.transaction() as blocker:
            blocker_pid = await blocker.fetch_value("SELECT pg_backend_pid()")
            if blocked_phase == "upstream":
                await blocker.fetch_value(
                    "SELECT job_id FROM {{tables.current_jobs}}"
                    " WHERE installation_id=$1 AND job_id=$2 FOR SHARE",
                    INSTALLATION_ID,
                    jobs[-1].job_id,
                )
            else:
                await blocker.fetch_value(
                    "SELECT subject FROM {{tables.passkey_approvers}}"
                    " WHERE scope=$1 AND subject=$2 FOR UPDATE",
                    *pairs[-1],
                )
            task = asyncio.create_task(prepare())
            waiter = await asyncio.wait_for(ready, 5)
            await wait_blocked(w, waiter, blocker_pid)
            if blocked_phase == "upstream":
                assert not calls
                async with w.db.transaction() as observer:
                    for scope, subject in pairs:
                        assert await observer.fetch_value(
                            "SELECT subject FROM {{tables.passkey_approvers}}"
                            " WHERE scope=$1 AND subject=$2 FOR UPDATE NOWAIT",
                            scope,
                            subject,
                        )
            else:
                assert len(calls) == 1
            async with w.db.transaction() as observer:
                free = await observer.fetch_all(
                    "SELECT approval_id FROM {{tables.approvals}}"
                    " WHERE approval_id=ANY($1::text[]) ORDER BY approval_id FOR UPDATE NOWAIT",
                    [confirming, associated],
                )
                assert {row["approval_id"] for row in free} == {confirming, associated}
        await asyncio.wait_for(task, 5)
    finally:
        if task is not None:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)


async def test_empty_forest_session_refusal_rolls_back_the_callers_transaction(uses):  # noqa: F811
    w = uses.world
    calls = []

    async def refuse(tx):
        calls.append(tx)
        raise HTTPException(401, "console_session_required")

    with pytest.raises(HTTPException) as refused:
        async with w.db.transaction() as tx:
            await tx.execute(
                "INSERT INTO {{tables.audit_outbox}} (kind,details) VALUES('callback-rollback','{}')"
            )
            await w.containment.prepare_replacements(
                tx,
                installation_id=INSTALLATION_ID,
                team_id=TEAM,
                secret_ids=(),
                before_approvals=refuse,
            )
    assert len(calls) == 1
    assert (refused.value.status_code, refused.value.detail) == (401, "console_session_required")
    assert not await w.db.fetch_value(
        "SELECT count(*) FROM {{tables.audit_outbox}} WHERE kind='callback-rollback'"
    )
