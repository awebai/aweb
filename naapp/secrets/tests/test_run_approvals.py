"""Joint run-slot approval through real PG, B2 and software passkeys."""

from __future__ import annotations

import asyncio
import copy
import json
import uuid
from dataclasses import replace
from datetime import timedelta

import pytest
from awid.signing import canonical_json_bytes

from aweb_secrets import derived_lineage, records, run_approvals, use_approvals
from aweb_secrets.derived_grants import GrantSnapshot
from aweb_secrets.derived_lineage import LineageNode
from aweb_secrets.grant import GrantTemplate
from aweb_secrets.jobs import JobDefinition, apply_job_migrations, create_job
from aweb_secrets.operation import operation_digest
from aweb_secrets.policy import Policy
from aweb_secrets.run_plan import FrozenRunPlan, PreparedRun, RunPlanRefused
from aweb_secrets.secret import SecretRecord
from aweb_secrets.use_approval import use_approval_view
from tests.test_change_sets import TEAM, world  # noqa: F401
from tests.test_run_plan import _short_lived_inputs
from tests.test_use_approvals import POLICY_BODY, REQUESTER, approve, designate, uses  # noqa: F401


async def plan_for(
    context,
    *,
    required=True,
    slot_count=2,
    child_approvers=None,
    derived=False,
    delivery="short_lived",
):
    await apply_job_migrations(context.world.db)
    await designate(context, "finance", "finance@acme.com")
    inputs = _short_lived_inputs()
    inputs.update(
        run_id="run_" + uuid.uuid4().hex,
        intent_id="int_" + uuid.uuid4().hex,
        dispatch_id=uuid.uuid4(),
        installation=context.world.admitted,
        requester=REQUESTER,
        requester_roles=(),
    )
    installation = inputs["installation"].installation_id
    policy = Policy.from_body({**POLICY_BODY, "approval": "per_use" if required else "none"})
    child_policy = (
        Policy.from_body({**policy.body, "approvers": list(child_approvers)})
        if child_approvers is not None
        else policy
    )
    original = inputs["slots"][0]
    slots = []
    job_body = inputs["job"].after
    job_body.update(credentials=[], env={})
    async with context.world.db.transaction() as tx:
        await records.create_policy(tx, installation, policy)
        await records.create_policy(tx, installation, child_policy)
        for ordinal in range(slot_count):
            source = replace(
                original.source,
                record=SecretRecord.from_after(
                    {
                        **original.source.record.after,
                        "secret_id": f"sec_10000{ordinal}",
                        "ref": f"run-source-{ordinal}",
                    }
                ),
            )
            await records.create_secret(tx, installation, TEAM, source.record)
            await records.set_active_version(tx, installation, TEAM, source.record.secret_id, 4)
            node = LineageNode(
                installation, TEAM, source, None, None, None, None, None, None, None, None
            )
            template = GrantTemplate.from_after(
                {
                    **original.mint.template.template.after,
                    "grant_template_id": f"gtp_run0{ordinal}",
                    "subject": {"principal": REQUESTER.did_aw},
                    "policy_digest": child_policy.digest,
                }
            )
            await records.set_grant_template(tx, installation, template)
            record = copy.deepcopy(original.mint.operation.after)
            record.update(secret_id=source.record.secret_id, operation_id=f"issue-run-{ordinal}")
            record["store_as_secret"].update(
                grant_template=template.grant_template_id, grant_template_digest=template.digest
            )
            operation = replace(
                original.mint.operation,
                secret_id=source.record.secret_id,
                operation_id=record["operation_id"],
                after=record,
                digest=operation_digest(record),
            )
            mint = replace(
                original.mint,
                operation=operation,
                template=GrantSnapshot(canonical_json_bytes(template.after)),
                template_policy=child_policy,
            )
            grant = replace(
                original.parent_grant,
                grant_id=f"grt_run0{ordinal}",
                secret_id=source.record.secret_id,
                subject_principal=REQUESTER.did_aw,
                policy_digest=policy.digest,
            )
            slots.append(
                replace(
                    original,
                    ordinal=ordinal,
                    label=source.record.ref,
                    source=source,
                    ancestry=(node,),
                    parent_grant=grant,
                    parent_policy=policy,
                    delivery=delivery,
                    mint=mint if delivery == "short_lived" else None,
                )
            )
            job_body["credentials"].append(
                {
                    "secret_ref": source.record.ref,
                    "delivery": delivery,
                    "mint": None
                    if delivery == "durable"
                    else {
                        "operation_id": operation.operation_id,
                        "digest": operation.digest,
                        "params": {"charge": {"$param": "database"}},
                    },
                }
            )
            job_body["env"][f"RUN_SLOT_{ordinal}"] = {
                "$credential": source.record.ref,
                "field": "value",
            }
        job = JobDefinition.from_after(job_body)
        slots = [
            replace(slot, parent_grant=replace(slot.parent_grant, jobs=((job.job_id, job.digest),)))
            for slot in slots
        ]
        for slot in slots:
            await records.create_grant(tx, installation, TEAM, slot.parent_grant)
        await create_job(tx, installation, TEAM, job)
        if derived:
            parent = replace(
                original.source,
                record=SecretRecord.from_after(
                    {
                        **original.source.record.after,
                        "secret_id": "sec_parent001",
                        "ref": "run-parent",
                    }
                ),
            )
            await records.create_secret(tx, installation, TEAM, parent.record)
            await records.set_active_version(tx, installation, TEAM, parent.record.secret_id, 4)
            grant = replace(
                slots[0].parent_grant, grant_id="grt_parent001", secret_id=parent.record.secret_id
            )
            await records.create_grant(tx, installation, TEAM, grant)
            descendants = []
            for slot in slots:
                now = context.clock()
                await derived_lineage.record_lineage(
                    tx,
                    installation_id=installation,
                    team_id=TEAM,
                    secret_id=slot.source.record.secret_id,
                    parent_secret_id=parent.record.secret_id,
                    parent_version=4,
                    source_dispatch_id=str(uuid.uuid4()),
                    source_grant_id=grant.grant_id,
                    issuing_principal=REQUESTER.did_aw,
                    policy_digest=policy.digest,
                    dispatch_started_at=now,
                    upstream_expires_at=now + timedelta(hours=1),
                    expires_at=now + timedelta(seconds=60),
                    clock=context.clock,
                )
                ancestry = await derived_lineage.lock_ancestry(
                    tx, installation, TEAM, slot.source.record.secret_id
                )
                descendants.append(replace(slot, ancestry=ancestry))
            slots = descendants
        await tx.execute(
            "UPDATE {{tables.approvers}} SET covers=$1 WHERE approver_ref='finance'",
            json.dumps([slot.source.record.secret_id for slot in slots]),
        )
    return FrozenRunPlan.freeze(**{**inputs, "job": job, "slots": slots})


async def prepare(context, tx, plan):
    await context.world.fence.admit(tx, context.grant)
    installation = context.world.admitted.installation_id
    nodes = []
    grant_ids = [slot.parent_grant.grant_id for slot in plan.slots]
    for slot in sorted(plan.slots, key=lambda slot: slot.source_id):
        nodes.append(await derived_lineage.lock_ancestry(tx, installation, TEAM, slot.source_id))
    for group in nodes:
        try:
            await derived_lineage.check_ancestry(
                tx, group, clock=context.clock, candidate_grant_ids=grant_ids
            )
        except derived_lineage.LineageRefused:
            # Preserve the refusal for the callback so stable original-run
            # retrieval can be classified without creating fresh authority.
            pass

    async def recheck(checked, *, clock, max_ttl_s):
        for group in nodes:
            try:
                await derived_lineage.check_ancestry(
                    checked, group, clock=clock, max_ttl_s=max_ttl_s, candidate_grant_ids=grant_ids
                )
            except derived_lineage.LineageRefused as exc:
                raise RunPlanRefused(exc.code) from None

    return await PreparedRun.bind(
        tx, plan=plan, clock=context.clock, max_ttl_s=3600, recheck=recheck
    )


async def request(context, plan):
    async with context.world.db.transaction() as tx:
        prepared = await prepare(context, tx, plan)
        pending = await run_approvals.request_run_approvals(
            tx, context.approvals, prepared=prepared, principal=REQUESTER, reason="scheduled run"
        )
    for item in pending:
        if item.pending is not None:
            await context.approvals.deliver(item.pending)
    return pending


async def admit(context, plan):
    async with context.world.db.transaction() as tx:
        prepared = await prepare(context, tx, plan)
        return await run_approvals.admit_run_approvals(tx, context.approvals, prepared=prepared)


async def test_joint_admission_rolls_back_partial_decisions_then_admits_once(uses):  # noqa: F811
    plan = await plan_for(uses)
    pending = await request(uses, plan)
    assert len(pending) == 2
    await approve(uses, pending[0], "finance@acme.com")
    partial = await admit(uses, plan)
    assert partial.refusal == "approval_pending" and not partial.may_send
    assert (
        await uses.approvals.get(pending[0].pending.approval.approval_id)
    ).consumed_operation_id is None
    await approve(uses, pending[1], "finance@acme.com")
    admitted = await admit(uses, plan)
    assert admitted.refusal is None and admitted.may_send
    assert (admitted.run_id, admitted.intent_id, admitted.dispatch_id, admitted.plan_digest) == (
        plan.body["run_id"],
        plan.body["intent_id"],
        plan.body["dispatch_id"],
        plan.digest,
    )
    assert [slot.ordinal for slot in admitted.slots] == [0, 1]
    for item in pending:
        assert (
            await uses.approvals.get(item.pending.approval.approval_id)
        ).consumed_operation_id == plan.body["dispatch_id"]
    replay = await admit(uses, plan)
    assert replay.refusal is None and not replay.may_send
    async with uses.world.db.transaction() as tx:
        stored = await run_approvals.run_approval_record(
            tx,
            installation_id=uses.world.admitted.installation_id,
            team_id=TEAM,
            run_id=plan.body["run_id"],
        )
        assert stored.plan_digest == plan.digest and stored.admitted
        assert stored.slots == admitted.slots


async def test_frozen_view_shows_mapped_values_beside_complete_child_authority(uses):  # noqa: F811
    plan = await plan_for(uses)
    pending = await request(uses, plan)
    item = pending[0]
    async with uses.world.db.transaction() as tx:
        view = await run_approvals.run_approval_view(
            tx,
            installation_id=uses.world.admitted.installation_id,
            team_id=TEAM,
            approval_id=item.approval_id,
        )
    assert view.job.slot_ordinal == 0 and view.job.plan_digest == plan.digest
    assert view.job.mint_params == {"charge": "orders"}
    assert view.job.child_grant_template == plan.body["slots"][0]["mint"]["grant_template"]
    repeat = await request(uses, plan)
    assert [p.approval_id for p in repeat] == [p.approval_id for p in pending]
    assert all(p.pending is None for p in repeat)


async def test_signed_run_request_keeps_v1_fields_and_view_is_scoped(uses):  # noqa: F811
    plan = await plan_for(uses)
    pending = await request(uses, plan)
    for item in pending:
        frozen = await uses.approvals._request(item.pending.approval)
        assert frozen["v"] == 1
        assert set(frozen["run_job"]) == {
            "runner_id",
            "job_id",
            "job_digest",
            "params",
            "credential_delivery",
        }
        assert use_approval_view(frozen).job.frozen_plan is None
        async with uses.world.db.transaction() as tx:
            args = dict(
                installation_id=uses.world.admitted.installation_id,
                team_id=TEAM,
                approval_id=item.approval_id,
            )
            view = await run_approvals.run_approval_view(tx, **args)
            assert view.job.frozen_plan == plan.body
            assert view.job.slot_ordinal == item.ordinal
            assert view.job.plan_digest == plan.digest
            view.job.frozen_plan["slots"].clear()
            assert (await run_approvals.run_approval_view(tx, **args)).job.frozen_plan == plan.body
            for wrong in (
                {"installation_id": "other-installation"},
                {"team_id": "other-team"},
                {"approval_id": "unknown-approval"},
            ):
                assert await run_approvals.run_approval_view(tx, **{**args, **wrong}) is None


async def test_withdrawn_coverage_voids_all_unsent_slots(uses):  # noqa: F811
    plan = await plan_for(uses)
    pending = await request(uses, plan)
    for item in pending:
        await approve(uses, item, "finance@acme.com")
    async with uses.world.db.transaction() as tx:
        await tx.execute("UPDATE {{tables.approvers}} SET covers='[]' WHERE approver_ref='finance'")
    result = await admit(uses, plan)
    assert result.refusal == "approval_revoked" and not result.may_send
    for item in pending:
        assert (await uses.approvals.get(item.pending.approval.approval_id)).revoked_at is not None


async def test_no_required_approval_still_records_one_joint_admission(uses):  # noqa: F811
    plan = await plan_for(uses, required=False)
    assert await request(uses, plan) == ()
    result = await admit(uses, plan)
    assert result.may_send and not result.slots[0].approval_id
    assert not (await admit(uses, plan)).may_send


async def test_changed_original_dispatch_cannot_remint_or_consume(uses):  # noqa: F811
    plan = await plan_for(uses)
    pending = await request(uses, plan)
    body = plan.body
    body["dispatch_id"] = str(uuid.uuid4())
    from aweb_secrets.runner_protocol import canonical

    changed = FrozenRunPlan.from_bytes(canonical(body))
    with pytest.raises(RunPlanRefused):
        await request(uses, changed)
    for item in pending:
        assert (
            await uses.approvals.get(item.pending.approval.approval_id)
        ).consumed_operation_id is None


async def test_run_slot_revoke_uses_the_shared_scoped_union(uses):  # noqa: F811
    plan = await plan_for(uses)
    pending = await request(uses, plan)
    async with uses.world.db.transaction() as tx:
        ids = await use_approvals.select_use_approval_ids(
            tx,
            installation_id=uses.world.admitted.installation_id,
            team_id=TEAM,
            secret_ids=[slot.source_id for slot in plan.slots],
        )
        assert ids == tuple(sorted(p.pending.approval.approval_id for p in pending))
        selected = await use_approvals.use_approval_secret_ids(
            tx,
            installation_id=uses.world.admitted.installation_id,
            team_id=TEAM,
            approval_id=pending[0].pending.approval.approval_id,
        )
        assert selected == (plan.slots[0].source_id,)
        revoked = await use_approvals.revoke_use_approvals(
            tx,
            uses.approvals,
            installation_id=uses.world.admitted.installation_id,
            team_id=TEAM,
            secret_ids=[plan.slots[0].source_id],
            revoked_by="owner",
            reason="secret_disabled",
        )
        assert revoked == [pending[0].pending.approval.approval_id]
    assert (await admit(uses, plan)).refusal == "approval_revoked"


async def test_concurrent_joint_consumers_get_one_send_authority(uses):  # noqa: F811
    plan = await plan_for(uses)
    pending = await request(uses, plan)
    for item in pending:
        await approve(uses, item, "finance@acme.com")
    results = await asyncio.gather(admit(uses, plan), admit(uses, plan))
    assert sum(result.may_send for result in results) == 1
    assert all(result.refusal is None for result in results)


async def test_joint_marker_and_b2_consumption_roll_back_with_caller(uses):  # noqa: F811
    plan = await plan_for(uses)
    pending = await request(uses, plan)
    for item in pending:
        await approve(uses, item, "finance@acme.com")
    with pytest.raises(RuntimeError):
        async with uses.world.db.transaction() as tx:
            prepared = await prepare(uses, tx, plan)
            result = await run_approvals.admit_run_approvals(tx, uses.approvals, prepared=prepared)
            assert result.may_send
            raise RuntimeError("caller rollback")
    for item in pending:
        assert (await uses.approvals.get(item.approval_id)).consumed_operation_id is None
    assert (await admit(uses, plan)).may_send


async def test_parent_and_template_must_list_a_common_approver(uses):  # noqa: F811
    plan = await plan_for(uses, child_approvers=["operations"])
    with pytest.raises(RunPlanRefused) as refused:
        await request(uses, plan)
    assert refused.value.code == "no_eligible_approver"
    async with uses.world.db.transaction() as tx:
        assert (
            await run_approvals.run_approval_record(
                tx,
                installation_id=uses.world.admitted.installation_id,
                team_id=TEAM,
                run_id=plan.body["run_id"],
            )
            is None
        )


@pytest.mark.parametrize("expires", [False, True])
async def test_final_expiry_after_b2_read_rolls_back_marker_consumption_and_audit(uses, expires):  # noqa: F811
    plan = await plan_for(uses, slot_count=1)
    pending = await request(uses, plan)
    await approve(uses, pending[0], "finance@acme.com")
    db = uses.world.db
    before = await db.fetch_value(
        "SELECT count(*) FROM {{tables.audit_outbox}} WHERE kind='dispatch_admitted'"
    )
    task = None
    try:
        async with db.transaction() as blocker:
            pid = await blocker.fetch_value("SELECT pg_backend_pid()")
            await blocker.execute(
                "LOCK TABLE {{tables.passkey_approvers}} IN ACCESS EXCLUSIVE MODE"
            )
            task = asyncio.create_task(admit(uses, plan))
            async with asyncio.timeout(5):
                while not await db.fetch_value(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)) "
                    "AND query LIKE '%passkey_approvers%')",
                    pid,
                ):
                    if task.done():
                        await task
                        pytest.fail("admission did not wait on real B2 decider read")
                    await asyncio.sleep(0.01)
            if expires:
                uses.clock.now += timedelta(seconds=901)
        result = await asyncio.wait_for(task, 5)
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    if not expires:
        assert result.may_send and result.refusal is None
        return
    assert not result.may_send and result.refusal == "approval_expired"
    assert (await uses.approvals.get(pending[0].approval_id)).consumed_operation_id is None
    assert (
        await db.fetch_value(
            "SELECT count(*) FROM {{tables.audit_outbox}} WHERE kind='dispatch_admitted'"
        )
        == before
    )
    async with db.transaction() as tx:
        stored = await run_approvals.run_approval_record(
            tx,
            installation_id=uses.world.admitted.installation_id,
            team_id=TEAM,
            run_id=plan.body["run_id"],
        )
        assert not stored.admitted


@pytest.mark.parametrize("admitted", [False, True])
async def test_scoped_read_only_lookups_include_every_approval_state(uses, admitted):  # noqa: F811
    plan = await plan_for(uses)
    pending = await request(uses, plan)
    if admitted:
        for item in pending:
            await approve(uses, item, "finance@acme.com")
        assert (await admit(uses, plan)).may_send
    installation = uses.world.admitted.installation_id
    sources = [slot.source_id for slot in plan.slots]
    async with uses.world.db.transaction() as tx:
        await tx.execute("SET TRANSACTION READ ONLY")
        for inst, team in [("other-installation", TEAM), (installation, "other:example.com")]:
            assert (
                await run_approvals.run_approval_record(
                    tx, installation_id=inst, team_id=team, run_id=plan.body["run_id"]
                )
                is None
            )
            assert (
                await use_approvals.select_use_approval_ids(
                    tx, installation_id=inst, team_id=team, secret_ids=sources
                )
                == ()
            )
            assert (
                await use_approvals.use_approval_secret_ids(
                    tx, installation_id=inst, team_id=team, approval_id=pending[0].approval_id
                )
                == ()
            )
        assert await use_approvals.select_use_approval_ids(
            tx,
            installation_id=installation,
            team_id=TEAM,
            secret_ids=[*sources, *sources, "sec_unknown"],
        ) == tuple(sorted(p.approval_id for p in pending))
        assert (
            await use_approvals.select_use_approval_ids(
                tx, installation_id=installation, team_id=TEAM, secret_ids=[]
            )
            == ()
        )
        assert (
            await use_approvals.use_approval_secret_ids(
                tx, installation_id=installation, team_id=TEAM, approval_id="missing-approval"
            )
            == ()
        )
        assert await use_approvals.use_approval_secret_ids(
            tx, installation_id=installation, team_id=TEAM, approval_id=pending[1].approval_id
        ) == (sources[1],)


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE {{tables.run_approval_plans}} SET plan_digest=repeat('0',64)",
        "UPDATE {{tables.run_slot_approvals}} SET secret_id='sec_other001'",
        "DELETE FROM {{tables.run_approval_admissions}}",
    ],
)
async def test_persisted_plan_slot_and_joint_admission_cannot_be_rewritten(uses, statement):  # noqa: F811
    import asyncpg

    plan = await plan_for(uses)
    pending = await request(uses, plan)
    for item in pending:
        await approve(uses, item, "finance@acme.com")
    assert (await admit(uses, plan)).may_send
    with pytest.raises(asyncpg.RaiseError):
        async with uses.world.db.transaction() as tx:
            await tx.execute(statement)
    async with uses.world.db.transaction() as tx:
        stored = await run_approvals.run_approval_record(
            tx,
            installation_id=uses.world.admitted.installation_id,
            team_id=TEAM,
            run_id=plan.body["run_id"],
        )
        assert stored.plan_digest == plan.digest and stored.admitted
        assert [s.secret_id for s in stored.slots] == [s.source_id for s in plan.slots]


async def test_request_rollback_leaves_no_plan_slot_or_b2_approval(uses):  # noqa: F811
    plan = await plan_for(uses)
    with pytest.raises(RuntimeError):
        async with uses.world.db.transaction() as tx:
            prepared = await prepare(uses, tx, plan)
            pending = await run_approvals.request_run_approvals(
                tx,
                uses.approvals,
                prepared=prepared,
                principal=REQUESTER,
                reason="rollback request",
            )
            raise RuntimeError("rollback")
    for item in pending:
        assert await uses.approvals.get(item.approval_id) is None
    async with uses.world.db.transaction() as tx:
        assert (
            await run_approvals.run_approval_record(
                tx,
                installation_id=uses.world.admitted.installation_id,
                team_id=TEAM,
                run_id=plan.body["run_id"],
            )
            is None
        )
    assert len(await request(uses, plan)) == 2


@pytest.mark.parametrize("admitted", [False, True])
async def test_stale_prepared_transaction_refuses_even_stable_retrieval(uses, admitted):  # noqa: F811
    plan = await plan_for(uses)
    pending = await request(uses, plan)
    if admitted:
        for item in pending:
            await approve(uses, item, "finance@acme.com")
        assert (await admit(uses, plan)).may_send
    async with uses.world.db.transaction() as tx:
        prepared = await prepare(uses, tx, plan)
    with pytest.raises(RunPlanRefused) as refusal:
        async with uses.world.db.transaction() as later:
            await run_approvals.admit_run_approvals(later, uses.approvals, prepared=prepared)
    assert refusal.value.code == "run_plan_transaction_changed"


async def test_admitted_original_run_remains_retrievable_after_coverage_loss(uses):  # noqa: F811
    plan = await plan_for(uses)
    pending = await request(uses, plan)
    for item in pending:
        await approve(uses, item, "finance@acme.com")
    assert (await admit(uses, plan)).may_send
    async with uses.world.db.transaction() as tx:
        await tx.execute("UPDATE {{tables.approvers}} SET covers='[]'")
    retrieved = await admit(uses, plan)
    assert retrieved.admitted and not retrieved.may_send and retrieved.refusal is None
    assert tuple(s.approval_id for s in retrieved.slots) == tuple(p.approval_id for p in pending)


@pytest.mark.parametrize("expires", [False, True])
async def test_no_approval_run_rechecks_real_ancestry_after_late_database_wait(uses, expires):  # noqa: F811
    plan = await plan_for(uses, required=False, derived=True)
    assert await request(uses, plan) == ()
    db = uses.world.db
    task = None
    try:
        async with db.transaction() as blocker:
            pid = await blocker.fetch_value("SELECT pg_backend_pid()")
            await blocker.execute(
                "LOCK TABLE {{tables.run_approval_admissions}} IN ACCESS EXCLUSIVE MODE"
            )
            task = asyncio.create_task(admit(uses, plan))
            async with asyncio.timeout(5):
                while not await db.fetch_value(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)) "
                    "AND query LIKE '%run_approval_admissions%')",
                    pid,
                ):
                    if task.done():
                        await task
                        pytest.fail("admission did not wait on its real association read")
                    await asyncio.sleep(0.01)
            if expires:
                uses.clock.now += timedelta(seconds=61)
        result = await asyncio.wait_for(task, 5)
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    if expires:
        assert result.refusal == "secret_disabled" and not result.may_send
        async with db.transaction() as tx:
            stored = await run_approvals.run_approval_record(
                tx,
                installation_id=uses.world.admitted.installation_id,
                team_id=TEAM,
                run_id=plan.body["run_id"],
            )
            assert not stored.admitted
    else:
        assert result.refusal is None and result.may_send
        uses.clock.now += timedelta(seconds=61)
        stable = await admit(uses, plan)
        assert stable.admitted and not stable.may_send and stable.refusal is None


async def test_lost_designation_before_mint_has_a_typed_refusal_and_no_orphan_plan(uses):  # noqa: F811
    from aweb_secrets.owners import approver_scope

    plan = await plan_for(uses)
    scope = approver_scope(uses.world.admitted.installation_id, TEAM, "finance")
    async with uses.world.db.transaction() as tx:
        await tx.execute(
            "UPDATE {{tables.passkey_approvers}} SET superseded_at=$2 WHERE scope=$1",
            scope,
            uses.clock(),
        )
    with pytest.raises(RunPlanRefused) as refused:
        await request(uses, plan)
    assert refused.value.code == "no_eligible_approver"
    async with uses.world.db.transaction() as tx:
        assert (
            await run_approvals.run_approval_record(
                tx,
                installation_id=uses.world.admitted.installation_id,
                team_id=TEAM,
                run_id=plan.body["run_id"],
            )
            is None
        )


@pytest.mark.parametrize("previous", ["other", "original", "not_sent"])
async def test_consumed_b2_cannot_supply_fresh_joint_authority(uses, previous):  # noqa: F811
    plan = await plan_for(uses)
    pending = await request(uses, plan)
    for item in pending:
        await approve(uses, item, "finance@acme.com")
    approval = pending[0].pending.approval
    frozen = await uses.approvals._request(approval)
    operation_id = plan.body["dispatch_id"] if previous != "other" else str(uuid.uuid4())
    assert (await uses.approvals.admit(approval.approval_id, frozen, operation_id)).may_send
    if previous == "not_sent":
        from aweb_naapp.runtime.approvals import DispatchOutcome

        await uses.approvals.record_outcome(
            approval.approval_id, operation_id, DispatchOutcome.NOT_SENT
        )
    result = await admit(uses, plan)
    assert not result.may_send and result.refusal == "approval_consumed"
    assert (await uses.approvals.get(pending[1].approval_id)).consumed_operation_id is None
    async with uses.world.db.transaction() as tx:
        stored = await run_approvals.run_approval_record(
            tx,
            installation_id=uses.world.admitted.installation_id,
            team_id=TEAM,
            run_id=plan.body["run_id"],
        )
        assert not stored.admitted


async def test_a_durable_child_uses_its_own_source_version_and_parent_run_policy(uses):  # noqa: F811
    plan = await plan_for(uses, derived=True, delivery="durable")
    pending = await request(uses, plan)
    assert len(pending) == 2
    for item in pending:
        async with uses.world.db.transaction() as tx:
            view = await run_approvals.run_approval_view(
                tx,
                installation_id=uses.world.admitted.installation_id,
                team_id=TEAM,
                approval_id=item.approval_id,
            )
        slot = plan.slots[item.ordinal]
        assert view.secret_ref == slot.body["source"]["ref"]
        assert view.secret_version == slot.source_version
        assert view.grant_id == slot.parent_grant.grant_id
        assert view.job.credential_delivery == "durable"
        assert view.job.slot_ordinal == item.ordinal
        assert view.job.mint_params is None and view.job.child_grant_template is None
        await approve(uses, item, "finance@acme.com")
    assert (await admit(uses, plan)).may_send
