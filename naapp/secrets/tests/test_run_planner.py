"""CURRENT run preparation and late fences use real PG/roles/runner records."""

import copy
from datetime import timedelta
from uuid import uuid4

import pytest
from aweb_naapp.egress import InternalDestinations
from aweb_naapp.hooks.strictjson import encode_base64url
from awid.did import did_from_public_key
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from nacl.signing import SigningKey

from aweb_secrets import jobs, records, runners
from aweb_secrets.run_plan import RunPlanRefused
from aweb_secrets.run_planner import RunPlanner
from tests.test_admission import (
    ALICE,
    INSTALLATION,
    NOW,
    SECRET,
    TEAM,
    _grant_source_grant,
    _install,
)
from tests.test_admission import db as db
from tests.test_admission import fence as fence
from tests.test_jobs import after


async def _setup(db, *, subject=None):
    await jobs.apply_job_migrations(db)
    await runners.apply_runner_migrations(db)
    body = after()
    body["credentials"][0]["secret_ref"] = SECRET["ref"]
    body["env"] = {"DB_ADMIN": {"$credential": SECRET["ref"]}}
    job = jobs.JobDefinition.from_after(body)
    await _install(
        db,
        capability="run",
        open_request=False,
        jobs=[{"job_id": job.job_id, "digest": job.digest}],
        subject=subject,
    )
    runner = runners.RunnerRecord.from_after(
        {
            "v": 1,
            "runner_id": body["runner_ids"][0],
            "label": "Test runner",
            "allowed_jobs": [job.job_id],
        }
    )
    async with db.transaction() as tx:
        await jobs.create_job(tx, INSTALLATION, TEAM, job)
        code = await runners.create_runner(tx, INSTALLATION, TEAM, runner, now=NOW)
        await runners.register_runner(
            tx,
            code=code,
            signing_key=did_from_public_key(bytes(SigningKey.generate().verify_key)),
            encryption_key=encode_base64url(
                X25519PrivateKey.generate().public_key().public_bytes_raw()
            ),
            clock=lambda: NOW,
        )
    return job


def _planner(fence, *, clock=lambda: NOW, cap=3600):
    return RunPlanner(
        fence,
        clock=clock,
        derived_max_ttl_s=cap,
        internal_destinations=InternalDestinations.DISABLED,
    )


async def _prepare(tx, planner, job):
    return await planner.prepare(
        tx,
        grant=_grant_source_grant(),
        principal=ALICE,
        run_id="run_original001",
        intent_id="int_original001",
        dispatch_id=uuid4(),
        candidate_job=job,
        runner_id=job.after["runner_ids"][0],
        params={"database": "orders"},
    )


async def test_fixed_selector_preparation_and_frozen_recheck_are_the_same_plan(db, fence):
    job = await _setup(db)
    planner = _planner(fence)
    async with db.transaction() as tx:
        prepared = await _prepare(tx, planner, job)
        async with tx.transaction() as joint:
            await prepared.recheck(joint)
        assert prepared.slots[0].source_id == SECRET["secret_id"]
        assert prepared.slots[0].parent_grant.capability == "run"
        assert not prepared.slots[0].approval_required
        assert await tx.fetch_value("SELECT count(*) FROM {{tables.intents}}") == 0
    async with db.transaction() as tx:
        restored = await planner.prepare_frozen(
            tx, grant=_grant_source_grant(), principal=ALICE, plan=prepared.plan
        )
        await restored.recheck(tx)
        assert restored.plan.canonical == prepared.plan.canonical


@pytest.mark.parametrize(
    "change,code",
    [
        ("job", "job_not_allowed"),
        ("runner", "runner_unavailable"),
        ("grant", "grant_revoked"),
        ("source", "secret_disabled"),
        ("version", "secret_version_changed"),
        ("installation", "installation_disabled"),
        ("flags", "job_not_allowed"),
    ],
)
async def test_frozen_authority_refusals_are_retained_for_stable_retrieval(db, fence, change, code):
    job = await _setup(db)
    planner = _planner(fence)
    async with db.transaction() as tx:
        plan = (await _prepare(tx, planner, job)).plan
    async with db.transaction() as tx:
        if change == "job":
            body = job.after
            body["timeout_s"] += 1
            await jobs.create_job(tx, INSTALLATION, TEAM, jobs.JobDefinition.from_after(body))
        elif change == "runner":
            await runners.deregister_runner(tx, INSTALLATION, job.after["runner_ids"][0], now=NOW)
        elif change == "grant":
            await records.revoke_grant(tx, INSTALLATION, "grt_alice001")
        elif change == "source":
            await tx.execute(
                "UPDATE {{tables.secrets}} SET state='disabled' WHERE secret_id=$1",
                SECRET["secret_id"],
            )
        elif change == "version":
            await records.set_active_version(tx, INSTALLATION, TEAM, SECRET["secret_id"], 5)
        elif change == "flags":
            from aweb_secrets.secret import SecretRecord

            await records.update_secret(
                tx,
                INSTALLATION,
                TEAM,
                SecretRecord.from_after(
                    {**SECRET, "approve_only": True, "sensitivity": "sensitive"}
                ),
            )
        else:
            await tx.execute(
                "INSERT INTO {{tables.containment_installations}} (installation_id,team_id,disabled_at) VALUES ($1,$2,now())",
                INSTALLATION,
                TEAM,
            )
    async with db.transaction() as tx:
        prepared = await planner.prepare_frozen(
            tx, grant=_grant_source_grant(), principal=ALICE, plan=plan
        )
        # Priming does not itself refuse stable retrieval; S12 classifies the
        # persisted result before deciding whether a new send can be admitted.
        assert prepared.plan.canonical == plan.canonical
        with pytest.raises(RunPlanRefused) as refused:
            await prepared.recheck(tx)
        assert refused.value.code == code


async def test_stale_job_discovery_never_changes_slots_or_falls_back_to_history(db, fence):
    job = await _setup(db)
    body = job.after
    body["timeout_s"] += 1
    async with db.transaction() as tx:
        await jobs.create_job(tx, INSTALLATION, TEAM, jobs.JobDefinition.from_after(body))
    async with db.transaction() as tx:
        with pytest.raises(RunPlanRefused) as refused:
            await _prepare(tx, _planner(fence), job)
        assert refused.value.code == "job_not_allowed"


@pytest.mark.parametrize("held", [True, False])
async def test_parent_run_role_requires_an_actual_held_role(db, fence, held):
    from aweb_naapp.roles import assign, principal_key

    role = "secrets.role.deployers"
    job = await _setup(db, subject={"role": role})
    if held:
        async with db.transaction() as tx:
            await assign(tx, principal_key(ALICE), role)
    async with db.transaction() as tx:
        if held:
            prepared = await _prepare(tx, _planner(fence), job)
            assert prepared.plan.body["requester"]["roles"] == [role]
        else:
            with pytest.raises(RunPlanRefused):
                await _prepare(tx, _planner(fence), job)


async def test_a_nonissuing_recipe_refuses_without_an_independent_broker_grant(db, fence):
    from aweb_secrets.operation import OperationTemplate
    from tests.test_change_records import OPERATION

    job = await _setup(db)
    issuer = OperationTemplate.from_after(copy.deepcopy(OPERATION))
    body = job.after
    body["credentials"][0].update(
        delivery="short_lived",
        mint={
            "operation_id": issuer.operation_id,
            "digest": issuer.digest,
            "params": {"charge": {"$param": "database"}},
        },
    )
    job = jobs.JobDefinition.from_after(body)
    # This owner-defined registry is inert; job applicability is still guarded.
    async with db.transaction() as tx:
        await jobs.create_job(tx, INSTALLATION, TEAM, job)
        await records.create_operation(tx, INSTALLATION, TEAM, issuer)
    await _install(
        db,
        grant_id="grt_run_new",
        capability="run",
        open_request=False,
        jobs=[{"job_id": job.job_id, "digest": job.digest}],
    )
    async with db.transaction() as tx:
        with pytest.raises(RunPlanRefused) as refused:
            await _prepare(tx, _planner(fence), job)
        assert refused.value.code == "operation_not_allowed"


@pytest.mark.parametrize("expired", [False, True])
async def test_live_planner_clock_survives_a_later_caller_lock_wait(db, fence, expired):
    import asyncio

    from aweb_secrets import derived_lineage
    from aweb_secrets.grant import GrantRecord
    from aweb_secrets.secret import SecretRecord
    from tests.test_derived_lineage import _wait_for_database_lock

    job = await _setup(db)
    async with db.transaction() as tx:
        original_policy = await tx.fetch_value(
            "SELECT policy_digest FROM {{tables.grants}} WHERE grant_id='grt_alice001'"
        )
        issuer = GrantRecord.from_after(
            {
                "v": 1,
                "grant_id": "grt_issuer01",
                "secret_id": SECRET["secret_id"],
                "subject": {"principal": ALICE.did_aw},
                "capability": "use",
                "operations": [],
                "open_request": True,
                "jobs": [],
                "policy_digest": original_policy,
            }
        )
        await records.create_grant(tx, INSTALLATION, TEAM, issuer)
        child = SecretRecord.from_after(
            {**SECRET, "secret_id": "sec_child001", "ref": "child-session"}
        )
        await records.create_secret(tx, INSTALLATION, TEAM, child)
        await records.set_active_version(tx, INSTALLATION, TEAM, child.secret_id, 4)
        await derived_lineage.record_lineage(
            tx,
            installation_id=INSTALLATION,
            team_id=TEAM,
            secret_id=child.secret_id,
            parent_secret_id=SECRET["secret_id"],
            parent_version=4,
            source_dispatch_id="source-dispatch",
            source_grant_id=issuer.grant_id,
            issuing_principal=ALICE.did_aw,
            policy_digest=original_policy,
            dispatch_started_at=NOW,
            upstream_expires_at=NOW + timedelta(hours=2),
            expires_at=NOW + timedelta(hours=1),
            clock=lambda: NOW,
        )
        body = job.after
        body["credentials"][0]["secret_ref"] = child.ref
        body["env"] = {"DB_ADMIN": {"$credential": child.ref}}
        job = jobs.JobDefinition.from_after(body)
        await jobs.create_job(tx, INSTALLATION, TEAM, job)
        await records.create_grant(
            tx,
            INSTALLATION,
            TEAM,
            GrantRecord.from_after(
                {
                    **issuer.after,
                    "grant_id": "grt_child_run",
                    "secret_id": child.secret_id,
                    "capability": "run",
                    "open_request": False,
                    "jobs": [{"job_id": job.job_id, "digest": job.digest}],
                }
            ),
        )
    at = NOW
    planner = _planner(fence, clock=lambda: at, cap=60)
    pid = asyncio.Future()

    async def submit():
        async with db.transaction() as tx:
            prepared = await _prepare(tx, planner, job)
            pid.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
            await tx.fetch_value("SELECT count(*) FROM {{tables.config_revisions}}")
            async with tx.transaction() as joint:
                await prepared.recheck(joint)
            return prepared

    async with db.transaction() as blocker:
        await blocker.execute("LOCK TABLE {{tables.config_revisions}} IN ACCESS EXCLUSIVE MODE")
        task = asyncio.create_task(submit())
        try:
            await _wait_for_database_lock(db, await asyncio.wait_for(asyncio.shield(pid), 3))
            if expired:
                at = NOW + timedelta(seconds=61)
        except BaseException:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            raise
    if expired:
        with pytest.raises(RunPlanRefused) as refused:
            await task
        assert refused.value.code == "secret_disabled"
    else:
        assert (await task).slots[0].source_id == child.secret_id


async def test_a_priming_refusal_cannot_resume_into_new_locks_after_approval(db, fence):
    job = await _setup(db)
    planner = _planner(fence)
    runner_id = job.after["runner_ids"][0]
    async with db.transaction() as tx:
        plan = (await _prepare(tx, planner, job)).plan
        runner = await runners.active_runner(tx, runner_id)
        assert runner is not None
    async with db.transaction() as tx:
        await runners.deregister_runner(tx, INSTALLATION, runner_id, now=NOW)
    async with db.transaction() as tx:
        prepared = await planner.prepare_frozen(
            tx, grant=_grant_source_grant(), principal=ALICE, plan=plan
        )
        # A missing row took no runner lock while priming. Even if a trusted
        # caller subsequently reenables it, this prepared attempt must retain
        # its refusal rather than reaching new authority locks after B2.
        code = await runners.replace_runner(tx, INSTALLATION, TEAM, runner.record, now=NOW)
        await runners.register_runner(
            tx,
            code=code,
            signing_key=did_from_public_key(bytes(SigningKey.generate().verify_key)),
            encryption_key=encode_base64url(
                X25519PrivateKey.generate().public_key().public_bytes_raw()
            ),
            clock=lambda: NOW,
        )
        with pytest.raises(RunPlanRefused) as refused:
            await prepared.recheck(tx)
        assert refused.value.code == "runner_unavailable"
    # A later transaction may prepare current authority from the beginning.
    async with db.transaction() as tx:
        restored = await planner.prepare_frozen(
            tx, grant=_grant_source_grant(), principal=ALICE, plan=plan
        )
        await restored.recheck(tx)
