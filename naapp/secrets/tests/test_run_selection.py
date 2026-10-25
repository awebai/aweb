"""Optional ordinary-child selection uses real lineage and its own run grant."""

from datetime import timedelta
from uuid import uuid4

import pytest

from aweb_secrets import derived_lineage, jobs, records
from aweb_secrets.grant import GrantRecord
from aweb_secrets.run_plan import RunPlanRefused
from aweb_secrets.secret import SecretRecord
from tests.test_admission import ALICE, INSTALLATION, NOW, SECRET, TEAM, _grant_source_grant
from tests.test_admission import db as db
from tests.test_admission import fence as fence
from tests.test_run_planner import _planner, _setup


async def child_for(db, job, *, grant=True):
    child = SecretRecord.from_after(
        {**SECRET, "secret_id": "sec_selected01", "ref": "selected-child"}
    )
    async with db.transaction() as tx:
        policy = await tx.fetch_value(
            "SELECT policy_digest FROM {{tables.grants}} WHERE grant_id='grt_alice001'"
        )
        issuer = GrantRecord.from_after(
            {
                "v": 1,
                "grant_id": "grt_selector_issuer",
                "secret_id": SECRET["secret_id"],
                "subject": {"principal": ALICE.did_aw},
                "capability": "use",
                "operations": [],
                "open_request": True,
                "jobs": [],
                "policy_digest": policy,
            }
        )
        await records.create_grant(tx, INSTALLATION, TEAM, issuer)
        await records.create_secret(tx, INSTALLATION, TEAM, child)
        await records.set_active_version(tx, INSTALLATION, TEAM, child.secret_id, 4)
        await derived_lineage.record_lineage(
            tx,
            installation_id=INSTALLATION,
            team_id=TEAM,
            secret_id=child.secret_id,
            parent_secret_id=SECRET["secret_id"],
            parent_version=4,
            source_dispatch_id="selector-source",
            source_grant_id=issuer.grant_id,
            issuing_principal=ALICE.did_aw,
            policy_digest=policy,
            dispatch_started_at=NOW,
            upstream_expires_at=NOW + timedelta(hours=2),
            expires_at=NOW + timedelta(hours=1),
            clock=lambda: NOW,
        )
        if grant:
            await records.create_grant(
                tx,
                INSTALLATION,
                TEAM,
                GrantRecord.from_after(
                    {
                        **issuer.after,
                        "grant_id": "grt_selector_child",
                        "secret_id": child.secret_id,
                        "capability": "run",
                        "open_request": False,
                        "jobs": [{"job_id": job.job_id, "digest": job.digest}],
                    }
                ),
            )
    return child


async def selected(tx, fence, job, ref):
    return await _planner(fence).prepare(
        tx,
        grant=_grant_source_grant(),
        principal=ALICE,
        run_id="run_selected001",
        intent_id="int_selected001",
        dispatch_id=uuid4(),
        candidate_job=job,
        runner_id=job.after["runner_ids"][0],
        params={"database": "orders"},
        selected_ref=ref,
    )


async def test_unique_ancestor_slot_freezes_actual_child_and_preserves_fixed_label(db, fence):
    job = await _setup(db)
    child = await child_for(db, job)
    async with db.transaction() as tx:
        prepared = await selected(tx, fence, job, child.ref)
        assert prepared.slots[0].source_id == child.secret_id
        assert prepared.slots[0].body["label"] == SECRET["ref"]
        assert prepared.slots[0].parent_grant.grant_id == "grt_selector_child"
        await prepared.recheck(tx)
    async with db.transaction() as tx:
        restored = await _planner(fence).prepare_frozen(
            tx, grant=_grant_source_grant(), principal=ALICE, plan=prepared.plan
        )
        await restored.recheck(tx)
        assert restored.plan.canonical == prepared.plan.canonical


@pytest.mark.parametrize("ref", ["missing-child", SECRET["ref"]])
async def test_unknown_or_nonderived_ref_cannot_select_a_durable_slot(db, fence, ref):
    job = await _setup(db)
    async with db.transaction() as tx:
        with pytest.raises(RunPlanRefused) as refused:
            await selected(tx, fence, job, ref)
        assert refused.value.code == "job_not_allowed"
        assert await tx.fetch_value("SELECT count(*) FROM {{tables.intents}}") == 0


async def test_child_does_not_borrow_its_ancestor_run_grant(db, fence):
    job = await _setup(db)
    child = await child_for(db, job, grant=False)
    async with db.transaction() as tx:
        with pytest.raises(RunPlanRefused) as refused:
            await selected(tx, fence, job, child.ref)
        assert refused.value.code == "grant_missing"


async def test_exact_child_and_ancestor_slots_are_ambiguous_without_priority(db, fence):
    job = await _setup(db)
    child = await child_for(db, job)
    body = job.after
    body["credentials"].append({"secret_ref": child.ref, "delivery": "durable", "mint": None})
    changed = jobs.JobDefinition.from_after(body)
    async with db.transaction() as tx:
        await jobs.create_job(tx, INSTALLATION, TEAM, changed)
        with pytest.raises(RunPlanRefused) as refused:
            await selected(tx, fence, changed, child.ref)
        assert refused.value.code == "job_not_allowed"
