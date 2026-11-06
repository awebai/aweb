"""Issuance pins complete terms and nearest current broker definitions on real PG."""

import pytest

from aweb_secrets import derived_grants, derived_lineage, records
from aweb_secrets.grant import GrantTemplate
from aweb_secrets.jobs import JobDefinition, apply_job_migrations, create_job, job_by_digest
from aweb_secrets.operation import OperationTemplate
from aweb_secrets.policy import Policy
from tests.test_derived_lineage import _child, _setup
from tests.test_jobs import after as job_after
from tests.test_operation_record import REFUND
from tests.test_records_store import DID_AW, DID_KEY, INSTALLATION, POLICY, SECRET, TEAM
from tests.test_records_store import db as db


def _template(**changes):
    return GrantTemplate.from_after(
        {
            "v": 1,
            "grant_template_id": "gtp_child001",
            "subject": {"principal": DID_AW},
            "capability": "use",
            "operations": [],
            "open_request": True,
            "jobs": [],
            "policy_digest": POLICY.digest,
            **changes,
        }
    )


async def _snapshot(tx, nodes, template):
    return await derived_grants.snapshot_grant_template(
        tx,
        nodes,
        template_id=template.grant_template_id,
        expected_digest=template.digest,
    )


async def test_snapshot_is_immutable_and_fence_refuses_edited_complete_terms(db):
    async with db.transaction() as tx:
        await _setup(tx)
        original = _template()
        await records.set_grant_template(tx, INSTALLATION, original)
        nodes = await derived_lineage.lock_ancestry(tx, INSTALLATION, TEAM, SECRET.secret_id)
        snapshot = await _snapshot(tx, nodes, original)
        # A caller's mutable view cannot alter the persisted canonical snapshot.
        snapshot.template.terms["subject"]["principal"] = DID_KEY
        assert snapshot.template.digest == original.digest
        assert (
            await derived_grants.fence_grant_snapshot(
                tx,
                nodes,
                snapshot,
                expected_digest=original.digest,
            )
        ).after == original.after
        await records.set_grant_template(
            tx, INSTALLATION, _template(subject={"principal": DID_KEY})
        )
        with pytest.raises(derived_grants.DerivedGrantRefused) as refused:
            await derived_grants.fence_grant_snapshot(
                tx, nodes, snapshot, expected_digest=original.digest
            )
        assert refused.value.code == "operation_not_allowed"


@pytest.mark.parametrize("missing", [True, False])
async def test_missing_or_unpinned_template_refuses(db, missing):
    async with db.transaction() as tx:
        await _setup(tx)
        template = _template()
        if not missing:
            await records.set_grant_template(tx, INSTALLATION, template)
        nodes = await derived_lineage.lock_ancestry(tx, INSTALLATION, TEAM, SECRET.secret_id)
        with pytest.raises(derived_grants.DerivedGrantRefused):
            await derived_grants.snapshot_grant_template(
                tx,
                nodes,
                template_id=template.grant_template_id,
                expected_digest="0" * 64,
            )


async def test_missing_current_job_cannot_authorize_a_run_template(db):
    async with db.transaction() as tx:
        await _setup(tx)
        template = _template(
            capability="run", open_request=False, jobs=[{"job_id": "backup", "digest": "1" * 64}]
        )
        await records.set_grant_template(tx, INSTALLATION, template)
        nodes = await derived_lineage.lock_ancestry(tx, INSTALLATION, TEAM, SECRET.secret_id)
        with pytest.raises(derived_grants.DerivedGrantRefused) as refused:
            await _snapshot(tx, nodes, template)
        assert refused.value.code == "job_not_allowed"


@pytest.mark.parametrize("incompatibility", ["sensitive_open", "policy_open", "missing_policy"])
async def test_child_open_grant_must_match_its_inherited_sensitivity_and_policy(
    db, incompatibility
):
    async with db.transaction() as tx:
        await _setup(tx)
        template = _template()
        if incompatibility == "sensitive_open":
            from aweb_secrets.secret import SecretRecord

            await records.update_secret(
                tx,
                INSTALLATION,
                TEAM,
                SecretRecord.from_after({**SECRET.after, "sensitivity": "sensitive"}),
            )
        elif incompatibility == "policy_open":
            policy = Policy.from_body({**POLICY.body, "open_request": False})
            await records.create_policy(tx, INSTALLATION, policy)
            template = _template(policy_digest=policy.digest)
        else:
            template = _template(policy_digest="0" * 64)
        await records.set_grant_template(tx, INSTALLATION, template)
        nodes = await derived_lineage.lock_ancestry(tx, INSTALLATION, TEAM, SECRET.secret_id)
        with pytest.raises(derived_grants.DerivedGrantRefused):
            await _snapshot(tx, nodes, template)


@pytest.mark.parametrize("mutation", ["edit", "nearer", "policy_pin", "missing_operation"])
async def test_only_the_nearest_current_operation_and_both_pins_can_authorize_child(db, mutation):
    async with db.transaction() as tx:
        await _setup(tx)
        operation = OperationTemplate.from_after({**REFUND, "secret_id": SECRET.secret_id})
        if mutation != "missing_operation":
            await records.create_operation(tx, INSTALLATION, TEAM, operation)
        child = await _child(tx)
        pin = {"operation_id": operation.operation_id, "digest": operation.digest}
        policy = Policy.from_body(
            {**POLICY.body, "operations": [] if mutation == "policy_pin" else [pin]}
        )
        await records.create_policy(tx, INSTALLATION, policy)
        template = _template(open_request=False, operations=[pin], policy_digest=policy.digest)
        await records.set_grant_template(tx, INSTALLATION, template)
        nodes = await derived_lineage.lock_ancestry(tx, INSTALLATION, TEAM, child.secret_id)
        if mutation in ("policy_pin", "missing_operation"):
            with pytest.raises(derived_grants.DerivedGrantRefused):
                await _snapshot(tx, nodes, template)
            return
        snapshot = await _snapshot(tx, nodes, template)
        after = {**operation.after}
        if mutation == "nearer":
            after["secret_id"] = child.secret_id
        else:
            after["response"] = {**after["response"], "max_bytes": 1024}
        await records.create_operation(tx, INSTALLATION, TEAM, OperationTemplate.from_after(after))
        with pytest.raises(derived_grants.DerivedGrantRefused):
            await derived_grants.fence_grant_snapshot(
                tx, nodes, snapshot, expected_digest=template.digest
            )


@pytest.fixture(autouse=True)
async def job_registry(db):
    await apply_job_migrations(db)


def _job(refs, *, delivery="durable"):
    body = job_after()
    body["job_id"] = "backup"
    body["credentials"] = [
        {
            "secret_ref": ref,
            "delivery": delivery,
            "mint": None
            if delivery == "durable"
            else {"operation_id": "mint-session", "digest": "c" * 64, "params": {}},
        }
        for ref in refs
    ]
    body["env"] = {
        "CREDENTIAL_" + str(i): {"$credential": ref, "field": "value"} for i, ref in enumerate(refs)
    }
    return JobDefinition.from_after(body)


def _run_template(job, **changes):
    return _template(
        capability="run",
        open_request=False,
        jobs=[{"job_id": job.job_id, "digest": job.digest}],
        **changes,
    )


@pytest.mark.parametrize("selector", ["root", "child"])
async def test_run_template_accepts_its_current_job_and_one_lineage_slot(db, selector):
    async with db.transaction() as tx:
        await _setup(tx)
        child = await _child(tx)
        nodes = await derived_lineage.lock_ancestry(tx, INSTALLATION, TEAM, child.secret_id)
        job = _job([SECRET.ref if selector == "root" else child.ref])
        await create_job(tx, INSTALLATION, TEAM, job)
        template = _run_template(job)
        await records.set_grant_template(tx, INSTALLATION, template)
        snapshot = await _snapshot(tx, nodes, template)
        assert (
            await derived_grants.fence_grant_snapshot(
                tx, nodes, snapshot, expected_digest=template.digest
            )
        ).after == template.after


@pytest.mark.parametrize(
    "boundary",
    [
        "two_ancestors",
        "exact_plus_ancestor",
        "unrelated",
        "short_lived",
        "other_installation",
        "wrong_digest",
    ],
)
async def test_run_template_refuses_incompatible_jobs_before_snapshot(db, boundary):
    from tests.test_records_store import OTHER_INSTALLATION

    async with db.transaction() as tx:
        await _setup(tx)
        child = await _child(tx)
        grandchild = await _child(
            tx, child.secret_id, child_id="sec_grand001", dispatch="dispatch-2"
        )
        nodes = await derived_lineage.lock_ancestry(tx, INSTALLATION, TEAM, grandchild.secret_id)
        selectors = {
            "two_ancestors": [SECRET.ref, child.ref],
            "exact_plus_ancestor": [SECRET.ref, grandchild.ref],
            "unrelated": ["other-source"],
        }.get(boundary, [SECRET.ref])
        job = _job(selectors, delivery="short_lived" if boundary == "short_lived" else "durable")
        await create_job(
            tx, OTHER_INSTALLATION if boundary == "other_installation" else INSTALLATION, TEAM, job
        )
        template = _run_template(job)
        if boundary == "wrong_digest":
            template = _template(
                capability="run",
                open_request=False,
                jobs=[{"job_id": job.job_id, "digest": "1" * 64}],
            )
        await records.set_grant_template(tx, INSTALLATION, template)
        with pytest.raises(derived_grants.DerivedGrantRefused) as refused:
            await _snapshot(tx, nodes, template)
        assert refused.value.code == "job_not_allowed"


async def test_current_job_edit_refuses_at_run_template_fence_without_history_fallback(db):
    async with db.transaction() as tx:
        await _setup(tx)
        job = _job([SECRET.ref])
        await create_job(tx, INSTALLATION, TEAM, job)
        template = _run_template(job)
        await records.set_grant_template(tx, INSTALLATION, template)
        nodes = await derived_lineage.lock_ancestry(tx, INSTALLATION, TEAM, SECRET.secret_id)
        snapshot = await _snapshot(tx, nodes, template)
        edited = job.after
        edited["timeout_s"] += 1
        await create_job(tx, INSTALLATION, TEAM, JobDefinition.from_after(edited))
        assert await job_by_digest(tx, INSTALLATION, job.job_id, job.digest) is not None
        with pytest.raises(derived_grants.DerivedGrantRefused) as refused:
            await derived_grants.fence_grant_snapshot(
                tx, nodes, snapshot, expected_digest=template.digest
            )
        assert refused.value.code == "job_not_allowed"


async def test_run_template_still_requires_its_child_policy_pin(db):
    async with db.transaction() as tx:
        await _setup(tx)
        job = _job([SECRET.ref])
        await create_job(tx, INSTALLATION, TEAM, job)
        template = _run_template(job, policy_digest="0" * 64)
        await records.set_grant_template(tx, INSTALLATION, template)
        nodes = await derived_lineage.lock_ancestry(tx, INSTALLATION, TEAM, SECRET.secret_id)
        with pytest.raises(derived_grants.DerivedGrantRefused) as refused:
            await _snapshot(tx, nodes, template)
        assert refused.value.code == "operation_not_allowed"


async def test_every_job_pin_in_a_run_template_must_be_current_and_compatible(db):
    async with db.transaction() as tx:
        await _setup(tx)
        job = _job([SECRET.ref])
        await create_job(tx, INSTALLATION, TEAM, job)
        template = _template(
            capability="run",
            open_request=False,
            jobs=[
                {"job_id": job.job_id, "digest": job.digest},
                {"job_id": "zz-missing", "digest": "1" * 64},
            ],
        )
        await records.set_grant_template(tx, INSTALLATION, template)
        nodes = await derived_lineage.lock_ancestry(tx, INSTALLATION, TEAM, SECRET.secret_id)
        with pytest.raises(derived_grants.DerivedGrantRefused) as refused:
            await _snapshot(tx, nodes, template)
        assert refused.value.code == "job_not_allowed"
