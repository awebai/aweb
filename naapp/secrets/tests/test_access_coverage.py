"""Configured coverage shares real admission's predicates, never its effects."""

from dataclasses import replace

import pytest
from aweb_naapp.roles import assign, principal_key, roles_of, unassign

from aweb_secrets import jobs, records
from aweb_secrets.admission import AdmissionRefused
from aweb_secrets.grant import GrantRecord, is_secrets_role
from aweb_secrets.jobs import JobDefinition
from aweb_secrets.run_plan import RunPlanRefused
from aweb_secrets.secret import SecretRecord
from tests.test_admission import (
    ALICE,
    INSTALLATION,
    POLICY_BODY,
    SECRET,
    TEAM,
    _admit,
    _install,
    _install_operation,
    _named,
    _operation,
    _request,
)
from tests.test_admission import db as db
from tests.test_admission import fence as fence
from tests.test_run_planner import _planner, _prepare, _setup


async def candidates(db):
    async with db.transaction() as tx:
        roles = [r for r in await roles_of(tx, principal_key(ALICE)) if is_secrets_role(r)]
        return await records.active_grants(
            tx,
            INSTALLATION,
            SECRET["secret_id"],
            principal_did=principal_key(ALICE).principal_did,
            roles=roles,
            lock=False,
        )


@pytest.mark.parametrize(
    "case,expected",
    [
        ("named", None),
        ("edited", "operation_not_allowed"),
        ("missing", "operation_not_allowed"),
        ("policy_pin", "operation_not_allowed"),
        ("grant_pin", "operation_not_allowed"),
        ("sensitive_projection", "operation_not_allowed"),
        ("token_denied", "token_issuing_denied"),
        ("token_withheld", None),
        ("open", None),
        ("open_policy", "open_request_not_allowed"),
        ("open_grant", "open_request_not_allowed"),
        ("open_sensitive", "open_request_not_allowed"),
    ],
)
async def test_use_coverage_matches_real_admission_at_fixed_current_inputs(
    db, fence, case, expected
):
    from aweb_secrets.admission import use_coverage_refusal

    operation = _operation()
    sensitivity = "standard"
    if case == "sensitive_projection":
        operation = _operation(
            response={"projection": None, "max_bytes": 4096, "content_types": ["application/json"]}
        )
        sensitivity = "sensitive"
    elif case.startswith("token_"):
        operation = _operation(
            token_issuing=True,
            result_handling="withhold" if case == "token_withheld" else "deny",
        )
    if case.startswith("open"):
        sensitivity = "sensitive" if case == "open_sensitive" else "standard"
        policy_changes = {"open_request": False} if case == "open_policy" else {}
        if case == "open_grant":
            policy = await _install_operation(db, operation, policy_changes={"open_request": True})
        else:
            policy = await _install(
                db,
                secret={**SECRET, "sensitivity": sensitivity},
                policy_body={**POLICY_BODY, **policy_changes},
            )
        request, operation = _request(), None
    else:
        policy = await _install_operation(
            db,
            operation,
            secret={**SECRET, "sensitivity": "standard"},
            policy_changes={"operations": []} if case == "policy_pin" else None,
            **({"operations": [], "open_request": True} if case == "grant_pin" else {}),
        )
        if case == "sensitive_projection":
            # The real writer refuses installing an unprojected operation on
            # an already-sensitive secret. Narrow an existing standard secret,
            # as the admission regression does, to exercise its live guard.
            async with db.transaction() as tx:
                await records.update_secret(
                    tx,
                    INSTALLATION,
                    TEAM,
                    SecretRecord.from_after({**SECRET, "sensitivity": sensitivity}),
                )
        request = _named()
        if case == "edited":
            operation = _operation(timeout_s=5)
            async with db.transaction() as tx:
                await records.create_operation(tx, INSTALLATION, TEAM, operation)
        elif case == "missing":
            operation = None
            request = replace(request, operation_id="missing-operation")
    [grant] = await candidates(db)
    assert (
        use_coverage_refusal(
            grant,
            policy,
            operation_id=request.operation_id,
            operation=operation,
            sensitivity=sensitivity,
        )
        == expected
    )
    if expected is None:
        assert (await _admit(db, fence, request=request)).grant_id == grant.grant_id
    else:
        with pytest.raises(AdmissionRefused) as refused:
            await _admit(db, fence, request=request)
        assert refused.value.code == expected


async def test_configured_coverage_does_not_validate_a_future_requests_parameters(db, fence):
    from aweb_secrets.admission import use_coverage_refusal

    operation = _operation()
    policy = await _install_operation(db, operation)
    [grant] = await candidates(db)
    assert (
        use_coverage_refusal(
            grant,
            policy,
            operation_id=operation.operation_id,
            operation=operation,
            sensitivity="standard",
        )
        is None
    )
    with pytest.raises(AdmissionRefused) as refused:
        await _admit(db, fence, request=replace(_named(), params={"charge": "ch/3Pq"}))
    assert refused.value.code == "params_invalid"


@pytest.mark.parametrize("capability", ["use", "run"])
@pytest.mark.parametrize("narrow", ["grant", "role"])
async def test_confirmed_candidates_and_real_admission_agree_after_narrowing(
    db, fence, capability, narrow
):
    from aweb_secrets.admission import use_coverage_refusal
    from aweb_secrets.run_planner import run_grant_covers_job

    role = "secrets.role.dbwriters"
    subject = {"role": role} if narrow == "role" else None
    if capability == "run":
        job = await _setup(db, subject=subject)
    else:
        operation = _operation()
        policy = await _install_operation(db, operation, subject=subject)
    if narrow == "role":
        async with db.transaction() as tx:
            await assign(tx, principal_key(ALICE), role)
    [grant] = await candidates(db)
    if capability == "run":
        assert run_grant_covers_job(grant, job)
        async with db.transaction() as tx:
            assert (await _prepare(tx, _planner(fence), job)).slots[0].parent_grant == grant
    else:
        assert (
            use_coverage_refusal(
                grant,
                policy,
                operation_id=operation.operation_id,
                operation=operation,
                sensitivity="standard",
            )
            is None
        )
        assert (await _admit(db, fence, request=_named())).grant_id == grant.grant_id
    async with db.transaction() as tx:
        if narrow == "role":
            await unassign(tx, principal_key(ALICE), role)
        else:
            await records.revoke_grant(tx, INSTALLATION, grant.grant_id)
    assert await candidates(db) == []
    if capability == "run":
        async with db.transaction() as tx:
            with pytest.raises(RunPlanRefused) as refused:
                await _prepare(tx, _planner(fence), job)
        assert refused.value.code == "job_not_allowed"
    else:
        with pytest.raises(AdmissionRefused) as refused:
            await _admit(db, fence, request=_named("after-narrowing"))
        assert refused.value.code == "grant_missing"


async def test_run_coverage_requires_the_exact_job_digest_and_run_capability(db, fence):
    from aweb_secrets.run_planner import run_grant_covers_job

    job = await _setup(db)
    [grant] = await candidates(db)
    assert run_grant_covers_job(grant, job)
    changed = job.after
    changed["timeout_s"] += 1
    edited = JobDefinition.from_after(changed)
    assert not run_grant_covers_job(grant, edited)
    async with db.transaction() as tx:
        await jobs.create_job(tx, INSTALLATION, TEAM, edited)
        with pytest.raises(RunPlanRefused) as refused:
            await _prepare(tx, _planner(fence), edited)
    assert refused.value.code == "job_not_allowed"
    use_grant = {**grant.after, "capability": "use", "jobs": [], "open_request": True}
    assert not run_grant_covers_job(GrantRecord.from_after(use_grant), job)
