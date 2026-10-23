"""The agent sees granted metadata, never custody or another team's inventory."""

from __future__ import annotations

import copy
from dataclasses import replace

import pytest
from aweb_naapp.roles import assign, principal_key, unassign

from aweb_secrets import records
from aweb_secrets.catalog import Catalog, CatalogRefused
from aweb_secrets.grant import GrantRecord
from aweb_secrets.jobs import JobDefinition, apply_job_migrations, create_job
from aweb_secrets.operation import OperationTemplate
from aweb_secrets.policy import Policy
from aweb_secrets.secret import SecretRecord
from tests.test_admission import (
    ALICE,
    BOB,
    INSTALLATION,
    POLICY_BODY,
    SECRET,
    TEAM,
    _grant_source_grant,
    db,  # noqa: F401
    fence,  # noqa: F401
)
from tests.test_jobs import after as job_after
from tests.test_operation_record import REFUND

ROLE = "secrets.role.deployers"


@pytest.fixture
async def catalog(db, fence):  # noqa: F811
    await apply_job_migrations(db)
    return Catalog(db, fence=fence)


def authority():
    return _grant_source_grant()


async def seed(db, *, subject=None, capability="use", operation=None, job=None, job_team=TEAM):  # noqa: F811
    policy = Policy.from_body(
        {
            **POLICY_BODY,
            "rate": [],
            "operations": []
            if operation is None
            else [{"operation_id": operation.operation_id, "digest": operation.digest}],
            "open_request": operation is None,
        }
    )
    secret = SecretRecord.from_after(SECRET)
    grant = GrantRecord.from_after(
        {
            "v": 1,
            "grant_id": "grt_catalog1",
            "secret_id": secret.secret_id,
            "subject": subject or {"role": ROLE},
            "capability": capability,
            "operations": []
            if operation is None
            else [{"operation_id": operation.operation_id, "digest": operation.digest}],
            "open_request": operation is None and capability == "use",
            "jobs": [] if job is None else [{"job_id": job.job_id, "digest": job.digest}],
            "policy_digest": policy.digest,
        }
    )
    async with db.transaction() as tx:
        await records.create_secret(tx, INSTALLATION, TEAM, secret)
        await records.create_policy(tx, INSTALLATION, policy)
        if operation:
            await records.create_operation(tx, INSTALLATION, TEAM, operation)
        if job:
            await create_job(tx, INSTALLATION, job_team, job)
        await records.create_grant(tx, INSTALLATION, TEAM, grant)
        await assign(tx, principal_key(ALICE), ROLE)
    return grant


async def test_role_members_see_only_their_granted_inventory(catalog, db):  # noqa: F811
    grant = await seed(db)
    visible = await catalog.list(grant=authority(), principal=ALICE)
    assert [item["ref"] for item in visible] == [SECRET["ref"]]
    assert set(visible[0]) == {"ref", "kind", "sensitivity", "approval_required", "destinations"}
    assert await catalog.list(grant=authority(), principal=BOB) == []
    async with db.transaction() as tx:
        await assign(tx, principal_key(BOB), ROLE)
    assert await catalog.list(grant=authority(), principal=BOB) == visible
    async with db.transaction() as tx:
        await unassign(tx, principal_key(ALICE), ROLE)
    assert await catalog.list(grant=authority(), principal=ALICE) == []
    assert await catalog.list(grant=authority(), principal=BOB) == visible
    async with db.transaction() as tx:
        await records.revoke_grant(tx, INSTALLATION, grant.grant_id)
    assert await catalog.list(grant=authority(), principal=BOB) == []


async def test_missing_and_ungranted_refs_are_indistinguishable(catalog, db):  # noqa: F811
    await seed(db)
    for ref in (SECRET["ref"], "missing"):
        with pytest.raises(CatalogRefused) as refused:
            await catalog.describe(ref, grant=authority(), principal=BOB)
        assert refused.value.code == "secret_not_found"


async def test_an_owner_sees_all_metadata_without_a_use_grant(catalog, db):  # noqa: F811
    await seed(db)
    async with db.transaction() as tx:
        await assign(tx, principal_key(BOB), "secrets.owner")
        await records.revoke_grant(tx, INSTALLATION, "grt_catalog1")
    assert [item["ref"] for item in await catalog.list(grant=authority(), principal=BOB)] == [
        SECRET["ref"]
    ]


async def test_another_team_cannot_read_a_principals_metadata(catalog, db):  # noqa: F811
    await seed(db, subject={"principal": principal_key(ALICE).principal_did})
    foreign = replace(ALICE, team_id="other:acme.com")
    assert (
        await catalog.list(grant=replace(authority(), team_id=foreign.team_id), principal=foreign)
        == []
    )
    with pytest.raises(CatalogRefused):
        await catalog.list(grant=authority(), principal=foreign)


async def test_only_current_pinned_operations_are_described(catalog, db):  # noqa: F811
    operation = OperationTemplate.from_after(copy.deepcopy(REFUND))
    await seed(db, operation=operation)
    result = await catalog.describe(SECRET["ref"], grant=authority(), principal=ALICE)
    assert result["operations"] == [
        {
            "operation_id": operation.operation_id,
            "digest": operation.digest,
            "params": operation.after["params"],
        }
    ]
    assert result["jobs"] == []
    changed = OperationTemplate.from_after({**operation.after, "timeout_s": 15})
    async with db.transaction() as tx:
        await records.create_operation(tx, INSTALLATION, TEAM, changed)
    assert (await catalog.describe(SECRET["ref"], grant=authority(), principal=ALICE))[
        "operations"
    ] == []
    assert not await db.fetch_value("SELECT count(*) FROM {{tables.intents}}")
    assert not await db.fetch_value("SELECT count(*) FROM {{tables.rate_buckets}}")


async def test_only_current_pinned_jobs_are_described(catalog, db):  # noqa: F811
    body = job_after()
    body["credentials"][0]["secret_ref"] = SECRET["ref"]
    body["env"]["DB_ADMIN"] = {"$credential": SECRET["ref"], "field": "value"}
    job = JobDefinition.from_after(body)
    await seed(db, capability="run", job=job)
    result = await catalog.describe(SECRET["ref"], grant=authority(), principal=ALICE)
    assert result["jobs"] == [
        {
            "job_id": job.job_id,
            "digest": job.digest,
            "params": body["params"],
            "runner_ids": body["runner_ids"],
        }
    ]
    assert result["operations"] == []
    async with db.transaction() as tx:
        await create_job(
            tx, INSTALLATION, TEAM, JobDefinition.from_after({**body, "timeout_s": 50})
        )
    assert (await catalog.describe(SECRET["ref"], grant=authority(), principal=ALICE))["jobs"] == []


async def test_disabled_secret_is_hidden_and_approval_requirement_is_explicit(catalog, db):  # noqa: F811
    await seed(db)
    async with db.transaction() as tx:
        await records.update_secret(
            tx,
            INSTALLATION,
            TEAM,
            SecretRecord.from_after({**SECRET, "sensitivity": "sensitive", "approve_only": True}),
        )
    assert (await catalog.list(grant=authority(), principal=ALICE))[0]["approval_required"] is True
    async with db.transaction() as tx:
        await tx.execute(
            "UPDATE {{tables.secrets}} SET state = 'disabled' WHERE installation_id = $1",
            INSTALLATION,
        )
    assert await catalog.list(grant=authority(), principal=ALICE) == []


async def test_reinstall_and_old_generation_never_reveal_the_previous_inventory(catalog, db):  # noqa: F811
    from aweb_naapp.runtime.installation import InstallationRefused

    await seed(db)
    assert await catalog.list(grant=authority(), principal=ALICE)
    newer = replace(authority(), installation_id="inst_reinstalled", generation=4)
    assert await catalog.list(grant=newer, principal=ALICE) == []
    with pytest.raises(InstallationRefused) as refused:
        await catalog.list(grant=authority(), principal=ALICE)
    assert refused.value.code == "generation_superseded"


async def test_job_metadata_cannot_cross_a_team_even_with_a_matching_pin(catalog, db):  # noqa: F811
    body = job_after()
    body["credentials"][0]["secret_ref"] = SECRET["ref"]
    body["env"]["DB_ADMIN"] = {"$credential": SECRET["ref"], "field": "value"}
    job = JobDefinition.from_after(body)
    # The reader still scopes the registry row if a corrupt import pointed at
    # another team's definition. A matching digest alone supplies no authority.
    await seed(db, capability="run", job=job, job_team="other:acme.com")
    assert (await catalog.describe(SECRET["ref"], grant=authority(), principal=ALICE))["jobs"] == []
