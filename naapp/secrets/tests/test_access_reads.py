"""Confirmed access metadata on real PG; these reads never admit a request."""

from dataclasses import replace

import asyncpg
import pytest
from aweb_naapp.roles import PrincipalKey, apply_roles_migrations, assign, roles_of, unassign
from aweb_naapp.runtime.installation import AdmittedInstallation

from aweb_secrets import access_reads, jobs, records
from aweb_secrets.grant import is_secrets_role
from aweb_secrets.operation import OperationTemplate
from tests.test_change_set_records import POLICY_BODY, grant_after, item
from tests.test_change_sets import (
    ALICE,
    CAROL,
    by_member,
    change_set,
    confirm,
    decide,
    draft,
    enrol_owner,
)
from tests.test_change_sets import SECRET as OWNER_SECRET
from tests.test_change_sets import world as _world
from tests.test_jobs import after as job_after
from tests.test_records_store import (
    DID_AW,
    DID_KEY,
    INSTALLATION,
    OTHER_INSTALLATION,
    POLICY,
    SECRET,
    TEAM,
    _grant,
    _operation,
    _setup,
)
from tests.test_records_store import db as _db

db = _db
world = _world
INSTALL = AdmittedInstallation(
    app_id="secrets", installation_id=INSTALLATION, team_id=TEAM, generation=1
)
ROLE = "secrets.role.deployers"
PRINCIPAL = PrincipalKey(TEAM, DID_AW)


def job_definition(**changes):
    body = job_after()
    body["credentials"][0]["secret_ref"] = SECRET.ref
    body["env"]["DB_ADMIN"]["$credential"] = SECRET.ref
    body.update(changes)
    return jobs.JobDefinition.from_after(body)


@pytest.fixture
async def store(db):
    await jobs.apply_job_migrations(db)
    await apply_roles_migrations(db)
    await _setup(db)
    return db


async def selected(tx):
    return [role for role in await roles_of(tx, PRINCIPAL) if is_secrets_role(role)]


async def test_subjects_candidates_and_provenance_share_the_scoped_confirmed_records(store):
    direct = _grant("grt_direct01", {"principal": DID_AW})
    role = _grant("grt_role0001", {"role": ROLE})
    revoked = _grant("grt_revoked1", {"principal": DID_KEY})
    async with store.transaction() as tx:
        for grant in (direct, role, revoked):
            await records.create_grant(tx, INSTALLATION, TEAM, grant)
        await records.revoke_grant(tx, INSTALLATION, revoked.grant_id)
        await assign(tx, PRINCIPAL, ROLE)
        await records.create_secret(
            tx, OTHER_INSTALLATION, TEAM, replace(SECRET, secret_id="sec_other1")
        )
        await records.create_policy(tx, OTHER_INSTALLATION, POLICY)
        await records.create_grant(
            tx,
            OTHER_INSTALLATION,
            TEAM,
            replace(
                direct, grant_id="grt_other001", secret_id="sec_other1", subject_principal=DID_KEY
            ),
        )
    async with store.transaction() as tx:
        await tx.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        subjects = await access_reads.configured_subjects(tx, INSTALL)
        assert subjects.direct_principals == (DID_AW,)
        assert subjects.roles == (ROLE,)
        result = await access_reads.confirmed_access(
            tx, INSTALL, principal_did=DID_AW, roles=await selected(tx)
        )
        assert result.revision == 1
        assert [row.grant for row in result.candidates] == [direct, role]
        assert all(
            row.secret.record == SECRET and row.policy == POLICY for row in result.candidates
        )
        assert all(row.operations == () and row.jobs == () for row in result.candidates)
        inverse = await access_reads.confirmed_access(
            tx, INSTALL, principal_did=DID_AW, roles=[ROLE], secret_id=SECRET.secret_id
        )
        assert inverse == result
        assert (
            await access_reads.configured_subjects(tx, INSTALL, secret_id="sec_missing")
        ).roles == ()
        for wrong in (
            replace(INSTALL, team_id="other:acme.com"),
            replace(INSTALL, installation_id="absent"),
        ):
            assert (await access_reads.configured_subjects(tx, wrong)).direct_principals == ()
            assert not (
                await access_reads.confirmed_access(tx, wrong, principal_did=DID_AW, roles=[ROLE])
            ).candidates


async def test_pins_report_current_or_missing_and_never_select_history(store):
    operation = _operation()
    edited_operation = OperationTemplate.from_after({**operation.after, "timeout_s": 6})
    job = job_definition()
    edited_job = job_definition(timeout_s=61)
    grant = _grant(
        "grt_pinned01",
        {"principal": DID_AW},
        open_request=False,
        operations=[
            {"operation_id": operation.operation_id, "digest": operation.digest},
            {"operation_id": "missing-operation", "digest": "a" * 64},
        ],
    )
    run = _grant(
        "grt_run0001",
        {"principal": DID_AW},
        capability="run",
        open_request=False,
        jobs=[
            {"job_id": job.job_id, "digest": job.digest},
            {"job_id": "missing-job", "digest": "b" * 64},
        ],
    )
    async with store.transaction() as tx:
        await records.create_operation(tx, INSTALLATION, TEAM, operation)
        await records.create_operation(tx, INSTALLATION, TEAM, edited_operation)
        await jobs.create_job(tx, INSTALLATION, TEAM, job)
        await jobs.create_job(tx, INSTALLATION, TEAM, edited_job)
        for candidate in (grant, run):
            await records.create_grant(tx, INSTALLATION, TEAM, candidate)
    async with store.transaction() as tx:
        await tx.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        result = await access_reads.confirmed_access(tx, INSTALL, principal_did=DID_AW, roles=[])
        use, running = result.candidates
        pin, absent = use.operations
        assert (pin.granted_digest, pin.current) == (operation.digest, edited_operation)
        assert absent.current is None
        pin, absent = running.jobs
        assert (pin.granted_digest, pin.current) == (job.digest, edited_job)
        assert pin.source_ids == (SECRET.secret_id,)
        assert pin.source_refusal is None
        assert absent.current is None and absent.source_ids is None


async def test_fixed_slot_absence_is_a_requirement_refusal_without_fabricated_sources(store):
    definition = job_definition(
        credentials=[{"secret_ref": "not-configured", "delivery": "durable", "mint": None}], env={}
    )
    async with store.transaction() as tx:
        await jobs.create_job(tx, INSTALLATION, TEAM, definition)
        await records.create_grant(
            tx,
            INSTALLATION,
            TEAM,
            _grant(
                "grt_run0001",
                {"principal": DID_AW},
                capability="run",
                open_request=False,
                jobs=[{"job_id": definition.job_id, "digest": definition.digest}],
            ),
        )
    async with store.transaction() as tx:
        result = await access_reads.confirmed_access(tx, INSTALL, principal_did=DID_AW, roles=[])
    [pin] = result.candidates[0].jobs
    assert pin.current == definition
    assert pin.source_ids is None and pin.source_refusal == "grant_missing"


async def test_repeatable_snapshot_survives_narrowing_and_refresh_reads_new_membership(store):
    direct = _grant("grt_direct01", {"principal": DID_AW})
    role = _grant("grt_role0001", {"role": ROLE})
    async with store.transaction() as tx:
        for grant in (direct, role):
            await records.create_grant(tx, INSTALLATION, TEAM, grant)
        await assign(tx, PRINCIPAL, ROLE)
    async with store.transaction() as snapshot:
        await snapshot.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        before = await access_reads.confirmed_access(
            snapshot, INSTALL, principal_did=DID_AW, roles=await selected(snapshot)
        )
        async with store.transaction() as narrowed:
            await records.revoke_grant(narrowed, INSTALLATION, direct.grant_id)
            await unassign(narrowed, PRINCIPAL, ROLE)
        assert (
            await access_reads.confirmed_access(
                snapshot, INSTALL, principal_did=DID_AW, roles=await selected(snapshot)
            )
            == before
        )
    async with store.transaction() as refreshed:
        result = await access_reads.confirmed_access(
            refreshed, INSTALL, principal_did=DID_AW, roles=await selected(refreshed)
        )
        assert not result.candidates and result.revision == before.revision + 1


@pytest.mark.parametrize("kind", ["operation", "job"])
@pytest.mark.parametrize("lock", [True, False])
async def test_current_getters_keep_default_locking_and_allow_plain_snapshot_reads(
    store, kind, lock
):
    operation, job = _operation(), job_definition()
    async with store.transaction() as tx:
        await records.create_operation(tx, INSTALLATION, TEAM, operation)
        await jobs.create_job(tx, INSTALLATION, TEAM, job)
    async with store.transaction() as reader:
        # Deliberately omit the keyword on the default path.
        options = {} if lock else {"lock": False}
        if kind == "operation":
            await records.current_operation(
                reader, INSTALLATION, SECRET.secret_id, operation.operation_id, **options
            )
            query = "UPDATE {{tables.current_operations}} SET digest=digest"
        else:
            await jobs.current_job(reader, INSTALLATION, job.job_id, **options)
            query = "UPDATE {{tables.current_jobs}} SET digest=digest"

        async def replace_current():
            async with store.transaction() as writer:
                await writer.execute("SET LOCAL lock_timeout='100ms'")
                await writer.execute(query)

        if lock:
            with pytest.raises(asyncpg.LockNotAvailableError):
                await replace_current()
        else:
            await replace_current()


async def test_draft_and_approved_but_unconfirmed_changes_do_not_contribute(world):
    from aweb_secrets.policy import Policy

    await enrol_owner(world, ALICE, "alice@acme.com")
    policy = Policy.from_body(POLICY_BODY)
    change = change_set(
        drafter=by_member(CAROL),
        changes=[
            item("secret", "create", OWNER_SECRET["ref"], OWNER_SECRET),
            item("policy", "create", policy.digest, {"v": 1, **POLICY_BODY}),
            item("grant", "create", grant_after()["grant_id"], grant_after()),
        ],
    )
    approval_id = await draft(world, change)
    for approve in (False, True):
        if approve:
            await decide(world, approval_id, "alice@acme.com")
        async with world.db.transaction() as tx:
            assert not (
                await access_reads.configured_subjects(tx, world.admitted)
            ).direct_principals
            assert not (
                await access_reads.confirmed_access(
                    tx, world.admitted, principal_did=CAROL.principal_did, roles=[]
                )
            ).candidates
    await confirm(world, change)
    async with world.db.transaction() as tx:
        result = await access_reads.confirmed_access(
            tx, world.admitted, principal_did=CAROL.principal_did, roles=[]
        )
    assert result.revision == 1 and len(result.candidates) == 1
