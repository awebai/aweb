"""Server-managed lineage and ancestor containment on real PostgreSQL."""

import asyncio
from datetime import UTC, datetime, timedelta

import asyncpg
import pytest

from aweb_secrets import derived_lineage as lineage
from aweb_secrets import records
from aweb_secrets.secret import SecretRecord
from tests.test_operation_record import REFUND
from tests.test_records_store import (
    DID_AW,
    INSTALLATION,
    OTHER_INSTALLATION,
    POLICY,
    SECRET,
    TEAM,
    _grant,
)
from tests.test_records_store import (
    db as db,
)

NOW = datetime(2026, 10, 21, 12, tzinfo=UTC)


async def _setup(tx):
    await records.create_secret(tx, INSTALLATION, TEAM, SECRET)
    await records.set_active_version(tx, INSTALLATION, TEAM, SECRET.secret_id, 1)
    await records.create_policy(tx, INSTALLATION, POLICY)
    grant = _grant("grt_issuer01", {"principal": DID_AW})
    await records.create_grant(tx, INSTALLATION, TEAM, grant)
    return grant


async def _child(tx, parent=SECRET.secret_id, *, child_id="sec_child001", dispatch="dispatch-1"):
    child = SecretRecord.from_after(
        {**SECRET.after, "secret_id": child_id, "ref": child_id.lower()}
    )
    await records.create_secret(tx, INSTALLATION, TEAM, child)
    await records.set_active_version(tx, INSTALLATION, TEAM, child_id, 1)
    grant_id = "grt_issuer01"
    if parent != SECRET.secret_id:
        grant_id = "grt_childissuer"
        await records.create_grant(
            tx,
            INSTALLATION,
            TEAM,
            _grant(grant_id, {"principal": DID_AW}, secret_id=parent),
        )
    await lineage.record_lineage(
        tx,
        installation_id=INSTALLATION,
        team_id=TEAM,
        secret_id=child_id,
        parent_secret_id=parent,
        parent_version=1,
        source_dispatch_id=dispatch,
        source_grant_id=grant_id,
        issuing_principal=DID_AW,
        policy_digest=POLICY.digest,
        dispatch_started_at=NOW,
        upstream_expires_at=NOW + timedelta(hours=2),
        expires_at=NOW + timedelta(hours=1),
        now=NOW,
    )
    return child


async def test_lineage_is_scoped_and_locks_root_to_leaf(db) -> None:
    async with db.transaction() as tx:
        await _setup(tx)
        child = await _child(tx)
        grandchild = await _child(
            tx, child.secret_id, child_id="sec_grand001", dispatch="dispatch-2"
        )
        nodes = await lineage.lock_ancestry(tx, INSTALLATION, TEAM, grandchild.secret_id)
        assert [node.secret.record.secret_id for node in nodes] == [
            SECRET.secret_id,
            child.secret_id,
            grandchild.secret_id,
        ]
        assert nodes[-1].source_grant_id == "grt_childissuer"
        assert await lineage.lock_ancestry(tx, OTHER_INSTALLATION, TEAM, grandchild.secret_id) == ()
        assert (
            await lineage.lock_ancestry(tx, INSTALLATION, "other:example.com", grandchild.secret_id)
            == ()
        )


async def test_one_dispatch_cannot_create_two_children(db) -> None:
    async with db.transaction() as tx:
        await _setup(tx)
        await _child(tx)
        with pytest.raises(asyncpg.UniqueViolationError):
            async with tx.transaction() as attempt:
                await _child(attempt, child_id="sec_child002")


async def test_directory_ancestry_read_does_not_wait_for_outer_admission_locks(db) -> None:
    async with db.transaction() as tx:
        await _setup(tx)
        child = await _child(tx)
    async with db.transaction() as outer:
        await lineage.lock_ancestry(outer, INSTALLATION, TEAM, child.secret_id)
        async with db.transaction() as directory:
            ids = await asyncio.wait_for(
                lineage.ancestry_ids(directory, INSTALLATION, TEAM, child.secret_id),
                timeout=1,
            )
            assert ids == (SECRET.secret_id, child.secret_id)


@pytest.mark.parametrize(
    "mutation,code",
    [
        ("disable", "secret_disabled"),
        ("version", "secret_version_changed"),
        ("revoke", "grant_revoked"),
        ("expire", "secret_disabled"),
    ],
)
async def test_ancestor_authority_is_rechecked_under_locks(db, mutation, code) -> None:
    async with db.transaction() as tx:
        await _setup(tx)
        child = await _child(tx)
        if mutation == "disable":
            await tx.execute(
                "UPDATE {{tables.secrets}} SET state='disabled' WHERE secret_id=$1",
                SECRET.secret_id,
            )
        elif mutation == "version":
            await records.set_active_version(tx, INSTALLATION, TEAM, SECRET.secret_id, 2)
        elif mutation == "revoke":
            await records.revoke_grant(tx, INSTALLATION, "grt_issuer01")
        nodes = await lineage.lock_ancestry(tx, INSTALLATION, TEAM, child.secret_id)
        with pytest.raises(lineage.LineageRefused) as refused:
            await lineage.check_ancestry(
                tx, nodes, now=NOW + timedelta(hours=1) if mutation == "expire" else NOW
            )
        assert refused.value.code == code


async def test_a_tighter_current_cap_narrows_but_never_extends_stored_expiry(db) -> None:
    async with db.transaction() as tx:
        await _setup(tx)
        child = await _child(tx)
        nodes = await lineage.lock_ancestry(tx, INSTALLATION, TEAM, child.secret_id)
        with pytest.raises(lineage.LineageRefused):
            await lineage.check_ancestry(tx, nodes, now=NOW + timedelta(seconds=61), max_ttl_s=60)
        with pytest.raises(lineage.LineageRefused):
            await lineage.check_ancestry(tx, nodes, now=NOW + timedelta(hours=1), max_ttl_s=7200)


async def test_operation_resolution_selects_nearest_current_definition_without_fallback(db) -> None:
    from aweb_secrets.operation import OperationTemplate

    async with db.transaction() as tx:
        await _setup(tx)
        child = await _child(tx)
        ancestor_operation = OperationTemplate.from_after({**REFUND, "secret_id": SECRET.secret_id})
        await records.create_operation(tx, INSTALLATION, TEAM, ancestor_operation)
        nodes = await lineage.lock_ancestry(tx, INSTALLATION, TEAM, child.secret_id)
        selected = await lineage.current_operation(tx, nodes, ancestor_operation.operation_id)
        assert selected.digest == ancestor_operation.digest
        assert selected.secret_id == SECRET.secret_id
        nearer = OperationTemplate.from_after({**REFUND, "secret_id": child.secret_id})
        await records.create_operation(tx, INSTALLATION, TEAM, nearer)
        selected = await lineage.current_operation(tx, nodes, nearer.operation_id)
        assert selected.digest == nearer.digest
        assert selected.digest != ancestor_operation.digest


async def test_lineage_is_immutable_and_rolls_back_with_creation(db) -> None:
    async with db.transaction() as tx:
        await _setup(tx)
        child = await _child(tx)
    with pytest.raises(asyncpg.RaiseError):
        async with db.transaction() as tx:
            await tx.execute(
                "UPDATE {{tables.derived_secrets}} SET parent_version=2 WHERE secret_id=$1",
                child.secret_id,
            )
    with pytest.raises(RuntimeError):
        async with db.transaction() as tx:
            await _child(tx, child_id="sec_roll001", dispatch="dispatch-rollback")
            raise RuntimeError("roll back")
    async with db.transaction() as tx:
        assert await records.secret_by_ref(tx, INSTALLATION, TEAM, "sec_roll001") is None
