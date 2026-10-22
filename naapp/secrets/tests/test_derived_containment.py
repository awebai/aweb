"""Grant cascades use real lineage, sealed custody and S12/B2 approvals."""

import secrets

import pytest
from aweb_naapp.runtime.approvals import ApprovalState
from aweb_naapp_testing.owner_acts import INSTALLATION_ID

from aweb_secrets import records
from aweb_secrets.custody import CustodyUnavailable, SealContext, encode_value
from aweb_secrets.derived_containment import revoke_grant_tree
from aweb_secrets.secret import SecretRecord
from tests.test_change_sets import TEAM, world  # noqa: F401
from tests.test_use_approval_lineage import child, grant_record, request_child, seed
from tests.test_use_approvals import SECRET, SECRET_ID, approve, uses  # noqa: F401


async def test_revoking_a_source_grant_atomically_contains_only_its_descendants(uses):  # noqa: F811
    source = await seed(uses)
    root = SecretRecord.from_after(SECRET)
    direct_pending = await request_child(uses, root)
    direct_approved = await request_child(uses, root)
    await approve(uses, direct_approved[2], "finance@acme.com")
    first, _ = await child(uses)
    grandchild, _ = await child(uses, secret_id="sec_grand001", parent=first.secret_id)
    async with uses.world.db.transaction() as tx:
        digest = await tx.fetch_value(
            "SELECT policy_digest FROM {{tables.grants}} WHERE grant_id=$1", source
        )
        sibling_source = grant_record("grt_----control", SECRET_ID, digest)
        await records.create_grant(tx, INSTALLATION_ID, TEAM, sibling_source)
    sibling, _ = await child(uses, secret_id="sec_sibling01", source_grant=sibling_source.grant_id)
    direct_control = await request_child(uses, root)
    assert direct_control[0].grant_id == sibling_source.grant_id
    pending = await request_child(uses, first)
    approved = await request_child(uses, grandchild)
    await approve(uses, approved[2], "finance@acme.com")
    untouched = await request_child(uses, sibling)
    contexts = []
    for secret in (first, grandchild, sibling):
        async with uses.world.db.transaction() as tx:
            version = await uses.world.custody.sealer.ingest(
                tx,
                installation_id=INSTALLATION_ID,
                team_id=TEAM,
                secret_id=secret.secret_id,
                value=encode_value(secret.kind, {"value": secrets.token_urlsafe(32)}),
            )
        contexts.append(SealContext(INSTALLATION_ID, TEAM, secret.secret_id, version))

    async def cascade(tx, team=TEAM):
        await uses.world.fence.admit(tx, uses.grant)
        return await revoke_grant_tree(
            tx,
            uses.approvals,
            uses.world.custody,
            installation_id=INSTALLATION_ID,
            team_id=team,
            grant_id=source,
            revoked_by="owner",
        )

    async with uses.world.db.transaction() as tx:
        assert await cascade(tx, team="other:example.com") == ()
    with pytest.raises(RuntimeError):
        async with uses.world.db.transaction() as tx:
            assert set(await cascade(tx)) == {first.secret_id, grandchild.secret_id}
            raise RuntimeError("rollback")
    assert (await uses.approvals.get(pending[2].pending.approval.approval_id)).revoked_at is None
    assert (
        await uses.approvals.get(approved[2].pending.approval.approval_id)
    ).state is ApprovalState.APPROVED
    assert (
        await uses.world.db.fetch_value(
            "SELECT revoked_at FROM {{tables.grants}} WHERE grant_id=$1", source
        )
        is None
    )
    assert (
        await uses.world.db.fetch_value(
            "SELECT state FROM {{tables.secrets}} WHERE secret_id=$1", first.secret_id
        )
        == "active"
    )
    for item in (direct_pending, direct_approved, direct_control):
        assert (await uses.approvals.get(item[2].pending.approval.approval_id)).revoked_at is None
    for context in contexts:
        await uses.world.custody.opener.open(context)
    async with uses.world.db.transaction() as tx:
        assert set(await cascade(tx)) == {first.secret_id, grandchild.secret_id}
    assert (
        await uses.approvals.get(pending[2].pending.approval.approval_id)
    ).state is ApprovalState.REVOKED
    assert (
        await uses.approvals.get(approved[2].pending.approval.approval_id)
    ).state is ApprovalState.REVOKED
    assert (await uses.approvals.get(untouched[2].pending.approval.approval_id)).revoked_at is None
    for item in (direct_pending, direct_approved):
        assert (
            await uses.approvals.get(item[2].pending.approval.approval_id)
        ).state is ApprovalState.REVOKED
    assert (
        await uses.approvals.get(direct_control[2].pending.approval.approval_id)
    ).revoked_at is None
    for context in contexts[:2]:
        with pytest.raises(CustodyUnavailable):
            await uses.world.custody.opener.open(context)
    await uses.world.custody.opener.open(contexts[-1])
    async with uses.world.db.transaction() as tx:
        states = await tx.fetch_all("SELECT secret_id,state FROM {{tables.secrets}}")
    state = {row["secret_id"]: row["state"] for row in states}
    assert state[first.secret_id] == state[grandchild.secret_id] == "disabled"
    assert state[SECRET_ID] == state[sibling.secret_id] == "active"
