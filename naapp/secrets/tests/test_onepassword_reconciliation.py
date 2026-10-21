"""Real scoped PG reconciliation; SDK model fixtures are not HO6 vault proof."""

import asyncio
import os
from dataclasses import replace

import pytest
from aweb_naapp.hooks.envelope import verify
from aweb_naapp_testing.owner_acts import INSTALLATION_ID

from aweb_secrets.custody import CustodyUnavailable
from aweb_secrets.custody.onepassword import project_item
from aweb_secrets.custody.opening import BackendObservation, active_binding
from aweb_secrets.onepassword_reconciliation import BackendReconciler
from aweb_secrets.revisions import config_revision
from tests.custody.test_onepassword import field, sdk_item
from tests.test_change_set_onepassword import apply, initial, pending, staged, token_item
from tests.test_change_sets import TEAM
from tests.test_change_sets import world as _world
from tests.test_use_approvals import uses as _uses

world = _world
uses = _uses


def reconciler(w):
    return BackendReconciler(db=w.db, custody=w.custody, containment=w.containment, fence=w.fence)


async def observe(w, context, *, version=8):
    binding = await active_binding(w.db, context)
    # One actual Item projection validates the whole mapping before bytes are discarded.
    read = project_item(
        binding.reference,
        sdk_item([field("credential", os.urandom(24).hex())], version=version),
        credential_context=binding.credential_context,
    )
    return BackendObservation(binding, read.item_version, read.updated_at)


@pytest.mark.parametrize("version", [8, 6])
async def test_changed_remote_version_activates_monotonic_context_and_records_opaque_event(
    world, version
):
    w = world
    _, record, token, old, _, first, _ = await initial(w)
    await apply(w, first)
    observation = await observe(w, old.context, version=version)
    revision = await config_revision(w.db, INSTALLATION_ID)
    result = await reconciler(w).reconcile(observation, admitted=w.admitted)
    assert result.changed
    assert result.affected_secret_ids == (record.secret_id,)
    current = replace(old.context, version=old.context.version + 1)
    binding = await active_binding(w.db, current)
    assert binding.item_version == version
    assert binding.reference == observation.binding.reference
    assert binding.credential_context == token
    assert binding.version_ref != old.version_ref
    assert await config_revision(w.db, INSTALLATION_ID) == revision + 1
    with pytest.raises(CustodyUnavailable):
        await active_binding(w.db, old.context)
    row = await w.db.fetch_one(
        "SELECT payload,signature FROM {{tables.outbox_events}}"
        " WHERE kind='post-governance-hook' ORDER BY created_at DESC LIMIT 1"
    )
    event = verify(bytes(row["payload"]), row["signature"], team_id=TEAM).fields
    assert event["actor"] == {"authority_mode": "system", "attestations": []}
    assert event["payload"] == {
        "act": "resource.version_observed",
        "direction": "narrowing",
        "authority": "backend_observation",
        "resource_type": "secret",
        "resource_ref": record.secret_id,
        "before_ref": old.version_ref,
        "after_ref": binding.version_ref,
        "reason_code": "external_version_changed",
    }
    # No registered target was supplied: delivery availability cannot gate this transition.
    count = await w.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}")
    with pytest.raises(CustodyUnavailable):
        await reconciler(w).reconcile(observation, admitted=w.admitted)
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == count


async def test_unchanged_observation_allocates_nothing_and_emits_nothing(world):
    w = world
    _, _, _, old, _, first, _ = await initial(w)
    await apply(w, first)
    observation = await observe(w, old.context, version=7)
    count = await w.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}")
    result = await reconciler(w).reconcile(observation, admitted=w.admitted)
    assert not result.changed and result.affected_secret_ids == ()
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == count
    assert (
        await w.db.fetch_value(
            "SELECT last_version FROM {{tables.custody_secrets}} WHERE secret_id=$1",
            old.context.secret_id,
        )
        == old.context.version
    )


async def test_stale_observation_cannot_change_replaced_token_or_new_binding(world):
    w = world
    scope, _, _, old, _, first, _ = await initial(w)
    await apply(w, first)
    observation = await observe(w, old.context)
    _, new_token, _, _ = await staged(w, create=False)
    rotation, _ = await pending(w, scope, [token_item(new_token)], [new_token])
    await apply(w, rotation)
    count = await w.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}")
    with pytest.raises(CustodyUnavailable):
        await reconciler(w).reconcile(observation, admitted=w.admitted)
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == count
    assert await w.db.fetch_value("SELECT active_version FROM {{tables.secrets}}") is None


async def test_outbox_storage_failure_rolls_back_version_destruction_and_allocation(world):
    import asyncpg

    w = world
    _, _, _, old, _, first, _ = await initial(w)
    await apply(w, first)
    observation = await observe(w, old.context)
    await w.db.execute(
        "ALTER TABLE {{tables.outbox_events}} ADD CONSTRAINT reject_observation CHECK ("
        "convert_from(payload,'UTF8') NOT LIKE '%resource.version_observed%')"
    )
    with pytest.raises(asyncpg.CheckViolationError):
        await reconciler(w).reconcile(observation, admitted=w.admitted)
    assert (await active_binding(w.db, old.context)).version_ref == old.version_ref
    assert (
        await w.db.fetch_value(
            "SELECT last_version FROM {{tables.custody_secrets}} WHERE secret_id=$1",
            old.context.secret_id,
        )
        == old.context.version
    )
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.onepassword_versions}}") == 1


@pytest.mark.parametrize("part", ["team_id", "installation_id"])
async def test_observation_scope_cannot_cross_the_admitted_installation(world, part):
    w = world
    _, _, _, old, _, first, _ = await initial(w)
    await apply(w, first)
    observation = await observe(w, old.context)
    admitted = replace(w.admitted, **{part: "another-scope"})
    with pytest.raises(CustodyUnavailable):
        await reconciler(w).reconcile(observation, admitted=admitted)
    assert (await active_binding(w.db, old.context)).version_ref == old.version_ref


@pytest.mark.parametrize("rollback", [False, True])
async def test_reconciliation_voids_real_root_and_descendant_approvals_atomically(uses, rollback):
    from aweb_naapp.runtime.approvals import ApprovalState

    from aweb_secrets import records
    from aweb_secrets.custody import encode_value
    from aweb_secrets.custody.opening import UseSecretOpener
    from aweb_secrets.owners import owner_scope
    from aweb_secrets.secret import SecretRecord
    from aweb_secrets.tokens import TokenKey
    from tests.test_change_set_onepassword import binding_item
    from tests.test_change_sets import ALICE
    from tests.test_use_approval_lineage import child, request_child, seed
    from tests.test_use_approvals import SECRET, approve

    w = uses.world
    record = SecretRecord.from_after({**SECRET, "backend": "onepassword"})
    async with w.db.transaction() as tx:
        token = await w.custody.stage_backend_credential(
            tx,
            installation_id=INSTALLATION_ID,
            team_id=TEAM,
            value=encode_value("bearer", {"value": os.urandom(24).hex()}),
        )
    from tests.custody.test_onepassword import reference

    read = project_item(
        reference(),
        sdk_item([field("credential", os.urandom(24).hex())]),
        credential_context=token,
    )
    async with w.db.transaction() as tx:
        binding = await w.custody.stage_onepassword_reference(
            tx,
            installation_id=INSTALLATION_ID,
            team_id=TEAM,
            secret_id=record.secret_id,
            observed=read,
            initial=record,
        )
    change, _ = await pending(
        w,
        owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did),
        [
            {"kind": "secret", "op": "create", "ref": record.ref, "after": record.after},
            token_item(token),
            binding_item(binding),
        ],
        [token, binding.context],
    )
    await apply(w, change)
    await seed(uses)
    descendant, _ = await child(uses)
    async with w.db.transaction() as tx:
        child_version = await w.custody.sealer.ingest(
            tx,
            installation_id=INSTALLATION_ID,
            team_id=TEAM,
            secret_id=descendant.secret_id,
            value=encode_value("bearer", {"value": os.urandom(24).hex()}),
        )
        await records.set_active_version(
            tx, INSTALLATION_ID, TEAM, descendant.secret_id, child_version
        )
    decisions = []
    for secret in (record, descendant):
        _, _, pending_use = await request_child(uses, secret)
        await approve(uses, pending_use, "finance@acme.com")
        decisions.append(pending_use.pending.approval.approval_id)
    from datetime import UTC, datetime, timedelta

    cache_key = TokenKey(
        INSTALLATION_ID,
        TEAM,
        record.secret_id,
        binding.context.version,
        "https://api.example/token",
        "",
    )
    await w.containment.tokens.put(
        cache_key, os.urandom(24).hex(), datetime.now(UTC) + timedelta(hours=1)
    )
    observation = await observe(w, binding.context)
    revision = await config_revision(w.db, INSTALLATION_ID)
    if rollback:
        import asyncpg

        await w.db.execute(
            "ALTER TABLE {{tables.outbox_events}} ADD CONSTRAINT reject_transition CHECK ("
            "convert_from(payload,'UTF8') NOT LIKE '%resource.version_observed%')"
        )
        with pytest.raises(asyncpg.CheckViolationError):
            await reconciler(w).reconcile(observation, admitted=w.admitted)
    else:
        import asyncpg

        from aweb_secrets.owners import approver_scope

        scope = approver_scope(INSTALLATION_ID, TEAM, "finance")
        holder = await w.passkeys.designated_approver(scope)
        task = None
        try:
            async with w.db.transaction() as retirement:
                pid = await retirement.fetch_value("SELECT pg_backend_pid()")
                low = min(decisions)
                await retirement.fetch_value(
                    "SELECT approval_id FROM {{tables.approvals}} WHERE approval_id=$1 FOR UPDATE",
                    low,
                )
                task = asyncio.create_task(
                    reconciler(w).reconcile(observation, admitted=w.admitted)
                )
                async with asyncio.timeout(5):
                    while not await w.db.fetch_value(
                        "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
                        pid,
                    ):
                        if task.done():
                            await task
                            pytest.fail("reconciliation did not wait for its B2 union")
                        await asyncio.sleep(0.01)
                # Both parent rows are locked before B2, while allocation has
                # not touched custody. A late consequence-only prelock fails
                # the custody NOWAIT control, even if its eventual revokes match.
                for secret in (record, descendant):
                    with pytest.raises(asyncpg.LockNotAvailableError):
                        async with w.db.transaction() as observer:
                            assert await observer.fetch_value("SELECT pg_backend_pid()") != pid
                            await observer.fetch_value(
                                "SELECT secret_id FROM {{tables.secrets}} WHERE secret_id=$1 FOR UPDATE NOWAIT",
                                secret.secret_id,
                            )
                async with w.db.transaction() as observer:
                    assert (
                        await observer.fetch_value(
                            "SELECT secret_id FROM {{tables.custody_secrets}} WHERE secret_id=$1 FOR UPDATE NOWAIT",
                            record.secret_id,
                        )
                        == record.secret_id
                    )
                await w.passkeys.retire_in(
                    retirement, scope=scope, subject=holder.subject, authorized_by="owner"
                )
            result = await asyncio.wait_for(task, 10)
        finally:
            if task is not None and not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        assert result.affected_secret_ids == tuple(sorted((record.secret_id, descendant.secret_id)))
    for decision in decisions:
        assert (await uses.approvals.get(decision)).state is (
            ApprovalState.APPROVED if rollback else ApprovalState.REVOKED
        )
    assert await w.db.fetch_value(
        "SELECT state FROM {{tables.secrets}} WHERE secret_id=$1",
        descendant.secret_id,
    ) == ("active" if rollback else "disabled")
    assert await config_revision(w.db, INSTALLATION_ID) == revision + (0 if rollback else 1)
    # Eviction is cleanup only: the old cache entry is still present when the
    # exact opener refuses the old authority, before it can read any SDK value.
    assert await w.containment.tokens.get(cache_key) is not None
    opener = UseSecretOpener(
        w.db, native=w.custody.opener, credential_opener=w.custody.backend_credential_opener
    )
    if rollback:
        assert (await active_binding(w.db, binding.context)).version_ref == binding.version_ref
    else:
        with pytest.raises(CustodyUnavailable):
            await opener.open(binding.context)


@pytest.mark.parametrize("broken", ["timestamp", "shape", "version"])
async def test_invalid_observation_metadata_cannot_allocate_or_emit(world, broken):
    w = world
    _, _, _, old, _, first, _ = await initial(w)
    await apply(w, first)
    observation = await observe(w, old.context)
    if broken == "timestamp":
        observation = replace(observation, updated_at=None)
    elif broken == "shape":
        observation = replace(observation, binding=replace(observation.binding, shape_json="{}"))
    else:
        observation = replace(observation, item_version=True)
    count = await w.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}")
    revision = await config_revision(w.db, INSTALLATION_ID)
    with pytest.raises(CustodyUnavailable):
        await reconciler(w).reconcile(observation, admitted=w.admitted)
    assert await config_revision(w.db, INSTALLATION_ID) == revision
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == count
    assert (await active_binding(w.db, old.context)).version_ref == old.version_ref


def parent_edit(record, kind):
    from aweb_secrets.policy import Policy
    from tests.test_change_set_records import DESTINATION, POLICY_BODY, grant_after
    from tests.test_operation_record import REFUND

    if kind == "secret":
        after = {**record.after, "description": "Updated owner description"}
        return [{"kind": "secret", "op": "update", "ref": record.ref, "after": after}]
    if kind == "destination":
        after = {**DESTINATION, "secret_id": record.secret_id}
        return [{"kind": kind, "op": "create", "ref": after["destination_id"], "after": after}]
    if kind == "operation":
        after = {**REFUND, "secret_id": record.secret_id}
        return [{"kind": kind, "op": "create", "ref": after["operation_id"], "after": after}]
    policy = Policy.from_body(POLICY_BODY)
    after = {**grant_after(), "secret_id": record.secret_id}
    return [
        {"kind": "policy", "op": "create", "ref": policy.digest, "after": {"v": 1, **POLICY_BODY}},
        {"kind": "grant", "op": "create", "ref": after["grant_id"], "after": after},
    ]


@pytest.mark.parametrize("kind", ["secret", "operation", "destination", "grant"])
async def test_unsealed_parent_record_confirmation_and_reconciliation_share_lock_order(world, kind):
    from aweb_naapp.runtime.approvals import ApprovalState

    w = world
    scope, record, _, old, _, first, _ = await initial(w)
    await apply(w, first)
    change, approval_id = await pending(w, scope, parent_edit(record, kind), [])
    assert (
        await w.db.fetch_value(
            "SELECT count(*) FROM {{tables.change_set_sealed}} WHERE change_id=$1",
            change["change_id"],
        )
        == 0
    )
    observation = await observe(w, old.context)
    revision = await config_revision(w.db, INSTALLATION_ID)
    started = asyncio.get_running_loop().create_future()

    async def confirm_edit():
        async with w.db.transaction() as tx:
            started.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
            return await w.change_sets.confirm(
                tx,
                change["change_id"],
                operation_id="parent-edit-" + change["change_id"],
                fence=w.fence,
                admitted=w.admitted,
            )

    confirming = rotating = None
    try:
        async with w.db.transaction() as gate:
            gate_pid = await gate.fetch_value("SELECT pg_backend_pid()")
            await gate.fetch_value(
                "SELECT revision FROM {{tables.config_revisions}} WHERE installation_id=$1 FOR UPDATE",
                INSTALLATION_ID,
            )
            confirming = asyncio.create_task(confirm_edit())
            confirmer_pid = await asyncio.wait_for(started, 5)
            async with asyncio.timeout(5):
                while gate_pid not in await w.db.fetch_value(
                    "SELECT pg_blocking_pids($1)", confirmer_pid
                ):
                    if confirming.done():
                        await confirming
                        pytest.fail("confirmation did not reach the revision gate")
                    await asyncio.sleep(0.01)
            rotating = asyncio.create_task(
                reconciler(w).reconcile(observation, admitted=w.admitted)
            )
            async with asyncio.timeout(5):
                # Old code lets reconciliation hold the parent while it waits
                # behind confirmation for the revision. The real queued order
                # then deadlocks when gate commits. Correct code holds the
                # parent in confirmation before it can wait at that revision.
                while not await w.db.fetch_value(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid<>$1"
                    " AND ($1=ANY(pg_blocking_pids(pid)) OR $2=ANY(pg_blocking_pids(pid))))",
                    confirmer_pid,
                    gate_pid,
                ):
                    if rotating.done():
                        await rotating
                        pytest.fail("reconciliation did not contend with confirmation")
                    await asyncio.sleep(0.01)
        confirmed, reconciled = await asyncio.wait_for(asyncio.gather(confirming, rotating), 10)
        assert confirmed.revision == revision + 1
        assert reconciled.changed and reconciled.affected_secret_ids == (record.secret_id,)
    finally:
        tasks = [task for task in (confirming, rotating) if task is not None]
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    assert (await w.approvals.get(approval_id)).state is ApprovalState.CONSUMED
    assert await config_revision(w.db, INSTALLATION_ID) == revision + 2
    current = await active_binding(w.db, replace(old.context, version=old.context.version + 1))
    assert current.item_version == observation.item_version
