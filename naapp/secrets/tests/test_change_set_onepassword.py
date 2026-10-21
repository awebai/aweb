"""Actual passkey confirmation of staged 1Password metadata, on real PG.

SDK Item fixtures test the local lifecycle, not successful HO6 vault access.
The registration view is catalog input; logs ingest remains release E2E proof.
"""

import os
from datetime import UTC, datetime, timedelta

import pytest
from aweb_naapp.hooks.envelope import verify
from aweb_naapp.hooks.producer import Registration, RegistrationView
from aweb_naapp.roles import hold_role
from aweb_naapp.runtime.approvals import ApprovalState
from aweb_naapp_testing.owner_acts import INSTALLATION_ID

from aweb_secrets.change import ChangeRefused
from aweb_secrets.custody import CustodyUnavailable, encode_value
from aweb_secrets.custody.onepassword import project_item
from aweb_secrets.custody.opening import active_binding
from aweb_secrets.owners import OWNER_ROLE
from aweb_secrets.revisions import config_revision
from tests.custody.test_onepassword import field, reference, sdk_item
from tests.custody.test_onepassword_staging import candidate
from tests.test_change_sets import ALICE, TEAM, change_set, decide, draft, enrol_owner, on_console
from tests.test_change_sets import world as _world

world = _world


def view():
    now = datetime.now(UTC)
    return RegistrationView(
        TEAM,
        "post-governance-hook",
        now,
        timedelta(seconds=60),
        (
            Registration(
                "local-logs-binding",
                "https://logs.example",
                "POST",
                "/hooks/ingest",
                now - timedelta(hours=1),
            ),
        ),
    )


async def staged(w, *, token=None, create=True):
    record = candidate()
    value = os.urandom(24).hex()
    async with w.db.transaction() as tx:
        await w.fence.check(tx, w.admitted)
        assert await hold_role(tx, ALICE, OWNER_ROLE)
        if token is None:
            token = await w.custody.stage_backend_credential(
                tx,
                installation_id=INSTALLATION_ID,
                team_id=TEAM,
                value=encode_value("bearer", {"value": os.urandom(24).hex()}),
            )
    # Actual SDK model projection; successful external SDK authentication is HO6.
    observed = project_item(
        reference(), sdk_item([field("credential", value)]), credential_context=token
    )
    async with w.db.transaction() as tx:
        await w.fence.check(tx, w.admitted)
        assert await hold_role(tx, ALICE, OWNER_ROLE)
        binding = await w.custody.stage_onepassword_reference(
            tx,
            installation_id=INSTALLATION_ID,
            team_id=TEAM,
            secret_id=record.secret_id,
            observed=observed,
            initial=record if create else None,
        )
    return record, token, binding, value


def token_item(token):
    return {
        "kind": "backend_credential",
        "op": "create",
        "ref": "onepassword",
        "after": {
            "v": 1,
            "backend": "onepassword",
            "credential_id": token.secret_id,
            "version": token.version,
        },
    }


def binding_item(binding):
    return {
        "kind": "onepassword_binding",
        "op": "create",
        "ref": binding.context.secret_id,
        "after": binding.after,
    }


async def pending(w, scope, items, contexts):
    change = change_set(
        drafter=on_console(scope),
        changes=items,
        base_revision=await config_revision(w.db, INSTALLATION_ID),
    )
    approval = await draft(w, change, contexts)
    await decide(w, approval, "alice@acme.com")
    return change, approval


async def apply(w, change, *, registration=True):
    registration_view = view() if registration else None
    async with w.db.transaction() as tx:
        return await w.change_sets.confirm(
            tx,
            change["change_id"],
            operation_id="confirm-" + change["change_id"],
            fence=w.fence,
            admitted=w.admitted,
            governance_view=registration_view,
        )


async def initial(w):
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    record, token, binding, value = await staged(w)
    change, approval = await pending(
        w,
        scope,
        [
            {"kind": "secret", "op": "create", "ref": record.ref, "after": record.after},
            binding_item(binding),
            token_item(token),
        ],
        [binding.context, token],
    )
    return scope, record, token, binding, value, change, approval


async def test_create_draft_is_inert_and_confirmation_uses_retained_approve_audit(world):
    w = world
    scope, record, token, binding, value, change, approval = await initial(w)
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.secrets}}") == 0
    with pytest.raises(CustodyUnavailable):
        await w.custody.backend_credential_opener.open(token)
    result = await apply(w, change)
    assert result.affected_secret_ids == (record.secret_id,)
    assert (await active_binding(w.db, binding.context)).credential_context == token
    assert (await w.approvals.get(approval)).state is ApprovalState.CONSUMED
    rows = await w.db.fetch_all(
        "SELECT payload, signature FROM {{tables.outbox_events}} WHERE kind='post-governance-hook'"
    )
    assert len(rows) == 2
    for row in rows:
        event = verify(bytes(row["payload"]), row["signature"], team_id=TEAM).fields
        assert event["actor"] == {"authority_mode": "system", "attestations": []}
        assert event["payload"]["authority"] == "passkey_session"
        assert len(event["payload"]["approval_evidence_sha256"]) == 64
        assert value not in str(event)
        assert "a" * 26 not in str(event) and "b" * 26 not in str(event)


@pytest.mark.parametrize("rebind", [False, True])
async def test_token_replacement_invalidates_old_context_and_only_explicit_rebind_activates(
    world, rebind
):
    w = world
    scope, record, old_token, old, _, first, _ = await initial(w)
    await apply(w, first)
    _, new_token, new, _ = await staged(w, create=False)
    items = [token_item(new_token)]
    contexts = [new_token]
    if rebind:
        items.insert(0, binding_item(new))  # apply order cannot leave the former token active.
        contexts.append(new.context)
    change, _ = await pending(w, scope, items, contexts)
    result = await apply(w, change)
    assert result.affected_secret_ids == (record.secret_id,)
    assert await w.db.fetch_value("SELECT active_version FROM {{tables.secrets}}") == (
        new.context.version if rebind else None
    )
    with pytest.raises(CustodyUnavailable):
        await w.custody.backend_credential_preview.open(old_token)
    with pytest.raises(CustodyUnavailable):
        await active_binding(w.db, old.context)
    if rebind:
        assert (await active_binding(w.db, new.context)).credential_context == new_token
    row = await w.db.fetch_one(
        "SELECT binding, version_ref, destroyed_at FROM {{tables.onepassword_versions}} WHERE version=$1",
        old.context.version,
    )
    assert row["binding"] is None and row["destroyed_at"] is not None
    assert row["version_ref"] == old.version_ref


async def test_unavailable_required_audit_rolls_back_activation_revision_and_consumption(world):
    w = world
    _, _, token, _, _, change, approval = await initial(w)
    with pytest.raises(ChangeRefused) as refused:
        await apply(w, change, registration=False)
    assert refused.value.code == "audit_target_unavailable"
    assert (
        await w.db.fetch_value("SELECT active_version FROM {{tables.onepassword_credentials}}")
        is None
    )
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.secrets}}") == 0
    assert await config_revision(w.db, INSTALLATION_ID) == 0
    assert (await w.approvals.get(approval)).state is ApprovalState.APPROVED
    # The inert candidate survives a refused confirmation; no cleanup ran early.
    await w.custody.backend_credential_preview.open(token)


async def test_missing_retained_approve_proof_refuses_without_activation(world):
    w = world
    _, _, token, _, _, change, approval_id = await initial(w)
    approved = await w.approvals.get(approval_id)
    await w.db.execute(
        "DELETE FROM {{tables.passkey_proofs}} WHERE evidence_ref=$1",
        approved.decided_by.evidence_ref,
    )
    with pytest.raises(ChangeRefused) as refused:
        await apply(w, change)
    assert refused.value.code == "passkey_proof_unavailable"
    assert (await w.approvals.get(approval_id)).state is ApprovalState.APPROVED
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.secrets}}") == 0
    await w.custody.backend_credential_preview.open(token)


async def test_staged_binding_is_compared_again_at_confirmation(world):
    w = world
    _, _, _, binding, _, change, approval_id = await initial(w)
    # Simulate a candidate deleted by lifecycle cleanup after approval.
    async with w.db.transaction() as tx:
        await w.custody.destroy(tx, binding.context)
    with pytest.raises(ChangeRefused) as refused:
        await apply(w, change)
    assert refused.value.code == "onepassword_binding_invalid"
    assert (await w.approvals.get(approval_id)).state is ApprovalState.APPROVED
    assert (
        await w.db.fetch_value("SELECT active_version FROM {{tables.onepassword_credentials}}")
        is None
    )


async def test_required_outbox_storage_failure_rolls_back_token_invalidation(world):
    import asyncpg

    w = world
    scope, record, old_token, old, _, first, _ = await initial(w)
    await apply(w, first)
    _, new_token, _, _ = await staged(w, create=False)
    change, approval_id = await pending(w, scope, [token_item(new_token)], [new_token])
    revision = await config_revision(w.db, INSTALLATION_ID)
    await w.db.execute(
        "ALTER TABLE {{tables.outbox_events}} ADD CONSTRAINT reject_new_governance"
        " CHECK(kind <> 'post-governance-hook') NOT VALID"
    )
    with pytest.raises(asyncpg.CheckViolationError):
        await apply(w, change)
    assert await config_revision(w.db, INSTALLATION_ID) == revision
    assert (await w.approvals.get(approval_id)).state is ApprovalState.APPROVED
    assert (await active_binding(w.db, old.context)).credential_context == old_token
    await w.custody.backend_credential_opener.open(old_token)
    assert (
        await w.db.fetch_value("SELECT active_version FROM {{tables.secrets}}")
        == old.context.version
    )


async def test_cancel_destroys_only_staged_candidates_and_retains_history(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    record, token, binding, _ = await staged(w)
    change = change_set(
        drafter=on_console(scope),
        changes=[
            {"kind": "secret", "op": "create", "ref": record.ref, "after": record.after},
            token_item(token),
            binding_item(binding),
        ],
    )
    await draft(w, change, [token, binding.context])
    async with w.db.transaction() as tx:
        await w.change_sets.cancel(tx, change["change_id"], cancelled_by=scope)
    with pytest.raises(CustodyUnavailable):
        await w.custody.backend_credential_preview.open(token)
    row = await w.db.fetch_one(
        "SELECT binding,version_ref,destroyed_at FROM {{tables.onepassword_versions}}"
    )
    assert row["binding"] is None and row["destroyed_at"] is not None
    assert row["version_ref"] == binding.version_ref
    assert await w.db.fetch_value("SELECT max(last_version) FROM {{tables.custody_secrets}}") == 1
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.secrets}}") == 0


async def test_new_binding_cannot_use_an_unapproved_inert_token(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    record, token, binding, _ = await staged(w)
    change = change_set(
        drafter=on_console(scope),
        changes=[
            {"kind": "secret", "op": "create", "ref": record.ref, "after": record.after},
            binding_item(binding),
        ],
    )
    with pytest.raises(ChangeRefused) as refused:
        await draft(w, change, [binding.context])
    assert refused.value.code == "onepassword_binding_invalid"
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.change_sets}}") == 0


@pytest.mark.parametrize(
    "field_name,new_value",
    [
        ("item_version", 8),
        ("item_id", "c" * 26),
        ("fields", {"value": "other"}),
        ("credential_version", 99),
    ],
)
async def test_draft_requires_full_equality_with_server_staged_binding(
    world, field_name, new_value
):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    record, token, binding, _ = await staged(w)
    item = binding_item(binding)
    item["after"][field_name] = new_value
    change = change_set(
        drafter=on_console(scope),
        changes=[
            {"kind": "secret", "op": "create", "ref": record.ref, "after": record.after},
            token_item(token),
            item,
        ],
    )
    with pytest.raises(ChangeRefused) as refused:
        await draft(w, change, [token, binding.context])
    assert refused.value.code == "onepassword_binding_invalid"
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.change_sets}}") == 0


async def test_old_pending_binding_cannot_restore_a_replaced_token_context(world):
    w = world
    scope, _, old_token, _, _, first, _ = await initial(w)
    await apply(w, first)
    _, _, stale, _ = await staged(w, token=old_token, create=False)
    old_change, old_approval = await pending(w, scope, [binding_item(stale)], [stale.context])
    _, new_token, _, _ = await staged(w, create=False)
    rotate, _ = await pending(w, scope, [token_item(new_token)], [new_token])
    await apply(w, rotate)
    with pytest.raises(ChangeRefused):
        await apply(w, old_change)
    assert (await w.approvals.get(old_approval)).state is ApprovalState.APPROVED
    assert (
        await w.db.fetch_value("SELECT active_version FROM {{tables.onepassword_credentials}}")
        == new_token.version
    )
    assert await w.db.fetch_value("SELECT active_version FROM {{tables.secrets}}") is None


async def test_token_only_confirmation_prepares_dependency_root_and_confirming_b2_first(world):
    import asyncpg

    w = world
    scope, record, _, _, _, first, _ = await initial(w)
    await apply(w, first)
    _, new_token, _, _ = await staged(w, create=False)
    change, approval_id = await pending(w, scope, [token_item(new_token)], [new_token])
    async with w.db.transaction() as tx:
        await w.fence.check(tx, w.admitted)
        assert await hold_role(tx, ALICE, OWNER_ROLE)
        row = await tx.fetch_one(
            "SELECT * FROM {{tables.change_sets}} WHERE change_id=$1 FOR UPDATE",
            change["change_id"],
        )
        await w.change_sets._prepare_containment(tx, row, change, w.admitted)
        async with w.db.transaction() as other:
            assert await tx.fetch_value("SELECT pg_backend_pid()") != await other.fetch_value(
                "SELECT pg_backend_pid()"
            )
            with pytest.raises(asyncpg.LockNotAvailableError):
                await other.fetch_one(
                    "SELECT secret_id FROM {{tables.secrets}} WHERE secret_id=$1 FOR UPDATE NOWAIT",
                    record.secret_id,
                )
        async with w.db.transaction() as other:
            with pytest.raises(asyncpg.LockNotAvailableError):
                await other.fetch_one(
                    "SELECT approval_id FROM {{tables.approvals}} WHERE approval_id=$1 FOR UPDATE NOWAIT",
                    approval_id,
                )
        assert (await w.approvals.get(approval_id)).state is ApprovalState.APPROVED


async def test_token_rotation_preserves_a_dependency_disabled_marker(world):
    from aweb_secrets.containment import disable_secret_tree

    w = world
    scope, record, _, old, _, first, _ = await initial(w)
    await apply(w, first)
    async with w.db.transaction() as tx:
        await w.fence.check(tx, w.admitted)
        assert await hold_role(tx, ALICE, OWNER_ROLE)
        await disable_secret_tree(
            tx,
            w.approvals,
            w.custody,
            installation_id=INSTALLATION_ID,
            team_id=TEAM,
            secret_id=record.secret_id,
            revoked_by="owner",
        )
    async with w.db.transaction() as tx:
        await w.fence.check(tx, w.admitted)
        assert await hold_role(tx, ALICE, OWNER_ROLE)
        new = await w.custody.stage_backend_credential(
            tx,
            installation_id=INSTALLATION_ID,
            team_id=TEAM,
            value=encode_value("bearer", {"value": os.urandom(24).hex()}),
        )
    change, _ = await pending(w, scope, [token_item(new)], [new])
    await apply(w, change)
    row = await w.db.fetch_one("SELECT state,active_version FROM {{tables.secrets}}")
    assert row["state"] == "disabled" and row["active_version"] is None
    assert await w.db.fetch_value(
        "SELECT disabled_at IS NOT NULL FROM {{tables.custody_secrets}} WHERE secret_id=$1",
        record.secret_id,
    )


async def test_separate_token_activation_then_binding_and_rebinding_use_one_active_epoch(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    record, token, _, _ = await staged(w)
    token_change, _ = await pending(w, scope, [token_item(token)], [token])
    await apply(w, token_change)
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.secrets}}") == 0
    record, _, binding, _ = await staged(w, token=token)
    create, _ = await pending(
        w,
        scope,
        [
            {"kind": "secret", "op": "create", "ref": record.ref, "after": record.after},
            binding_item(binding),
        ],
        [binding.context],
    )
    await apply(w, create)
    assert (await active_binding(w.db, binding.context)).credential_context == token
    _, _, replacement, _ = await staged(w, token=token, create=False)
    rebind, _ = await pending(w, scope, [binding_item(replacement)], [replacement.context])
    await apply(w, rebind)
    assert replacement.context.version > binding.context.version
    assert (await active_binding(w.db, replacement.context)).credential_context == token
    with pytest.raises(CustodyUnavailable):
        await active_binding(w.db, binding.context)


async def test_rotated_disabled_root_recovers_only_through_confirmed_reenable_and_rebinding(world):
    from aweb_secrets.containment import disable_secret_tree
    from aweb_secrets.custody.opening import UseSecretOpener

    w = world
    scope, record, _, old, _, first, _ = await initial(w)
    await apply(w, first)
    async with w.db.transaction() as tx:
        await w.fence.check(tx, w.admitted)
        assert await hold_role(tx, ALICE, OWNER_ROLE)
        await disable_secret_tree(
            tx,
            w.approvals,
            w.custody,
            installation_id=INSTALLATION_ID,
            team_id=TEAM,
            secret_id=record.secret_id,
            revoked_by="owner",
        )
        token = await w.custody.stage_backend_credential(
            tx,
            installation_id=INSTALLATION_ID,
            team_id=TEAM,
            value=encode_value("bearer", {"value": os.urandom(24).hex()}),
        )
    rotation, _ = await pending(w, scope, [token_item(token)], [token])
    await apply(w, rotation)
    with pytest.raises(CustodyUnavailable):
        await staged(w, token=token, create=False)

    reenable, approval_id = await pending(
        w,
        scope,
        [
            {
                "kind": "reenable",
                "op": "enable",
                "ref": record.ref,
                "after": {"v": 1, "target_kind": "secret", "target_ref": record.ref},
            }
        ],
        [],
    )
    result = await apply(w, reenable)
    assert result.affected_secret_ids == (record.secret_id,)
    assert (await w.approvals.get(approval_id)).state is ApprovalState.CONSUMED
    row = await w.db.fetch_one("SELECT state,active_version FROM {{tables.secrets}}")
    assert row["state"] == "active" and row["active_version"] is None
    assert not await w.db.fetch_value(
        "SELECT disabled_at IS NOT NULL FROM {{tables.custody_secrets}} WHERE secret_id=$1",
        record.secret_id,
    )
    opener = UseSecretOpener(
        w.db,
        native=w.custody.opener,
        credential_opener=w.custody.backend_credential_opener,
    )
    with pytest.raises(CustodyUnavailable):
        await opener.open(old.context)
    _, _, replacement, _ = await staged(w, token=token, create=False)
    assert replacement.context.version > old.context.version
    with pytest.raises(CustodyUnavailable):
        await opener.open(replacement.context)
    rebind, _ = await pending(w, scope, [binding_item(replacement)], [replacement.context])
    await apply(w, rebind)
    assert (await active_binding(w.db, replacement.context)).credential_context == token
    with pytest.raises(CustodyUnavailable):
        await active_binding(w.db, old.context)
