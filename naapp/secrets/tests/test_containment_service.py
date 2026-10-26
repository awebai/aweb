"""Owner actions share real team roles, PostgreSQL, custody and hook outbox."""

import os
from datetime import UTC, datetime, timedelta
from functools import partial

import pytest
from aweb_naapp.hooks.envelope import verify
from aweb_naapp.hooks.producer import HookProducer, ServerProducer
from aweb_naapp.outbox import apply_outbox_migrations
from aweb_naapp.roles import assign, principal_key
from aweb_naapp.runtime.clock import seconds_to_ns
from aweb_naapp_testing.owner_acts import INSTALLATION_ID

from aweb_secrets.containment import Containment, ContainmentRefused
from aweb_secrets.owners import OWNER_ROLE
from aweb_secrets.tokens import ProcessTokenCache, TokenKey
from tests.test_change_sets import TEAM, world  # noqa: F401
from tests.test_use_approval_lineage import child, seed
from tests.test_use_approvals import REQUESTER, SECRET_ID
from tests.test_use_approvals import uses as _uses

uses = _uses


async def service(uses):  # noqa: F811
    w = uses.world
    await apply_outbox_migrations(w.db)
    async with w.db.transaction() as tx:
        await assign(tx, principal_key(REQUESTER), OWNER_ROLE)
    producer = HookProducer(
        ServerProducer.app(
            origin="https://api.secrets.example.com",
            app_id="secrets",
            installation_id=INSTALLATION_ID,
            generation=1,
            kid="test-key",
            seed=os.urandom(32),
        )
    )
    tokens = ProcessTokenCache()
    return Containment(
        db=w.db,
        fence=w.fence,
        approvals=uses.approvals,
        custody=w.custody,
        passkeys=w.passkeys,
        directory=w.directory,
        tokens=tokens,
        governance=partial(producer.enqueue, hook="post-governance-hook"),
    )


async def act(svc, uses, action="disable-secret", target=SECRET_ID, request_id="contain-1"):  # noqa: F811
    return await svc.by_member(
        grant=uses.grant,
        principal=REQUESTER,
        request_id=request_id,
        action=action,
        target=target,
    )


@pytest.mark.parametrize("stalled", [False, True])
async def test_team_auth_containment_succeeds_without_audit_target_and_with_stalled_delivery(
    uses, stalled
):  # noqa: F811
    await seed(uses)
    svc = await service(uses)
    if stalled:
        await act(svc, uses, "disable-installation", None, "earlier-event")
        event_id = await uses.world.db.fetch_value("SELECT event_id FROM {{tables.outbox_events}}")
        await uses.world.db.execute(
            "INSERT INTO {{tables.outbox_deliveries}} (event_id,target_id,state,attempts)"
            " VALUES ($1,'stalled-target','stalled',40)",
            event_id,
        )
    first, _ = await child(uses)
    result = await act(svc, uses)
    assert set(result.affected_secret_ids) == {SECRET_ID, first.secret_id}
    rows = await uses.world.db.fetch_all(
        "SELECT payload,signature FROM {{tables.outbox_events}} ORDER BY position"
    )
    envelope = verify(bytes(rows[-1]["payload"]), rows[-1]["signature"], team_id=TEAM)
    assert envelope.fields["payload"]["act"] == "resource.disabled"
    assert envelope.fields["payload"]["direction"] == "narrowing"
    assert envelope.fields["payload"]["authority"] == "team_cert"


async def test_role_and_team_are_checked_before_containment(uses):  # noqa: F811
    from dataclasses import replace

    from aweb_naapp.roles import unassign

    await seed(uses)
    svc = await service(uses)
    async with uses.world.db.transaction() as tx:
        await unassign(tx, principal_key(REQUESTER), OWNER_ROLE)
    with pytest.raises(ContainmentRefused) as refused:
        await act(svc, uses)
    assert refused.value.code == "owner_required"
    with pytest.raises(ContainmentRefused) as refused:
        await svc.by_member(
            grant=uses.grant,
            principal=replace(REQUESTER, team_id="other:example.com"),
            request_id="bad-team",
            action="disable-secret",
            target=SECRET_ID,
        )
    assert refused.value.code == "owner_required"
    assert (
        await uses.world.db.fetch_value(
            "SELECT state FROM {{tables.secrets}} WHERE secret_id=$1", SECRET_ID
        )
        == "active"
    )
    assert await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 0


async def test_receipt_replays_without_duplicate_event_and_conflicting_id_refuses(uses):  # noqa: F811
    await seed(uses)
    svc = await service(uses)
    first = await act(svc, uses)
    assert await act(svc, uses) == first
    assert await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 1
    with pytest.raises(ContainmentRefused) as refused:
        await act(svc, uses, "disable-installation", None)
    assert refused.value.code == "idempotency_conflict"


@pytest.mark.parametrize("action", ["disable-secret", "disable-installation"])
async def test_successful_commit_evicts_all_cached_versions(uses, action):  # noqa: F811
    await seed(uses)
    svc = await service(uses)
    keys = [
        TokenKey(INSTALLATION_ID, TEAM, SECRET_ID, version, "https://api.example.com/token", "")
        for version in (3, 4)
    ]
    for key in keys:
        await svc.tokens.put(key, os.urandom(24).hex(), datetime.now(UTC) + timedelta(hours=1))
    await act(svc, uses, action, SECRET_ID if action == "disable-secret" else None)
    assert all([await svc.tokens.get(key) is None for key in keys])


async def test_reenable_is_not_a_team_auth_containment_action(uses):  # noqa: F811
    await seed(uses)
    svc = await service(uses)
    await act(svc, uses)
    with pytest.raises(ContainmentRefused) as refused:
        await act(svc, uses, "reenable", SECRET_ID, "enable-1")
    assert refused.value.code == "containment_action_invalid"


async def test_approval_revoke_is_scoped_and_stops_consumption(uses):  # noqa: F811
    from aweb_naapp.runtime.approvals import ApprovalState

    from tests.test_use_approval_lineage import admit, request_child
    from tests.test_use_approvals import approve

    await seed(uses)
    first, _ = await child(uses)
    admission, dispatch_id, pending = await request_child(uses, first)
    await approve(uses, pending, "finance@acme.com")
    svc = await service(uses)
    approval_id = pending.pending.approval.approval_id
    await act(svc, uses, "revoke-approvals", approval_id)
    assert (await uses.approvals.get(approval_id)).state == ApprovalState.REVOKED
    assert (await admit(uses, admission, dispatch_id)).refusal == "approval_revoked"
    with pytest.raises(ContainmentRefused) as refused:
        await act(svc, uses, "revoke-approvals", "another-installations-approval", "other")
    assert refused.value.code == "approval_unknown"


async def test_confirmed_reenable_restores_only_named_root(uses):  # noqa: F811
    from aweb_secrets.custody import CustodyUnavailable
    from tests.test_containment import seal

    await seed(uses)
    svc = await service(uses)
    first, _ = await child(uses)
    root_context = await seal(uses, SECRET_ID)
    child_context = await seal(uses, first.secret_id)
    await act(svc, uses)
    async with uses.world.db.transaction() as tx:
        await uses.world.fence.admit(tx, uses.grant)
        await svc.prepare_replacements(
            tx,
            installation_id=INSTALLATION_ID,
            team_id=TEAM,
            secret_ids=(SECRET_ID,),
        )
        await svc.reenable(
            tx,
            installation_id=INSTALLATION_ID,
            team_id=TEAM,
            target_kind="secret",
            target_ref="staging-api",
        )
    assert await uses.world.custody.opener.open(root_context) is not None
    with pytest.raises(CustodyUnavailable):
        await uses.world.custody.opener.open(child_context)
    assert (
        await uses.world.db.fetch_value(
            "SELECT state FROM {{tables.secrets}} WHERE secret_id=$1",
            first.secret_id,
        )
        == "disabled"
    )


@pytest.mark.parametrize("passkey", [False, True])
async def test_team_auth_refuses_last_enrolled_owner_contact_or_key(uses, passkey):  # noqa: F811
    from aweb_secrets.owners import owner_scope
    from tests.test_change_sets import ALICE

    await seed(uses)
    svc = await service(uses)
    scope = owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did)
    credential_id = (
        next(iter(uses.world.devices["alice@acme.com"].credentials)) if passkey else None
    )
    with pytest.raises(ContainmentRefused) as refused:
        await svc.by_member(
            grant=uses.grant,
            principal=REQUESTER,
            request_id="last-owner",
            action="revoke-approver",
            target=scope,
            credential_id=credential_id,
        )
    assert refused.value.code == "last_owner_protected"
    assert await uses.world.passkeys.designated_approver(scope) is not None
    assert await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 0


@pytest.mark.parametrize("passkey", [False, True])
async def test_another_enrolled_owner_allows_team_auth_credential_containment(uses, passkey):  # noqa: F811
    from aweb_secrets.owners import owner_scope
    from tests.test_change_sets import ALICE, BOB, enrol_owner

    await seed(uses)
    await enrol_owner(uses.world, BOB, "bob@acme.com")
    svc = await service(uses)
    scope = owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did)
    credential_id = (
        next(iter(uses.world.devices["alice@acme.com"].credentials)) if passkey else None
    )
    await svc.by_member(
        grant=uses.grant,
        principal=REQUESTER,
        request_id="contain-owner",
        action="revoke-approver",
        target=scope,
        credential_id=credential_id,
    )
    assert await uses.world.passkeys.designated_approver(scope) is None
    assert (
        await uses.world.passkeys.designated_approver(
            owner_scope(INSTALLATION_ID, TEAM, BOB.principal_did)
        )
        is not None
    )


async def test_approver_retirement_voids_their_decisions_in_same_transaction(uses):  # noqa: F811
    from aweb_naapp.runtime.approvals import ApprovalState

    from tests.test_use_approval_lineage import request_child
    from tests.test_use_approvals import approve

    await seed(uses)
    first, _ = await child(uses)
    _, _, pending = await request_child(uses, first)
    await approve(uses, pending, "finance@acme.com")
    svc = await service(uses)
    await act(svc, uses, "revoke-approver", "finance")
    assert (
        await uses.approvals.get(pending.pending.approval.approval_id)
    ).state == ApprovalState.REVOKED
    assert not await uses.world.db.fetch_value(
        "SELECT EXISTS(SELECT 1 FROM {{tables.approvers}} WHERE approver_ref='finance')"
    )


async def test_failed_local_outbox_write_rolls_back_containment_and_keeps_cache(uses):  # noqa: F811
    import asyncpg

    await seed(uses)
    svc = await service(uses)
    key = TokenKey(INSTALLATION_ID, TEAM, SECRET_ID, 4, "https://api.example.com/token", "")
    await svc.tokens.put(key, os.urandom(24).hex(), datetime.now(UTC) + timedelta(hours=1))
    await uses.world.db.execute(
        "ALTER TABLE {{tables.outbox_events}} ADD CONSTRAINT refuse_local_commit CHECK (kind <> 'post-governance-hook')"
    )
    with pytest.raises(asyncpg.CheckViolationError):
        await act(svc, uses)
    assert await svc.tokens.get(key) is not None
    assert (
        await uses.world.db.fetch_value(
            "SELECT state FROM {{tables.secrets}} WHERE secret_id=$1", SECRET_ID
        )
        == "active"
    )
    assert (
        await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.containment_receipts}}") == 0
    )


async def test_last_owner_can_revoke_one_key_when_another_survives(uses):  # noqa: F811
    from aweb_naapp.runtime.passkeys import verify_registration
    from aweb_naapp_testing.webauthn import SoftAuthenticator, b64url

    from aweb_secrets.owners import owner_scope
    from tests.test_change_sets import ALICE, ORIGIN

    await seed(uses)
    svc = await service(uses)
    scope = owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did)
    holder = await uses.world.passkeys.designated_approver(scope)
    kept = SoftAuthenticator(ORIGIN)
    challenge = os.urandom(32)
    registration = verify_registration(
        kept.create(
            {
                "rp": {"id": uses.world.passkeys.rp.rp_id},
                "user": {"id": b64url(holder.subject.encode())},
                "challenge": b64url(challenge),
            }
        ),
        challenge=challenge,
        rp=uses.world.passkeys.rp,
    )
    await uses.world.db.execute(
        "INSERT INTO {{tables.passkey_credentials}}"
        " (credential_id,subject,public_key,sign_count,created_at) VALUES ($1,$2,$3,$4,$5)",
        registration.credential_id,
        holder.subject,
        registration.public_key,
        registration.sign_count,
        datetime.now(UTC),
    )
    lost = next(iter(uses.world.devices["alice@acme.com"].credentials))
    await svc.by_member(
        grant=uses.grant,
        principal=REQUESTER,
        request_id="lost-device",
        action="revoke-approver",
        target=scope,
        credential_id=lost,
    )
    assert await uses.world.passkeys.designated_approver(scope) is not None
    options = await uses.world.passkeys.login_options(scope)
    assert (
        await uses.world.passkeys.verify_login(scope, kept.get(options))
    ).subject == holder.subject


async def test_runner_deregistration_invalidates_registered_key_and_unused_code(uses):  # noqa: F811
    from aweb_secrets import runners
    from aweb_secrets.runner_protocol import RunnerRefused
    from tests.test_runners import keys

    await seed(uses)
    svc = await service(uses)
    await runners.apply_runner_migrations(uses.world.db)
    svc.deregister_runner = runners.deregister_runner
    record = runners.RunnerRecord.from_after(
        {
            "v": 1,
            "runner_id": runners.mint_runner_id(),
            "label": "Build runner",
            "allowed_jobs": ["build"],
        }
    )
    now = datetime.now(UTC)
    async with uses.world.db.transaction() as tx:
        code = await runners.create_runner(tx, INSTALLATION_ID, TEAM, record, now=now)
        signing, encryption = keys()
        await runners.register_runner(
            tx,
            code=code,
            signing_key=signing,
            encryption_key=encryption,
        )
    await act(svc, uses, "deregister-runner", record.runner_id)
    async with uses.world.db.transaction() as tx:
        assert await runners.active_runner(tx, record.runner_id) is None
        with pytest.raises(RunnerRefused):
            await runners.register_runner(
                tx,
                code=code,
                signing_key=signing,
                encryption_key=encryption,
            )


@pytest.mark.parametrize("decided", [False, True])
async def test_assigned_member_approver_can_revoke_own_approval_only(uses, decided):  # noqa: F811
    from tests.test_use_approvals import _member, approve, designate, install, request

    approver = _member(8)
    await designate(
        uses, "finance", "finance@acme.com", principal=principal_key(approver).principal_did
    )
    await install(uses)
    _, _, pending = await request(uses)
    if decided:
        await approve(uses, pending, "finance@acme.com")
    svc = await service(uses)
    approval_id = pending.pending.approval.approval_id
    await svc.by_member(
        grant=uses.grant,
        principal=approver,
        request_id="own-approval",
        action="revoke-approvals",
        target=approval_id,
    )
    assert (await uses.approvals.get(approval_id)).state.value == "revoked"
    with pytest.raises(ContainmentRefused):
        await svc.by_member(
            grant=uses.grant,
            principal=approver,
            request_id="broader",
            action="disable-secret",
            target=SECRET_ID,
        )


@pytest.mark.parametrize("withdrawal", ["coverage", "principal"])
async def test_member_approver_needs_current_and_frozen_assignment(uses, withdrawal):  # noqa: F811
    from tests.test_use_approvals import _member, designate, install, request

    approver = _member(8)
    await designate(
        uses, "finance", "finance@acme.com", principal=principal_key(approver).principal_did
    )
    await install(uses)
    _, _, pending = await request(uses)
    svc = await service(uses)
    async with uses.world.db.transaction() as tx:
        if withdrawal == "coverage":
            await tx.execute(
                "UPDATE {{tables.approvers}} SET covers='[]' WHERE approver_ref='finance'"
            )
        else:
            approver = _member(9)
            await tx.execute(
                "UPDATE {{tables.approvers}} SET principal_did=$1 WHERE approver_ref='finance'",
                principal_key(approver).principal_did,
            )
    with pytest.raises(ContainmentRefused):
        await svc.by_member(
            grant=uses.grant,
            principal=approver,
            request_id="withdrawn",
            action="revoke-approvals",
            target=pending.pending.approval.approval_id,
        )
    assert (await uses.approvals.get(pending.pending.approval.approval_id)).state.value == "pending"


async def test_by_member_grant_revoke_contains_exact_subtree_and_source_approvals(uses):  # noqa: F811
    import asyncpg

    from aweb_secrets import records
    from aweb_secrets.admission import AdmissionRefused
    from aweb_secrets.secret import SecretRecord
    from tests.test_use_approval_lineage import grant_record, request_child
    from tests.test_use_approvals import SECRET, approve

    source = await seed(uses)
    svc = await service(uses)
    root = SecretRecord.from_after(SECRET)
    direct = await request_child(uses, root)
    first, _ = await child(uses, source_grant=source)
    pending = await request_child(uses, first)
    await approve(uses, pending[2], "finance@acme.com")
    async with uses.world.db.transaction() as tx:
        digest = await tx.fetch_value(
            "SELECT policy_digest FROM {{tables.grants}} WHERE grant_id=$1", source
        )
        other = grant_record("grt_----control", SECRET_ID, digest)
        await records.create_grant(tx, INSTALLATION_ID, TEAM, other)
    sibling, _ = await child(uses, secret_id="sec_sibling01", source_grant=other.grant_id)
    untouched = await request_child(uses, sibling)
    keys = [
        TokenKey(INSTALLATION_ID, TEAM, sid, 1, "https://api.example.com/token", "")
        for sid in (first.secret_id, sibling.secret_id)
    ]
    for key in keys:
        await svc.tokens.put(key, os.urandom(24).hex(), datetime.now(UTC) + timedelta(hours=1))
    await uses.world.db.execute(
        "ALTER TABLE {{tables.outbox_events}} ADD CONSTRAINT reject_grant_event CHECK (kind <> 'post-governance-hook')"
    )
    with pytest.raises(asyncpg.CheckViolationError):
        await act(svc, uses, "revoke-grant", source)
    assert await svc.tokens.get(keys[0]) is not None
    assert (await uses.approvals.get(direct[2].pending.approval.approval_id)).revoked_at is None
    await uses.world.db.execute(
        "ALTER TABLE {{tables.outbox_events}} DROP CONSTRAINT reject_grant_event"
    )
    result = await act(svc, uses, "revoke-grant", source)
    assert result.affected_secret_ids == (first.secret_id,)
    assert await svc.tokens.get(keys[0]) is None
    assert await svc.tokens.get(keys[1]) is not None
    for item in (direct, pending):
        assert (
            await uses.approvals.get(item[2].pending.approval.approval_id)
        ).state.value == "revoked"
    assert (
        await uses.approvals.get(untouched[2].pending.approval.approval_id)
    ).state.value == "pending"
    with pytest.raises(AdmissionRefused) as refused:
        await request_child(uses, first)
    assert refused.value.code == "grant_revoked"
    assert await uses.world.db.fetch_value(
        "SELECT revoked_at IS NOT NULL FROM {{tables.grants}} WHERE grant_id=$1",
        source,
    )
    await request_child(uses, sibling)


async def test_unknown_grant_is_refused_at_service_boundary(uses):  # noqa: F811
    await seed(uses)
    svc = await service(uses)
    with pytest.raises(ContainmentRefused) as refused:
        await act(svc, uses, "revoke-grant", "grt_missing01")
    assert (refused.value.code, refused.value.status) == ("grant_unknown", 404)


async def test_uninstall_then_reinstall_does_not_restore_former_owner_role(uses):  # noqa: F811
    import time
    from types import SimpleNamespace

    from aweb_naapp.roles import has_role
    from aweb_naapp.runtime.authorization import Grant

    from aweb_secrets.app import installation_fence
    from aweb_secrets.owners import owner_scope
    from tests.test_change_sets import ALICE

    class InstallationAuthority:
        """The remote installation authority, not an application store."""

        state = "active"
        installation_id = INSTALLATION_ID
        generation = 1

        async def grant_for(self, team_id, certificate_id=None):
            if team_id != TEAM or self.state != "active":
                return None
            return Grant(
                team_id=TEAM,
                scopes=frozenset({"secrets:admin"}),
                fresh_until=time.monotonic_ns() + seconds_to_ns(55),
                installation_id=self.installation_id,
                generation=self.generation,
            )

        async def status_for(self, team_id):
            if team_id != TEAM:
                return None
            return SimpleNamespace(
                team_id=TEAM,
                app_id="secrets",
                state=self.state,
                installation_id=self.installation_id,
                generation=self.generation,
                fresh_until=time.monotonic_ns() + seconds_to_ns(55),
                granted_scopes=frozenset({"secrets:admin"}),
            )

    authority = InstallationAuthority()
    fence = installation_fence(uses.world.db, app_id="secrets", grants=authority)
    assert await has_role(uses.world.db, ALICE, OWNER_ROLE)
    authority.state = "uninstalled"
    await fence.refresh(TEAM)
    authority.state = "active"
    authority.installation_id = "reinstalled-generation-two"
    authority.generation = 2
    await fence.refresh(TEAM)
    assert not await has_role(uses.world.db, ALICE, OWNER_ROLE)
    async with uses.world.db.transaction() as tx:
        grant = await authority.grant_for(TEAM)
        admitted = await fence.admit(tx, grant)
        assert admitted.installation_id == authority.installation_id
        assert (
            await uses.world.directory.owner_of(
                tx,
                owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did),
            )
            is None
        )
