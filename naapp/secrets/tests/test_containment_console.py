"""Console authority uses enrolled passkeys and live scoped records in PostgreSQL."""

import asyncio
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from aweb_naapp.console import ConsoleSession

from aweb_secrets.containment import ContainmentRefused
from aweb_secrets.owners import approver_scope
from tests.test_change_sets import TEAM, world  # noqa: F401
from tests.test_containment_service import service
from tests.test_use_approval_lineage import child, seed
from tests.test_use_approvals import SECRET_ID
from tests.test_use_approvals import uses as _uses

uses = _uses


async def finance_session(context):
    w = context.world
    scope = approver_scope(w.admitted.installation_id, TEAM, "finance")
    return await login_session(w, scope, w.devices["finance@acme.com"])


async def login_session(w, scope, device):
    logged_in = await w.passkeys.verify_login(
        scope,
        device.get(await w.passkeys.login_options(scope)),
    )
    return ConsoleSession(
        subject=logged_in.subject,
        scope=scope,
        evidence_ref=logged_in.evidence_ref,
        expires_at=datetime.now(UTC) + timedelta(minutes=15),
        token_sha256=b"",
    )


async def authorize(svc, context, session, action, target=None):
    async with context.world.db.transaction() as tx:
        await context.world.fence.admit(tx, context.grant)
        return await svc.authorize_console(
            tx,
            admitted=context.world.admitted,
            session=session,
            action=action,
            target=target,
        )


async def test_approver_covers_descendants_but_cannot_kill_installation(uses):
    await seed(uses)
    svc = await service(uses)
    first, _ = await child(uses)
    session = await finance_session(uses)
    assert not await authorize(svc, uses, session, "disable-secret", first.secret_id)
    with pytest.raises(ContainmentRefused) as refused:
        await authorize(svc, uses, session, "disable-installation")
    assert refused.value.code == "owner_required"
    with pytest.raises(ContainmentRefused) as refused:
        await authorize(svc, uses, session, "deregister-runner", "runner-1")
    assert refused.value.code == "owner_required"


@pytest.mark.parametrize("covered", [False, True])
async def test_current_coverage_is_required_at_action_time(uses, covered):
    await seed(uses)
    svc = await service(uses)
    session = await finance_session(uses)
    async with uses.world.db.transaction() as tx:
        await tx.execute(
            "UPDATE {{tables.approvers}} SET covers=$1::jsonb WHERE approver_ref='finance'",
            '["sec_19ab42"]' if covered else "[]",
        )
    if covered:
        assert not await authorize(svc, uses, session, "disable-secret", SECRET_ID)
    else:
        with pytest.raises(ContainmentRefused) as refused:
            await authorize(svc, uses, session, "disable-secret", SECRET_ID)
        assert refused.value.code == "coverage_denied"


async def test_approver_credential_target_is_self_only(uses):
    await seed(uses)
    svc = await service(uses)
    session = await finance_session(uses)
    assert not await authorize(svc, uses, session, "revoke-approver", "finance")
    with pytest.raises(ContainmentRefused):
        await authorize(svc, uses, session, "revoke-approver", "other-approver")


async def test_same_team_owner_scope_of_another_installation_is_refused(uses):
    await seed(uses)
    svc = await service(uses)
    session = await finance_session(uses)
    async with uses.world.db.transaction() as tx:
        await uses.world.fence.admit(tx, uses.grant)
        with pytest.raises(ContainmentRefused):
            await svc.authorize_console(
                tx,
                admitted=replace(uses.world.admitted, installation_id="other-installation"),
                session=session,
                action="disable-secret",
                target=SECRET_ID,
            )


async def test_designated_approver_can_open_the_shared_s4_console_session(uses):
    from tests.test_console import clients

    await seed(uses)
    scope = approver_scope(uses.world.admitted.installation_id, TEAM, "finance")
    async with clients(uses.world) as (human, _):
        options = await human.post("/login/options", json={"scope": scope})
        assert options.status_code == 200
        logged_in = await human.post(
            "/login",
            json={
                "scope": scope,
                "assertion": uses.world.devices["finance@acme.com"].get(options.json()),
            },
        )
        assert logged_in.status_code == 200
        assert (await human.get("/session")).json()["scope"] == scope


async def sibling_session(w, session):
    """Register a genuine second software key for the existing holder."""
    from aweb_naapp.runtime.passkeys import verify_registration
    from aweb_naapp_testing.webauthn import SoftAuthenticator, b64url

    from tests.test_change_sets import ORIGIN

    kept = SoftAuthenticator(ORIGIN)
    challenge = os.urandom(32)
    credential = verify_registration(
        kept.create(
            {
                "rp": {"id": w.passkeys.rp.rp_id},
                "user": {"id": b64url(session.subject.encode())},
                "challenge": b64url(challenge),
            }
        ),
        challenge=challenge,
        rp=w.passkeys.rp,
    )
    await w.db.execute(
        "INSERT INTO {{tables.passkey_credentials}}"
        " (credential_id,subject,public_key,sign_count,created_at) VALUES ($1,$2,$3,$4,$5)",
        credential.credential_id,
        session.subject,
        credential.public_key,
        credential.sign_count,
        datetime.now(UTC),
    )
    return await login_session(w, session.scope, kept)


@pytest.mark.parametrize(
    "owner,action",
    [(True, "disable-secret"), (False, "disable-secret"), (False, "revoke-approver")],
)
async def test_action_checks_exact_login_key_while_another_key_remains(uses, owner, action):
    from aweb_secrets.owners import owner_scope
    from tests.test_change_sets import ALICE

    await seed(uses)
    svc = await service(uses)
    w = uses.world
    if owner:
        scope = owner_scope(w.admitted.installation_id, TEAM, ALICE.principal_did)
        lost = w.devices["alice@acme.com"]
        session = await login_session(w, scope, lost)
    else:
        lost = w.devices["finance@acme.com"]
        session = await finance_session(uses)
    kept = await sibling_session(w, session)
    target = SECRET_ID if action == "disable-secret" else "finance"
    assert await authorize(svc, uses, session, action, target) is owner
    async with w.db.transaction() as tx:
        await w.passkeys.revoke_passkey_in(
            tx,
            scope=session.scope,
            subject=session.subject,
            credential_id=next(iter(lost.credentials)),
            authorized_by="owner",
        )
    assert await w.passkeys.can_log_in(session.scope, session.subject)
    with pytest.raises(ContainmentRefused) as refused:
        await authorize(svc, uses, session, action, target)
    assert refused.value.status == 401
    assert await authorize(svc, uses, kept, action, target) is owner


@pytest.mark.parametrize("binding", ["missing", "foreign-evidence", "foreign-subject", "approval"])
async def test_action_binds_login_evidence_to_scope_subject_and_purpose(uses, binding):
    from aweb_secrets.owners import owner_scope
    from aweb_secrets.secret import SecretRecord
    from tests.test_change_sets import ALICE
    from tests.test_use_approval_lineage import request_child
    from tests.test_use_approvals import SECRET, approve

    await seed(uses)
    svc = await service(uses)
    session = await finance_session(uses)
    if binding == "missing":
        invalid = replace(session, evidence_ref="missing-evidence")
    elif binding == "approval":
        pending = await request_child(uses, SecretRecord.from_after(SECRET))
        await approve(uses, pending[2], "finance@acme.com")
        approval = await uses.approvals.get(pending[2].pending.approval.approval_id)
        invalid = replace(session, evidence_ref=approval.decided_by.evidence_ref)
    else:
        w = uses.world
        other = await login_session(
            w,
            owner_scope(w.admitted.installation_id, TEAM, ALICE.principal_did),
            w.devices["alice@acme.com"],
        )
        invalid = (
            replace(session, evidence_ref=other.evidence_ref)
            if binding == "foreign-evidence"
            else replace(session, subject=other.subject)
        )
    with pytest.raises(ContainmentRefused) as refused:
        await authorize(svc, uses, invalid, "disable-secret", SECRET_ID)
    assert refused.value.status == 401
    assert not await authorize(svc, uses, session, "disable-secret", SECRET_ID)


async def test_action_retains_login_liveness_locks_until_its_transaction_commits(uses):
    await seed(uses)
    svc = await service(uses)
    session = await finance_session(uses)
    w = uses.world
    started = asyncio.get_running_loop().create_future()

    async def revoke():
        async with w.db.transaction() as tx:
            started.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
            await w.passkeys.revoke_passkey_in(
                tx,
                scope=session.scope,
                subject=session.subject,
                credential_id=next(iter(w.devices["finance@acme.com"].credentials)),
                authorized_by="owner",
            )

    task = None
    try:
        async with w.db.transaction() as action:
            await w.fence.admit(action, uses.grant)
            assert not await svc.authorize_console(
                action,
                admitted=w.admitted,
                session=session,
                action="disable-secret",
                target=SECRET_ID,
            )
            blocker = await action.fetch_value("SELECT pg_backend_pid()")
            task = asyncio.create_task(revoke())
            pid = await asyncio.wait_for(started, 5)
            async with asyncio.timeout(5):
                while blocker not in await w.db.fetch_value("SELECT pg_blocking_pids($1)", pid):
                    assert not task.done(), "credential retirement escaped the action transaction"
                    await asyncio.sleep(0.01)
        await asyncio.wait_for(task, 5)
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    with pytest.raises(ContainmentRefused):
        await authorize(svc, uses, session, "disable-secret", SECRET_ID)
