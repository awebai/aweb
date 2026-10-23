"""Credential-bound session evidence over real B3 logins and retirement."""
# ruff: noqa: F811 -- pw is the imported real passkey composition fixture.

import asyncio

import pytest

from tests.runtime.approvals.support import SCOPE
from tests.runtime.approvals.test_passkeys import (
    ceremony,
    decide,
    enrol,
    login,
    mint,
    pw,  # noqa: F401
)
from tests.runtime.approvals.test_team_retirement import second_passkey


async def test_session_evidence_tracks_its_exact_key_while_a_sibling_survives(pw):
    approver, lost = await enrol(pw)
    kept = await second_passkey(pw, approver.subject)
    first, second = await login(pw, lost), await login(pw, kept)
    current = pw.passkeys.login_evidence_is_current
    assert await current(SCOPE, approver.subject, first.evidence_ref)
    assert await current(SCOPE, approver.subject, second.evidence_ref)
    async with pw.passkeys.db.transaction() as tx:
        await pw.passkeys.revoke_passkey_in(
            tx,
            scope=SCOPE,
            subject=approver.subject,
            credential_id=next(iter(lost.credentials)),
            authorized_by="owner",
        )
    assert await pw.passkeys.can_log_in(SCOPE, approver.subject)
    assert not await current(SCOPE, approver.subject, first.evidence_ref)
    assert await current(SCOPE, approver.subject, second.evidence_ref)


@pytest.mark.parametrize("last_key", [False, True])
async def test_full_or_last_key_retirement_ends_login_evidence(pw, last_key):
    approver, device = await enrol(pw)
    session = await login(pw, device)
    async with pw.passkeys.db.transaction() as tx:
        kwargs = dict(scope=SCOPE, subject=approver.subject, authorized_by="owner")
        if last_key:
            await pw.passkeys.revoke_passkey_in(
                tx, credential_id=next(iter(device.credentials)), **kwargs
            )
        else:
            await pw.passkeys.retire_in(tx, **kwargs)
    assert not await pw.passkeys.login_evidence_is_current(
        SCOPE, approver.subject, session.evidence_ref
    )


async def test_login_evidence_rejects_wrong_scope_subject_missing_and_non_login_refs(pw):
    approver, device = await enrol(pw)
    session = await login(pw, device)
    approval = await mint(pw)
    decided = await decide(pw, approval, await ceremony(pw, approval, device))
    current = pw.passkeys.login_evidence_is_current
    for scope, subject, evidence in [
        ("other-scope", approver.subject, session.evidence_ref),
        (SCOPE, "other-subject", session.evidence_ref),
        (SCOPE, approver.subject, "missing-evidence"),
        (SCOPE, approver.subject, decided.decided_by.evidence_ref),
    ]:
        assert not await current(scope, subject, evidence)
    assert await current(SCOPE, approver.subject, session.evidence_ref)


async def test_action_transaction_holds_live_evidence_until_commit(pw):
    approver, device = await enrol(pw)
    session = await login(pw, device)
    db = pw.passkeys.db
    started = asyncio.get_running_loop().create_future()

    async def revoke():
        async with db.transaction() as tx:
            started.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
            await pw.passkeys.revoke_passkey_in(
                tx,
                scope=SCOPE,
                subject=approver.subject,
                credential_id=next(iter(device.credentials)),
                authorized_by="owner",
            )

    task = None
    try:
        async with db.transaction() as action:
            blocker = await action.fetch_value("SELECT pg_backend_pid()")
            assert await pw.passkeys.login_evidence_is_current(
                SCOPE, approver.subject, session.evidence_ref, tx=action
            )
            task = asyncio.create_task(revoke())
            pid = await asyncio.wait_for(started, 5)
            async with asyncio.timeout(5):
                while blocker not in await db.fetch_value("SELECT pg_blocking_pids($1)", pid):
                    await asyncio.sleep(0.01)
            assert not task.done()
        await asyncio.wait_for(task, 5)
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    assert not await pw.passkeys.login_evidence_is_current(
        SCOPE, approver.subject, session.evidence_ref
    )
