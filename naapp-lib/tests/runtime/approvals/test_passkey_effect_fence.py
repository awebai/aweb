"""Completion fences compose with real B3 effects, audit and PostgreSQL holds."""
# ruff: noqa: F811 -- pw is the imported real passkey composition fixture.

import asyncio
from copy import copy
from datetime import timedelta

import pytest
from aweb_naapp_testing.webauthn import SoftAuthenticator

from aweb_naapp.runtime.passkeys import ContactChangeRefused, EnrolmentRefused
from tests.runtime.approvals.test_passkeys import (
    ORIGIN,
    change_contact,
    designate,
    enrol,
    pw,  # noqa: F401
)


async def effect_rows(db):
    return [
        await db.fetch_all("SELECT * FROM {{tables." + table + "}} ORDER BY 1")
        for table in (
            "passkey_approvers",
            "passkey_enrolments",
            "passkey_credentials",
            "passkey_contact_proofs",
            "audit_outbox",
        )
    ]


class CompletionFence:
    """Example app's real SQL authority, supplied through the generic callback."""

    def __init__(self, pw, kind, *, refuse=None):
        self.pw, self.kind, self.refuse = pw, kind, refuse
        self.tx = None
        self.calls = []
        self.audit_tx = None

    def denied(self):
        if self.kind == "enrolment":
            return EnrolmentRefused("completion_authority_unavailable")
        return ContactChangeRefused("completion_authority_unavailable")

    async def prepare(self, tx):
        self.tx = tx
        self.calls.append("prepare")
        # This callback must run before the first B3 statement in THIS effect tx.
        assert not await tx.fetch_value(
            "SELECT EXISTS (SELECT 1 FROM pg_locks l JOIN pg_class c ON c.oid=l.relation "
            "WHERE l.pid=pg_backend_pid() AND c.relname=ANY($1::text[]))",
            [
                "passkey_approvers",
                "passkey_enrolments",
                "passkey_credentials",
                "passkey_contact_proofs",
            ],
        )
        await tx.fetch_one("SELECT * FROM {{tables.completion_authority}} FOR SHARE")
        # Prepare the final plain read as well; check takes no new locks.
        await tx.fetch_one("SELECT * FROM {{tables.completion_authority}}")
        if self.refuse == "prepare":
            raise self.denied()

    async def check(self, tx):
        assert tx is self.tx is self.audit_tx
        self.calls.append("check")
        row = await tx.fetch_one("SELECT * FROM {{tables.completion_authority}}")
        if self.refuse == "check" or not row["active"] or self.pw.clock() >= row["expires_at"]:
            raise self.denied()


class CompletionAudit:
    """An app's required sink: authority is already held when it writes."""

    def __init__(self, pw, fence, *, expire=False):
        self.pw, self.fence, self.expire = pw, fence, expire

    async def emit(self, event, tx):
        assert tx is self.fence.tx
        self.fence.calls.append("audit")
        self.fence.audit_tx = tx
        await self.pw.audit.emit(event, tx)
        if self.expire:
            # Time passes while the awaited effect/audit work runs.
            self.pw.clock.advance(timedelta(hours=1))


async def completion(pw, kind):
    if kind == "enrolment":
        designation = await designate(pw, "human@example.com")
        subject = designation.approver.subject
        token = pw.contacts.last("human@example.com")
        device = SoftAuthenticator(ORIGIN)
        credential = device.create(await pw.passkeys.enrolment_options(token))
    else:
        approver, device = await enrol(pw)
        subject = approver.subject
        await change_contact(pw, device, "new@example.com")
        token = pw.contacts.proofs["new@example.com"][-1]
        credential = None
    db = pw.passkeys.db
    await db.execute(
        "CREATE TABLE {{tables.completion_authority}} (active boolean NOT NULL, expires_at timestamptz NOT NULL)"
    )
    await db.execute(
        "INSERT INTO {{tables.completion_authority}} VALUES(true,$1)",
        pw.clock() + timedelta(hours=1),
    )
    service = copy(pw.passkeys)

    async def invoke(fence, *, fresh=False, expire=False):
        service._audit = CompletionAudit(pw, fence, expire=expire)
        if kind == "enrolment":
            response = (
                device.create(await service.enrolment_options(token)) if fresh else credential
            )
            return await service.complete_enrolment(token, response, fence=fence)
        return await service.prove_contact(token, fence=fence)

    return invoke, subject


@pytest.mark.parametrize("kind", ["enrolment", "contact"])
async def test_prepare_holds_authority_before_b3_and_check_follows_audit(pw, kind):
    invoke, subject = await completion(pw, kind)
    db = pw.passkeys.db
    fence = CompletionFence(pw, kind)
    started = asyncio.get_running_loop().create_future()

    class ObservedFence(CompletionFence):
        async def prepare(self, tx):
            started.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
            await super().prepare(tx)

    fence = ObservedFence(pw, kind)
    task = None
    try:
        async with db.transaction() as holder:
            blocker = await holder.fetch_value("SELECT pg_backend_pid()")
            await holder.fetch_one("SELECT * FROM {{tables.completion_authority}} FOR UPDATE")
            task = asyncio.create_task(invoke(fence))
            pid = await asyncio.wait_for(started, 5)
            async with asyncio.timeout(5):
                while blocker not in await db.fetch_value("SELECT pg_blocking_pids($1)", pid):
                    if task.done():
                        await task
                    await asyncio.sleep(0.01)
            # Authority still blocks, but neither operation has taken B3 effect locks.
            async with db.transaction() as observer:
                assert (
                    await observer.fetch_value(
                        "SELECT subject FROM {{tables.passkey_approvers}} "
                        "WHERE subject=$1 FOR UPDATE NOWAIT",
                        subject,
                    )
                    == subject
                )
        await asyncio.wait_for(task, 5)
        assert fence.calls == ["prepare", "audit", "check"]
        async with db.transaction() as observer:
            assert await observer.fetch_one(
                "SELECT * FROM {{tables.completion_authority}} FOR UPDATE NOWAIT"
            )
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("kind", ["enrolment", "contact"])
@pytest.mark.parametrize("stage", ["prepare", "check"])
async def test_refusal_rolls_back_effect_token_and_audit_but_not_enrolment_challenge(
    pw, kind, stage
):
    invoke, _ = await completion(pw, kind)
    db = pw.passkeys.db
    before = await effect_rows(db)
    fence = CompletionFence(pw, kind, refuse=stage)
    refusal = EnrolmentRefused if kind == "enrolment" else ContactChangeRefused
    with pytest.raises(refusal):
        await invoke(fence)
    assert await effect_rows(db) == before
    assert fence.calls == (["prepare"] if stage == "prepare" else ["prepare", "audit", "check"])
    if kind == "enrolment":
        assert await db.fetch_value(
            "SELECT used_at IS NOT NULL FROM {{tables.passkey_challenges}} WHERE purpose='enrolment'"
        )
        # The old registration cannot replay, even though the link effect rolled back.
        replay = CompletionFence(pw, kind)
        with pytest.raises(EnrolmentRefused):
            await invoke(replay)
        assert replay.calls == []
    retry = CompletionFence(pw, kind)
    await invoke(retry, fresh=True)
    assert retry.calls == ["prepare", "audit", "check"]
    assert await effect_rows(db) != before


@pytest.mark.parametrize("kind", ["enrolment", "contact"])
async def test_final_check_observes_live_expiry_after_effect_and_audit(pw, kind):
    invoke, _ = await completion(pw, kind)
    db = pw.passkeys.db
    before = await effect_rows(db)
    fence = CompletionFence(pw, kind)
    refusal = EnrolmentRefused if kind == "enrolment" else ContactChangeRefused
    with pytest.raises(refusal):
        await invoke(fence, expire=True)
    assert fence.calls == ["prepare", "audit", "check"]
    assert await effect_rows(db) == before
