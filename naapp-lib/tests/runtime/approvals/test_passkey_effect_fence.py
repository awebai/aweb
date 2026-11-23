"""B3 rechecks its own completion deadlines after the caller's fence: a lock
wait in the fence cannot complete an enrolment or a contact proof late.

The fence here only lets time pass; the real fences, as the console passes
them, are tested in tests/runtime/credential_audit/test_enrolment_fence.py and
secrets' tests/test_contact_audit.py."""
# ruff: noqa: F811 -- pw is the imported real passkey composition fixture.

from datetime import timedelta

import pytest
from aweb_naapp_testing.webauthn import SoftAuthenticator

from aweb_naapp.runtime.passkeys import ContactChangeRefused, EnrolmentRefused
from tests.runtime.approvals.test_passkeys import (
    ORIGIN,
    designate,
    finance_approver,
    owner_changes_contact,
    pw,  # noqa: F401
)

NEW_CONTACT = "finance-new@example.com"


async def effect_rows(db):
    return [
        await db.fetch_all("SELECT * FROM {{tables.passkey_approvers}} ORDER BY 1"),
        await db.fetch_all("SELECT * FROM {{tables.passkey_enrolments}} ORDER BY 1"),
        await db.fetch_all("SELECT * FROM {{tables.passkey_contact_proofs}} ORDER BY 1"),
        await db.fetch_all("SELECT * FROM {{tables.audit_outbox}} ORDER BY 1"),
        await db.fetch_all("SELECT * FROM {{tables.passkey_credentials}} ORDER BY 1"),
    ]


class LockWait:
    """A fence whose prepare waits on the app's locks until `until`."""

    def __init__(self, pw, until):
        self.pw, self.until = pw, until

    async def prepare(self, tx):
        self.pw.clock.now = self.until

    async def check(self, tx):
        pass


@pytest.mark.parametrize("deadline", ["challenge", "link"])
async def test_enrolment_refuses_once_a_lock_wait_outlasts_its_deadline(pw, deadline):
    contact = "human@example.com"
    await designate(pw, contact)
    token = pw.contacts.last(contact)
    db = pw.passkeys.db
    link_expiry = await db.fetch_value("SELECT expires_at FROM {{tables.passkey_enrolments}}")
    if deadline == "link":
        pw.clock.now = link_expiry - timedelta(seconds=1)
    credential = SoftAuthenticator(ORIGIN).create(await pw.passkeys.enrolment_options(token))
    challenge_expiry = await db.fetch_value(
        "SELECT expires_at FROM {{tables.passkey_challenges}} WHERE purpose = 'enrolment'"
    )
    before = await effect_rows(db)
    wait = LockWait(pw, challenge_expiry if deadline == "challenge" else link_expiry)
    with pytest.raises(EnrolmentRefused):
        await pw.passkeys.complete_enrolment(token, credential, fence=wait)
    assert await effect_rows(db) == before


async def test_a_contact_proof_refuses_once_a_lock_wait_outlasts_the_change(pw):
    await finance_approver(pw)
    change, _ = await owner_changes_contact(pw, "approvers.finance", NEW_CONTACT, attempt=2)
    token = pw.contacts.proofs[NEW_CONTACT][-1]
    db = pw.passkeys.db
    before = await effect_rows(db)
    with pytest.raises(ContactChangeRefused) as refused:
        await pw.passkeys.prove_contact(token, fence=LockWait(pw, change.effective_at))
    assert refused.value.reason == "contact_proof_unavailable"
    assert await effect_rows(db) == before
    approver = await pw.passkeys.designated_approver("approvers.finance")
    assert approver.contact == "finance@example.com"
