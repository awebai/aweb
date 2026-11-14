"""One requester's approval mail is bounded: NOTICE_BUDGET notices an hour,
one per approver mailed. Past it the request is still created and waits for
its approver as before; it is not mailed, the signer records that, and
the prepare answer is the same as any other."""

import asyncio
import uuid
from dataclasses import asdict, replace
from datetime import timedelta

from aweb_naapp.runtime.protected_signer import NOTICE_BUDGET, NOTICE_WINDOW, RestrictedRequester
from tests.runtime.approvals.test_passkeys import Contacts
from tests.runtime.protected_signer_support import CONTACT
from tests.runtime.test_protected_signer_link import mailing_signer


def fresh(world):
    return replace(world.operation, operation_id=str(uuid.uuid4()))


async def suppressions(world):
    return [row for row in await world.audit.rows() if row["kind"] == "protected_notice_suppressed"]


async def test_past_the_budget_a_request_is_created_but_not_mailed_and_that_is_recorded(world):
    contacts = Contacts()
    signer = mailing_signer(world, contacts)
    mailed = [await signer.prepare(fresh(world), requester=world.requester) for _ in range(NOTICE_BUDGET)]
    assert len(contacts.inbox[CONTACT]) == NOTICE_BUDGET
    over = await signer.prepare(fresh(world), requester=world.requester)
    assert len(contacts.inbox[CONTACT]) == NOTICE_BUDGET
    # The answer has the same members as a mailed one: deployed aw reads it unchanged.
    assert asdict(over).keys() == asdict(mailed[0]).keys()
    receipt = await signer.receipt(over.operation_id, reader=world.reader)
    assert (receipt.state, receipt.reason) == ("pending", "awaiting_human")
    [suppressed] = await suppressions(world)
    assert suppressed["subject"] == over.operation_id and suppressed["actor"] == world.requester.principal


async def test_resending_the_same_prepare_mints_no_new_notice_or_reservation(world):
    contacts = Contacts()
    signer = mailing_signer(world, contacts)
    operation = fresh(world)
    first = await signer.prepare(operation, requester=world.requester)
    again = await signer.prepare(operation, requester=world.requester)
    assert again == first and len(contacts.inbox[CONTACT]) == 1
    used = await world.passkeys.db.fetch_value(
        "SELECT coalesce(sum(notices), 0) FROM {{tables.protected_signer_notice_reservations}}")
    assert used == 1


async def test_concurrent_prepares_cannot_exceed_the_budget(world):
    contacts = Contacts()
    signer = mailing_signer(world, contacts)
    await asyncio.gather(*(signer.prepare(fresh(world), requester=world.requester)
                           for _ in range(NOTICE_BUDGET + 3)))
    assert len(contacts.inbox[CONTACT]) == NOTICE_BUDGET
    assert len(await suppressions(world)) == 3


async def test_the_budget_is_the_requesters_own_and_refills_after_the_window(world, monkeypatch):
    import tests.runtime.protected_signer_support as support

    contacts = Contacts()
    signer = mailing_signer(world, contacts)
    for _ in range(NOTICE_BUDGET + 1):
        await signer.prepare(fresh(world), requester=world.requester)
    assert len(contacts.inbox[CONTACT]) == NOTICE_BUDGET
    # Another requester of the same authority has its own budget.
    monkeypatch.setattr(support, "REQUESTERS", {*support.REQUESTERS, "other-requester"})
    other = RestrictedRequester("other-requester", world.requester.context)
    await signer.prepare(fresh(world), requester=other)
    assert len(contacts.inbox[CONTACT]) == NOTICE_BUDGET + 1
    # A window later, the first requester is mailed again.
    world.clock.advance(NOTICE_WINDOW)
    await signer.prepare(fresh(world), requester=world.requester)
    assert len(contacts.inbox[CONTACT]) == NOTICE_BUDGET + 2
    assert NOTICE_WINDOW == timedelta(hours=1) and NOTICE_BUDGET == 10
