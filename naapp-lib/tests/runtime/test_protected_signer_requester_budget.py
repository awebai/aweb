"""One requester's approval requests and mail are bounded. At most
OPEN_REQUEST_LIMIT requests wait for a human at once; past it prepare is
refused and creates nothing. Mail is NOTICE_BUDGET notices an hour, one per
approver mailed, and never less than one full round. Past it the request is
still created and waits for its approver as before; it is not mailed, the
signer records that, and the prepare answer is the same as any other."""

import asyncio
import uuid
from dataclasses import asdict, replace
from datetime import timedelta

import pytest

from aweb_naapp.runtime.protected_signer import (
    NOTICE_BUDGET,
    NOTICE_WINDOW,
    OPEN_REQUEST_LIMIT,
    RestrictedRequester,
    SignerRefused,
)
from aweb_naapp.runtime.protected_signer.requester_budget import reserve_notices
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
    assert receipt.state == "pending" and receipt.expires_at == over.expires_at
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
    assert NOTICE_WINDOW == timedelta(hours=1) and NOTICE_BUDGET == 10 and OPEN_REQUEST_LIMIT == 20


async def open_rows(world):
    return await world.passkeys.db.fetch_value(
        "SELECT count(*) FROM {{tables.protected_signer_operations}} WHERE approval_id IS NOT NULL")


async def test_past_the_open_request_limit_prepare_is_refused_and_creates_nothing(world):
    contacts = Contacts()
    signer = mailing_signer(world, contacts)
    first = fresh(world)
    await signer.prepare(first, requester=world.requester)
    for _ in range(OPEN_REQUEST_LIMIT - 1):
        await signer.prepare(fresh(world), requester=world.requester)
    mailed, rows = len(contacts.inbox[CONTACT]), await open_rows(world)
    with pytest.raises(SignerRefused) as refused:
        await signer.prepare(fresh(world), requester=world.requester)
    assert refused.value.code == "open_requests_limit_reached"
    assert await open_rows(world) == rows and len(contacts.inbox[CONTACT]) == mailed
    # A request already made still answers: a resent prepare is not a new one.
    assert (await signer.prepare(first, requester=world.requester)).operation_id == first.operation_id


async def test_an_expired_request_frees_its_place_and_another_requester_has_its_own(world, monkeypatch):
    import tests.runtime.protected_signer_support as support

    signer = mailing_signer(world, Contacts())
    for _ in range(OPEN_REQUEST_LIMIT):
        await signer.prepare(fresh(world), requester=world.requester)
    monkeypatch.setattr(support, "REQUESTERS", {*support.REQUESTERS, "other-requester"})
    other = RestrictedRequester("other-requester", world.requester.context)
    await signer.prepare(fresh(world), requester=other)
    world.clock.advance(timedelta(hours=25))
    await signer.prepare(fresh(world), requester=world.requester)


async def test_concurrent_prepares_cannot_exceed_the_open_request_limit(world):
    signer = mailing_signer(world, Contacts())
    results = await asyncio.gather(*(signer.prepare(fresh(world), requester=world.requester)
                                     for _ in range(OPEN_REQUEST_LIMIT + 3)), return_exceptions=True)
    refused = [r for r in results if isinstance(r, SignerRefused)]
    assert len(refused) == 3 and {r.code for r in refused} == {"open_requests_limit_reached"}
    assert await open_rows(world) == OPEN_REQUEST_LIMIT


async def test_a_round_to_more_approvers_than_the_budget_is_mailed_once_per_window(world):
    async def reserve(notices):
        # A real stored operation, prepared by a signer that mails nothing.
        prepared = await world.signer.prepare(fresh(world), requester=world.requester)
        async with world.passkeys.db.transaction() as tx:
            return await reserve_notices(tx, operation_id=prepared.operation_id, service_id="s", authority_id="a",
                                         requester="r", notices=notices, now=world.clock())

    # Twelve approvers: the first round goes out whole, the next waits for the window.
    assert await reserve(NOTICE_BUDGET + 2) is True
    assert await reserve(NOTICE_BUDGET + 2) is False
    world.clock.advance(NOTICE_WINDOW)
    assert await reserve(NOTICE_BUDGET + 2) is True


async def test_an_approved_request_whose_signing_failed_still_holds_its_place(world, monkeypatch):
    """A slot frees when its request is signed, refused or expired, never at
    the human decision alone: an approval recorded before a failed read
    leaves the act unsigned and still finishable."""
    signer = mailing_signer(world, Contacts())
    approved = fresh(world)
    await signer.prepare(approved, requester=world.requester)
    for _ in range(OPEN_REQUEST_LIMIT - 1):
        await signer.prepare(fresh(world), requester=world.requester)
    # The approval is recorded, then the very next authority read fails, once.
    authority, armed = signer.authority, {"read": False}
    observe, decide = authority.observe, signer.approvals.decide

    async def fail_once_after_the_decision(context, *, purpose):
        if armed["read"]:
            armed["read"] = False
            raise SignerRefused("evidence_unavailable")
        return await observe(context, purpose=purpose)

    async def decided(*args, **kwargs):
        result = await decide(*args, **kwargs)
        armed["read"] = True
        return result

    monkeypatch.setattr(authority, "observe", fail_once_after_the_decision)
    monkeypatch.setattr(signer.approvals, "decide", decided)
    options = await signer.approval_options(approved.operation_id, human=world.human)
    with pytest.raises(SignerRefused, match="evidence_unavailable"):
        await signer.execute(approved.operation_id, world.device.get(dict(options)), human=world.human)
    assert (await signer.receipt(approved.operation_id, reader=world.reader)).state == "pending"
    assert await signer.approval_options(approved.operation_id, human=world.human) == {"state": "approved"}
    with pytest.raises(SignerRefused, match="open_requests_limit_reached"):
        await signer.prepare(fresh(world), requester=world.requester)
