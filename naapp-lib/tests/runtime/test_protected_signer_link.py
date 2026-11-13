"""Mailed approval links: the signer mails each approver after prepare commits,
the personal link reveals the request, and one fresh exact-act UV approves or
rejects it (human-assurance-contract.md, "Mailed approval links").

These exercise the policy scenarios mailed-link-reveals-and-decides-nothing,
mailed-link-approves-with-one-exact-act-uv, mailed-link-denies-with-one-exact-act-uv,
mailed-link-assertion-for-the-other-decision, mailed-link-other-candidate-or-spent,
mailed-link-not-revealing-policy and mailed-wait-capped-by-frozen-owner-act
of the human-assurance policy vectors."""

from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import datetime, timedelta

import pytest
import pytest_asyncio

from aweb_naapp.runtime.approvals import ActionPolicy, Assurance
from aweb_naapp.runtime.protected_signer import ProtectedSigner, SignerRefused
from tests.runtime.approvals.support import Policies
from tests.runtime.approvals.test_passkeys import Contacts
from tests.runtime.test_protected_signer import CONTACT, SCOPE

pytest_plugins = ("tests.runtime.test_protected_signer",)


def mailing_signer(world, contacts, *, reveal=True):
    """The same real world's signer, as a deployment that mails approvals."""
    policy = ActionPolicy("aweb.human-assurance/1", 1, Assurance.PASSKEY, timedelta(hours=24), (SCOPE,),
        link_reveals_request=reveal)
    return ProtectedSigner(world.passkeys.db, passkeys=world.passkeys, policies=Policies(policy),
        delivery=contacts, audit=world.audit, authority=world.signer.authority, custody=world.signer.custody,
        clock=world.clock, mailed_approval_wait=timedelta(hours=24))


@pytest_asyncio.fixture
async def mailing(world):
    contacts = Contacts()
    return replace(world, signer=mailing_signer(world, contacts)), contacts


def stamp(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


async def mailed(world, contacts):
    prepared = await world.signer.prepare(world.operation, requester=world.requester)
    return prepared, contacts.last(CONTACT)


async def test_prepare_mails_each_approver_their_link_after_commit_and_tells_the_requester_nothing(mailing):
    world, contacts = mailing
    prepared, token = await mailed(world, contacts)
    assert contacts.inbox[CONTACT] == [token]
    assert token not in repr(prepared) and token not in str(prepared.payload)
    receipt = await world.signer.receipt(prepared.operation_id, reader=world.reader)
    assert receipt.state == "pending" and token not in repr(receipt)
    # An exact retry of the same prepare mails nobody again.
    assert await world.signer.prepare(world.operation, requester=world.requester) == prepared
    assert contacts.inbox[CONTACT] == [token]


async def test_the_link_reveals_the_frozen_request_and_decides_nothing(mailing):
    world, contacts = mailing
    prepared, token = await mailed(world, contacts)
    view = await world.signer.link_view(prepared.handoff_id, token)
    assert view.operation_id == prepared.operation_id
    assert view.digest == prepared.digest and view.payload == prepared.payload
    assert (await world.signer.receipt(prepared.operation_id, reader=world.reader)).state == "pending"


async def test_one_touch_from_the_link_approves_and_commits_once(mailing):
    world, contacts = mailing
    prepared, token = await mailed(world, contacts)
    options = await world.signer.link_options(prepared.handoff_id, token, "approve")
    assert options["userVerification"] == "required"
    proof = world.device.get(dict(options))
    result = await world.signer.link_decide(prepared.handoff_id, token, "approve", proof)
    assert result.state == "committed"
    assert await world.signer.receipt(prepared.operation_id, reader=world.reader) == result
    assert (await world.audit.kinds()).count("protected_operation_signed") == 1
    # The link is spent: it neither decides again nor reads anything more.
    with pytest.raises(SignerRefused, match="scope_refused"):
        await world.signer.link_decide(prepared.handoff_id, token, "approve", proof)
    with pytest.raises(SignerRefused, match="scope_refused"):
        await world.signer.link_view(prepared.handoff_id, token)
    assert (await world.audit.kinds()).count("protected_operation_signed") == 1


async def test_one_touch_from_the_link_denies_and_the_requester_reads_human_refused(mailing):
    world, contacts = mailing
    prepared, token = await mailed(world, contacts)
    proof = world.device.get(dict(await world.signer.link_options(prepared.handoff_id, token, "reject")))
    result = await world.signer.link_decide(prepared.handoff_id, token, "reject", proof)
    assert result.state == "refused" and result.code == "human_refused"
    assert await world.signer.receipt(prepared.operation_id, reader=world.reader) == result
    assert "protected_operation_signed" not in await world.audit.kinds()


@pytest.mark.parametrize("asked, presented", [("approve", "reject"), ("reject", "approve")])
async def test_an_assertion_decides_only_what_it_was_made_for(mailing, asked, presented):
    world, contacts = mailing
    world = replace(world, operation=replace(world.operation, operation_id=str(uuid.uuid4())))
    prepared, token = await mailed(world, contacts)
    proof = world.device.get(dict(await world.signer.link_options(prepared.handoff_id, token, asked)))
    with pytest.raises(SignerRefused, match="proof_invalid"):
        await world.signer.link_decide(prepared.handoff_id, token, presented, proof)
    receipt = await world.signer.receipt(prepared.operation_id, reader=world.reader)
    assert (receipt.state, receipt.code) == ("refused", "proof_invalid")
    assert "protected_operation_signed" not in await world.audit.kinds()


@pytest.mark.parametrize("wrong", ["other-token", "", "handoff"])
async def test_a_wrong_link_reveals_and_decides_nothing(mailing, wrong):
    world, contacts = mailing
    prepared, token = await mailed(world, contacts)
    handoff, presented = prepared.handoff_id, {"other-token": token[:-2] + "xx", "": "", "handoff": token}[wrong]
    if wrong == "handoff":
        handoff = "00000000-0000-4000-8000-000000000000"
    for call in (lambda: world.signer.link_view(handoff, presented),
                 lambda: world.signer.link_options(handoff, presented, "approve")):
        with pytest.raises(SignerRefused):
            await call()
    assert (await world.signer.receipt(prepared.operation_id, reader=world.reader)).state == "pending"


async def test_without_the_reveal_policy_the_link_reveals_nothing(world):
    contacts = Contacts()
    world = replace(world, signer=mailing_signer(world, contacts, reveal=False))
    prepared, token = await mailed(world, contacts)
    with pytest.raises(SignerRefused, match="scope_refused"):
        await world.signer.link_view(prepared.handoff_id, token)
    # The same link still decides with its exact-act UV (variant B keeps the login page).
    assert (await world.signer.receipt(prepared.operation_id, reader=world.reader)).state == "pending"


async def test_a_signer_that_does_not_mail_sends_nothing(world):
    contacts = Contacts()
    signer = ProtectedSigner(world.passkeys.db, passkeys=world.passkeys, policies=world.signer.policies,
        delivery=contacts, audit=world.audit, authority=world.signer.authority, custody=world.signer.custody,
        clock=world.clock)
    prepared = await signer.prepare(world.operation, requester=world.requester)
    assert contacts.inbox == {}
    assert stamp(prepared.expires_at) <= world.clock() + timedelta(seconds=600)


async def test_a_mailed_owner_act_still_expires_with_its_frozen_artifact(mailing):
    world, contacts = mailing
    prepared, _ = await mailed(world, contacts)
    # The 24-hour mailed wait never outlives the owner act's own frozen expiry.
    assert prepared.expires_at == prepared.payload["artifact"]["expires_at"]
    assert stamp(prepared.expires_at) <= world.clock() + timedelta(seconds=600)


async def test_the_links_own_approver_is_told_the_request_expired(mailing):
    world, contacts = mailing
    prepared, token = await mailed(world, contacts)
    world.clock.advance(timedelta(hours=25))
    with pytest.raises(SignerRefused, match="operation_expired"):
        await world.signer.link_view(prepared.handoff_id, token)
    # Anyone else's token still learns nothing, not even that it expired.
    with pytest.raises(SignerRefused, match="scope_refused"):
        await world.signer.link_view(prepared.handoff_id, token[:-2] + "xx")


def test_only_reviewed_operations_may_reveal_their_frozen_request_on_a_link():
    from aweb_naapp.runtime.protected_signer.catalog import OPERATIONS

    # Each row's whole frozen request was checked to hold only public
    # identifiers, labels and policy (human-assurance-contract.md, "Mailed
    # approval links"); every other row refuses by default.
    assert {key for key, spec in OPERATIONS.items() if spec.link_revealable} == {
        ("identity.root.endorse", "default"), ("human-role.revoke", "default")}


async def test_an_operation_not_classified_revealable_refuses_the_reveal(mailing, monkeypatch):
    from dataclasses import replace as replace_spec

    from aweb_naapp.runtime.protected_signer import catalog

    world, contacts = mailing
    prepared, token = await mailed(world, contacts)
    unclassified = replace_spec(catalog.OPERATIONS[("human-role.revoke", "default")], link_revealable=False)
    monkeypatch.setattr(catalog, "OPERATIONS", {**catalog.OPERATIONS, ("human-role.revoke", "default"): unclassified})
    # The deployment's B2 policy reveals on links; the operation's own
    # classification still refuses, and the token stays usable.
    with pytest.raises(SignerRefused, match="scope_refused"):
        await world.signer.link_view(prepared.handoff_id, token)
    assert (await world.signer.receipt(prepared.operation_id, reader=world.reader)).state == "pending"
