"""Mailed approval links: the signer mails each approver after prepare commits,
the personal link reveals the request, and one fresh exact-act UV approves or
rejects it (human-assurance-contract.md, "Mailed approval links").

These exercise the policy scenarios mailed-link-reveals-and-decides-nothing,
mailed-link-approves-with-one-exact-act-uv, mailed-link-denies-with-one-exact-act-uv,
mailed-link-assertion-for-the-other-decision, mailed-link-other-candidate-or-spent,
mailed-link-not-revealing-policy and mailed-owner-act-after-ten-minutes
of the human-assurance policy vectors."""

from __future__ import annotations

import base64
import json
import uuid
from dataclasses import replace
from datetime import datetime, timedelta

import pytest
import pytest_asyncio

from aweb_naapp.runtime.approvals import ActionPolicy, Assurance
from aweb_naapp.runtime.protected_signer import ProtectedSigner, SignerRefused
from tests.runtime.approvals.support import Policies
from tests.runtime.approvals.test_passkeys import Contacts
from tests.runtime.protected_signer_support import CONTACT, SCOPE


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


async def test_a_mailed_owner_act_freezes_an_intent_for_the_original_day_window(mailing):
    world, contacts = mailing
    prepared, _ = await mailed(world, contacts)
    descriptor = prepared.payload["artifact"]
    assert prepared.expires_at == descriptor["issuance_window"]["not_after"]
    assert stamp(prepared.expires_at) == world.clock() + timedelta(hours=24)
    assert "issued_at" not in descriptor["template"] and "expires_at" not in descriptor["template"]


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
    # Whole intent/request classification: security TEXT ACK12faf072;
    # contract "Frozen intent, execution-time issuance" excludes private
    # issued artifacts, retained proof/authentication and session/link tokens.
    assert {key for key, spec in OPERATIONS.items() if spec.link_revealable} == {
        ("identity.root.endorse", "default"), ("human-role.revoke", "default"),
        ("team.agent.remove", "owner_approved")}


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


async def test_a_signed_but_unconfirmed_request_is_never_reported_expired_to_its_link(mailing):
    """The candidate is read before signing (its link still stored), the
    effect is then signed but not confirmed, and the request expires: the
    link must not say it expired undecided, since it may already be applied."""
    world, contacts = mailing
    prepared, token = await mailed(world, contacts)
    # The candidate lookup happens first, as a racing link view would do it.
    operation_id, _ = await world.signer._link_human(prepared.handoff_id, token)
    await world.passkeys.db.execute(
        "UPDATE {{tables.protected_signer_operations}} SET signed_result=$2::jsonb WHERE operation_id=$1",
        operation_id, '{"signing":"c2lnbmVk","signature":"c2lnbmF0dXJl"}')
    world.clock.advance(timedelta(hours=25))
    with pytest.raises(SignerRefused) as refused:
        await world.signer.link_view(prepared.handoff_id, token)
    assert refused.value.code == "scope_refused"
    # The signer's own receipt keeps it unresolved, not expired.
    receipt = await world.signer.receipt(prepared.operation_id, reader=world.reader)
    assert (receipt.state, receipt.code) == ("unknown", "external_effect_unresolved")


@pytest.mark.parametrize("provider_name", [None, "admission"])
@pytest.mark.parametrize("expired", [False, True])
async def test_a_signed_receipt_without_a_confirmation_provider_preserves_its_history(
    mailing, monkeypatch, provider_name, expired
):
    from aweb_naapp.hooks.owner_act import owner_act_signing_bytes
    from aweb_naapp.runtime.protected_signer import catalog

    world, contacts = mailing
    prepared, _ = await mailed(world, contacts)
    from aweb_naapp.runtime.protected_signer.execution_intent import materialize_artifact
    from aweb_naapp.runtime.protected_signer.types import owner_act_operation

    operation = owner_act_operation(world.signer._operation(prepared.payload))
    issued = materialize_artifact(operation, prepared.payload["artifact"], world.clock())
    signing = owner_act_signing_bytes(issued)
    signed = {"signing": base64.b64encode(signing).decode(),
        "signature": base64.b64encode(world.key.sign(signing).signature).decode()}
    # Model a historical signed, non-retained row. The definition either has
    # no external confirmation port, or its named port is no longer installed.
    await world.passkeys.db.execute(
        "UPDATE {{tables.protected_signer_operations}} SET signed_result=$2::jsonb,issued_artifact=$3::jsonb WHERE operation_id=$1",
        prepared.operation_id, json.dumps(signed), json.dumps(issued))
    spec = catalog.OPERATIONS[("human-role.revoke", "default")]
    monkeypatch.setattr(catalog, "OPERATIONS", {**catalog.OPERATIONS,
        ("human-role.revoke", "default"): replace(spec, effect=replace(spec.effect, provider=provider_name))})
    assert world.signer.admission is None
    if expired:
        world.clock.advance(timedelta(hours=25))
    query = "SELECT * FROM {{tables.protected_signer_operations}} WHERE operation_id=$1"
    before = await world.passkeys.db.fetch_one(query, prepared.operation_id)
    audit_before = await world.audit.kinds()

    def never_sign(*args):
        pytest.fail("a receipt read cannot sign another artifact")

    monkeypatch.setattr(world.signer.custody, "sign_owner_act", never_sign)
    receipt = await world.signer.receipt(prepared.operation_id, reader=world.reader)
    assert (receipt.state, receipt.code) == (
        ("unknown", "external_effect_unresolved") if expired else ("pending", "effect_in_progress"))
    assert receipt.result is None
    assert await world.passkeys.db.fetch_one(query, prepared.operation_id) == before
    assert await world.audit.kinds() == audit_before


async def test_a_signing_after_the_authorized_read_still_spends_the_link(mailing, monkeypatch):
    """Barrier at the authorized-read boundary: the effect is signed after
    that read released its lock and the request then expires, before link_view
    classifies it. The classification must see the signed row, not the
    snapshot, so the link never answers 410 (nothing was signed)."""
    world, contacts = mailing
    prepared, token = await mailed(world, contacts)
    authorized = world.signer._authorized

    async def then_signed_and_expired(operation_id, actor, purpose, **kwargs):
        row = await authorized(operation_id, actor, purpose, **kwargs)
        await world.passkeys.db.execute(
            "UPDATE {{tables.protected_signer_operations}} SET signed_result=$2::jsonb WHERE operation_id=$1",
            operation_id, '{"signing":"c2lnbmVk","signature":"c2lnbmF0dXJl"}')
        world.clock.advance(timedelta(hours=25))
        return row

    monkeypatch.setattr(world.signer, "_authorized", then_signed_and_expired)
    with pytest.raises(SignerRefused) as refused:
        await world.signer.link_view(prepared.handoff_id, token)
    assert refused.value.code == "scope_refused"


async def test_owner_act_is_issued_after_hours_and_delivered_without_a_waiting_client(mailing):
    """Real B2/B3/SQL, explicit transport double; no genuine consumer claim."""
    world, contacts = mailing
    prepared, token = await mailed(world, contacts)
    before = await world.passkeys.db.fetch_one(
        "SELECT * FROM {{tables.protected_signer_operations}} WHERE operation_id=$1", prepared.operation_id)
    assert before["issued_artifact"] is None and before["signed_result"] is None
    nonce = prepared.payload["artifact"]["template"]["nonce"]
    world.clock.advance(timedelta(hours=2))
    options = await world.signer.link_options(prepared.handoff_id, token, "approve")
    result = await world.signer.link_decide(prepared.handoff_id, token, "approve", world.device.get(dict(options)))
    assert result.state == "committed" and result.result["delivery"]["state"] == "applied"
    after = await world.passkeys.db.fetch_one(
        "SELECT * FROM {{tables.protected_signer_operations}} WHERE operation_id=$1", prepared.operation_id)
    issued = json.loads(after["issued_artifact"])
    assert issued["nonce"] == nonce and stamp(issued["issued_at"]) == world.clock()
    assert stamp(issued["expires_at"]) == world.clock() + timedelta(minutes=10)
    assert after["request"] == before["request"] and after["digest"] == before["digest"]
    assert after["expires_at"] == before["expires_at"]
    assert world.signer.custody.applied == {prepared.operation_id}
    world.clock.advance(timedelta(hours=25))
    assert await world.signer.receipt(prepared.operation_id, reader=world.reader) == result
    assert (await world.audit.kinds()).count("protected_operation_signed") == 1
    assert world.signer.custody.applied == {prepared.operation_id}
