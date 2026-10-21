"""approve_only use approvals (S12, secrets §10) on real PostgreSQL.

The world is the change-set world: owners enrolled through real team owner
acts, approvers designated through confirmed change sets, real passkeys. A
member's use is admitted by S11's admit_use, put to an approver through B2,
decided with a real passkey ceremony and then admitted exactly once.
"""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from aweb_naapp.idempotency import apply_idempotency_migrations
from aweb_naapp.roles import principal_key
from aweb_naapp.runtime.approvals import (
    Approvals,
    ApprovalState,
    Assurance,
    Decision,
    PgApprovalStore,
)
from aweb_naapp.runtime.team_auth import Principal
from aweb_naapp_testing.owner_acts import INSTALLATION_ID
from aweb_naapp_testing.webauthn import SoftAuthenticator
from awid.did import did_from_public_key, stable_id_from_public_key
from nacl.signing import SigningKey
from pgdbm import AsyncMigrationManager

from aweb_secrets import records
from aweb_secrets.admission import AdmissionRefused, UseRequest, admit_use
from aweb_secrets.app import MIGRATIONS_PATH, MODULE_NAME
from aweb_secrets.grant import GrantRecord
from aweb_secrets.policy import Policy
from aweb_secrets.revisions import config_revision
from aweb_secrets.secret import SecretRecord
from aweb_secrets.use_approval import BrokerOpen
from aweb_secrets.use_approvals import (
    UseApprovalRefused,
    UseApprovers,
    UsePolicies,
    admit_approved_use,
    apply_use_approval_migrations,
    request_use_approval,
    use_approval_status,
    void_use_approvals,
)
from tests.test_change_sets import (
    ALICE,
    ORIGIN,
    TEAM,
    Installations,
    World,
    by_member,
    change_set,
    decide,
    draft,
    enrol_owner,
    world,  # noqa: F401  (the fixture this module builds on)
)

SECRET_ID = "sec_19ab42"
GRANT_ID = "grt_req001"


def _member(seed: int) -> Principal:
    key = bytes(SigningKey(bytes([seed]) * 32).verify_key)
    return Principal(
        team_id=TEAM,
        did_key=did_from_public_key(key),
        did_aw=stable_id_from_public_key(key),
        address=None,
        alias=f"member-{seed}",
        certificate_id=f"cert-{seed}",
        team_did_key="did:key:z6MkteamKey",
    )


REQUESTER = _member(7)


class Clock:
    def __init__(self) -> None:
        self.now = datetime.now(UTC).replace(microsecond=0)

    def __call__(self) -> datetime:
        return self.now


@dataclass
class Uses:
    world: World
    approvals: Approvals
    clock: Clock
    grant: Any


def designate_approver(ref: str, contact: str, covers: list[str], principal: str | None = None):
    return {
        "kind": "approver",
        "op": "create",
        "ref": ref,
        "after": {
            "v": 1,
            "approver_ref": ref,
            "contact": contact,
            "covers": covers,
            "principal": principal,
        },
    }


async def designate(uses: Uses, ref: str, contact: str, *, principal: str | None = None) -> None:
    """An owner-confirmed change set designates an approver covering the secret; it enrols."""
    w = uses.world
    change = change_set(
        drafter=by_member(ALICE),
        changes=[designate_approver(ref, contact, [SECRET_ID], principal)],
        base_revision=await config_revision(w.db, INSTALLATION_ID),
    )
    await decide(w, await draft(w, change), "alice@acme.com")
    async with w.db.transaction() as tx:
        confirmation = await w.change_sets.confirm(
            tx,
            change["change_id"],
            operation_id=f"apply-{change['change_id']}",
            fence=w.fence,
            admitted=w.admitted,
        )
    await w.change_sets.deliver(confirmation)
    token = w.inbox.enrolments[contact][-1]
    device = SoftAuthenticator(ORIGIN)
    await w.passkeys.complete_enrolment(
        token, device.create(await w.passkeys.enrolment_options(token))
    )
    w.devices[contact] = device


POLICY_BODY: dict[str, Any] = {
    "approval": "per_use",
    "approvers": ["finance"],
    "approval_ttl_s": 900,
    "rate": [{"per": "principal_secret", "capacity": 100, "window_s": 3600}],
    "windows": None,
    "operations": [],
    "open_request": True,
    "request": {"max_bytes": 65536},
    "result": {"max_bytes": 65536},
    "requires_attestation": None,
    "distinct_approver": "not_required",
}
SECRET: dict[str, Any] = {
    "v": 1,
    "secret_id": SECRET_ID,
    "ref": "staging-api",
    "description": "Staging API key",
    "kind": "bearer",
    "kind_params": {},
    "sensitivity": "standard",
    "approve_only": False,
    "backend": "native",
}


async def install(uses: Uses, **policy_changes) -> Policy:
    policy = Policy.from_body({**POLICY_BODY, **policy_changes})
    record = SecretRecord.from_after(SECRET)
    async with uses.world.db.transaction() as tx:
        if await records.secret_by_ref(tx, INSTALLATION_ID, TEAM, record.ref) is None:
            await records.create_secret(tx, INSTALLATION_ID, TEAM, record)
            await records.set_active_version(tx, INSTALLATION_ID, TEAM, SECRET_ID, 4)
        await records.create_policy(tx, INSTALLATION_ID, policy)
        grant_id = f"grt_{policy.digest[:10]}"
        await records.create_grant(
            tx,
            INSTALLATION_ID,
            TEAM,
            GrantRecord.from_after(
                {
                    "v": 1,
                    "grant_id": grant_id,
                    "secret_id": SECRET_ID,
                    "subject": {"principal": principal_key(REQUESTER).principal_did},
                    "capability": "use",
                    "operations": [],
                    "open_request": True,
                    "jobs": [],
                    "policy_digest": policy.digest,
                }
            ),
        )
    return policy


@pytest.fixture
async def uses(world: World) -> Uses:  # noqa: F811
    db = world.db
    await apply_idempotency_migrations(db)
    await AsyncMigrationManager(
        db, migrations_path=str(MIGRATIONS_PATH), module_name=MODULE_NAME
    ).apply_pending_migrations()
    await apply_use_approval_migrations(db)
    clock = Clock()
    approvals = Approvals(
        store=PgApprovalStore(db),
        policies=UsePolicies(db),
        approvers=UseApprovers(db, world.passkeys, world.directory),
        delivery=world.inbox,
        authenticators=[world.passkeys.authenticator()],
        audit=world.approvals._audit,
        clock=clock,
    )
    await enrol_owner(world, ALICE, "alice@acme.com")
    return Uses(world, approvals, clock, Installations().grant)


BODY = b'{"amount_minor_units":1250}'


def use_request(request_id: str = "req_1", body: bytes = BODY) -> UseRequest:
    return UseRequest(
        secret_ref="staging-api",
        request_id=request_id,
        request_sha256=hashlib.sha256(body).digest(),
        operation_id=None,
        params=None,
    )


def open_action(body: bytes = BODY) -> BrokerOpen:
    return BrokerOpen(
        method="POST",
        canonical_url="https://api.payments.example/v1/refunds",
        header_names=("content-type",),
        body=body,
    )


async def request(uses: Uses, request_id: str = "req_1", *, body: bytes = BODY, reason="refund"):
    """S11's first submission: admission, then the use approval, in one transaction;
    links are delivered after the commit."""
    dispatch_id = uuid.uuid4()
    async with uses.world.db.transaction() as tx:
        admission = await admit_use(
            tx,
            fence=uses.world.fence,
            grant=uses.grant,
            principal=REQUESTER,
            request=use_request(request_id, body),
            attestation=None,
            now=uses.clock(),
        )
        assert admission.approval_required
        pending = await request_use_approval(
            tx,
            uses.approvals,
            admission=admission,
            dispatch_id=dispatch_id,
            principal=REQUESTER,
            action=open_action(body),
            reason=reason,
        )
    await uses.approvals.deliver(pending.pending)
    return admission, dispatch_id, pending


async def approve(uses: Uses, pending, contact: str, decision=Decision.APPROVE) -> None:
    approval_id = pending.pending.approval.approval_id
    [token] = [t for a, t in uses.world.inbox.links.get(contact, []) if a == approval_id]
    options = await uses.approvals.challenge(
        approval_id, decision, Assurance.PASSKEY, link_token=token
    )
    await uses.approvals.decide(
        approval_id,
        decision,
        Assurance.PASSKEY,
        uses.world.devices[contact].get(dict(options)),
        link_token=token,
    )


async def admit(uses: Uses, admission, dispatch_id):
    async with uses.world.db.transaction() as tx:
        return await admit_approved_use(
            tx, uses.approvals, intent_id=admission.intent_id, dispatch_id=dispatch_id
        )


async def test_an_approved_use_is_admitted_once_and_the_requester_never_sees_a_link(uses):
    await designate(uses, "finance", "finance@acme.com")
    await install(uses)
    admission, dispatch_id, pending = await request(uses)
    links = uses.world.inbox.links
    assert [contact for contact in links if contact != "alice@acme.com"] == ["finance@acme.com"]
    status = await use_approval_status(
        uses.approvals, approval_ref=pending.approval_ref, principal=REQUESTER
    )
    assert status.state == "awaiting_approval"
    assert all(token not in repr(status) for _, token in links["finance@acme.com"])
    await approve(uses, pending, "finance@acme.com")
    status = await use_approval_status(
        uses.approvals, approval_ref=pending.approval_ref, principal=REQUESTER
    )
    assert (status.state, status.next) == ("approved", "resubmit")
    admitted = await admit(uses, admission, dispatch_id)
    assert admitted.refusal is None and admitted.admission.first and admitted.admission.may_send


async def test_reuse_after_consume_is_refused_and_a_retry_retrieves(uses):
    await designate(uses, "finance", "finance@acme.com")
    await install(uses)
    admission, dispatch_id, pending = await request(uses)
    await approve(uses, pending, "finance@acme.com")
    assert (await admit(uses, admission, dispatch_id)).admission.first
    again = await admit(uses, admission, dispatch_id)
    assert again.refusal is None and not again.admission.first and not again.admission.may_send
    assert (await admit(uses, admission, uuid.uuid4())).refusal == "approval_consumed"


async def test_parallel_consumers_yield_one_dispatch(uses):
    await designate(uses, "finance", "finance@acme.com")
    await install(uses)
    admission, dispatch_id, pending = await request(uses)
    await approve(uses, pending, "finance@acme.com")
    results = await asyncio.gather(
        *(admit(uses, admission, d) for d in (dispatch_id, uuid.uuid4(), uuid.uuid4()))
    )
    first = [r for r in results if r.refusal is None and r.admission.first]
    assert len(first) == 1


async def test_changed_parameters_after_approval_are_refused(uses):
    await designate(uses, "finance", "finance@acme.com")
    await install(uses)
    _, _, pending = await request(uses)
    await approve(uses, pending, "finance@acme.com")
    with pytest.raises(AdmissionRefused) as refused:
        async with uses.world.db.transaction() as tx:
            await admit_use(
                tx,
                fence=uses.world.fence,
                grant=uses.grant,
                principal=REQUESTER,
                request=use_request(body=b'{"amount_minor_units":999999}'),
                attestation=None,
                now=uses.clock(),
            )
    assert refused.value.code == "idempotency_conflict"


async def test_a_denied_expired_or_revoked_approval_admits_nothing(uses):
    await designate(uses, "finance", "finance@acme.com")
    await install(uses)
    denied = await request(uses, "req_denied")
    await approve(uses, denied[2], "finance@acme.com", Decision.REJECT)
    assert (await admit(uses, denied[0], denied[1])).refusal == "approval_denied"
    revoked = await request(uses, "req_revoked")
    await approve(uses, revoked[2], "finance@acme.com")
    await uses.approvals.revoke(revoked[2].pending.approval.approval_id, revoked_by="owner")
    assert (await admit(uses, revoked[0], revoked[1])).refusal == "approval_revoked"
    expired = await request(uses, "req_expired")
    await approve(uses, expired[2], "finance@acme.com")
    uses.clock.now += timedelta(seconds=901)
    assert (await admit(uses, expired[0], expired[1])).refusal == "approval_expired"


async def test_an_undecided_approval_admits_nothing_yet(uses):
    await designate(uses, "finance", "finance@acme.com")
    await install(uses)
    admission, dispatch_id, _ = await request(uses)
    assert (await admit(uses, admission, dispatch_id)).refusal == "approval_pending"


async def test_a_replaced_value_before_consume_voids_the_approval(uses):
    await designate(uses, "finance", "finance@acme.com")
    await install(uses)
    admission, dispatch_id, pending = await request(uses)
    await approve(uses, pending, "finance@acme.com")
    async with uses.world.db.transaction() as tx:
        await records.set_active_version(tx, INSTALLATION_ID, TEAM, SECRET_ID, 5)
    assert (await admit(uses, admission, dispatch_id)).refusal == "secret_version_changed"
    approval = await uses.approvals.get(pending.pending.approval.approval_id)
    assert approval.state_at(uses.clock()) is ApprovalState.REVOKED


async def test_a_changed_external_item_voids_the_pending_and_approved_approvals(uses):
    await designate(uses, "finance", "finance@acme.com")
    await install(uses)
    approved = await request(uses, "req_a")
    await approve(uses, approved[2], "finance@acme.com")
    waiting = await request(uses, "req_b")
    async with uses.world.db.transaction() as tx:
        voided = await void_use_approvals(
            tx,
            uses.approvals,
            installation_id=INSTALLATION_ID,
            team_id=TEAM,
            secret_id=SECRET_ID,
            current_version=5,
            revoked_by="custody",
        )
    assert set(voided) == {
        approved[2].pending.approval.approval_id,
        waiting[2].pending.approval.approval_id,
    }
    assert (await admit(uses, approved[0], approved[1])).refusal == "approval_revoked"


async def test_four_eyes_leaves_no_approver_when_the_requester_is_the_only_one(uses):
    await designate(
        uses, "finance", "finance@acme.com", principal=principal_key(REQUESTER).principal_did
    )
    await install(uses, distinct_approver="required")
    with pytest.raises(UseApprovalRefused) as refused:
        await request(uses)
    assert refused.value.code == "no_eligible_approver"


async def test_without_four_eyes_the_requester_may_be_its_own_approver(uses):
    await designate(
        uses, "finance", "finance@acme.com", principal=principal_key(REQUESTER).principal_did
    )
    await install(uses, distinct_approver="not_required")
    _, _, pending = await request(uses)
    assert [c.principal_did for c in pending.pending.approval.candidates] == [
        principal_key(REQUESTER).principal_did
    ]


async def test_only_listed_approvers_that_cover_the_secret_are_candidates(uses):
    await designate(uses, "finance", "finance@acme.com")
    await designate(uses, "ops", "ops@acme.com")
    await install(uses, approvers=["finance"])
    _, _, pending = await request(uses)
    assert "ops@acme.com" not in uses.world.inbox.links
    assert len(pending.pending.approval.candidates) == 1


async def test_no_eligible_approver_is_refused_at_request_and_nothing_is_minted(uses):
    await install(uses, approvers=["finance"])
    with pytest.raises(UseApprovalRefused) as refused:
        await request(uses)
    assert refused.value.code == "no_eligible_approver"
    assert await uses.world.db.fetch_value("SELECT count(*) FROM {{tables.use_approvals}}") == 0


async def test_a_listed_owner_is_a_candidate_and_an_unlisted_one_is_not(uses):
    await install(uses, approvers=[f"owner:{ALICE.principal_did}"])
    _, _, pending = await request(uses)
    assert [c.principal_did for c in pending.pending.approval.candidates] == [ALICE.principal_did]
    await install(uses, approvers=["finance"])  # a second policy and grant, no owner listed
    with pytest.raises(UseApprovalRefused):
        await request(uses, "req_2")


async def test_resubmitting_the_same_request_mints_nothing_new(uses):
    await designate(uses, "finance", "finance@acme.com")
    await install(uses)
    first = await request(uses)
    again = await request(uses)
    assert again[2].approval_ref == first[2].approval_ref
    assert again[2].pending.deliveries == ()
    assert len(uses.world.inbox.links["finance@acme.com"]) == 1


async def test_a_revoked_grant_voids_the_approval(uses):
    await designate(uses, "finance", "finance@acme.com")
    await install(uses)
    admission, dispatch_id, pending = await request(uses)
    await approve(uses, pending, "finance@acme.com")
    async with uses.world.db.transaction() as tx:
        await records.revoke_grant(tx, INSTALLATION_ID, admission.grant_id)
    assert (await admit(uses, admission, dispatch_id)).refusal == "grant_revoked"
    approval = await uses.approvals.get(pending.pending.approval.approval_id)
    assert approval.state_at(uses.clock()) is ApprovalState.REVOKED


async def test_an_open_request_the_console_cannot_show_is_refused_unrenderable(uses):
    await designate(uses, "finance", "finance@acme.com")
    await install(uses)
    with pytest.raises(UseApprovalRefused) as refused:
        await request(uses, body=b"\xff\xfe")
    assert refused.value.code == "approval_unrenderable"


async def test_the_approval_lives_as_long_as_the_policy_says(uses):
    await designate(uses, "finance", "finance@acme.com")
    await install(uses, approval_ttl_s=600)
    _, _, pending = await request(uses)
    approval = pending.pending.approval
    assert approval.expires_at - approval.created_at == timedelta(seconds=600)


async def test_a_grant_revoked_before_the_approval_is_requested_is_refused_as_revoked(uses):
    await designate(uses, "finance", "finance@acme.com")
    await install(uses)
    async with uses.world.db.transaction() as tx:
        admission = await admit_use(
            tx,
            fence=uses.world.fence,
            grant=uses.grant,
            principal=REQUESTER,
            request=use_request(),
            attestation=None,
            now=uses.clock(),
        )
    async with uses.world.db.transaction() as tx:
        await records.revoke_grant(tx, INSTALLATION_ID, admission.grant_id)
    with pytest.raises(UseApprovalRefused) as refused:
        async with uses.world.db.transaction() as tx:
            await request_use_approval(
                tx,
                uses.approvals,
                admission=admission,
                dispatch_id=uuid.uuid4(),
                principal=REQUESTER,
                action=open_action(),
                reason="refund",
            )
    assert refused.value.code == "grant_revoked"
