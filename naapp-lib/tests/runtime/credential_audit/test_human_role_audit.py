"""What the shared credential recorder retains for the human-role acts
(human-role-holders.md, What the credential audit retains), on real
PostgreSQL with real owner acts and the real recorder: each act's own receipt,
the holder's principal and credential in the restricted authorization, an
opaque reference for its key, and nothing a contact act or another holding
could stand in for."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import asyncpg
import pytest
from aweb_naapp_testing.owner_acts import APP_ID, INSTALLATION_ID, TEAM_ID, revocation_subject
from pgdbm.core import TransactionManager
from pgdbm.errors import QueryError

from aweb_naapp.hooks.owner_act import VerifiedOwnerAct
from aweb_naapp.roles import PrincipalKey, assign, begin_holding, end_holding, holding_scope
from aweb_naapp.runtime.audit import AuditEvent, AuditKind
from aweb_naapp.runtime.credential_audit import GovernanceUnavailable
from aweb_naapp.runtime.passkeys import DesignationRefused, contact_sha256
from aweb_naapp.runtime.team_auth import Principal
from tests.runtime.approvals.test_human_role_holders import Holder, holder
from tests.runtime.credential_audit.support import (
    HOLDER_ROLE,
    ROLE,
    World,
    bind,
    enrol,
    events,
    owner_act,
)
from tests.runtime.credential_audit.support import designate as designate_contact

PRINCIPAL = "did:aw:2Wq7mXn4kP9rT1vY5zA8bC3dE6"
OTHER_PRINCIPAL = "did:aw:3Xr8nYo5mQ1sU2wZ6aB9cD4eF7"
CERTIFICATE = b'{"certificate_id":"cert-1"}'
NOTICE = "holder@example.com"
MEMBER = Principal(
    team_id=TEAM_ID,
    did_key="did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    did_aw="did:aw:4Ys9oZp6nR2tV3xA7bC1dE5fG8",
    address=None,
    alias="member",
    certificate_id="cert-member",
    team_did_key="did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
)


def subject(
    member: Holder | None, *, principal: str = PRINCIPAL, role: str = HOLDER_ROLE, notice=None
) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "app_id": APP_ID,
        "installation_id": INSTALLATION_ID,
        "role": role,
        "principal": principal,
    }
    if member is not None:
        fields["credential_sha256"] = member.credential.sha256
    if notice is not None:
        fields["notice_contact_sha256"] = contact_sha256(notice)
    return fields


def key(principal: str = PRINCIPAL, role: str = HOLDER_ROLE) -> dict[str, str]:
    return dict(installation_id=INSTALLATION_ID, team_id=TEAM_ID, role=role, principal=principal)


def retired_event(act: VerifiedOwnerAct, scope: str, principal: str) -> AuditEvent:
    """The event revoke_holder emits for a holding that never had an approver."""
    return AuditEvent(
        kind=AuditKind.APPROVER_RETIRED,
        actor=str(act.fields["team_key_did"]),
        subject=principal,
        occurred_at=datetime.now(UTC),
        details={
            "scope": scope,
            "principal": principal,
            "owner_act_id": f"{act.team_id}:{act.nonce}",
            "owner_act_kind": "human-role.revoke",
        },
    )


async def holding(world: World, principal: str = PRINCIPAL, role: str = HOLDER_ROLE) -> str:
    """Bind the holding's scope to the installation, as the app's resolver does."""
    return await bind(world, holding_scope(INSTALLATION_ID, TEAM_ID, role, principal), role)


async def designate(
    world: World,
    member: Holder,
    *,
    principal: str = PRINCIPAL,
    role: str = HOLDER_ROLE,
    notice: str | None = None,
):
    async def effect(tx: TransactionManager, act: VerifiedOwnerAct):
        return await world.passkeys.designate_holder(
            tx,
            act=act,
            credential=member.credential,
            certificate=CERTIFICATE,
            notice_contact=notice,
        )

    return await owner_act(
        world,
        "human-role.designate",
        subject(member, principal=principal, role=role, notice=notice),
        effect,
    )


async def replace(world: World, member: Holder):
    async def effect(tx: TransactionManager, act: VerifiedOwnerAct):
        return await world.passkeys.replace_holder_credential(
            tx, act=act, credential=member.credential, certificate=CERTIFICATE, notice_contact=None
        )

    return await owner_act(world, "human-credential.replace", subject(member), effect)


async def revoke(world: World, principal: str = PRINCIPAL) -> None:
    async def effect(tx: TransactionManager, act: VerifiedOwnerAct) -> None:
        await world.passkeys.revoke_holder(tx, act=act)

    await owner_act(world, "human-role.revoke", subject(None, principal=principal), effect)


async def backfilled(world: World, principal: str = PRINCIPAL) -> None:
    """A holding begun without a designation, as a backfill does: no approver
    and no authorization exist for it."""
    async with world.db.transaction() as tx:
        await begin_holding(
            tx,
            installation_id=INSTALLATION_ID,
            team_id=TEAM_ID,
            role=HOLDER_ROLE,
            principal=principal,
            certificate=None,
        )


async def authorization(world: World, approver: str):
    return await world.db.fetch_one(
        "SELECT * FROM {{tables.credential_authorizations}} WHERE subject=$1", approver
    )


async def payloads(world: World) -> list[dict]:
    return [fields["payload"] for _, fields in await events(world)]


async def contained(world: World, effect) -> None:
    """Containment by a member the app has authorized, in one fenced transaction."""
    async with world.db.transaction() as tx:
        await world.fence.check(tx, world.admitted)
        prepared = await world.recorder.prepare_containment(
            tx, admitted=world.admitted, principal=MEMBER
        )
        with world.recorder.prepared(prepared):
            await effect(tx)
        await world.fence.check(tx, world.admitted)


async def test_a_designation_retains_its_principal_and_credential_and_an_opaque_key_ref(
    world: World,
):
    scope = await holding(world)
    member = holder()
    designation = await designate(world, member)
    row = await authorization(world, designation.approver.subject)
    assert (row["scope"], row["role"], row["authority"]) == (scope, HOLDER_ROLE, "owner_act")
    assert row["contact_sha256"] is None and row["notice_contact_sha256"] is None
    assert (row["principal"], row["credential_sha256"]) == (PRINCIPAL, member.credential.sha256)
    assert row["credential_ref"].startswith("key_")
    assert member.credential.sha256 not in row["credential_ref"]
    [designated] = await payloads(world)
    assert designated["act"] == "role.designated"
    assert designated["subject_ref"] == designation.approver.subject
    assert designated["owner_act_sha256"] == row["commitment"]
    assert PRINCIPAL not in str(designated) and member.credential.sha256 not in str(designated)


async def test_a_notice_contact_is_retained_apart_from_any_enrolment_contact(world: World):
    await holding(world)
    designation = await designate(world, holder(), notice=NOTICE)
    row = await authorization(world, designation.approver.subject)
    assert row["contact_sha256"] is None
    assert row["notice_contact_sha256"] == contact_sha256(NOTICE)


async def test_a_replacement_is_one_recovery_receipt_with_its_own_key_ref(world: World):
    await holding(world)
    first = await designate(world, holder())
    member = holder()
    second = await replace(world, member)
    assert [p["act"] for p in await payloads(world)] == ["role.designated", "credential.recovered"]
    old = await authorization(world, first.approver.subject)
    new = await authorization(world, second.approver.subject)
    assert new["credential_sha256"] == member.credential.sha256
    assert new["effective_at"] == second.effective_at
    assert new["credential_ref"] != old["credential_ref"]
    assert old["credential_sha256"] != new["credential_sha256"]


async def recovered_event(world: World) -> dict:
    return json.loads(
        await world.db.fetch_value(
            "SELECT details FROM {{tables.credential_audit_events}} WHERE kind=$1",
            AuditKind.APPROVER_REDESIGNATED.value,
        )
    )


async def test_a_replacement_after_containment_names_the_approver_containment_retired(
    world: World,
):
    scope = await holding(world)
    first = await designate(world, holder())
    await contained(
        world,
        lambda tx: world.passkeys.retire_in(
            tx, scope=scope, subject=first.approver.subject, authorized_by=MEMBER.did_aw
        ),
    )
    second = await replace(world, holder())
    assert (await payloads(world))[-1]["act"] == "credential.recovered"
    assert (await recovered_event(world)).get("previous_subject") == first.approver.subject
    assert (await authorization(world, second.approver.subject))["principal"] == PRINCIPAL


async def test_a_replacement_of_a_holding_that_never_had_an_approver_names_no_predecessor(
    world: World,
):
    await holding(world)
    await backfilled(world)
    second = await replace(world, holder())
    assert [p["act"] for p in await payloads(world)] == ["credential.recovered"]
    assert "previous_subject" not in await recovered_event(world)
    assert (await authorization(world, second.approver.subject))["principal"] == PRINCIPAL


async def test_a_revoke_records_the_holdings_end_under_the_owner_act(world: World):
    await holding(world)
    designation = await designate(world, holder())
    await revoke(world)
    revoked = (await payloads(world))[-1]
    assert (revoked["act"], revoked["direction"]) == ("role.revoked", "narrowing")
    assert revoked["subject_ref"] == designation.approver.subject
    assert (revoked["role"], revoked["authority"]) == (HOLDER_ROLE, "owner_act")


async def test_a_revoke_after_containment_retired_the_approver_still_records_the_end(
    world: World,
):
    scope = await holding(world)
    designation = await designate(world, holder())
    approver = designation.approver.subject
    await contained(
        world,
        lambda tx: world.passkeys.retire_in(
            tx, scope=scope, subject=approver, authorized_by=MEMBER.did_aw
        ),
    )
    before = datetime.now(UTC)
    await revoke(world)
    contained_receipt, owner_receipt = (await payloads(world))[-2:]
    assert contained_receipt["authority"] == "team_cert"
    assert (owner_receipt["act"], owner_receipt["authority"]) == ("role.revoked", "owner_act")
    assert owner_receipt["subject_ref"] == approver
    occurred = await world.db.fetch_value(
        "SELECT occurred_at FROM {{tables.credential_narrowing_authority}}"
        " WHERE authority='owner_act'"
    )
    assert occurred >= before


async def test_a_second_revoke_of_an_ended_holding_refuses_and_records_nothing(world: World):
    await holding(world)
    await designate(world, holder())
    await revoke(world)
    recorded = await payloads(world)
    with pytest.raises(DesignationRefused):
        await revoke(world)
    assert await payloads(world) == recorded


async def test_a_holding_that_never_had_an_approver_is_revoked_under_its_principal(
    world: World,
):
    # No authorization is made up for the receipt.
    await holding(world)
    await backfilled(world)
    await revoke(world)
    [revoked] = await payloads(world)
    assert (revoked["act"], revoked["subject_ref"]) == ("role.revoked", PRINCIPAL)
    assert not await world.db.fetch_value(
        "SELECT count(*) FROM {{tables.credential_authorizations}}"
    )


async def test_a_revoke_event_naming_another_holdings_scope_records_nothing(world: World):
    other = await holding(world, OTHER_PRINCIPAL)
    await holding(world)
    for principal in (PRINCIPAL, OTHER_PRINCIPAL):
        await backfilled(world, principal)

    async def misnamed(tx: TransactionManager, act: VerifiedOwnerAct) -> None:
        await end_holding(tx, **key(OTHER_PRINCIPAL))
        await world.recorder.emit(retired_event(act, other, OTHER_PRINCIPAL), tx)

    with pytest.raises(GovernanceUnavailable):
        await owner_act(world, "human-role.revoke", subject(None), misnamed)
    assert await payloads(world) == []


async def test_a_revoke_event_for_a_holding_ended_earlier_records_nothing(world: World):
    # The holding ended in an earlier transaction; a fresh consumed revoke act
    # cannot record its end again.
    scope = await holding(world)
    await backfilled(world)
    async with world.db.transaction() as tx:
        await end_holding(tx, **key(PRINCIPAL))

    async def late(tx: TransactionManager, act: VerifiedOwnerAct) -> None:
        await world.recorder.emit(retired_event(act, scope, PRINCIPAL), tx)

    with pytest.raises(GovernanceUnavailable):
        await owner_act(world, "human-role.revoke", subject(None), late)
    assert await payloads(world) == []


async def test_containment_revoking_a_holders_key_names_it_by_its_opaque_ref(world: World):
    scope = await holding(world)
    member = holder()
    designation = await designate(world, member)
    approver = designation.approver.subject
    await contained(
        world,
        lambda tx: world.passkeys.revoke_passkey_in(
            tx,
            scope=scope,
            subject=approver,
            credential_id=member.credential.credential_id,
            authorized_by=MEMBER.did_aw,
        ),
    )
    revoked = (await payloads(world))[-1]
    assert (revoked["act"], revoked["resource_type"]) == ("credential.revoked", "passkey")
    assert revoked["resource_ref"] == (await authorization(world, approver))["credential_ref"]
    assert revoked["resource_ref"] != member.credential.sha256


async def test_a_human_role_act_for_a_contact_role_takes_no_effect(world: World):
    await holding(world, role=ROLE)
    with pytest.raises(GovernanceUnavailable):
        await designate(world, holder(), role=ROLE)
    assert await payloads(world) == []
    assert not await world.db.fetch_value("SELECT count(*) FROM {{tables.passkey_approvers}}")


async def test_a_contact_act_for_a_holder_role_takes_no_effect(world: World):
    from aweb_naapp_testing.owner_acts import designation_subject

    scope = await bind(world, role=HOLDER_ROLE)

    async def effect(tx: TransactionManager, act: VerifiedOwnerAct):
        return await world.passkeys.designate(tx, scope=scope, contact=NOTICE, evidence=act)

    with pytest.raises(GovernanceUnavailable):
        await owner_act(world, "app-role.designate", designation_subject(scope, NOTICE), effect)
    assert await payloads(world) == []


@pytest.mark.parametrize(
    "columns",
    [
        # Both models at once.
        {
            "contact_sha256": "c",
            "principal": PRINCIPAL,
            "credential_sha256": "k",
            "credential_ref": "key_a",
        },
        # A holder without its key reference.
        {"principal": PRINCIPAL, "credential_sha256": "k"},
        # Neither model.
        {},
        # A contact row carrying a holder's key reference.
        {"contact_sha256": "c", "credential_ref": "key_b"},
    ],
)
async def test_an_authorization_is_exactly_one_model(world: World, columns: dict[str, str]):
    names = ", ".join(columns)
    values = ", ".join(f"${i}" for i in range(9, 9 + len(columns)))
    with pytest.raises(QueryError) as refused:
        await world.db.execute(
            "INSERT INTO {{tables.credential_authorizations}} "
            "(subject,scope,app_id,team_id,installation_id,generation,role,effective_at,"
            f"authority,commitment,signing,signature,created_at{', ' + names if names else ''}) "
            f"VALUES($1,$2,$3,$4,$5,1,$6,$7,'owner_act',$8,'\\x00','s',$7{', ' + values if values else ''})",
            "subject-1",
            "scope-1",
            APP_ID,
            TEAM_ID,
            INSTALLATION_ID,
            HOLDER_ROLE,
            datetime.now(UTC),
            "commitment",
            *columns.values(),
        )
    assert isinstance(refused.value.__context__, asyncpg.CheckViolationError)


async def test_a_revoke_event_under_a_replacement_act_records_nothing(world: World):
    # The act the event claims is the signed act's own kind, not its label.
    scope = await holding(world)
    await backfilled(world)

    async def relabelled(tx: TransactionManager, act: VerifiedOwnerAct) -> None:
        await end_holding(tx, **key())
        await world.recorder.emit(retired_event(act, scope, PRINCIPAL), tx)

    with pytest.raises(GovernanceUnavailable):
        await owner_act(world, "human-credential.replace", subject(holder()), relabelled)
    assert await payloads(world) == []


async def test_a_designation_event_under_a_replacement_act_records_nothing(world: World):
    scope = await holding(world)
    member = holder()
    designation = await designate(world, member)
    recorded = await payloads(world)

    async def relabelled(tx: TransactionManager, act: VerifiedOwnerAct) -> None:
        await world.recorder.emit(
            AuditEvent(
                kind=AuditKind.APPROVER_DESIGNATED,
                actor=str(act.fields["team_key_did"]),
                subject=designation.approver.subject,
                occurred_at=datetime.now(UTC),
                details={
                    "scope": scope,
                    "owner_act_id": f"{act.team_id}:{act.nonce}",
                    "owner_act_kind": "human-role.designate",
                },
            ),
            tx,
        )

    with pytest.raises(GovernanceUnavailable):
        await owner_act(world, "human-credential.replace", subject(member), relabelled)
    assert await payloads(world) == recorded


async def test_a_contact_revoke_of_a_role_now_declared_human_without_its_holding_records_nothing(
    world: World,
):
    # A contact approver retained from before its role was declared with the
    # human-role acts, and not yet backfilled into a holding: no contact act
    # revokes it, and no human-role act can either until the holding exists.
    scope = await bind(world)
    await designate_contact(world, scope)
    await enrol(world)
    for table in ("example_bindings", "credential_authorizations"):
        await world.db.execute(
            f"UPDATE {{{{tables.{table}}}}} SET role=$1 WHERE scope=$2", HOLDER_ROLE, scope
        )
    approver = await world.db.fetch_value(
        "SELECT subject FROM {{tables.passkey_approvers}} WHERE scope=$1", scope
    )
    recorded = await payloads(world)

    async def effect(tx: TransactionManager, act: VerifiedOwnerAct) -> None:
        await world.passkeys.retire(tx, scope=scope, evidence=act)

    with pytest.raises(GovernanceUnavailable):
        await owner_act(world, "app-role.revoke", revocation_subject(scope, approver), effect)
    assert await payloads(world) == recorded


async def test_a_revoke_event_for_a_holding_held_again_in_its_transaction_records_nothing(
    world: World,
):
    # The holding ended in this transaction, then its role was assigned again:
    # it is held now, so no end of it is recorded.
    scope = await holding(world)
    await backfilled(world)

    async def reassigned(tx: TransactionManager, act: VerifiedOwnerAct) -> None:
        await end_holding(tx, **key())
        await assign(tx, PrincipalKey(TEAM_ID, PRINCIPAL), HOLDER_ROLE)
        await world.recorder.emit(retired_event(act, scope, PRINCIPAL), tx)

    with pytest.raises(GovernanceUnavailable):
        await owner_act(world, "human-role.revoke", subject(None), reassigned)
    assert await payloads(world) == []
