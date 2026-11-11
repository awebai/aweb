"""The shared human-role effect behind the owner-act delivery route
(owner-act-delivery.md, Effects), on real PostgreSQL with a real AWID registry,
a real human member, real owner acts, the real recorder and fence, and a
software passkey. Each delivery runs as the route runs it: the act is
authenticated, the effect prepared outside every lock, the act consumed and
the effect applied in one fenced transaction, checked fresh before commit, and
its notices sent after it."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import Any

import pytest
from aweb_naapp_testing import Member
from aweb_naapp_testing.human_members import HumanMember, registered_human
from aweb_naapp_testing.owner_acts import APP_ID, INSTALLATION_ID, TEAM_ID
from pgdbm.core import TransactionManager

from aweb_naapp.hooks.owner_act_nonces import Refused
from aweb_naapp.roles import holding_scope
from aweb_naapp.runtime.human_role_acts import HumanRoleActs
from aweb_naapp.runtime.human_roles import HumanRoleHoldings
from aweb_naapp.runtime.owner_act_delivery import (
    OwnerActDelivery,
    OwnerActDeliveryRefused,
    OwnerActEffectResult,
)
from aweb_naapp.runtime.passkeys import NoticeKind, contact_sha256, prepare_retirement
from tests.runtime.approvals.test_human_role_holders import Holder, holder
from tests.runtime.credential_audit.support import (
    HOLDER_ROLE,
    ROLE,
    World,
    bind,
    events,
)
from tests.runtime.credential_audit.support import world as world_fixture  # noqa: F401
from tests.runtime.test_runtime_team_services import _runtime

DESIGNATE = "human-role.designate"
REPLACE = "human-credential.replace"
REVOKE = "human-role.revoke"
NOTICE = "holder@example.com"


@dataclass
class Effects:
    world: World
    human: HumanMember
    runtime: Any
    holdings: HumanRoleHoldings
    applied: list[tuple[int, OwnerActEffectResult]]
    acts: HumanRoleActs

    @property
    def principal(self) -> str:
        return self.human.principal

    @property
    def certificate(self) -> bytes:
        return json.dumps(self.human.member.certificate()).encode()

    def scope(self, role: str = HOLDER_ROLE) -> str:
        return holding_scope(INSTALLATION_ID, TEAM_ID, role, self.principal)


def subject(
    principal: str, member: Holder | None, *, role: str = HOLDER_ROLE, notice: str | None = None
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


def delivery(
    fx: Effects,
    act: str,
    member: Holder | None,
    *,
    role: str = HOLDER_ROLE,
    notice: str | None = None,
    certificate: bytes | None = None,
    signed: dict[str, Any] | None = None,
) -> OwnerActDelivery:
    """The delivery the route parses for the owner's signed act: by default it
    signs exactly what it carries."""
    carried = subject(fx.principal, member, role=role, notice=notice)
    signing, signature = fx.world.owner.sign(act, signed or carried)
    return OwnerActDelivery(
        signing=signing,
        signature=signature,
        act=act,
        team_id=TEAM_ID,
        subject=carried,
        credential=None if member is None else member.credential,
        notice_contact=notice,
        certificate=(certificate or fx.certificate) if member is not None else None,
    )


async def deliver(fx: Effects, sent: OwnerActDelivery) -> OwnerActEffectResult:
    """Run one delivery as the route does."""
    world = fx.world
    act = await world.owner.verifier.prepare(sent.signing, sent.signature, team_id=sent.team_id)
    prepared = await fx.acts.prepare(installation=world.admitted, delivery=sent)
    async with world.db.transaction() as tx:
        await world.fence.check(tx, world.admitted)
        verified = await world.owner.verifier.consume_in(
            tx, act, expected_subject=prepared.expected_subject
        )
        result = await prepared.apply(tx, installation=world.admitted, act=verified)
        await world.fence.check(tx, world.admitted)
        prepared.require_fresh()
    await prepared.after_commit(result)
    return result


async def refused(fx: Effects, sent: OwnerActDelivery) -> str:
    with pytest.raises(OwnerActDeliveryRefused) as refusal:
        await deliver(fx, sent)
    return refusal.value.code


def effects(
    world: World,
    human: HumanMember,
    runtime: Any,
    applied: list[tuple[int, OwnerActEffectResult]],
    **options: Any,
) -> HumanRoleActs:
    """The app's effect for its two declared human roles, with an app hook that
    records the transaction it runs in."""

    async def hook(tx: TransactionManager, result: OwnerActEffectResult) -> None:
        applied.append((await tx.fetch_value("SELECT txid_current()"), result))

    return HumanRoleActs(
        roles=frozenset({HOLDER_ROLE}),
        passkeys=world.passkeys,
        recorder=world.recorder,
        check_member=partial(runtime.check_human_role_member, identity_client=human.client),
        on_applied=hook,
        **options,
    )


@pytest.fixture
async def fx(world: World, tmp_path) -> AsyncIterator[Effects]:
    member = Member(team_id=TEAM_ID, team_key=world.owner.team_key, certificate_id="cert-holder")
    async with registered_human(world.registry, member) as human:
        holdings = HumanRoleHoldings(roles=frozenset({HOLDER_ROLE}), passkeys=world.passkeys)
        runtime = _runtime(
            tmp_path, registry=world.registry, database_url=world.db.config.get_dsn()
        )
        applied: list[tuple[int, OwnerActEffectResult]] = []
        acts = effects(world, human, runtime, applied)
        state = Effects(world, human, runtime, holdings, applied, acts)
        await bind(world, state.scope(), HOLDER_ROLE)
        yield state


async def read(fx: Effects, role: str = HOLDER_ROLE):
    async with fx.world.db.transaction() as tx:
        return await fx.holdings.read_holding(
            tx, installation=fx.world.admitted, role=role, principal=fx.principal
        )


async def payloads(fx: Effects) -> list[dict]:
    return [fields["payload"] for _, fields in await events(fx.world)]


async def consumed(fx: Effects, sent: OwnerActDelivery) -> bool:
    nonce = json.loads(sent.signing.split(b"\n", 1)[1])["nonce"]
    return bool(
        await fx.world.db.fetch_value(
            "SELECT 1 FROM {{tables.owner_act_nonces}} WHERE nonce=$1", nonce
        )
    )


async def live_credentials(fx: Effects, scope: str) -> int:
    return await fx.world.db.fetch_value(
        "SELECT count(*) FROM {{tables.passkey_credentials}} c"
        " JOIN {{tables.passkey_approvers}} a USING(subject) WHERE a.scope=$1",
        scope,
    )


async def test_a_designation_holds_the_role_with_the_exact_certificate_and_records_it(fx):
    member = holder()
    result = await deliver(fx, delivery(fx, DESIGNATE, member))
    held = await read(fx)
    assert held is not None and held.subject is not None
    assert held.certificate == fx.certificate
    assert (result.act, result.role, result.principal) == (DESIGNATE, HOLDER_ROLE, fx.principal)
    [designated] = await payloads(fx)
    assert (designated["act"], designated["authority"]) == ("role.designated", "owner_act")
    assert designated["subject_ref"] == held.subject


async def test_the_app_hook_runs_in_the_effect_transaction(fx):
    result = await deliver(fx, delivery(fx, DESIGNATE, holder()))
    [(txid, hooked)] = fx.applied
    assert hooked == result
    # The governance event was enqueued in the same transaction.
    assert [handed for handed, _ in fx.world.handed] == [txid]


async def test_a_role_the_app_does_not_declare_is_refused_before_any_effect(fx):
    sent = delivery(fx, DESIGNATE, holder(), role=ROLE)
    assert await refused(fx, sent) == "owner_required"
    assert not await consumed(fx, sent)


async def test_a_delivery_for_another_team_is_refused(fx):
    sent = replace(delivery(fx, DESIGNATE, holder()), team_id="other:example.com")
    with pytest.raises(OwnerActDeliveryRefused) as refusal:
        await fx.acts.prepare(installation=fx.world.admitted, delivery=sent)
    assert refusal.value.code == "owner_required"


async def test_a_certificate_of_another_principal_is_refused(fx):
    other = Member(team_id=TEAM_ID, team_key=fx.world.owner.team_key, certificate_id="cert-2")
    other.extra_cert_fields = {"member_did_aw": "did:aw:3Xr8nYo5mQ1sU2wZ6aB9cD4eF7"}
    certificate = json.dumps(other.certificate()).encode()
    assert await refused(fx, delivery(fx, DESIGNATE, holder(), certificate=certificate)) == (
        "owner_required"
    )
    assert await read(fx) is None


async def test_a_principal_who_left_the_team_is_not_designated(fx):
    await fx.world.registry.revoke(fx.human.member.certificate_id)
    assert await refused(fx, delivery(fx, DESIGNATE, holder())) == "principal_not_member"
    assert await read(fx) is None


async def test_the_act_binds_the_credential_the_delivery_carries(fx):
    sent = delivery(fx, DESIGNATE, holder(), signed=subject(fx.principal, holder()))
    with pytest.raises(Refused):
        await deliver(fx, sent)
    assert await read(fx) is None
    assert not await consumed(fx, sent)


async def test_a_role_whose_holders_take_notices_needs_a_notice_contact(fx):
    noticed = replace(
        fx,
        acts=effects(
            fx.world, fx.human, fx.runtime, fx.applied, notice_roles=frozenset({HOLDER_ROLE})
        ),
    )
    sent = delivery(fx, DESIGNATE, holder())
    assert await refused(noticed, sent) == "owner_required"
    assert not await consumed(fx, sent)
    await deliver(noticed, delivery(fx, DESIGNATE, holder(), notice=NOTICE))
    assert await read(fx) is not None


async def test_a_designation_of_a_held_role_rolls_back_with_its_nonce(fx):
    await deliver(fx, delivery(fx, DESIGNATE, holder()))
    first = await read(fx)
    again = delivery(fx, DESIGNATE, holder())
    assert await refused(fx, again) == "owner_required"
    assert not await consumed(fx, again)
    assert await read(fx) == first
    assert len(fx.applied) == 1


async def test_a_replacement_keeps_the_holding_and_notifies_after_commit(fx):
    await deliver(fx, delivery(fx, DESIGNATE, holder(), notice=NOTICE))
    before = await read(fx)
    renewed = Member(
        team_id=TEAM_ID,
        team_key=fx.world.owner.team_key,
        member_key=fx.human.member.member_key,
        certificate_id="cert-3",
        extra_cert_fields=dict(fx.human.member.extra_cert_fields),
    )
    await fx.world.registry.add_certificate(renewed.certificate())
    certificate = json.dumps(renewed.certificate()).encode()
    result = await deliver(fx, delivery(fx, REPLACE, holder(), certificate=certificate))
    after = await read(fx)
    assert after is not None and before is not None
    assert after.held_since == before.held_since
    assert after.certificate == certificate
    assert after.subject is None  # the new credential is in its cooling-off
    assert result.effective_at > datetime.now(UTC)
    assert [(contact, notice.kind) for contact, notice in fx.world.inbox.notices] == [
        (NOTICE, NoticeKind.RECOVERY_STARTED)
    ]


async def test_a_replacement_of_a_role_not_held_is_refused(fx):
    assert await refused(fx, delivery(fx, REPLACE, holder())) == "owner_required"
    assert fx.world.inbox.notices == []


async def test_a_revoke_ends_the_holding_and_its_credentials(fx):
    await deliver(fx, delivery(fx, DESIGNATE, holder()))
    await deliver(fx, delivery(fx, REVOKE, None))
    assert await read(fx) is None
    assert await live_credentials(fx, fx.scope()) == 0
    assert (await payloads(fx))[-1]["act"] == "role.revoked"


async def test_a_revoke_reads_no_membership(fx):
    await deliver(fx, delivery(fx, DESIGNATE, holder()))
    await fx.world.registry.revoke(fx.human.member.certificate_id)
    await deliver(fx, delivery(fx, REVOKE, None))
    assert await read(fx) is None


async def test_a_revoke_of_a_role_not_held_is_refused(fx):
    assert await refused(fx, delivery(fx, REVOKE, None)) == "owner_required"


@pytest.mark.parametrize("act", [REPLACE, REVOKE])
async def test_a_retiring_effect_waits_for_the_installations_retirement_gate(fx, act):
    await deliver(fx, delivery(fx, DESIGNATE, holder()))
    sent = delivery(fx, act, holder() if act == REPLACE else None)
    async with fx.world.db.transaction() as gate:
        await prepare_retirement(gate, installation=fx.world.admitted)
        effect = asyncio.create_task(deliver(fx, sent))
        while not await fx.world.db.fetch_value(
            "SELECT 1 FROM pg_stat_activity WHERE datname=current_database()"
            " AND wait_event_type='Lock' AND wait_event='advisory'"
        ):
            assert not effect.done(), effect
            await asyncio.sleep(0.01)
        # Waiting at the gate, the effect has locked no role or holding row.
        assert (
            await fx.world.db.fetch_value(
                "SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid=l.relation"
                " WHERE c.relname IN ('role_holdings','role_assignments') AND l.granted"
                " AND l.mode IN ('RowShareLock','RowExclusiveLock')"
                " AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())"
            )
            == 0
        )
    await effect
    assert (await read(fx) is None) == (act == REVOKE)


async def test_an_act_past_its_validity_is_refused_before_commit(fx):
    later = effects(
        fx.world,
        fx.human,
        fx.runtime,
        fx.applied,
        clock=lambda: datetime.now(UTC) + timedelta(minutes=10),
    )
    sent = delivery(fx, DESIGNATE, holder())
    assert await refused(replace(fx, acts=later), sent) == "owner_required"
    assert not await consumed(fx, sent)
    assert await read(fx) is None


async def test_a_membership_proof_past_its_deadline_is_refused_before_commit(fx, tmp_path):
    runtime = _runtime(
        tmp_path,
        registry=fx.world.registry,
        database_url=fx.world.db.config.get_dsn(),
        auth_cache_ttl_seconds=1,
    )
    acts = effects(fx.world, fx.human, runtime, fx.applied)
    sent = delivery(fx, DESIGNATE, holder())
    act = await fx.world.owner.verifier.prepare(sent.signing, sent.signature, team_id=TEAM_ID)
    prepared = await acts.prepare(installation=fx.world.admitted, delivery=sent)
    await asyncio.sleep(1.1)
    with pytest.raises(OwnerActDeliveryRefused) as refusal:
        async with fx.world.db.transaction() as tx:
            await fx.world.fence.check(tx, fx.world.admitted)
            verified = await fx.world.owner.verifier.consume_in(
                tx, act, expected_subject=prepared.expected_subject
            )
            await prepared.apply(tx, installation=fx.world.admitted, act=verified)
            prepared.require_fresh()
    assert refusal.value.code == "principal_status_unavailable"
    assert await read(fx) is None
    assert not await consumed(fx, sent)


async def test_retiring_the_installation_ends_its_holdings_and_their_credentials(fx):
    await deliver(fx, delivery(fx, DESIGNATE, holder()))
    async with fx.world.db.transaction() as tx:
        retired = await fx.acts.retire(tx, app_id=APP_ID, team_id=TEAM_ID)
    assert [r.installation.installation_id for r in retired] == [INSTALLATION_ID]
    assert await read(fx) is None
    assert await live_credentials(fx, fx.scope()) == 0
    # A new holding of the same principal starts afresh.
    await deliver(fx, delivery(fx, DESIGNATE, holder()))
    assert (await read(fx)) is not None
