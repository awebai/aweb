# ruff: noqa: F811 -- pw is the imported real passkey composition fixture.
"""An app's one read of its human-role holdings (human-role-holders.md, Reading
a holding), over the shared holding store and B3, on real PostgreSQL.

The holding's approver is made through B3's existing designation here; the
human-role writers bind it the same way, to the same scope.
"""

from __future__ import annotations

from dataclasses import replace

from aweb_naapp_testing.owner_acts import INSTALLATION_ID, TEAM_ID
from aweb_naapp_testing.webauthn import SoftAuthenticator

from aweb_naapp.roles import apply_roles_migrations, begin_holding, end_holding, holding_scope
from aweb_naapp.runtime.human_roles import HumanRoleHoldings
from aweb_naapp.runtime.installation import AdmittedInstallation
from tests.runtime.approvals.test_passkeys import (
    ORIGIN,
    PasskeyWorld,
    designate_by_act,
    pw,  # noqa: F401
)

ROLE = "example.reader"
PRINCIPAL = "did:aw:2Wq7mXn4kP9rT1vY5zA8bC3dE6"
CERTIFICATE = b'{"certificate_id":"cert-1"}'
CONTACT = "reader@example.com"
INSTALLATION = AdmittedInstallation(
    team_id=TEAM_ID, app_id="example", installation_id=INSTALLATION_ID, generation=1
)
SCOPE = holding_scope(INSTALLATION_ID, TEAM_ID, ROLE, PRINCIPAL)


async def holdings(pw: PasskeyWorld) -> HumanRoleHoldings:
    await apply_roles_migrations(pw.passkeys.db)
    return HumanRoleHoldings(roles=frozenset({ROLE}), passkeys=pw.passkeys)


async def held(pw: PasskeyWorld) -> None:
    async with pw.passkeys.db.transaction() as tx:
        await begin_holding(
            tx,
            installation_id=INSTALLATION_ID,
            team_id=TEAM_ID,
            role=ROLE,
            principal=PRINCIPAL,
            certificate=CERTIFICATE,
        )


async def enrolled(pw: PasskeyWorld, act: str = "app-role.designate") -> str:
    designation = await designate_by_act(pw, act, CONTACT, SCOPE)
    token = pw.contacts.last(CONTACT)
    device = SoftAuthenticator(ORIGIN)
    credential = device.create(await pw.passkeys.enrolment_options(token))
    approver = await pw.passkeys.complete_enrolment(token, credential)
    if designation.effective_at > pw.clock():
        pw.clock.now = designation.effective_at
    return approver.subject


async def read(store: HumanRoleHoldings, pw: PasskeyWorld, *, role=ROLE, principal=PRINCIPAL):
    async with pw.passkeys.db.transaction() as tx:
        return await store.read_holding(
            tx, installation=INSTALLATION, role=role, principal=principal
        )


async def test_a_holding_reads_with_its_credential_subject_and_certificate(pw: PasskeyWorld):
    store = await holdings(pw)
    await held(pw)
    subject = await enrolled(pw)
    holding = await read(store, pw)
    assert holding is not None
    assert (holding.installation_id, holding.team_id, holding.role, holding.principal) == (
        INSTALLATION_ID,
        TEAM_ID,
        ROLE,
        PRINCIPAL,
    )
    assert (holding.b3_scope, holding.subject, holding.certificate) == (SCOPE, subject, CERTIFICATE)


async def test_held_and_hold_read_the_same_holding(pw: PasskeyWorld):
    store = await holdings(pw)
    await held(pw)
    await enrolled(pw)
    async with pw.passkeys.db.transaction() as tx:
        holding = await store.hold_holding(
            tx, installation=INSTALLATION, role=ROLE, principal=PRINCIPAL
        )
    assert holding == await read(store, pw)


async def test_a_holding_with_no_usable_credential_reads_with_no_subject(pw: PasskeyWorld):
    store = await holdings(pw)
    await held(pw)
    subject = await enrolled(pw)
    async with pw.passkeys.db.transaction() as tx:
        await pw.passkeys.retire_in(tx, scope=SCOPE, subject=subject, authorized_by="test")
    holding = await read(store, pw)
    assert holding is not None and holding.subject is None


async def test_a_replacement_in_its_cooling_off_reads_with_no_subject(pw: PasskeyWorld):
    store = await holdings(pw)
    await held(pw)
    await enrolled(pw)
    await designate_by_act(pw, "app-credential.recover", CONTACT, SCOPE)
    holding = await read(store, pw)
    assert holding is not None and holding.subject is None


async def test_no_holding_reads_as_none_even_with_an_approver(pw: PasskeyWorld):
    store = await holdings(pw)
    await enrolled(pw)
    assert await read(store, pw) is None
    await held(pw)
    async with pw.passkeys.db.transaction() as tx:
        await end_holding(
            tx, installation_id=INSTALLATION_ID, team_id=TEAM_ID, role=ROLE, principal=PRINCIPAL
        )
    assert await read(store, pw) is None


async def test_an_undeclared_role_or_a_non_did_aw_principal_holds_nothing(pw: PasskeyWorld):
    store = await holdings(pw)
    await held(pw)
    await enrolled(pw)
    assert await read(store, pw, role="example.other") is None
    assert await read(store, pw, principal="did:key:z6MkfirstKey") is None


async def test_a_refresh_retains_a_new_certificate_for_the_same_holding(pw: PasskeyWorld):
    store = await holdings(pw)
    await held(pw)
    await enrolled(pw)
    holding = await read(store, pw)
    assert holding is not None
    async with pw.passkeys.db.transaction() as tx:
        assert await store.refresh_holding_certificate(
            tx, holding=holding, certificate=b'{"certificate_id":"cert-2"}'
        )
    assert (await read(store, pw)).certificate == b'{"certificate_id":"cert-2"}'


async def read_scope(
    store: HumanRoleHoldings, pw: PasskeyWorld, scope=SCOPE, installation=INSTALLATION
):
    async with pw.passkeys.db.transaction() as tx:
        return await store.read_holding_of_scope(tx, installation=installation, b3_scope=scope)


async def test_a_holding_reads_the_same_by_its_scope(pw: PasskeyWorld):
    store = await holdings(pw)
    await held(pw)
    await enrolled(pw)
    holding = await read_scope(store, pw)
    assert holding is not None and holding.subject is not None
    assert holding == await read(store, pw)


async def test_an_ended_holding_reads_as_none_by_its_scope(pw: PasskeyWorld):
    store = await holdings(pw)
    await held(pw)
    await enrolled(pw)
    async with pw.passkeys.db.transaction() as tx:
        await end_holding(
            tx, installation_id=INSTALLATION_ID, team_id=TEAM_ID, role=ROLE, principal=PRINCIPAL
        )
    assert await read_scope(store, pw) is None


async def test_a_scope_reads_nothing_for_another_installation_or_team(pw: PasskeyWorld):
    store = await holdings(pw)
    await held(pw)
    await enrolled(pw)
    for other in (
        replace(INSTALLATION, installation_id="6f9619ff-8b86-4011-b42d-00c04fc964ff"),
        replace(INSTALLATION, team_id="aweb:other.example.com"),
    ):
        assert await read_scope(store, pw, installation=other) is None


async def test_a_scope_of_an_undeclared_role_holds_nothing(pw: PasskeyWorld):
    other_role = "example.other"
    store = await holdings(pw)
    async with pw.passkeys.db.transaction() as tx:
        begun = await begin_holding(
            tx,
            installation_id=INSTALLATION_ID,
            team_id=TEAM_ID,
            role=other_role,
            principal=PRINCIPAL,
            certificate=CERTIFICATE,
        )
    assert begun is not None
    assert await read_scope(store, pw, scope=begun.b3_scope) is None
