# ruff: noqa: F811 -- imported pre-cutover component fixtures.
"""16.43a upgrades populated legacy owners; this is component evidence only.

Legacy state is checked-in data captured through the genuine pre-cutover path.
No test inserts a new generic holding or treats a login as a holding writer.
"""

from copy import deepcopy

import asyncpg
import pytest
from aweb_naapp.roles import PrincipalKey
from aweb_naapp.runtime.human_roles import HumanRoleHoldings
from aweb_naapp.runtime.installation import InstallationFence
from aweb_naapp.runtime.passkeys import EnrolmentRefused
from aweb_naapp_testing.owner_acts import APP_ID, INSTALLATION_ID
from aweb_naapp_testing.webauthn import SoftAuthenticator
from pgdbm.errors import MigrationError

from aweb_secrets.owners import (
    OWNER_ROLE,
    OwnerRequired,
    apply_owner_migrations,
    hold_owner,
    record_owner,
)
from tests.owner_history import load_owner_history
from tests.test_change_sets import Installations
from tests.test_owner_bootstrap import TEAM, _subject
from tests.test_owner_bootstrap import world as bootstrap_world  # noqa: F401
from tests.test_owner_directory import _policy

ALICE = PrincipalKey(TEAM, "did:aw:jPUMBAvNeJo8USHNtJ81Wm7cqnk")
BOB = PrincipalKey(TEAM, "did:aw:2Uq51iFVLnqmgbVY3vLZtMD5PR87")

pytestmark = pytest.mark.parametrize("bootstrap_world", [{"owner_history": True}], indirect=True)


async def authority_snapshot(db):
    tables = (
        "owner_principals",
        "role_assignments",
        "role_holdings",
        "passkey_approvers",
        "passkey_credentials",
        "passkey_enrolments",
        "owner_act_nonces",
    )
    return {
        table: [dict(row) for row in await db.fetch_all(f"SELECT * FROM {{{{tables.{table}}}}}")]
        for table in tables
    }


async def admitted_owner_installation(db):
    installations = Installations(team_id=TEAM, app_id=APP_ID)
    fence = InstallationFence(db, app_id=installations.app_id, grants=installations)
    async with db.transaction() as tx:
        return await fence.admit(tx, installations.grant)


async def test_populated_upgrade_preserves_scopes_stamps_subjects_and_credentials(bootstrap_world):
    w = bootstrap_world
    history = await load_owner_history(w)
    scopes = [r["scope"] for r in history["tables"]["owner_principals"]]
    before = await authority_snapshot(w.db)
    assert before["role_holdings"] == []
    await apply_owner_migrations(w.db)
    assert (
        await w.db.fetch_value(
            "SELECT count(*) FROM {{tables.role_holdings}} WHERE role=$1", OWNER_ROLE
        )
        == 2
    )
    after = await authority_snapshot(w.db)
    assert {k: v for k, v in after.items() if k != "role_holdings"} == {
        k: v for k, v in before.items() if k != "role_holdings"
    }
    assert len(after["role_holdings"]) == len(scopes)
    bindings = {row["b3_scope"]: row for row in after["role_holdings"]}
    stamps = {row["principal_did"]: row["assigned_at"] for row in before["role_assignments"]}
    subjects = {row["scope"]: row["subject"] for row in before["passkey_approvers"]}
    admitted = await admitted_owner_installation(w.db)
    holdings = HumanRoleHoldings(roles=frozenset({OWNER_ROLE}), passkeys=w.passkeys)
    for principal, scope in zip((ALICE, BOB), scopes, strict=True):
        assert bindings[scope] == {
            "b3_scope": scope,
            "installation_id": INSTALLATION_ID,
            "team_id": TEAM,
            "role": OWNER_ROLE,
            "principal_did": principal.principal_did,
            "certificate": None,
            "ended_in": None,
        }
        async with w.db.transaction() as tx:
            held = await holdings.hold_holding(
                tx, installation=admitted, role=OWNER_ROLE, principal=principal.principal_did
            )
            assert held is not None
            assert (held.b3_scope, held.subject, held.held_since, held.certificate) == (
                scope,
                subjects[scope],
                stamps[principal.principal_did],
                None,
            )
        # The migration neither replaces the passkey nor issues a new subject.
        login = await w.passkeys.verify_login(scope, history["login_assertions"][scope])
        assert login.subject == subjects[scope]


async def test_one_did_key_owner_refuses_the_whole_upgrade_atomically(bootstrap_world):
    w = bootstrap_world
    await load_owner_history(w, mixed_key=True)
    before = await authority_snapshot(w.db)
    with pytest.raises(MigrationError):
        await apply_owner_migrations(w.db)
    assert await authority_snapshot(w.db) == before


async def test_one_inconsistent_scope_refuses_the_whole_upgrade_atomically(bootstrap_world):
    w = bootstrap_world
    await load_owner_history(w)
    await w.db.execute(
        "UPDATE {{tables.owner_principals}} SET scope=$1 WHERE principal_did=$2",
        "secrets.owner." + "0" * 40,
        ALICE.principal_did,
    )
    before = await authority_snapshot(w.db)
    with pytest.raises(MigrationError):
        await apply_owner_migrations(w.db)
    assert await authority_snapshot(w.db) == before


async def test_directory_uses_the_generic_holding_for_exclusion_and_withdrawal(bootstrap_world):
    w = bootstrap_world
    history = await load_owner_history(w)
    alice, bob = [r["scope"] for r in history["tables"]["owner_principals"]]
    await apply_owner_migrations(w.db)
    policy = _policy(alice, allow_requester_approval=False)
    for drafter in (
        {"via": "team_auth", "principal": ALICE.principal_did},
        {"via": "console", "scope": alice},
    ):
        assert (
            await w.directory.candidates(
                policy, {"type": "aweb.secrets.change", "drafter": drafter}
            )
            == []
        )
    async with w.db.transaction() as tx:
        # Removing the association grants nothing. A remaining bare role and
        # legacy history must not substitute for the missing generic record.
        await tx.execute("DELETE FROM {{tables.role_holdings}} WHERE b3_scope=$1", alice)
        assert await w.directory.owner_of(tx, alice) is None
        assert await w.directory.enrolled_owners(
            tx, installation_id=INSTALLATION_ID, team_id=TEAM
        ) == [BOB]
    assert await w.directory.owner_of(w.db, bob) == BOB
    # The old mapping remains history and cannot restore authority.
    assert (
        await w.db.fetch_value(
            "SELECT principal_did FROM {{tables.owner_principals}} WHERE scope=$1", alice
        )
        == ALICE.principal_did
    )
    assert not await w.directory.candidates(_policy(alice), {})


@pytest.mark.parametrize("existing", [False, True], ids=["new-owner", "recovery"])
async def test_legacy_entry_refuses_before_any_binding_nonce_or_delivery(bootstrap_world, existing):
    w = bootstrap_world
    await load_owner_history(w)
    principal = ALICE if existing else PrincipalKey(TEAM, "did:aw:3Uq51iFVLnqmgbVY3vLZtMD5PR87")
    await apply_owner_migrations(w.db)
    before = await authority_snapshot(w.db)
    delivered = deepcopy((w.contacts.inbox, w.contacts.notices))
    contact = "new-contact@example.com"
    signing, signature = w.owner.sign(
        "app-credential.recover" if existing else "app-role.designate",
        _subject(principal, contact),
    )
    with pytest.raises(OwnerRequired):
        await w.console.apply_owner_act(
            signing=signing,
            signature=signature,
            admitted=w.admitted,
            principal=principal,
            contact=contact,
        )
    assert await authority_snapshot(w.db) == before
    assert (w.contacts.inbox, w.contacts.notices) == delivered


async def test_login_never_recreates_a_removed_holding(bootstrap_world):
    w = bootstrap_world
    history = await load_owner_history(w)
    await apply_owner_migrations(w.db)
    scope = history["tables"]["owner_principals"][0]["scope"]
    await w.db.execute("DELETE FROM {{tables.role_holdings}} WHERE b3_scope=$1", scope)
    before = await authority_snapshot(w.db)
    await w.passkeys.verify_login(scope, history["login_assertions"][scope])
    assert await w.directory.owner_of(w.db, scope) is None
    assert (
        await w.db.fetch_value("SELECT 1 FROM {{tables.role_holdings}} WHERE b3_scope=$1", scope)
        is None
    )
    assert await w.db.fetch_all("SELECT * FROM {{tables.owner_principals}}")
    # The B3 assertion spends its own challenge/counter but writes no holding.
    assert before["role_holdings"] == (await authority_snapshot(w.db))["role_holdings"]


async def test_the_legacy_mapping_writer_is_retired_for_every_scope(bootstrap_world):
    w = bootstrap_world
    await load_owner_history(w)
    await apply_owner_migrations(w.db)
    before = await authority_snapshot(w.db)
    async with w.db.transaction() as tx:
        with pytest.raises(OwnerRequired):
            await record_owner(tx, installation_id=INSTALLATION_ID, principal=ALICE)
    assert await authority_snapshot(w.db) == before


async def test_owner_hold_retains_both_shared_rows(bootstrap_world):
    w = bootstrap_world
    history = await load_owner_history(w)
    await apply_owner_migrations(w.db)
    scope = history["tables"]["owner_principals"][0]["scope"]
    probes = (
        (
            "SELECT principal_did FROM {{tables.role_assignments}} WHERE team_id=$1 AND role=$2 AND principal_did=$3 FOR UPDATE NOWAIT",
            (TEAM, OWNER_ROLE, ALICE.principal_did),
        ),
        (
            "SELECT b3_scope FROM {{tables.role_holdings}} WHERE b3_scope=$1 FOR UPDATE NOWAIT",
            (scope,),
        ),
    )
    async with w.db.transaction() as tx:
        await w.console.fence.check(tx, w.admitted)
        assert await hold_owner(tx, ALICE, installation_id=INSTALLATION_ID)
        for sql, args in probes:
            with pytest.raises(asyncpg.LockNotAvailableError):
                async with w.db.transaction() as observer:
                    await observer.fetch_value(sql, *args)
    for sql, args in probes:
        async with w.db.transaction() as observer:
            assert await observer.fetch_value(sql, *args) is not None


async def test_an_owner_enrolment_link_issued_before_cutover_enrols_nothing_after_it(
    bootstrap_world,
):
    w = bootstrap_world
    history = await load_owner_history(w)
    scope = history["tables"]["owner_principals"][0]["scope"]
    subject = history["tables"]["passkey_approvers"][0]["subject"]
    # Fork captured historical data to a retired-key owner. The shared B3
    # reissue API creates a real pending link; no owner or holding is written.
    await w.db.execute(
        "UPDATE {{tables.passkey_credentials}} SET revoked_at=clock_timestamp() WHERE subject=$1",
        subject,
    )
    async with w.db.transaction() as tx:
        await w.console.fence.check(tx, w.admitted)
        designation = await w.passkeys.reissue_enrolment(tx, scope=scope)
    await w.passkeys.deliver(designation)
    token = designation.link_token
    assert token
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.role_holdings}}") == 0
    # Even a valid registration already answering real pre-cutover options
    # cannot cross the migration's contact-to-human boundary.
    device = SoftAuthenticator(w.passkeys.rp.origin)
    credential = device.create(await w.passkeys.enrolment_options(token))
    spent_before = await w.db.fetch_value(
        "SELECT count(*) FROM {{tables.passkey_challenges}}"
        " WHERE subject=$1 AND purpose='enrolment' AND used_at IS NOT NULL",
        subject,
    )
    await apply_owner_migrations(w.db)
    prepared = await w.credential_audit.prepare_enrolment(token)
    before = await authority_snapshot(w.db)
    retained = {
        table: [dict(row) for row in await w.db.fetch_all("SELECT * FROM {{tables." + table + "}}")]
        for table in ("credential_completion_links", "credential_audit_events", "outbox_events")
    }
    with w.credential_audit.prepared(prepared), pytest.raises(EnrolmentRefused):
        await w.passkeys.complete_enrolment(token, credential, fence=prepared)
    assert await authority_snapshot(w.db) == before
    assert {
        table: [dict(row) for row in await w.db.fetch_all("SELECT * FROM {{tables." + table + "}}")]
        for table in retained
    } == retained
    assert (
        await w.db.fetch_value(
            "SELECT count(*) FROM {{tables.passkey_credentials}} WHERE subject=$1 AND revoked_at IS NULL",
            subject,
        )
        == 0
    )
    pending = await w.db.fetch_one(
        "SELECT used_at,revoked_at,expires_at>clock_timestamp() AS unexpired"
        " FROM {{tables.passkey_enrolments}} WHERE subject=$1 AND used_at IS NULL AND revoked_at IS NULL",
        subject,
    )
    assert pending is not None and pending["unexpired"]
    # Assertion spending is separate from the refused enrolment effect.
    assert (
        await w.db.fetch_value(
            "SELECT count(*) FROM {{tables.passkey_challenges}}"
            " WHERE subject=$1 AND purpose='enrolment' AND used_at IS NOT NULL",
            subject,
        )
        == spent_before + 1
    )
