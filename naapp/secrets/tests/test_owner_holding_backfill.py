# ruff: noqa: F811 -- imported pre-cutover component fixtures.
"""16.43a upgrades populated legacy owners; this is component evidence only.

Legacy state is created through the pre-cutover owner-act/B3 component path.
No test inserts a new generic holding or treats a login as a holding writer.
"""

from copy import deepcopy

import pytest
from aweb_naapp.roles import PrincipalKey
from aweb_naapp.runtime.human_roles import HumanRoleHoldings
from aweb_naapp.runtime.installation import InstallationFence
from aweb_naapp_testing import did_key
from aweb_naapp_testing.owner_acts import INSTALLATION_ID
from pgdbm.errors import MigrationError

from aweb_secrets.owners import OWNER_ROLE, OwnerRequired, apply_owner_migrations
from tests.test_change_sets import Installations
from tests.test_owner_bootstrap import _apply, _enrol
from tests.test_owner_bootstrap import world as bootstrap_world  # noqa: F401
from tests.test_owner_directory import ALICE, BOB, TEAM, _policy, designate_owner
from tests.test_owner_directory import world as legacy_world  # noqa: F401


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
    installations = Installations()
    fence = InstallationFence(db, app_id=installations.app_id, grants=installations)
    async with db.transaction() as tx:
        return await fence.admit(tx, installations.grant)


async def test_populated_upgrade_preserves_scopes_stamps_subjects_and_credentials(legacy_world):
    w = legacy_world
    scopes = [
        await designate_owner(w, ALICE, "alice@example.com"),
        await designate_owner(w, BOB, "bob@example.com"),
    ]
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
        login = await w.passkeys.verify_login(
            scope, w.devices[scope].get(await w.passkeys.login_options(scope))
        )
        assert login.subject == subjects[scope]


async def test_one_did_key_owner_refuses_the_whole_upgrade_atomically(legacy_world):
    w = legacy_world
    await designate_owner(w, ALICE, "alice@example.com")
    legacy_key = PrincipalKey(TEAM, did_key(w.owner.team_key))
    await designate_owner(w, legacy_key, "legacy@example.com")
    before = await authority_snapshot(w.db)
    with pytest.raises(MigrationError):
        await apply_owner_migrations(w.db)
    assert await authority_snapshot(w.db) == before


async def test_directory_uses_the_generic_holding_for_exclusion_and_withdrawal(legacy_world):
    w = legacy_world
    alice = await designate_owner(w, ALICE, "alice@example.com")
    bob = await designate_owner(w, BOB, "bob@example.com")
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
    if existing:
        await _apply(w, "app-role.designate", ALICE, "alice@example.com")
        await _enrol(w, "alice@example.com")
    await apply_owner_migrations(w.db)
    before = await authority_snapshot(w.db)
    delivered = deepcopy((w.contacts.inbox, w.contacts.notices))
    with pytest.raises(OwnerRequired):
        await _apply(
            w,
            "app-credential.recover" if existing else "app-role.designate",
            ALICE,
            "new-contact@example.com",
        )
    assert await authority_snapshot(w.db) == before
    assert (w.contacts.inbox, w.contacts.notices) == delivered
