"""Canonical owner components and migration fixture setup.

Migration capture is checked-in historical data. Ordinary setup registers a
real human and uses the canonical shared holder writer; it never reopens the
old contact-model owner binding path.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta

import pytest
from aweb_naapp.hooks.owner_act_nonces import apply_owner_act_migrations
from aweb_naapp.roles import apply_roles_migrations, has_role, is_holding_scope
from aweb_naapp.runtime.approvals import (
    ActionPolicy,
    ApprovalRevocation,
    Assurance,
    PgApprovalStore,
)
from aweb_naapp.runtime.installation import (
    InstallationFence,
    InstallationRefused,
    apply_installation_migrations,
)
from aweb_naapp.runtime.passkeys import Passkeys, RelyingParty
from aweb_naapp_testing.owner_acts import (
    APP_ID,
    INSTALLATION_ID,
    TeamOwner,
    team_owner,
)
from awid_service.testing import running_registry
from pgdbm import AsyncMigrationManager

from aweb_secrets.change_policy import apply_change_policy_migrations
from aweb_secrets.change_sets import apply_change_set_migrations
from aweb_secrets.console import OwnerConsole
from aweb_secrets.owners import (
    OWNER_ROLE,
    OwnerDirectory,
    apply_owner_migrations,
    is_owner_scope,
    owner_scope,
)
from aweb_secrets.passkey_context import PasskeyContexts
from aweb_secrets.revisions import apply_revision_migrations
from tests.human_owner import apply_holder, fixture_principal
from tests.test_change_sets import Installations
from tests.test_owner_directory import ORIGIN, Audit, Contacts

TEAM = "demo:example.com"
ALICE = fixture_principal(TEAM, "alice")
BOB = fixture_principal(TEAM, "bob")


class World:
    def __init__(
        self,
        db,
        passkeys,
        owner: TeamOwner,
        contacts: Contacts,
        registry,
        fence,
        admitted,
        credential_audit,
    ) -> None:
        self.registry = registry
        self.db = db
        self.passkeys = passkeys
        self.owner = owner
        self.contacts = contacts
        self.directory = OwnerDirectory(passkeys, db)
        self.admitted = admitted
        self.credential_audit = credential_audit

        async def installation(installation_id, *, team_id: str):
            assert installation_id == admitted.installation_id
            return admitted

        self.console = OwnerConsole(
            db=db,
            passkeys=passkeys,
            credential_audit=credential_audit,
            directory=self.directory,
            fence=fence,
            installation=installation,
        )


@pytest.fixture
async def world(test_db_factory, request) -> AsyncIterator[World]:
    db = await test_db_factory.create_db(suffix="secrets_bootstrap")
    registry_db = await test_db_factory.create_db(suffix="secrets_bootstrap_awid")
    await db.execute(
        "CREATE TABLE {{tables.audit_outbox}} (id SERIAL PRIMARY KEY, kind TEXT, details TEXT)"
    )
    store = PgApprovalStore(db)
    await store.migrate()
    audit = Audit(db)
    contacts = Contacts()
    passkeys = Passkeys(
        db,
        rp=RelyingParty(origin=ORIGIN, name="secrets"),
        delivery=contacts,
        audit=audit,
        retirement=ApprovalRevocation(store, audit),
        enrolment_ttl=timedelta(hours=1),
        challenge_ttl=timedelta(minutes=5),
        owner_scopes=is_owner_scope,
        holding_scopes=is_holding_scope,
        proof_context=PasskeyContexts(app_id=APP_ID),
    )
    await passkeys.migrate()
    from aweb_secrets.app import MIGRATIONS_PATH, MODULE_NAME

    await AsyncMigrationManager(
        db, migrations_path=str(MIGRATIONS_PATH), module_name=MODULE_NAME
    ).apply_pending_migrations()
    await apply_roles_migrations(db)
    await apply_owner_act_migrations(db)
    if getattr(request, "param", {}).get("owner_history"):
        # Migration tests load captured history into the actual old schema.
        from aweb_secrets.owners import MIGRATIONS_MODULE
        from aweb_secrets.owners import MIGRATIONS_PATH as OWNER_MIGRATIONS

        migrations = AsyncMigrationManager(
            db, migrations_path=str(OWNER_MIGRATIONS), module_name=MIGRATIONS_MODULE
        )
        await migrations.ensure_migrations_table()
        original = next(
            m
            for m in await migrations.find_migration_files()
            if m.filename == "001_owner_principals.sql"
        )
        await migrations.apply_migration(original)
    else:
        await apply_owner_migrations(db)
    await apply_change_set_migrations(db)
    await apply_installation_migrations(db)
    await apply_change_policy_migrations(db)
    await apply_revision_migrations(db)
    installations = Installations(team_id=TEAM, app_id=APP_ID)
    fence = InstallationFence(db, app_id=APP_ID, grants=installations)
    await fence.refresh(TEAM)
    async with db.transaction() as tx:
        admitted = await fence.admit(tx, installations.grant)
    async with running_registry(registry_db.config.get_dsn()) as registry:
        from tests.governance import credential_audit

        owner = await team_owner(registry)
        audit = await credential_audit(
            db=db,
            passkeys=passkeys,
            owner=owner,
            fence=fence,
            admitted=admitted,
            origin=ORIGIN,
        )
        yield World(db, passkeys, owner, contacts, registry, fence, admitted, audit)


CHANGE_REQUEST = {"type": "aweb.secrets.change", "drafter": {"via": "console", "scope": "-"}}


async def _approver(world: World, scope: str):
    found = await world.directory.candidates(_policy(scope), CHANGE_REQUEST)
    return found[0] if found else None


def _policy(scope: str, *, allow_requester_approval: bool = True) -> ActionPolicy:
    return ActionPolicy(
        policy_ref="secrets.change",
        version=1,
        min_assurance=Assurance.PASSKEY,
        ttl=timedelta(minutes=15),
        approver_scopes=(scope,),
        allow_requester_approval=allow_requester_approval,
    )


async def test_the_canonical_component_writer_binds_a_human_owner(world: World) -> None:
    await apply_holder(world, "human-role.designate", ALICE, "alice@example.com")
    assert await has_role(world.db, ALICE, OWNER_ROLE)
    scope = owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did)
    approver = await _approver(world, scope)
    assert approver is not None and approver.contact == "alice@example.com"


async def test_the_canonical_component_writer_refuses_a_stale_installation(world: World) -> None:
    await world.db.execute(
        "UPDATE {{tables.installation_fences}}"
        " SET fresh_until = clock_timestamp() - interval '1 second'"
    )
    with pytest.raises(InstallationRefused) as refused:
        await apply_holder(world, "human-role.designate", ALICE, "alice@example.com")
    assert refused.value.code == "authority_unavailable"
    assert not await has_role(world.db, ALICE, OWNER_ROLE)
    assert not await world.db.fetch_value("SELECT count(*) FROM {{tables.owner_act_nonces}}")
    assert world.contacts.inbox == {}
