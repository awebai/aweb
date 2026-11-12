"""Lifecycle deletion requires fresh statements after draining real B3 writers."""

import pytest

from aweb_naapp.console import apply_console_migrations
from aweb_naapp.runtime.passkeys import RetiringInstallation, retire_subjects
from tests.runtime.approvals.support import SCOPE
from tests.runtime.approvals.test_passkeys import enrol
from tests.runtime.approvals.test_passkeys import pw as pw

INSTALLATION = RetiringInstallation(
    app_id="fixture", team_id="fixture-team", installation_id="fixture-installation"
)


@pytest.mark.parametrize("isolation", ["REPEATABLE READ", "SERIALIZABLE"])
async def test_retirement_refuses_an_existing_non_read_committed_snapshot(pw, isolation):
    await enrol(pw)
    db = pw.passkeys.db
    await apply_console_migrations(db)
    async with db.transaction() as tx:
        await tx.execute(f"SET TRANSACTION ISOLATION LEVEL {isolation}")
        assert await tx.fetch_value("SELECT count(*) FROM {{tables.passkey_credentials}}") == 1
        with pytest.raises(ValueError):
            await retire_subjects(tx, installation=INSTALLATION, scopes={SCOPE})
        assert await tx.fetch_value("SHOW transaction_isolation") == isolation.lower()
        assert await tx.fetch_value("SELECT count(*) FROM {{tables.passkey_credentials}}") == 1
        assert not await tx.fetch_value(
            "SELECT EXISTS(SELECT 1 FROM {{tables.passkey_approvers}} WHERE superseded_at IS NOT NULL)"
        )


async def test_retirement_refuses_a_transaction_that_has_ended(pw):
    db = pw.passkeys.db
    async with db.transaction() as tx:
        pass
    with pytest.raises(ValueError):
        await retire_subjects(tx, installation=INSTALLATION, scopes={SCOPE})


async def test_read_committed_retirement_returns_scoped_destruction_counts(pw):
    await enrol(pw)
    db = pw.passkeys.db
    await apply_console_migrations(db)
    async with db.transaction() as tx:
        retired = await retire_subjects(tx, installation=INSTALLATION, scopes={SCOPE})
        assert retired.installation == INSTALLATION
        assert retired.destroyed["passkey_credentials"] == 1
        assert await tx.fetch_value("SELECT count(*) FROM {{tables.passkey_credentials}}") == 0
        assert (
            await tx.fetch_value(
                "SELECT count(*) FROM {{tables.passkey_approvers}} WHERE superseded_at IS NOT NULL"
            )
            == 1
        )


async def test_empty_scope_collection_does_not_destroy_unselected_material(pw):
    await enrol(pw)
    db = pw.passkeys.db
    await apply_console_migrations(db)
    async with db.transaction() as tx:
        retired = await retire_subjects(tx, installation=INSTALLATION, scopes=set())
        assert all(count == 0 for count in retired.destroyed.values())
        assert await tx.fetch_value("SELECT count(*) FROM {{tables.passkey_credentials}}") == 1
