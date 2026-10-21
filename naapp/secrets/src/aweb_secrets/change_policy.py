"""Each installation's four-eyes setting for change sets (decision 61).

While four eyes is required, the owner who drafted a change set cannot
confirm it. Requiring four eyes narrows, so an owner applies it directly;
relaxing it widens, so it applies only from a confirmed change set, which the
setting in force at its confirmation governs.

Four eyes needs a second owner to confirm anything, so while it is required
the installation keeps at least two enrolled owners: requiring it takes two,
and revoking an owner that would leave fewer is refused. Both paths take the
setting's row lock before counting, and the revocation counts after its own
role delete, so the two can never interleave into four eyes with one owner.
"""

from __future__ import annotations

from pathlib import Path

from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.core import TransactionManager

from aweb_secrets.change import ChangeRefused
from aweb_secrets.owners import OwnerDirectory
from aweb_secrets.revisions import bump_config_revision, config_revision

MIGRATIONS_PATH = Path(__file__).resolve().parent / "change_policy_migrations"
MIGRATIONS_MODULE = "aweb_secrets_change_policy"
MIN_FOUR_EYES_OWNERS = 2


async def apply_change_policy_migrations(db: AsyncDatabaseManager) -> None:
    await AsyncMigrationManager(
        db, migrations_path=str(MIGRATIONS_PATH), module_name=MIGRATIONS_MODULE
    ).apply_pending_migrations()


async def four_eyes(db: AsyncDatabaseManager | TransactionManager, installation_id: str) -> str:
    """The installation's setting: ``required`` or ``not_required``."""
    value = await db.fetch_value(
        "SELECT distinct_approver FROM {{tables.change_set_settings}} WHERE installation_id = $1",
        installation_id,
    )
    return str(value or "not_required")


async def _locked_setting(tx: TransactionManager, installation_id: str) -> str:
    await tx.execute(
        "INSERT INTO {{tables.change_set_settings}} (installation_id) VALUES ($1)"
        " ON CONFLICT (installation_id) DO NOTHING",
        installation_id,
    )
    return str(
        await tx.fetch_value(
            "SELECT distinct_approver FROM {{tables.change_set_settings}}"
            " WHERE installation_id = $1 FOR UPDATE",
            installation_id,
        )
    )


async def _require_owners(
    tx: TransactionManager, *, installation_id: str, team_id: str, directory: OwnerDirectory
) -> None:
    owners = await directory.enrolled_owners(tx, installation_id=installation_id, team_id=team_id)
    if len(owners) < MIN_FOUR_EYES_OWNERS:
        raise ChangeRefused(
            "four eyes needs at least two enrolled owners", code="four_eyes_needs_two_owners"
        )


async def require_four_eyes(
    tx: TransactionManager, *, installation_id: str, team_id: str, directory: OwnerDirectory
) -> None:
    """Require four eyes, as an owner's direct narrowing act. Refused unless
    the installation has at least two enrolled owners."""
    await _locked_setting(tx, installation_id)
    await _require_owners(tx, installation_id=installation_id, team_id=team_id, directory=directory)
    revision = await bump_config_revision(tx, installation_id)
    await tx.execute(
        "UPDATE {{tables.change_set_settings}} SET distinct_approver = 'required',"
        " revision = $2, updated_at = NOW() WHERE installation_id = $1",
        installation_id,
        revision,
    )


async def relax_four_eyes(tx: TransactionManager, *, installation_id: str) -> None:
    """Relax four eyes, as the effect of a confirmed change set, which has
    already claimed the configuration revision in this transaction."""
    await _locked_setting(tx, installation_id)
    await tx.execute(
        "UPDATE {{tables.change_set_settings}} SET distinct_approver = 'not_required',"
        " revision = $2, updated_at = NOW() WHERE installation_id = $1",
        installation_id,
        await config_revision(tx, installation_id),
    )


async def keep_four_eyes_owners(
    tx: TransactionManager, *, installation_id: str, team_id: str, directory: OwnerDirectory
) -> None:
    """Refuse an owner revocation that would leave four eyes with fewer than
    two enrolled owners. Call it after the role delete, in its transaction."""
    if await _locked_setting(tx, installation_id) == "required":
        await _require_owners(
            tx, installation_id=installation_id, team_id=team_id, directory=directory
        )
