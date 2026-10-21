"""Each installation's configuration revision (decision 54).

A change set is drafted against the installation's current revision. It is
confirmed through :func:`claim_config_revision`, which moves the revision on
and refuses unless the draft's revision was the current one, in one atomic
step. Every narrowing act calls :func:`bump_config_revision` inside its own
transaction, so a draft computed before any of them is refused as stale.
"""

from __future__ import annotations

from pathlib import Path

from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.core import TransactionManager

from aweb_secrets.change import ChangeRefused

MIGRATIONS_PATH = Path(__file__).resolve().parent / "revision_migrations"
MIGRATIONS_MODULE = "aweb_secrets_revisions"


async def apply_revision_migrations(db: AsyncDatabaseManager) -> None:
    await AsyncMigrationManager(
        db, migrations_path=str(MIGRATIONS_PATH), module_name=MIGRATIONS_MODULE
    ).apply_pending_migrations()


async def config_revision(
    db: AsyncDatabaseManager | TransactionManager, installation_id: str
) -> int:
    """The installation's current revision; 0 before anything has changed.

    For display and for drafting only. It reads without a lock, so a change
    set is confirmed with :func:`claim_config_revision`, never by comparing
    against this."""
    revision = await db.fetch_value(
        "SELECT revision FROM {{tables.config_revisions}} WHERE installation_id = $1",
        installation_id,
    )
    return int(revision or 0)


async def bump_config_revision(tx: TransactionManager, installation_id: str) -> int:
    """Move the installation to its next revision in the caller's transaction.

    Returns the new revision. The row stays locked until the transaction
    ends, so concurrent changes take turns."""
    revision = await tx.fetch_value(
        """
        INSERT INTO {{tables.config_revisions}} (installation_id, revision) VALUES ($1, 1)
        ON CONFLICT (installation_id) DO UPDATE
            SET revision = {{tables.config_revisions}}.revision + 1
        RETURNING revision
        """,
        installation_id,
    )
    return int(revision)


async def claim_config_revision(tx: TransactionManager, installation_id: str, base: int) -> int:
    """Claim the next revision for a change set drafted at revision ``base``.

    The bump comes first and takes the installation's row lock (or, at
    revision 0, its insert conflict), so the check against ``base`` cannot
    race another confirmation: of two change sets drafted at the same
    revision, exactly one is confirmed. Raises ``base_revision_stale``
    otherwise; the caller's rollback then undoes the bump.

    Call it at the start of the confirming transaction's write phase, after
    the installation fence, the role hold and the approval admit, so the
    revision row is the last lock the transaction takes."""
    revision = await bump_config_revision(tx, installation_id)
    if revision != base + 1:
        raise ChangeRefused(
            "the configuration changed after this change set was drafted",
            code="base_revision_stale",
        )
    return revision
