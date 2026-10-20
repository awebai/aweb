"""Each installation's configuration revision (decision 54).

A change set is drafted against the installation's current revision and is
confirmed only while the revision is unchanged. Every applied change set and
every narrowing act calls :func:`bump_config_revision` inside its own
transaction, so a draft computed before any of them is refused as stale.
"""

from __future__ import annotations

from pathlib import Path

from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.core import TransactionManager

MIGRATIONS_PATH = Path(__file__).resolve().parent / "revision_migrations"
MIGRATIONS_MODULE = "aweb_secrets_revisions"


async def apply_revision_migrations(db: AsyncDatabaseManager) -> None:
    await AsyncMigrationManager(
        db, migrations_path=str(MIGRATIONS_PATH), module_name=MIGRATIONS_MODULE
    ).apply_pending_migrations()


async def config_revision(
    db: AsyncDatabaseManager | TransactionManager, installation_id: str
) -> int:
    """The installation's current revision; 0 before anything has changed."""
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
