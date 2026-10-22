"""Scoped replay protection in the caller's effect transaction.

A consume never reuses an existing row, even an expired one. The protocol
checks time before consuming and sets its complete retention deadline; this
store adds no clock allowance. Only explicit pruning removes old rows.
"""

from datetime import datetime
from pathlib import Path

from pgdbm import AsyncDatabaseManager, AsyncMigrationManager, TransactionManager


async def apply_nonce_migrations(db: AsyncDatabaseManager) -> None:
    await AsyncMigrationManager(
        db,
        migrations_path=str(Path(__file__).parent / "migrations"),
        module_name="aweb_naapp_nonces",
    ).apply_pending_migrations()


async def consume_nonce(
    tx: TransactionManager,
    *,
    scope: str,
    nonce: str,
    expires_at: datetime,
) -> bool:
    """True for a new nonce, False for an existing one; never commits.

    Database failures propagate. A failed effect must roll back this same
    transaction, including its tentative nonce insert.
    """
    if not scope or not nonce or expires_at.tzinfo is None:
        raise ValueError("scope, nonce and an aware expiry are required")
    inserted = await tx.fetch_value(
        "INSERT INTO {{tables.scoped_nonces}} (scope, nonce, expires_at) "
        "VALUES ($1, $2, $3) ON CONFLICT DO NOTHING RETURNING nonce",
        scope,
        nonce,
        expires_at,
    )
    return inserted is not None


async def prune_nonces(tx: TransactionManager, *, now: datetime) -> int:
    """Remove only strictly older deadlines, preserving inclusive clock boundaries."""
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    rows = await tx.fetch_all(
        "DELETE FROM {{tables.scoped_nonces}} WHERE expires_at < $1 RETURNING nonce",
        now,
    )
    return len(rows)
