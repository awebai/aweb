"""The shared idempotency store for naapp requests.

A caller claims a key, an app-chosen tuple such as (installation, principal,
request id), with the canonical hash of the request and the reference of the
receipt the request produces. The claim runs inside the caller's transaction
and rolls back with it. The first claim of a key wins. A later claim with the
same bytes gets the stored receipt, and with different bytes a conflict.
After the app's retention the key is expired: it is refused and never runs
again. :func:`expire_keys` then clears an expired key's request hash and
receipt, leaving the key alone as a content-free tombstone.

The caller rechecks the principal's current read permission before it returns
a stored receipt.

Imports only the standard library and pgdbm, so it needs no naapp runtime.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.core import TransactionManager

MIGRATIONS_PATH = Path(__file__).resolve().parent / "migrations"
MIGRATIONS_MODULE = "aweb_naapp_idempotency"


class IdempotencyConflict(Exception):
    """The key was claimed for a request with different bytes."""

    code = "idempotency_conflict"
    status = 409


class IdempotencyExpired(Exception):
    """The key's retention has passed; the request is never executed again."""

    code = "idempotency_expired"
    status = 410


@dataclass(frozen=True)
class Receipt:
    """The receipt a key stands for; ``created`` is true for the claim that made it."""

    receipt_ref: str
    created: bool


async def apply_idempotency_migrations(db: AsyncDatabaseManager) -> None:
    await AsyncMigrationManager(
        db, migrations_path=str(MIGRATIONS_PATH), module_name=MIGRATIONS_MODULE
    ).apply_pending_migrations()


async def claim(
    tx: TransactionManager,
    *,
    key: Sequence[str],
    request_hash: bytes,
    receipt_ref: str,
    retention: timedelta,
) -> Receipt:
    """Claim ``key`` for this request in the caller's transaction.

    Returns the new receipt, or the stored one for the same bytes. Raises
    :class:`IdempotencyConflict` for different bytes and
    :class:`IdempotencyExpired` once the key's retention has passed.
    """
    if not key or not request_hash or not receipt_ref or retention <= timedelta(0):
        raise ValueError("a claim needs a key, a request hash, a receipt and a retention")
    key = list(key)
    inserted = await tx.fetch_value(
        """
        INSERT INTO {{tables.idempotency_keys}} (key, request_hash, receipt_ref, expires_at)
        VALUES ($1, $2, $3, NOW() + $4)
        ON CONFLICT (key) DO NOTHING
        RETURNING receipt_ref
        """,
        key,
        request_hash,
        receipt_ref,
        retention,
    )
    if inserted is not None:
        return Receipt(receipt_ref=inserted, created=True)
    stored = await tx.fetch_one(
        """
        SELECT request_hash, receipt_ref, expires_at <= NOW() AS expired
        FROM {{tables.idempotency_keys}} WHERE key = $1
        """,
        key,
    )
    if stored is None:
        raise RuntimeError("an idempotency key conflicted but cannot be read")
    if stored["expired"]:
        raise IdempotencyExpired("the idempotency key has expired")
    if stored["request_hash"] is None or bytes(stored["request_hash"]) != request_hash:
        raise IdempotencyConflict("the idempotency key was used for a different request")
    return Receipt(receipt_ref=stored["receipt_ref"], created=False)


async def expire_keys(db: AsyncDatabaseManager) -> int:
    """Clear the request hash and receipt of every key past its retention.

    The keys stay as tombstones that answer expired. Returns how many were cleared.
    """
    cleared = await db.fetch_value(
        """
        WITH cleared AS (
            UPDATE {{tables.idempotency_keys}}
            SET request_hash = NULL, receipt_ref = NULL
            WHERE request_hash IS NOT NULL AND expires_at <= NOW()
            RETURNING 1
        )
        SELECT count(*) FROM cleared
        """
    )
    return int(cleared)
