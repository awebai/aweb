"""Prepared B3 authority for a final read in the original caller transaction."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import asyncpg
from pgdbm.core import TransactionManager

if TYPE_CHECKING:
    from aweb_naapp.runtime.passkeys.service import Passkeys


@dataclass(frozen=True)
class PreparedCurrentApprovers:
    """Authority held by one Passkeys instance in one original caller tx.

    Cache this handle in the app's authority adapter; its repeated preparation
    after B2 must reuse it, without reacquiring B3 locks. It grants no approval,
    login or send authority and does not validate retained APPROVE evidence.
    """

    _service: Passkeys = field(repr=False)
    _tx: TransactionManager = field(repr=False)
    _transaction_id: int = field(repr=False)
    _guard_key: int = field(repr=False)
    _pairs: frozenset[tuple[str, str]] = field(repr=False)
    _credentials: tuple[bytes, ...] = field(repr=False)


def _live(tx: TransactionManager) -> bool:
    try:
        return tx.connection.is_in_transaction()
    except asyncpg.InterfaceError:
        return False


async def _guard_live(tx: TransactionManager, xid: int, key: int) -> bool:
    # The unique prepare-time lock disappears on rollback-to-savepoint too.
    # Observing it cannot restore authority whose locks have been released.
    return bool(
        await tx.fetch_value(
            "SELECT txid_current_if_assigned()=$1 AND EXISTS ("
            "SELECT 1 FROM pg_locks WHERE pid=pg_backend_pid() AND locktype='advisory' "
            "AND classid=$2::oid AND objid=$3::oid AND objsubid=1 "
            "AND mode='ExclusiveLock' AND granted)",
            xid,
            key >> 32,
            key & 0xFFFFFFFF,
        )
    )


async def _read(tx: TransactionManager, scope: str, subject: str, credentials: tuple[bytes, ...]):
    return await tx.fetch_one(
        "SELECT a.superseded_at,a.effective_at,EXISTS ("
        "SELECT 1 FROM {{tables.passkey_credentials}} c WHERE c.subject=a.subject "
        "AND c.credential_id=ANY($3::bytea[]) AND c.revoked_at IS NULL) AS usable "
        "FROM {{tables.passkey_approvers}} a WHERE a.scope=$1 AND a.subject=$2",
        scope,
        subject,
        list(credentials),
    )


async def prepare_current_approvers(
    service: Passkeys, tx: TransactionManager, pairs: Sequence[tuple[str, str]]
) -> PreparedCurrentApprovers:
    if not _live(tx) or await tx.fetch_value("SHOW transaction_isolation") != "read committed":
        raise ValueError("current approver preparation needs a live READ COMMITTED transaction")
    ordered = sorted(set(pairs))
    # Entire designation union, then entire credential union, in retirement order.
    # Keep missing pairs absent: later insertions cannot heal an unprepared pair.
    designations = await tx.fetch_all(
        "SELECT a.scope,a.subject FROM {{tables.passkey_approvers}} a "
        "JOIN unnest($1::text[],$2::text[]) AS p(scope,subject) "
        "ON a.scope=p.scope AND a.subject=p.subject ORDER BY a.scope,a.subject FOR SHARE OF a",
        [scope for scope, _ in ordered],
        [subject for _, subject in ordered],
    )
    locked_pairs = frozenset((row["scope"], row["subject"]) for row in designations)
    credentials = await tx.fetch_all(
        "SELECT credential_id FROM {{tables.passkey_credentials}} "
        "WHERE subject=ANY($1::text[]) AND revoked_at IS NULL "
        "ORDER BY subject,credential_id FOR SHARE",
        sorted({subject for _, subject in locked_pairs}),
    )
    credential_ids = tuple(row["credential_id"] for row in credentials)
    # Plain final reads need their relation/index locks prepared as well.
    for scope, subject in sorted(locked_pairs):
        await _read(tx, scope, subject, credential_ids)
    guard = uuid.uuid4().int & ((1 << 63) - 1)
    await tx.execute("SELECT pg_advisory_xact_lock($1::bigint)", guard)
    xid = int(await tx.fetch_value("SELECT txid_current()"))
    if not await _guard_live(tx, xid, guard):
        raise ValueError("current approver preparation lost its transaction")
    return PreparedCurrentApprovers(service, tx, xid, guard, locked_pairs, credential_ids)


async def check_current_approver(
    service: Passkeys,
    tx: TransactionManager,
    prepared: PreparedCurrentApprovers,
    *,
    scope: str,
    subject: str,
) -> bool:
    if (
        prepared._service is not service
        or prepared._tx is not tx
        or (scope, subject) not in prepared._pairs
        or not _live(tx)
        or not await _guard_live(tx, prepared._transaction_id, prepared._guard_key)
    ):
        return False
    row = await _read(tx, scope, subject, prepared._credentials)
    # No await follows this live sample. This is authority, never LOGIN evidence.
    now = service._clock()
    return bool(
        row is not None
        and row["superseded_at"] is None
        and row["effective_at"] <= now
        and row["usable"]
    )
