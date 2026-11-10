"""Transactional publication and disposal of original-slot equivalence pins.

Every caller takes upstream installation/role/B2 authority first. The shared
order below is then the COMPLETE sorted dispatch union, followed by pin rows
in (dispatch_id,secret_id) order. No disposer locks a pin then seeks S3.
No provider, custody or vault I/O belongs here.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable
from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from pgdbm.core import TransactionManager

if TYPE_CHECKING:
    from aweb_secrets.custody.run_pins import PreparedRunPin


async def _read_committed(tx: TransactionManager) -> None:
    try:
        live = tx.connection.is_in_transaction()
    except RuntimeError:
        live = False
    if not live or await tx.fetch_value("SHOW transaction_isolation") != "read committed":
        raise ValueError("run pin lifecycle requires a live READ COMMITTED transaction")


async def retain(
    tx: TransactionManager, pins: Iterable[PreparedRunPin], *, deadline: datetime
) -> None:
    for pin in sorted(pins, key=lambda p: (p.dispatch_id, p.context.secret_id)):
        await tx.execute(
            "INSERT INTO {{tables.run_redaction_pins}}"
            " (installation_id,team_id,dispatch_id,secret_id,version,grant_id,observation,credential_version,"
            "digest,key_id,wrapped_key,nonce,ciphertext,deadline)"
            " VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
            *pin.columns(),
            deadline,
        )


async def read(
    tx: TransactionManager,
    *,
    installation_id: str,
    team_id: str,
    dispatch_id: UUID,
    hold: bool = False,
) -> list[Any]:
    return list(
        await tx.fetch_all(
            "SELECT p.* FROM {{tables.run_redaction_pins}} p"
            " WHERE p.installation_id=$1 AND p.team_id=$2 AND p.dispatch_id=$3"
            " ORDER BY p.secret_id" + (" FOR UPDATE OF p" if hold else ""),
            installation_id,
            team_id,
            dispatch_id,
        )
    )


async def prepare_dispatches(tx: TransactionManager, dispatch_ids: Collection[UUID]) -> None:
    """After full B2, before revision/effects: S3 union, then ALL pin rows."""
    await _read_committed(tx)
    ids = sorted(set(dispatch_ids))
    if not ids:
        return
    await tx.fetch_all(
        "SELECT dispatch_id FROM {{tables.dispatches}} WHERE dispatch_id=ANY($1::uuid[])"
        " ORDER BY dispatch_id FOR UPDATE",
        ids,
    )
    await tx.fetch_all(
        "SELECT dispatch_id,secret_id FROM {{tables.run_redaction_pins}}"
        " WHERE dispatch_id=ANY($1::uuid[]) ORDER BY dispatch_id,secret_id FOR UPDATE",
        ids,
    )


async def _prepare(tx: TransactionManager, predicate: str, *args: Any) -> None:
    await _read_committed(tx)
    # The caller's upstream F6 hold excludes new assignment publication while
    # this complete set is discovered/prepared. No pin is locked before S3.
    rows = await tx.fetch_all(
        "SELECT DISTINCT dispatch_id FROM {{tables.run_redaction_pins}} WHERE " + predicate,
        *args,
    )
    # Non-runner composition has no pins and needs no optional dispatch schema.
    if rows:
        await prepare_dispatches(tx, [row["dispatch_id"] for row in rows])


async def prepare_secrets(
    tx: TransactionManager, *, installation_id: str, team_id: str, secret_ids: Collection[str]
) -> None:
    await _prepare(
        tx,
        "installation_id=$1 AND team_id=$2 AND secret_id=ANY($3::text[])",
        installation_id,
        team_id,
        sorted(set(secret_ids)),
    )


async def prepare_installation(
    tx: TransactionManager, *, installation_id: str, team_id: str
) -> None:
    await _prepare(tx, "installation_id=$1 AND team_id=$2", installation_id, team_id)


async def prepare_retired_installations(
    tx: TransactionManager, *, team_id: str, installation_ids: Collection[str]
) -> None:
    await _prepare(
        tx, "team_id=$1 AND installation_id=ANY($2::text[])", team_id, sorted(set(installation_ids))
    )


async def _discard(tx: TransactionManager, predicate: str, *args: Any) -> int:
    # Only delete under the caller's prepared S3/pin union. Never rediscover
    # dispatches or acquire S3 here, after a revision or per-secret effect.
    await _read_committed(tx)
    removed = await tx.fetch_all(
        "DELETE FROM {{tables.run_redaction_pins}} WHERE " + predicate + " RETURNING 1", *args
    )
    return len(removed)


async def discard_dispatch(
    tx: TransactionManager, *, installation_id: str, team_id: str, dispatch_id: UUID
) -> int:
    return await _discard(
        tx,
        "installation_id=$1 AND team_id=$2 AND dispatch_id=$3",
        installation_id,
        team_id,
        dispatch_id,
    )


async def discard_installation(
    tx: TransactionManager, *, installation_id: str, team_id: str
) -> int:
    return await _discard(tx, "installation_id=$1 AND team_id=$2", installation_id, team_id)


async def discard_secret(
    tx: TransactionManager,
    *,
    installation_id: str,
    team_id: str,
    secret_id: str,
    version: int | None = None,
    keep_version: int | None = None,
    backend_credential: bool = False,
) -> int:
    if backend_credential:
        predicate = "credential_version IS NOT NULL"
        column = "credential_version"
        args: list[Any] = [installation_id, team_id]
    else:
        predicate = "secret_id=$3"
        column = "version"
        args = [installation_id, team_id, secret_id]
    if version is not None:
        args.append(version)
        predicate += f" AND {column}=${len(args)}"
    if keep_version is not None:
        args.append(keep_version)
        predicate += f" AND {column}<>${len(args)}"
    return await _discard(tx, "installation_id=$1 AND team_id=$2 AND " + predicate, *args)


async def discard_grant(
    tx: TransactionManager, *, installation_id: str, team_id: str, secret_id: str, grant_id: str
) -> int:
    return await _discard(
        tx,
        "installation_id=$1 AND team_id=$2 AND secret_id=$3 AND grant_id=$4",
        installation_id,
        team_id,
        secret_id,
        grant_id,
    )
