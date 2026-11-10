"""Transactional publication and disposal of original-slot equivalence pins.

Every caller takes upstream installation/role/B2 authority first. The shared
order below is then the COMPLETE sorted dispatch union, followed by pin rows
in (dispatch_id,secret_id) order. No disposer locks a pin then seeks S3.
No provider, custody or vault I/O belongs here.
"""

from __future__ import annotations

from collections.abc import Iterable
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
            " (installation_id,team_id,dispatch_id,secret_id,version,observation,credential_version,"
            "digest,key_id,wrapped_key,nonce,ciphertext,deadline)"
            " VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
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


async def _discard(tx: TransactionManager, predicate: str, *args: Any) -> int:
    await _read_committed(tx)
    rows = await tx.fetch_all(
        "SELECT DISTINCT dispatch_id FROM {{tables.run_redaction_pins}} WHERE " + predicate,
        *args,
    )
    if not rows:
        # A deployment without runner composition has no pins or dispatch table.
        return 0
    await tx.fetch_all(
        "SELECT dispatch_id FROM {{tables.dispatches}} WHERE dispatch_id=ANY($1::uuid[])"
        " ORDER BY dispatch_id FOR UPDATE",
        sorted(row["dispatch_id"] for row in rows),
    )
    await tx.fetch_all(
        "SELECT dispatch_id,secret_id FROM {{tables.run_redaction_pins}} WHERE "
        + predicate
        + " ORDER BY dispatch_id,secret_id FOR UPDATE",
        *args,
    )
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
