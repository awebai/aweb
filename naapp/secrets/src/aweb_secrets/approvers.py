"""Approver records (design §10.2): who decides use approvals for which secrets.

An applied change set creates each record in the transaction that designates
the approver's B3 scope. S12 reads them to route a use approval. ``covers``
holds S8 secret_ids: minted once and never reused or renamed, so a record
covers exactly the secrets the confirmed change set named, whatever their
display refs later become. Removing an
approver is a narrowing act: the record is deleted before B3 retires the
designation, the order every withdrawal takes.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass

from pgdbm.core import TransactionManager


@dataclass(frozen=True)
class ApproverRecord:
    approver_ref: str
    scope: str
    principal_did: str | None
    change_id: str


async def record_approver(
    tx: TransactionManager,
    *,
    installation_id: str,
    team_id: str,
    approver_ref: str,
    scope: str,
    covers: Sequence[str],
    principal_did: str | None,
    change_id: str,
) -> None:
    await tx.execute(
        """
        INSERT INTO {{tables.approvers}}
            (installation_id, team_id, approver_ref, scope, covers, principal_did, change_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        """,
        installation_id,
        team_id,
        approver_ref,
        scope,
        json.dumps(sorted(covers)),
        principal_did,
        change_id,
    )


async def approvers_for_secret(
    tx: TransactionManager, *, installation_id: str, team_id: str, secret_id: str
) -> list[ApproverRecord]:
    """Every approver record of the installation covering ``secret_id``, held
    FOR SHARE in the caller's transaction, so an approver's removal waits for it."""
    rows = await tx.fetch_all(
        """
        SELECT approver_ref, scope, principal_did, change_id FROM {{tables.approvers}}
        WHERE installation_id = $1 AND team_id = $2 AND covers ? $3
        ORDER BY approver_ref
        FOR SHARE
        """,
        installation_id,
        team_id,
        secret_id,
    )
    return [
        ApproverRecord(
            approver_ref=row["approver_ref"],
            scope=row["scope"],
            principal_did=row["principal_did"],
            change_id=row["change_id"],
        )
        for row in rows
    ]
