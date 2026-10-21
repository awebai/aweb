"""Server-managed ancestry, expiry fences and nearest-current operation lookup.

Decision 78 extends decision 59's common lock order: installation fence, role
hold, secret ancestry root to leaf, all source and candidate grants in ascending
grant-ID order, covering approver rows FOR SHARE in deterministic order, B2
approval locks, then writes. Callers hold the fence and any role hold first;
lock_ancestry and check_ancestry take only their respective ancestry/grant locks.
The guard stays closed until admission, capture and containment all use this
order and issuance can commit its mandatory audit event.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from pgdbm.core import TransactionManager

from aweb_secrets import records
from aweb_secrets.derived_capture import DEFAULT_MAX_TTL_S, effective_expiry
from aweb_secrets.operation import OperationTemplate
from aweb_secrets.secret import SecretRecord


def utc_now() -> datetime:
    return datetime.now(UTC)


class LineageRefused(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class LineageNode:
    installation_id: str
    team_id: str
    secret: records.StoredSecret
    parent_secret_id: str | None
    parent_version: int | None
    source_grant_id: str | None
    issuing_principal: str | None
    policy_digest: str | None
    dispatch_started_at: datetime | None
    upstream_expires_at: datetime | None
    expires_at: datetime | None


async def ancestry_ids(
    tx: TransactionManager, installation_id: str, team_id: str, secret_id: str
) -> tuple[str, ...]:
    """Read immutable ancestry root-to-leaf without taking mutable record locks.

    For directory coverage reads in B2's separate transaction, not authority
    admission. The caller's fenced transaction must check_ancestry under locks.
    """
    rows = await tx.fetch_all(
        """
        WITH RECURSIVE ancestry AS (
            SELECT s.secret_id, ARRAY[s.secret_id] AS path, 0 AS depth
            FROM {{tables.secrets}} s
            WHERE s.installation_id=$1 AND s.team_id=$2 AND s.secret_id=$3
            UNION ALL
            SELECT d.parent_secret_id, a.path || d.parent_secret_id, a.depth+1
            FROM ancestry a JOIN {{tables.derived_secrets}} d ON d.secret_id=a.secret_id
            WHERE d.installation_id=$1 AND d.team_id=$2
              AND NOT d.parent_secret_id = ANY(a.path)
        ) SELECT a.secret_id, d.parent_secret_id FROM ancestry a
          LEFT JOIN {{tables.derived_secrets}} d
            ON d.installation_id=$1 AND d.team_id=$2 AND d.secret_id=a.secret_id
          ORDER BY depth DESC
        """,
        installation_id,
        team_id,
        secret_id,
    )
    if rows and rows[0]["parent_secret_id"] is not None:
        raise LineageRefused("secret_disabled")
    return tuple(row["secret_id"] for row in rows)


async def lock_ancestry(
    tx: TransactionManager, installation_id: str, team_id: str, secret_id: str
) -> tuple[LineageNode, ...]:
    """Lock existing ancestry root-to-leaf, then read mutable state again.

    Creation and cascades use the same locks, so an insertion either precedes
    containment or observes its result. The installation fence is held first.
    """
    ids = await ancestry_ids(tx, installation_id, team_id, secret_id)
    nodes = []
    for discovered in ids:
        row = await tx.fetch_one(
            """
            SELECT s.record, s.state, s.active_version, d.parent_secret_id, d.parent_version,
                d.source_grant_id, d.issuing_principal, d.policy_digest,
                d.dispatch_started_at, d.upstream_expires_at, d.expires_at
            FROM {{tables.secrets}} s LEFT JOIN {{tables.derived_secrets}} d
                USING (installation_id, team_id, secret_id)
            WHERE s.installation_id=$1 AND s.team_id=$2 AND s.secret_id=$3
            FOR UPDATE OF s
            """,
            installation_id,
            team_id,
            discovered,
        )
        if row is None:
            raise LineageRefused("secret_disabled")
        nodes.append(
            LineageNode(
                installation_id,
                team_id,
                records.StoredSecret(
                    SecretRecord.from_after(json.loads(row["record"])),
                    row["state"],
                    row["active_version"],
                ),
                row["parent_secret_id"],
                row["parent_version"],
                row["source_grant_id"],
                row["issuing_principal"],
                row["policy_digest"],
                row["dispatch_started_at"],
                row["upstream_expires_at"],
                row["expires_at"],
            )
        )
    if nodes and nodes[0].parent_secret_id is not None:
        raise LineageRefused("secret_disabled")
    return tuple(nodes)


async def check_ancestry(
    tx: TransactionManager,
    nodes: Sequence[LineageNode],
    *,
    clock: Callable[[], datetime] = utc_now,
    max_ttl_s: int = DEFAULT_MAX_TTL_S,
    candidate_grant_ids: Sequence[str] = (),
) -> frozenset[str]:
    """Lock the grant union, then sample a live UTC clock and check authority.

    Pass a callable, never a datetime captured before awaiting locks. Call again
    after any later blocking phase before a new admission or recording write.
    """
    grants = await _lock_grants(tx, nodes, candidate_grant_ids)
    _check_locked_ancestry(nodes, grants, now=clock(), max_ttl_s=max_ttl_s)
    return frozenset(
        grant_id
        for grant_id, row in grants.items()
        if row is not None and row["revoked_at"] is None
    )


async def _lock_grants(
    tx: TransactionManager,
    nodes: Sequence[LineageNode],
    candidate_grant_ids: Sequence[str],
) -> dict[str, Any]:
    if not nodes:
        raise LineageRefused("secret_disabled")
    installation_id, team_id = nodes[0].installation_id, nodes[0].team_id
    source_ids = {node.source_grant_id for node in nodes if node.source_grant_id is not None}
    grants = {}
    for grant_id in sorted(source_ids | set(candidate_grant_ids)):
        row = await tx.fetch_one(
            "SELECT secret_id, policy_digest, revoked_at FROM {{tables.grants}}"
            " WHERE installation_id=$1 AND team_id=$2 AND grant_id=$3 FOR SHARE",
            installation_id,
            team_id,
            grant_id,
        )
        grants[grant_id] = row
    return grants


def _check_locked_ancestry(
    nodes: Sequence[LineageNode],
    grants: Mapping[str, Any],
    *,
    now: datetime,
    max_ttl_s: int,
) -> None:
    for node in nodes:
        if node.source_grant_id is not None:
            grant = grants[node.source_grant_id]
            if (
                grant is None
                or grant["revoked_at"] is not None
                or grant["secret_id"] != node.parent_secret_id
            ):
                raise LineageRefused("grant_revoked")
    for index, node in enumerate(nodes):
        if node.secret.state != "active" or node.secret.active_version is None:
            raise LineageRefused("secret_disabled")
        if index and (
            node.parent_secret_id != nodes[index - 1].secret.record.secret_id
            or node.parent_version != nodes[index - 1].secret.active_version
        ):
            raise LineageRefused("secret_version_changed")
        if node.expires_at is not None:
            assert node.dispatch_started_at is not None and node.upstream_expires_at is not None
            deadline = effective_expiry(
                node.upstream_expires_at,
                dispatch_started_at=node.dispatch_started_at,
                ancestor_expiries=[node.expires_at],
                max_ttl_s=max_ttl_s,
            )
            if deadline <= now:
                raise LineageRefused("secret_disabled")


async def record_lineage(
    tx: TransactionManager,
    *,
    installation_id: str,
    team_id: str,
    secret_id: str,
    parent_secret_id: str,
    parent_version: int,
    source_dispatch_id: str,
    source_grant_id: str,
    issuing_principal: str,
    policy_digest: str,
    dispatch_started_at: datetime,
    upstream_expires_at: datetime,
    expires_at: datetime,
    clock: Callable[[], datetime] = utc_now,
    max_ttl_s: int = DEFAULT_MAX_TTL_S,
) -> None:
    """Persist immutable provenance in the child-creation transaction.

    Parent authority is locked and checked by the issuance fence before the
    child is inserted. This write also constrains the source grant's binding;
    database foreign keys enforce same-installation/team parent and child.
    """
    ancestry = await lock_ancestry(tx, installation_id, team_id, parent_secret_id)
    grants = await _lock_grants(tx, ancestry, [source_grant_id])
    # Both the ancestors and prospective child use one clock sample, taken
    # after the last relevant lock. The source policy was read under that lock.
    now = clock()
    _check_locked_ancestry(ancestry, grants, now=now, max_ttl_s=max_ttl_s)
    if secret_id in {node.secret.record.secret_id for node in ancestry}:
        raise LineageRefused("operation_not_allowed")
    if ancestry[-1].secret.active_version != parent_version:
        raise LineageRefused("secret_version_changed")
    deadlines = [node.expires_at for node in ancestry if node.expires_at is not None]
    if expires_at <= now or any(expires_at > deadline for deadline in deadlines):
        raise LineageRefused("secret_disabled")
    source = grants[source_grant_id]
    if (
        source is None
        or source["revoked_at"] is not None
        or source["secret_id"] != parent_secret_id
    ):
        raise LineageRefused("grant_revoked")
    if source["policy_digest"] != policy_digest:
        raise LineageRefused("operation_not_allowed")
    await tx.execute(
        """
        INSERT INTO {{tables.derived_secrets}} (
            installation_id, team_id, secret_id, parent_secret_id, parent_version,
            source_dispatch_id, source_grant_id, issuing_principal, policy_digest,
            dispatch_started_at, upstream_expires_at, expires_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
        """,
        installation_id,
        team_id,
        secret_id,
        parent_secret_id,
        parent_version,
        source_dispatch_id,
        source_grant_id,
        issuing_principal,
        policy_digest,
        dispatch_started_at,
        upstream_expires_at,
        expires_at,
    )


async def current_operation(
    tx: TransactionManager, nodes: Sequence[LineageNode], operation_id: str
) -> OperationTemplate | None:
    """Select the nearest CURRENT definition once; the caller checks child pins."""
    for node in reversed(nodes):
        operation = await records.current_operation(
            tx,
            node.installation_id,
            node.secret.record.secret_id,
            operation_id,
        )
        if operation is not None:
            return operation
    return None
