"""Atomic grant containment after the caller's installation fence and role hold.

Lock source ancestry, descendants root-to-leaf with siblings sorted, the whole
source/candidate grant union ascending, then S12/B2 approvals, before writes.
Expired or disabled lineage still permits containment.
"""

from __future__ import annotations

from aweb_naapp.runtime.approvals import Approvals
from pgdbm.core import TransactionManager

from aweb_secrets import derived_lineage, records
from aweb_secrets.custody import Custody
from aweb_secrets.revisions import bump_config_revision
from aweb_secrets.use_approvals import revoke_use_approvals


async def revoke_grant_tree(
    tx: TransactionManager,
    approvals: Approvals,
    custody: Custody,
    *,
    installation_id: str,
    team_id: str,
    grant_id: str,
    revoked_by: str,
) -> tuple[str, ...]:
    """Revoke one grant and disable exactly the child subtrees it issued.

    The caller holds its installation fence and owner authorization. All state,
    custody and all-version approval writes share this transaction. Children of
    other grants on the same parent remain active.
    """
    source = await tx.fetch_value(
        "SELECT secret_id FROM {{tables.grants}}"
        " WHERE installation_id=$1 AND team_id=$2 AND grant_id=$3",
        installation_id,
        team_id,
        grant_id,
    )
    if source is None:
        return ()
    ancestry = await derived_lineage.lock_ancestry(tx, installation_id, team_id, source)
    rows = await tx.fetch_all(
        """
        WITH RECURSIVE subtree AS (
            SELECT secret_id, ARRAY[secret_id] AS path
            FROM {{tables.derived_secrets}}
            WHERE installation_id=$1 AND team_id=$2 AND source_grant_id=$3
            UNION ALL
            SELECT d.secret_id, s.path || d.secret_id
            FROM subtree s JOIN {{tables.derived_secrets}} d
                ON d.parent_secret_id=s.secret_id
            WHERE d.installation_id=$1 AND d.team_id=$2
                AND NOT d.secret_id=ANY(s.path)
        ) SELECT secret_id FROM subtree ORDER BY path
        """,
        installation_id,
        team_id,
        grant_id,
    )
    ids = tuple(row["secret_id"] for row in rows)
    for secret_id in ids:
        await tx.fetch_one(
            "SELECT secret_id FROM {{tables.secrets}}"
            " WHERE installation_id=$1 AND team_id=$2 AND secret_id=$3 FOR UPDATE",
            installation_id,
            team_id,
            secret_id,
        )
    grants = await tx.fetch_all(
        "SELECT grant_id FROM {{tables.grants}}"
        " WHERE installation_id=$1 AND team_id=$2 AND secret_id=ANY($3::text[])",
        installation_id,
        team_id,
        list(ids),
    )
    union = {grant_id, *(row["grant_id"] for row in grants)}
    union.update(node.source_grant_id for node in ancestry if node.source_grant_id is not None)
    for current in sorted(union):
        await tx.fetch_one(
            "SELECT grant_id FROM {{tables.grants}}"
            " WHERE installation_id=$1 AND team_id=$2 AND grant_id=$3 FOR UPDATE",
            installation_id,
            team_id,
            current,
        )
    await revoke_use_approvals(
        tx,
        approvals,
        installation_id=installation_id,
        team_id=team_id,
        secret_ids=ids,
        source_grant_id=grant_id,
        revoked_by=revoked_by,
        reason="grant_revoked",
    )
    await records.revoke_grant(tx, installation_id, grant_id)
    for secret_id in ids:
        await tx.execute(
            "UPDATE {{tables.secrets}} SET state='disabled'"
            " WHERE installation_id=$1 AND team_id=$2 AND secret_id=$3",
            installation_id,
            team_id,
            secret_id,
        )
        await custody.disable(
            tx,
            installation_id=installation_id,
            team_id=team_id,
            secret_id=secret_id,
        )
    if ids:
        await bump_config_revision(tx, installation_id)
    return ids
