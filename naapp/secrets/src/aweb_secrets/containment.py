"""Transactional containment (§12), after the caller's installation and role fences.

Ancestry is locked before descendant selection. Issuance uses the same locks,
so a concurrent child is either selected or refused. B2 revocations and custody
writes commit together. No audit availability predicate is consulted here.
"""

from aweb_naapp.runtime.approvals import Approvals
from pgdbm.core import TransactionManager

from aweb_secrets import derived_lineage, use_approvals
from aweb_secrets.containment_state import ContainmentRefused
from aweb_secrets.containment_state import require_enabled as require_enabled
from aweb_secrets.custody import Custody, SealContext
from aweb_secrets.revisions import bump_config_revision


async def _lock_tree(
    tx: TransactionManager,
    installation_id: str,
    team_id: str,
    secret_id: str,
    *,
    lock_grants: bool = True,
) -> tuple[str, ...]:
    ancestors = await derived_lineage.lock_ancestry(tx, installation_id, team_id, secret_id)
    if not ancestors:
        raise ContainmentRefused("secret_unknown", 404)
    rows = await tx.fetch_all(
        """
        WITH RECURSIVE descendants AS (
            SELECT $3::text AS secret_id, ARRAY[$3::text] AS path
            UNION ALL
            SELECT d.secret_id, a.path || d.secret_id FROM descendants a
            JOIN {{tables.derived_secrets}} d ON d.parent_secret_id=a.secret_id
            WHERE d.installation_id=$1 AND d.team_id=$2
              AND NOT d.secret_id=ANY(a.path)
        ) SELECT secret_id FROM descendants ORDER BY path
        """,
        installation_id,
        team_id,
        secret_id,
    )
    ids = tuple(row["secret_id"] for row in rows)
    for descendant_id in ids[1:]:
        await derived_lineage.lock_ancestry(tx, installation_id, team_id, descendant_id)
    if lock_grants:
        await tx.fetch_all(
            "SELECT grant_id FROM {{tables.grants}}"
            " WHERE installation_id=$1 AND team_id=$2 AND secret_id=ANY($3::text[])"
            " ORDER BY grant_id FOR SHARE",
            installation_id,
            team_id,
            list({node.secret.record.secret_id for node in ancestors} | set(ids)),
        )
    return ids


async def _disable(
    tx: TransactionManager,
    custody: Custody,
    *,
    installation_id: str,
    team_id: str,
    secret_ids: tuple[str, ...],
) -> None:
    for secret_id in secret_ids:
        await tx.execute(
            "UPDATE {{tables.secrets}} SET state='disabled', updated_at=NOW()"
            " WHERE installation_id=$1 AND team_id=$2 AND secret_id=$3 AND state<>'disabled'",
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


async def disable_secret_tree(
    tx: TransactionManager,
    approvals: Approvals,
    custody: Custody,
    *,
    installation_id: str,
    team_id: str,
    secret_id: str,
    revoked_by: str,
) -> tuple[str, ...]:
    ids = await _lock_tree(tx, installation_id, team_id, secret_id)
    await use_approvals.revoke_use_approvals(
        tx,
        approvals,
        installation_id=installation_id,
        team_id=team_id,
        secret_ids=ids,
        revoked_by=revoked_by,
        reason="secret_disabled",
    )
    await _disable(
        tx,
        custody,
        installation_id=installation_id,
        team_id=team_id,
        secret_ids=ids,
    )
    await bump_config_revision(tx, installation_id)
    return ids


async def replace_value_consequences(
    tx: TransactionManager,
    approvals: Approvals,
    custody: Custody,
    *,
    installation_id: str,
    team_id: str,
    secret_id: str,
    current_version: int,
    revoked_by: str,
) -> tuple[str, ...]:
    """S10 calls before activation; returned IDs are evicted only after commit."""
    ids = await _lock_tree(tx, installation_id, team_id, secret_id)
    await use_approvals.void_use_approvals(
        tx,
        approvals,
        installation_id=installation_id,
        team_id=team_id,
        secret_id=secret_id,
        current_version=current_version,
        revoked_by=revoked_by,
    )
    await use_approvals.revoke_use_approvals(
        tx,
        approvals,
        installation_id=installation_id,
        team_id=team_id,
        secret_ids=ids[1:],
        revoked_by=revoked_by,
        reason="secret_version_changed",
    )
    await _disable(
        tx,
        custody,
        installation_id=installation_id,
        team_id=team_id,
        secret_ids=ids[1:],
    )
    return ids


async def disable_installation(
    tx: TransactionManager,
    approvals: Approvals,
    custody: Custody,
    *,
    installation_id: str,
    team_id: str,
    revoked_by: str,
) -> tuple[str, ...]:
    """One local flag survives remote grant refreshes. Fence held first."""
    rows = await tx.fetch_all(
        "SELECT secret_id FROM {{tables.secrets}} WHERE installation_id=$1 AND team_id=$2"
        " ORDER BY secret_id",
        installation_id,
        team_id,
    )
    ids = tuple(row["secret_id"] for row in rows)
    await use_approvals.revoke_use_approvals(
        tx,
        approvals,
        installation_id=installation_id,
        team_id=team_id,
        secret_ids=ids,
        revoked_by=revoked_by,
        reason="installation_disabled",
    )
    await tx.execute(
        "INSERT INTO {{tables.containment_installations}} (installation_id, team_id, disabled_at)"
        " VALUES ($1,$2,NOW()) ON CONFLICT (installation_id, team_id)"
        " DO UPDATE SET disabled_at=EXCLUDED.disabled_at",
        installation_id,
        team_id,
    )
    await bump_config_revision(tx, installation_id)
    return ids


class Containment:
    """Services shared by containment actions and S10 confirmation callbacks."""

    def __init__(self, *, approvals: Approvals, custody: Custody) -> None:
        self.approvals = approvals
        self.custody = custody

    async def replacement_consequences(
        self,
        tx: TransactionManager,
        *,
        old: SealContext,
        new: SealContext,
        revoked_by: str,
    ) -> tuple[str, ...]:
        if (old.installation_id, old.team_id, old.secret_id) != (
            new.installation_id,
            new.team_id,
            new.secret_id,
        ):
            raise ContainmentRefused("replacement_scope_mismatch")
        if old.version == new.version:
            return ()
        return await replace_value_consequences(
            tx,
            self.approvals,
            self.custody,
            installation_id=new.installation_id,
            team_id=new.team_id,
            secret_id=new.secret_id,
            current_version=new.version,
            revoked_by=revoked_by,
        )

    async def prepare_replacements(
        self,
        tx: TransactionManager,
        *,
        installation_id: str,
        team_id: str,
        secret_ids: tuple[str, ...],
    ) -> None:
        locked: set[str] = set()
        for secret_id in sorted(set(secret_ids)):
            locked.update(
                await _lock_tree(
                    tx,
                    installation_id,
                    team_id,
                    secret_id,
                    lock_grants=False,
                )
            )
            locked.update(
                await derived_lineage.ancestry_ids(
                    tx,
                    installation_id,
                    team_id,
                    secret_id,
                )
            )
        await tx.fetch_all(
            "SELECT grant_id FROM {{tables.grants}}"
            " WHERE installation_id=$1 AND team_id=$2 AND secret_id=ANY($3::text[])"
            " ORDER BY grant_id FOR SHARE",
            installation_id,
            team_id,
            list(locked),
        )
