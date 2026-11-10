"""Destroy live credential material in the installation fence's retirement tx.

The callback can run twice during one refresh. Tombstones identify the retired
installations; immutable receipts distinguish work already completed. Retained
authority, broker history and custody version allocators are not credentials.
"""

import json

from aweb_naapp.roles import purge_team
from aweb_naapp.runtime.passkeys import RetiringInstallation, retire_subjects
from pgdbm.core import TransactionManager

from aweb_secrets import run_pin_store


async def retire_team(tx: TransactionManager, team_id: str, *, app_id: str) -> None:
    """Called only under the shared installation fence, before new admission."""
    retired = await tx.fetch_all(
        "SELECT r.installation_id FROM {{tables.retired_installation_fences}} r"
        " LEFT JOIN {{tables.installation_retirement_events}} e"
        " USING(app_id,team_id,installation_id)"
        " WHERE r.app_id=$1 AND r.team_id=$2 AND e.installation_id IS NULL"
        " ORDER BY r.installation_id",
        app_id,
        team_id,
    )
    scopes_by_installation = {}
    for row in retired:
        installation_id = row["installation_id"]
        scopes = await tx.fetch_all(
            "SELECT scope FROM {{tables.owner_principals}} WHERE installation_id=$1 AND team_id=$2"
            " UNION SELECT scope FROM {{tables.approvers}} WHERE installation_id=$1 AND team_id=$2"
            # Designation retains this binding in the same transaction. Unlike
            # coverage, it survives approver revocation; use it only to destroy
            # this installation's material, never as current authority.
            " UNION SELECT scope FROM {{tables.credential_authorizations}}"
            " WHERE installation_id=$1 AND team_id=$2 AND app_id=$3",
            installation_id,
            team_id,
            app_id,
        )
        scopes_by_installation[installation_id] = [scope["scope"] for scope in scopes]
    # Discovery precedes role/holding deletion. Preserve the existing role
    # cleanup contract and acquire B3 locks only after these role locks.
    await purge_team(tx, team_id)
    for row in retired:
        installation_id = row["installation_id"]
        retired_subjects = await retire_subjects(
            tx,
            installation=RetiringInstallation(
                app_id=app_id, team_id=team_id, installation_id=installation_id
            ),
            scopes=scopes_by_installation[installation_id],
        )
        identity = retired_subjects.installation
        destroyed = dict(retired_subjects.destroyed)
        destroyed["run_redaction_pins"] = await run_pin_store.discard_installation(
            tx, installation_id=installation_id, team_id=team_id
        )
        for table in ("sealed_versions", "onepassword_credentials"):
            removed = await tx.fetch_all(
                f"DELETE FROM {{{{tables.{table}}}}} WHERE installation_id=$1 AND team_id=$2 RETURNING 1",
                installation_id,
                team_id,
            )
            destroyed[table] = len(removed)
        await tx.execute(
            "UPDATE {{tables.custody_secrets}} SET disabled_at=COALESCE(disabled_at,clock_timestamp())"
            " WHERE installation_id=$1 AND team_id=$2",
            installation_id,
            team_id,
        )
        await tx.execute(
            "UPDATE {{tables.onepassword_versions}} SET binding=NULL,destroyed_at=clock_timestamp()"
            " WHERE installation_id=$1 AND team_id=$2 AND destroyed_at IS NULL",
            installation_id,
            team_id,
        )
        await tx.execute(
            "INSERT INTO {{tables.installation_retirement_events}}"
            " (app_id,team_id,installation_id,destroyed) VALUES ($1,$2,$3,$4)",
            identity.app_id,
            identity.team_id,
            identity.installation_id,
            json.dumps(destroyed),
        )
