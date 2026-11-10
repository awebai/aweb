"""Destroy live credential material in the installation fence's retirement tx.

The callback can run twice during one refresh. Tombstones identify the retired
installations; immutable receipts distinguish work already completed. Retained
authority, broker history and custody version allocators are not credentials.
"""

import json

from aweb_naapp.roles import purge_team
from pgdbm.core import TransactionManager


async def retire_team(tx: TransactionManager, team_id: str, *, app_id: str) -> None:
    """Called only under the shared installation fence, before new admission."""
    # Preserve the shared role hold/cleanup contract and lock order.
    await purge_team(tx, team_id)
    retired = await tx.fetch_all(
        "SELECT r.installation_id FROM {{tables.retired_installation_fences}} r"
        " LEFT JOIN {{tables.installation_retirement_events}} e"
        " USING(app_id,team_id,installation_id)"
        " WHERE r.app_id=$1 AND r.team_id=$2 AND e.installation_id IS NULL"
        " ORDER BY r.installation_id",
        app_id,
        team_id,
    )
    for row in retired:
        installation_id = row["installation_id"]
        scopes = await tx.fetch_all(
            "SELECT scope FROM {{tables.owner_principals}} WHERE installation_id=$1 AND team_id=$2"
            " UNION SELECT scope FROM {{tables.approvers}} WHERE installation_id=$1 AND team_id=$2",
            installation_id,
            team_id,
        )
        scope_names = [scope["scope"] for scope in scopes]
        subjects = await tx.fetch_all(
            "SELECT subject FROM {{tables.passkey_approvers}} WHERE scope=ANY($1::text[])"
            " ORDER BY subject FOR UPDATE",
            scope_names,
        )
        subject_ids = [subject["subject"] for subject in subjects]
        destroyed = {}
        # Assertions' restricted proof sidecars cascade; historical audit and
        # owner-act authorization remain separately attributable.
        for table in (
            "passkey_assertions",
            "passkey_credentials",
            "passkey_challenges",
            "passkey_enrolments",
            "passkey_contact_proofs",
        ):
            removed = await tx.fetch_all(
                f"DELETE FROM {{{{tables.{table}}}}} WHERE subject=ANY($1::text[]) RETURNING 1",
                subject_ids,
            )
            destroyed[table] = len(removed)
        removed = await tx.fetch_all(
            "DELETE FROM {{tables.console_sessions}} WHERE scope=ANY($1::text[]) RETURNING 1",
            scope_names,
        )
        destroyed["console_sessions"] = len(removed)
        for table in ("sealed_versions", "onepassword_credentials", "run_redaction_contexts"):
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
            app_id,
            team_id,
            installation_id,
            json.dumps(destroyed),
        )
