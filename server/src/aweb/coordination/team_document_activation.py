"""Making one version of a team's instructions or roles the active one."""

from __future__ import annotations

from fastapi import HTTPException

from aweb.service_errors import RESOURCE_NOT_FOUND_DETAIL


async def activate_team_document(db, *, table: str, team_id: str, document_id: str) -> None:
    """Activate the team's version ``document_id`` in ``table`` and deactivate the rest.

    ``table`` is the templated name of a table with ``id``, ``team_id`` and
    ``is_active`` columns. The change is one transaction, nested when ``db`` is
    already one, so a failure leaves the previous version active.
    """
    target = await db.fetch_one(f"SELECT id, team_id FROM {table} WHERE id = $1", document_id)
    if not target or target["team_id"] != team_id:
        raise HTTPException(status_code=404, detail=RESOURCE_NOT_FOUND_DETAIL)

    async with db.transaction() as tx:
        # Activations of one team's document run one at a time, so each
        # deactivates the version the one before it activated.
        await tx.fetch_value(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            f"{table}-activation:{team_id}",
        )
        await tx.execute(
            f"UPDATE {table} SET is_active = false WHERE team_id = $1 AND is_active = true",
            team_id,
        )
        await tx.execute(f"UPDATE {table} SET is_active = true WHERE id = $1", document_id)
