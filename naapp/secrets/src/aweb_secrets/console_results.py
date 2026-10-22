"""Explicit projections of internal confirmations; never serialize the whole object.

The caller obtains current from ConsoleSessions.current on the human origin.
Codes are returned only to the deciding owner's session after commit. Generic
receipts contain metadata only. Codes are not persisted for later retrieval.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from aweb_naapp.console import ConsoleSession
from pgdbm import AsyncDatabaseManager

from aweb_secrets.change import ChangeRefused
from aweb_secrets.change_sets import Confirmation
from aweb_secrets.owners import OwnerDirectory


def confirmation_receipt(confirmation: Confirmation) -> dict[str, Any]:
    """The public receipt; safe for a tool or the agent API."""
    return {"change_id": confirmation.change_id, "revision": confirmation.revision}


async def owner_confirmation_result(
    db: AsyncDatabaseManager,
    directory: OwnerDirectory,
    confirmation: Confirmation,
    current: ConsoleSession,
) -> dict[str, Any]:
    """Project a committed result for a current, verified owner-console session."""
    if (
        current.scope != confirmation.confirmed_scope
        or current.subject != confirmation.confirmed_subject
        or current.expires_at <= datetime.now(UTC)
        or await directory.owner_of(db, current.scope) is None
    ):
        raise ChangeRefused("owner result unavailable", code="owner_required")
    applied = await db.fetch_value(
        "SELECT state = 'applied' FROM {{tables.change_sets}}"
        " WHERE change_id = $1 AND installation_id = $2 AND team_id = $3",
        confirmation.change_id,
        confirmation.installation_id,
        confirmation.team_id,
    )
    if not applied:
        raise ChangeRefused("confirmation has not committed", code="change_not_applied")
    return {
        **confirmation_receipt(confirmation),
        "runner_registrations": [
            {
                "runner_id": result.runner_id,
                "registration_code": result.registration_code,
                "reenabled": result.reenabled,
                "keys_replaced": result.keys_replaced,
                "registration_required": True,
            }
            for result in confirmation.runner_registrations
        ],
    }
