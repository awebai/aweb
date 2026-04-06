"""Garbage collection for inactive scopes and expired messages."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)


def _rows_affected(status: str) -> int:
    parts = status.strip().split()
    if len(parts) >= 2 and parts[-1].isdigit():
        return int(parts[-1])
    return 0


async def gc_expired_messages(db_infra, *, ttl_days: int = 30) -> dict:
    aweb_db = db_infra.get_manager("aweb")
    cutoff = datetime.now(timezone.utc) - timedelta(days=ttl_days)

    chat_status = await aweb_db.execute(
        "DELETE FROM {{tables.chat_messages}} WHERE created_at < $1",
        cutoff,
    )
    chat_deleted = _rows_affected(chat_status)

    mail_status = await aweb_db.execute(
        "DELETE FROM {{tables.messages}} WHERE created_at < $1",
        cutoff,
    )
    mail_deleted = _rows_affected(mail_status)

    total = chat_deleted + mail_deleted
    logger.info("gc_expired_messages: deleted %d messages (cutoff=%s)", total, cutoff.isoformat())
    return {"messages_deleted": total, "chat_deleted": chat_deleted, "mail_deleted": mail_deleted}


async def gc_inactive_scopes(db_infra, *, ttl_days: int = 30) -> dict:
    aweb_db = db_infra.get_manager("aweb")
    cutoff = datetime.now(timezone.utc) - timedelta(days=ttl_days)

    inactive = await aweb_db.fetch_all(
        """
        SELECT p.project_id
        FROM {{tables.projects}} p
        WHERE p.created_at < $1
          AND p.deleted_at IS NULL
          AND NOT EXISTS (
              SELECT 1 FROM {{tables.messages}} m
              WHERE (m.project_id = p.project_id OR m.recipient_project_id = p.project_id)
                AND m.created_at >= $1
          )
          AND NOT EXISTS (
              SELECT 1 FROM {{tables.chat_session_participants}} csp
              JOIN {{tables.chat_messages}} cm ON cm.session_id = csp.session_id
              JOIN {{tables.agents}} a ON a.agent_id = csp.agent_id
              WHERE a.project_id = p.project_id
                AND cm.created_at >= $1
          )
        """,
        cutoff,
    )

    deleted_count = 0
    for row in inactive:
        await _hard_delete_scope(aweb_db, project_id=row["project_id"])
        deleted_count += 1

    logger.info("gc_inactive_scopes: deleted %d scopes (cutoff=%s)", deleted_count, cutoff.isoformat())
    return {"scopes_deleted": deleted_count}


async def _hard_delete_scope(aweb_db, *, project_id) -> None:
    async with aweb_db.transaction() as tx:
        await tx.execute(
            """
            DELETE FROM {{tables.chat_read_receipts}}
            WHERE agent_id IN (
                SELECT agent_id FROM {{tables.agents}} WHERE project_id = $1
            )
            """,
            project_id,
        )
        await tx.execute(
            """
            DELETE FROM {{tables.chat_session_participants}}
            WHERE agent_id IN (
                SELECT agent_id FROM {{tables.agents}} WHERE project_id = $1
            )
            """,
            project_id,
        )
        await tx.execute(
            """
            DELETE FROM {{tables.chat_sessions}} cs
            WHERE NOT EXISTS (
                SELECT 1 FROM {{tables.chat_session_participants}} csp
                WHERE csp.session_id = cs.session_id
            )
            """,
        )
        await tx.execute(
            "DELETE FROM {{tables.messages}} WHERE project_id = $1 OR recipient_project_id = $1",
            project_id,
        )
        await tx.execute(
            "DELETE FROM {{tables.control_signals}} WHERE project_id = $1",
            project_id,
        )
        await tx.execute(
            "DELETE FROM {{tables.agent_log}} WHERE project_id = $1",
            project_id,
        )
        await tx.execute(
            "DELETE FROM {{tables.api_keys}} WHERE project_id = $1",
            project_id,
        )
        await tx.execute(
            "DELETE FROM {{tables.agents}} WHERE project_id = $1",
            project_id,
        )
        await tx.execute(
            "DELETE FROM {{tables.projects}} WHERE project_id = $1",
            project_id,
        )
