"""Deletion of rows no reader needs again, and of expired messages."""

from __future__ import annotations

import logging
from dataclasses import dataclass
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


@dataclass(frozen=True)
class DeadRowRule:
    """Rows of ``table`` whose ``age_column`` is more than ``age_days`` old are dead.

    A NULL ``age_column`` is never older than anything, so a row that is not
    yet consumed or delivered is never dead, whatever its age.
    """

    table: str
    key: str
    age_column: str
    age_days: int


DEAD_ROW_RULES = (
    # The event stream reads app events from the last APP_EVENT_LOOKBACK_SECONDS
    # (app_events.current_app_events_for_agent) and nothing reads older ones.
    DeadRowRule("app_events", "event_id", "created_at", 30),
    # A stream consumes a signal once, by setting consumed_at
    # (routes/events._poll_control_signals); only unconsumed signals are read.
    DeadRowRule("control_signals", "signal_id", "consumed_at", 30),
    # Delivery and recovery read only rows whose delivered_at is NULL
    # (federation/delivery.deliver_federation_mutation_outbox).
    DeadRowRule("federation_mutation_outbox", "outbox_id", "delivered_at", 30),
    # Replay and recovery read only rows whose delivered_at is NULL
    # (lifecycle.replay_lifecycle_side_effects); an operation's id is not reused.
    DeadRowRule("lifecycle_side_effect_outbox", "outbox_id", "delivered_at", 30),
)


async def delete_dead_rows(db, *, apply: bool = False, batch_size: int = 1000) -> dict:
    """Report, and with ``apply`` delete, the rows DEAD_ROW_RULES name.

    Each DELETE statement removes at most ``batch_size`` rows and commits on
    its own. The report carries, per table, the rule's age, the number of dead
    rows found and the number deleted.
    """
    if batch_size < 1:
        raise ValueError("batch_size must be at least 1")
    now = datetime.now(timezone.utc)
    tables: dict[str, dict[str, int]] = {}
    for rule in DEAD_ROW_RULES:
        table = f"{{{{tables.{rule.table}}}}}"
        cutoff = now - timedelta(days=rule.age_days)
        dead = await db.fetch_value(
            f"SELECT COUNT(*) FROM {table} WHERE {rule.age_column} < $1",
            cutoff,
        )
        deleted = 0
        while apply:
            batch = _rows_affected(
                await db.execute(
                    f"""
                    DELETE FROM {table}
                    WHERE {rule.key} IN (
                        SELECT {rule.key} FROM {table}
                        WHERE {rule.age_column} < $1
                        LIMIT $2
                    )
                    """,
                    cutoff,
                    batch_size,
                )
            )
            deleted += batch
            if batch < batch_size:
                break
        tables[rule.table] = {
            "older_than_days": rule.age_days,
            "dead_rows": int(dead),
            "deleted_rows": deleted,
        }
    logger.info("delete_dead_rows: apply=%s tables=%s", apply, tables)
    return {"apply": apply, "tables": tables}
