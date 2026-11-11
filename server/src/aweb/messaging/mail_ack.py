"""Acknowledging mail: an identity marks mail it received read."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from aweb.agent_wake import agent_wake_scope, record_did_wakes
from aweb.hooks import fire_mutation_callback
from aweb.identity_auth_deps import MessagingAuth, participant_dids
from aweb.messaging.mail_attribution import incoming_mail_sql
from aweb.messaging.runtime import MessagingRuntime


async def acknowledge_mail(
    db, auth: MessagingAuth, message_ids: list[UUID], runtime: MessagingRuntime, *, read_at: datetime,
) -> list[UUID]:
    """Mark read the unread mail among ``message_ids`` that ``auth`` received.

    Wakes the reader's streams and fires ``message.acknowledged`` once for each
    message it marked, and returns those messages' ids. Mail that is already
    read, or that ``auth`` did not receive, is left as it is.
    """
    inbox_dids = participant_dids(auth)
    with agent_wake_scope(runtime.agent_wake_publisher):
        acknowledged = await db.get_manager("aweb").fetch_all(
            f"""
            UPDATE {{{{tables.messages}}}} m
            SET read_at = $1
            WHERE {incoming_mail_sql('$2')}
              AND message_id = ANY($3::uuid[])
              AND read_at IS NULL
            RETURNING message_id, from_alias, subject, content_mode
            """,
            read_at,
            inbox_dids,
            message_ids,
        )
        if acknowledged:
            record_did_wakes(inbox_dids, "mail")
    for row in acknowledged:
        await fire_mutation_callback(
            runtime.on_mutation,
            "message.acknowledged",
            {
                "team_id": auth.team_id,
                "agent_id": auth.agent_id,
                "alias": auth.alias,
                "message_id": str(row["message_id"]),
                "from_alias": row["from_alias"],
                "subject": row["subject"] or "",
                "content_mode": row["content_mode"] or "legacy_plaintext_v1",
            },
        )
    return [row["message_id"] for row in acknowledged]
