"""Per-recipient room notices, independent of mail/chat delivery state."""

from __future__ import annotations

import logging
from uuid import UUID

from fastapi import HTTPException
from aweb.grant_streams import grant_has_scope
from aweb.messaging.room import _active_member, _post_dict, _uuid
from aweb.service_errors import ServiceError
from aweb.team_auth_deps import team_identity_with_grant_scope

logger = logging.getLogger(__name__)
_read_actor = team_identity_with_grant_scope("chat.read")


async def pending_room_notices(db, actor, *, limit=50):
    async with db.get_manager("aweb").transaction() as tx:
        await _active_member(tx, actor)
        rows = await tx.fetch_all(
            """
            SELECT m.*, count(*) OVER () AS pending_count
            FROM {{tables.room_post_notices}} n
            JOIN {{tables.room_messages}} m ON m.message_id=n.message_id
            JOIN {{tables.team_rooms}} r ON r.room_id=m.room_id
            WHERE n.recipient_agent_id=$1 AND r.team_id=$2
            ORDER BY m.sequence LIMIT $3
        """,
            UUID(actor.agent_id),
            actor.team_id,
            limit,
        )
        notices = []
        for row in rows:
            post = _post_dict(row, actor.team_id)
            notices.append(
                {
                    "type": "actionable_room_post",
                    "team_id": actor.team_id,
                    "agent_id": str(actor.agent_id),
                    "room_id": post["room_id"],
                    "message_id": post["message_id"],
                    "from_alias": post["from_alias"],
                    "from_did": post["from_did"],
                    "from_stable_id": post["from_stable_id"],
                    "subject": post["subject"],
                }
            )
        count = int(rows[0]["pending_count"]) if rows else 0
        return {
            "pending_count": count,
            "notices": notices,
            "has_more": count > len(notices),
        }


async def ack_room_notice(db, actor, message_id):
    message_id = _uuid(message_id)
    async with db.get_manager("aweb").transaction() as tx:
        await _active_member(tx, actor)
        await tx.execute(
            """DELETE FROM {{tables.room_post_notices}} n
            USING {{tables.room_messages}} m, {{tables.team_rooms}} r
            WHERE n.message_id=$1 AND n.recipient_agent_id=$2
              AND m.message_id=n.message_id AND r.room_id=m.room_id AND r.team_id=$3
        """,
            message_id,
            UUID(actor.agent_id),
            actor.team_id,
        )
    return {"message_id": str(message_id), "status": "acknowledged"}


async def current_room_events(request, db, identity):
    if not grant_has_scope(identity, "chat.read"):
        return []
    # No room activity adds no authority call to an existing mail/chat stream.
    exists = await db.get_manager("aweb").fetch_val(
        """
        SELECT EXISTS (SELECT 1 FROM {{tables.room_post_notices}}
        WHERE recipient_agent_id=$1)
    """,
        UUID(identity.agent_id),
    )
    if not exists:
        return []
    try:
        # Reuse ordinary production request admission and its cache bounds,
        # including current grants/certificates; no stream-lifetime room ACL.
        actor = await _read_actor(request, db)
        if actor.agent_id != identity.agent_id or actor.team_id != identity.team_id:
            logger.warning("Room event actor changed after stream admission")
            return []
        return (await pending_room_notices(db, actor))["notices"]
    except (HTTPException, ServiceError):
        logger.warning(
            "Room notice snapshot refused by current membership authority",
            exc_info=True,
        )
        return []
