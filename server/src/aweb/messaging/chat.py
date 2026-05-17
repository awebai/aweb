from __future__ import annotations

import logging
import uuid as uuid_mod
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from aweb.service_errors import ConflictError, ForbiddenError, NotFoundError, ServiceError
from aweb.messaging.conversations import (
    _equivalent_identity_refs,
    find_active_one_to_one_conversation_between,
)

logger = logging.getLogger(__name__)

HANG_ON_EXTENSION_SECONDS = 300


def _uuid_or_none(value: str | UUID | None) -> UUID | None:
    if value is None:
        return None
    if isinstance(value, UUID):
        return value
    text = str(value).strip()
    if not text:
        return None
    return UUID(text)


def _participant_did(row: dict[str, Any]) -> str:
    return (row.get("did") or row.get("did_aw") or row.get("did_key") or "").strip()


async def get_agent_by_id(db, *, agent_id: str, team_id: str | None = None) -> dict[str, Any] | None:
    aweb_db = db.get_manager("aweb")
    if team_id is None:
        row = await aweb_db.fetch_one(
            """
            SELECT agent_id, team_id, alias, did_key, did_aw, address, messaging_policy, deleted_at
            FROM {{tables.agents}}
            WHERE agent_id = $1 AND deleted_at IS NULL
            """,
            _uuid_or_none(agent_id),
        )
    else:
        row = await aweb_db.fetch_one(
            """
            SELECT agent_id, team_id, alias, did_key, did_aw, address, messaging_policy, deleted_at
            FROM {{tables.agents}}
            WHERE agent_id = $1 AND team_id = $2 AND deleted_at IS NULL
            """,
            _uuid_or_none(agent_id),
            team_id,
        )
    return None if not row else dict(row)


async def get_agent_by_alias(db, *, team_id: str, alias: str) -> dict[str, Any] | None:
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, team_id, alias, did_key, did_aw, address, messaging_policy, deleted_at
        FROM {{tables.agents}}
        WHERE team_id = $1 AND alias = $2 AND deleted_at IS NULL
          AND COALESCE(agent_type, 'agent') != 'human'
        """,
        team_id,
        alias,
    )
    return None if not row else dict(row)


async def get_agents_by_aliases(db, *, team_id: str, aliases: list[str]) -> list[dict[str, Any]]:
    if not aliases:
        return []
    aweb_db = db.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        """
        SELECT agent_id, team_id, alias, did_key, did_aw, address, messaging_policy, deleted_at
        FROM {{tables.agents}}
        WHERE team_id = $1 AND alias = ANY($2::text[]) AND deleted_at IS NULL
          AND COALESCE(agent_type, 'agent') != 'human'
        """,
        team_id,
        aliases,
    )
    return [dict(row) for row in rows]


async def resolve_agent_by_did(db, did: str) -> dict[str, Any] | None:
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, team_id, alias, did_key, did_aw, address, messaging_policy, deleted_at
        FROM {{tables.agents}}
        WHERE deleted_at IS NULL
          AND (did_aw = $1 OR did_key = $1)
        ORDER BY CASE WHEN did_aw = $1 THEN 0 ELSE 1 END, created_at DESC
        LIMIT 1
        """,
        did,
    )
    return None if not row else dict(row)


async def find_session_between(
    db,
    *,
    did_a: str,
    did_b: str,
    did_key_a: str | None = None,
    did_key_b: str | None = None,
    agent_id_a: str | UUID | None = None,
    agent_id_b: str | UUID | None = None,
    address_a: str | None = None,
    address_b: str | None = None,
) -> UUID | None:
    conversation = await find_active_one_to_one_conversation_between(
        db,
        conversation_type="chat",
        did_a=did_a,
        did_b=did_b,
        did_key_a=did_key_a,
        did_key_b=did_key_b,
        agent_id_a=agent_id_a,
        agent_id_b=agent_id_b,
        address_a=address_a,
        address_b=address_b,
    )
    if conversation is None:
        # Fallback: legacy chat_sessions row without a matching conversations
        # row. Use _equivalent_identity_refs so the multi-team agent expansion
        # is the same here as in the conversations-table path: single shared
        # walk anchored on did_key, collision-resistant against did_aw collisions.
        dids_a, agent_ids_a = await _equivalent_identity_refs(
            db, did_a, did_key=did_key_a, agent_id=agent_id_a
        )
        dids_b, agent_ids_b = await _equivalent_identity_refs(
            db, did_b, did_key=did_key_b, agent_id=agent_id_b
        )
        addresses_a = [value for value in (address_a,) if str(value or "").strip()]
        addresses_b = [value for value in (address_b,) if str(value or "").strip()]
        if not (dids_a or agent_ids_a or addresses_a) or not (dids_b or agent_ids_b or addresses_b):
            return None
        aweb_db = db.get_manager("aweb")
        rows = await aweb_db.fetch_all(
            """
            SELECT s.session_id
            FROM {{tables.chat_sessions}} s
            JOIN {{tables.chat_participants}} pa
              ON pa.session_id = s.session_id
            JOIN {{tables.chat_participants}} pb
              ON pb.session_id = s.session_id
            WHERE (
                    ($2::uuid[] <> '{}'::uuid[] AND pa.agent_id = ANY($2::uuid[]))
                 OR ($2::uuid[] = '{}'::uuid[] AND pa.did = ANY($1::text[]))
                 OR ($3::text[] <> '{}'::text[] AND pa.address = ANY($3::text[]))
              )
              AND (
                    ($5::uuid[] <> '{}'::uuid[] AND pb.agent_id = ANY($5::uuid[]))
                 OR ($5::uuid[] = '{}'::uuid[] AND pb.did = ANY($4::text[]))
                 OR ($6::text[] <> '{}'::text[] AND pb.address = ANY($6::text[]))
              )
              AND pa.did <> pb.did
              AND (
                    SELECT COUNT(*)::int
                    FROM {{tables.chat_participants}} cp
                    WHERE cp.session_id = s.session_id
                  ) = 2
            ORDER BY s.created_at DESC, s.session_id DESC
            LIMIT 2
            """,
            dids_a,
            agent_ids_a,
            addresses_a,
            dids_b,
            agent_ids_b,
            addresses_b,
        )
        if len(rows) > 1:
            raise ConflictError("Multiple active chat sessions match these participants")
        if not rows:
            return None
        return rows[0]["session_id"]
    return UUID(conversation["conversation_id"])


async def _ensure_chat_conversation(
    executor,
    *,
    session_id: UUID,
    team_id: str | None,
    created_by_did: str,
    participants: list[dict[str, Any]],
) -> None:
    await executor.execute(
        """
        INSERT INTO {{tables.conversations}} (
            conversation_id, conversation_type, team_id, created_by_did
        )
        VALUES ($1, 'chat', $2, $3)
        ON CONFLICT (conversation_id) DO NOTHING
        """,
        session_id,
        team_id,
        created_by_did,
    )
    for participant in participants:
        await executor.execute(
            """
            INSERT INTO {{tables.conversation_participants}} (
                conversation_id, did, agent_id, alias, address, delivery_origin, transport_hint, role
            )
            VALUES ($1, $2, $3, $4, $5, $6, 'chat', $7)
            ON CONFLICT (conversation_id, did) DO UPDATE
            SET agent_id = EXCLUDED.agent_id,
                alias = EXCLUDED.alias,
                address = EXCLUDED.address,
                delivery_origin = EXCLUDED.delivery_origin,
                transport_hint = EXCLUDED.transport_hint
            """,
            session_id,
            participant["did"],
            participant["agent_id"],
            participant["alias"],
            participant["address"],
            participant.get("delivery_origin"),
            "initiator" if participant["did"] == created_by_did else "participant",
        )


async def ensure_session(
    db,
    *,
    team_id: str | None,
    participant_rows: list[dict[str, Any]],
    created_by: str,
    session_id: UUID | None = None,
) -> UUID:
    aweb_db = db.get_manager("aweb")
    normalized_participants: list[dict[str, Any]] = []
    seen_dids: set[str] = set()
    for row in participant_rows:
        did = _participant_did(row)
        if not did or did in seen_dids:
            continue
        seen_dids.add(did)
        normalized_participants.append(
            {
                "did": did,
                "did_key": (row.get("did_key") or "").strip() or None,
                "agent_id": _uuid_or_none(row.get("agent_id")),
                "alias": (row.get("alias") or did).strip(),
                "address": (row.get("address") or "").strip() or None,
                "delivery_origin": (row.get("delivery_origin") or "").strip() or None,
            }
        )
    if len(normalized_participants) < 2:
        raise ServiceError("Chat session requires at least two participants")

    if session_id is not None:
        existing = await aweb_db.fetch_one(
            "SELECT session_id FROM {{tables.chat_sessions}} WHERE session_id = $1",
            session_id,
        )
        if existing is not None:
            created_by_did = created_by if created_by.startswith("did:") else normalized_participants[0]["did"]
            await _ensure_chat_conversation(
                aweb_db,
                session_id=UUID(str(session_id)),
                team_id=team_id,
                created_by_did=created_by_did,
                participants=normalized_participants,
            )
            return UUID(str(session_id))

    if session_id is None and len(normalized_participants) == 2:
        existing = await find_session_between(
            db,
            did_a=normalized_participants[0]["did"],
            did_b=normalized_participants[1]["did"],
            did_key_a=normalized_participants[0].get("did_key"),
            did_key_b=normalized_participants[1].get("did_key"),
            agent_id_a=normalized_participants[0].get("agent_id"),
            agent_id_b=normalized_participants[1].get("agent_id"),
            address_a=normalized_participants[0].get("address"),
            address_b=normalized_participants[1].get("address"),
        )
        if existing is not None:
            created_by_did = created_by if created_by.startswith("did:") else normalized_participants[0]["did"]
            await _ensure_chat_conversation(
                aweb_db,
                session_id=UUID(str(existing)),
                team_id=team_id,
                created_by_did=created_by_did,
                participants=normalized_participants,
            )
            return existing

    async with aweb_db.transaction() as tx:
        row = await tx.fetch_one(
            """
            INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by)
            VALUES (COALESCE($1::uuid, gen_random_uuid()), $2, $3)
            RETURNING session_id
            """,
            session_id,
            team_id,
            created_by,
        )
        if not row:
            raise ServiceError("Failed to create chat session")
        session_id = row["session_id"]
        created_by_did = created_by if created_by.startswith("did:") else normalized_participants[0]["did"]

        for participant in normalized_participants:
            await tx.execute(
                """
                INSERT INTO {{tables.chat_participants}} (session_id, did, agent_id, alias, address, delivery_origin)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (session_id, did) DO UPDATE
                SET agent_id = EXCLUDED.agent_id,
                    alias = EXCLUDED.alias,
                    address = EXCLUDED.address,
                    delivery_origin = EXCLUDED.delivery_origin
                """,
                session_id,
                participant["did"],
                participant["agent_id"],
                participant["alias"],
                participant["address"],
                participant["delivery_origin"],
            )
        await _ensure_chat_conversation(
            tx,
            session_id=UUID(str(session_id)),
            team_id=team_id,
            created_by_did=created_by_did,
            participants=normalized_participants,
        )

    return UUID(str(session_id))


async def send_in_session(
    db,
    *,
    session_id: UUID,
    sender_did: str,
    body: str,
    sender_agent_id: str | UUID | None = None,
    sender_address: str | None = None,
    reply_to: UUID | None = None,
    leaving: bool = False,
    hang_on: bool = False,
    signature: str | None = None,
    signed_payload: str | None = None,
    created_at: datetime | None = None,
    message_id: UUID | None = None,
) -> dict[str, Any] | None:
    aweb_db = db.get_manager("aweb")
    participant = await aweb_db.fetch_one(
        """
        SELECT alias, did, agent_id
        FROM {{tables.chat_participants}}
        WHERE session_id = $1 AND did = $2
        """,
        session_id,
        sender_did,
    )
    if not participant:
        return None

    effective_created_at = created_at if created_at is not None else datetime.now(timezone.utc)
    effective_message_id = message_id if message_id is not None else uuid_mod.uuid4()
    sender_agent_uuid = _uuid_or_none(sender_agent_id) or participant.get("agent_id")

    msg_row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.chat_messages}}
            (message_id, session_id, from_agent_id, from_did, from_alias, from_address,
             body, sender_leaving, hang_on, reply_to, signature, signed_payload, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        RETURNING message_id, created_at
        """,
        effective_message_id,
        session_id,
        sender_agent_uuid,
        participant["did"],
        participant["alias"],
        (sender_address or "").strip() or None,
        body,
        bool(leaving),
        bool(hang_on),
        reply_to,
        signature,
        signed_payload,
        effective_created_at,
    )

    await aweb_db.execute(
        """
        INSERT INTO {{tables.chat_read_receipts}}
            (session_id, did, agent_id, last_read_message_id, last_read_at)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (session_id, did) DO UPDATE
        SET last_read_message_id = EXCLUDED.last_read_message_id,
            agent_id = EXCLUDED.agent_id,
            last_read_at = EXCLUDED.last_read_at
        WHERE {{tables.chat_read_receipts}}.last_read_at IS NULL
           OR EXCLUDED.last_read_at > {{tables.chat_read_receipts}}.last_read_at
        """,
        session_id,
        participant["did"],
        sender_agent_uuid,
        msg_row["message_id"],
        msg_row["created_at"],
    )

    return dict(msg_row)


async def get_pending_conversations(
    db,
    *,
    participant_did: str,
    participant_agent_id: str | None = None,
) -> list[dict[str, Any]]:
    aweb_db = db.get_manager("aweb")
    participant_agent_uuid = _uuid_or_none(participant_agent_id)
    rows = await aweb_db.fetch_all(
        """
        SELECT
            s.session_id,
            s.team_id,
            array_agg(p2.alias ORDER BY p2.alias) AS participants,
            array_agg(p2.did ORDER BY p2.alias) AS participant_dids,
            array_agg(p2.address ORDER BY p2.alias) AS participant_addresses,
            lm.body AS last_message,
            lm.from_alias AS last_from,
            lm.from_address AS last_from_address,
            lm.from_did AS last_from_did,
            lm.from_agent_id AS last_from_agent_id,
            lm.hang_on AS last_message_hang_on,
            lm.created_at AS last_activity,
            COALESCE(unread.cnt, 0) AS unread_count,
            s.wait_seconds,
            s.wait_started_at,
            s.wait_started_by,
            COALESCE(wait_ext.total_seconds, 0) AS extended_wait_seconds
        FROM {{tables.chat_sessions}} s
        JOIN {{tables.chat_participants}} p
          ON p.session_id = s.session_id AND p.did = $1
        JOIN {{tables.chat_participants}} p2
          ON p2.session_id = s.session_id
        LEFT JOIN LATERAL (
            SELECT body, from_alias, from_address, from_did, from_agent_id, hang_on, created_at
            FROM {{tables.chat_messages}}
            WHERE session_id = s.session_id
            ORDER BY created_at DESC
            LIMIT 1
        ) lm ON TRUE
        LEFT JOIN {{tables.chat_read_receipts}} rr
          ON rr.session_id = s.session_id AND rr.did = $1
        LEFT JOIN {{tables.chat_messages}} last_read_msg
          ON last_read_msg.message_id = rr.last_read_message_id
        LEFT JOIN LATERAL (
            SELECT COUNT(*)::int AS cnt
            FROM {{tables.chat_messages}} m
            WHERE m.session_id = s.session_id
              AND m.from_did <> $1
              AND m.created_at > COALESCE(last_read_msg.created_at, 'epoch'::timestamptz)
        ) unread ON TRUE
        LEFT JOIN LATERAL (
            SELECT COALESCE(SUM($2::int), 0)::int AS total_seconds
            FROM {{tables.chat_messages}} m
            WHERE m.session_id = s.session_id
              AND m.hang_on = TRUE
              AND (s.wait_started_at IS NULL OR m.created_at >= s.wait_started_at)
        ) wait_ext ON TRUE
        GROUP BY
            s.session_id,
            s.team_id,
            lm.body,
            lm.from_alias,
            lm.from_address,
            lm.from_did,
            lm.from_agent_id,
            lm.hang_on,
            lm.created_at,
            unread.cnt,
            s.wait_seconds,
            s.wait_started_at,
            s.wait_started_by,
            wait_ext.total_seconds
        HAVING COALESCE(unread.cnt, 0) > 0
            OR (
                s.wait_started_at IS NOT NULL
                AND s.wait_seconds IS NOT NULL
                AND (
                    $3::uuid IS NULL
                    OR s.wait_started_by IS NULL
                    OR s.wait_started_by <> $3
                )
                AND (
                    lm.from_did IS NULL
                    OR lm.from_did <> $1
                    OR COALESCE(lm.hang_on, FALSE) = TRUE
                )
                AND s.wait_started_at
                    + ((s.wait_seconds + COALESCE(wait_ext.total_seconds, 0)) * INTERVAL '1 second')
                    > NOW()
            )
        ORDER BY lm.created_at DESC
        """,
        participant_did,
        HANG_ON_EXTENSION_SECONDS,
        participant_agent_uuid,
    )

    return [
        {
            "session_id": str(row["session_id"]),
            "team_id": row["team_id"] or "",
            "participants": list(row["participants"] or []),
            "participant_dids": list(row["participant_dids"] or []),
            "participant_addresses": list(row["participant_addresses"] or []),
            "last_message": row["last_message"] or "",
            "last_from": row["last_from"] or "",
            "last_from_address": row["last_from_address"] or "",
            "last_from_did": row.get("last_from_did"),
            "last_from_agent_id": (
                str(row["last_from_agent_id"]) if row.get("last_from_agent_id") else None
            ),
            "unread_count": int(row["unread_count"] or 0),
            "last_activity": row["last_activity"],
            "wait_seconds": int(row["wait_seconds"]) if row.get("wait_seconds") is not None else None,
            "wait_started_at": row.get("wait_started_at"),
            "wait_started_by": (
                str(row["wait_started_by"]) if row.get("wait_started_by") is not None else None
            ),
            "extended_wait_seconds": int(row["extended_wait_seconds"] or 0),
        }
        for row in rows
    ]


async def get_message_history(
    db,
    *,
    session_id: UUID,
    participant_did: str,
    unread_only: bool = False,
    limit: int = 200,
    message_id: str | None = None,
) -> list[dict[str, Any]]:
    aweb_db = db.get_manager("aweb")
    is_participant = await aweb_db.fetch_one(
        """
        SELECT 1
        FROM {{tables.chat_participants}}
        WHERE session_id = $1 AND did = $2
        """,
        session_id,
        participant_did,
    )
    if not is_participant:
        raise ForbiddenError("Not a participant in this session")

    rr = await aweb_db.fetch_one(
        """
        SELECT last_read_msg.created_at AS last_read_message_at
        FROM {{tables.chat_read_receipts}}
        LEFT JOIN {{tables.chat_messages}} last_read_msg
          ON last_read_msg.message_id = {{tables.chat_read_receipts}}.last_read_message_id
        WHERE {{tables.chat_read_receipts}}.session_id = $1
          AND {{tables.chat_read_receipts}}.did = $2
        """,
        session_id,
        participant_did,
    )
    last_read_message_at = rr["last_read_message_at"] if rr else None

    message_uuid = _uuid_or_none(message_id)

    if message_uuid is not None:
        rows = await aweb_db.fetch_all(
            """
            SELECT message_id, from_alias, from_address, body, created_at, sender_leaving,
                   from_agent_id, reply_to, from_did, signature, signed_payload
            FROM {{tables.chat_messages}}
            WHERE session_id = $1
              AND message_id = $2
            ORDER BY created_at DESC
            LIMIT 1
            """,
            session_id,
            message_uuid,
        )
    else:
        rows = await aweb_db.fetch_all(
            """
            SELECT message_id, from_alias, from_address, body, created_at, sender_leaving,
                   from_agent_id, reply_to, from_did, signature, signed_payload
            FROM {{tables.chat_messages}}
            WHERE session_id = $1
              AND (
                $2::bool IS FALSE
                OR (
                    created_at > COALESCE($3::timestamptz, 'epoch'::timestamptz)
                    AND from_did <> $4
                )
              )
            ORDER BY created_at DESC
            LIMIT $5
            """,
            session_id,
            bool(unread_only),
            last_read_message_at,
            participant_did,
            int(limit),
        )
    rows = list(reversed(rows))

    return [
        {
            "message_id": str(row["message_id"]),
            "from_agent_id": (
                str(row["from_agent_id"]) if row.get("from_agent_id") is not None else None
            ),
            "from_did": row.get("from_did"),
            "from_alias": row["from_alias"],
            "from_address": row["from_address"] or "",
            "body": row["body"],
            "created_at": row["created_at"],
            "sender_leaving": bool(row["sender_leaving"]),
            "reply_to": str(row["reply_to"]) if row.get("reply_to") is not None else None,
            "signature": row.get("signature"),
            "signed_payload": row.get("signed_payload"),
        }
        for row in rows
    ]


async def mark_messages_read(
    db,
    *,
    session_id: UUID,
    participant_did: str,
    up_to_message_id: str,
    participant_agent_id: str | None = None,
) -> dict[str, Any]:
    aweb_db = db.get_manager("aweb")
    participant_agent_uuid = _uuid_or_none(participant_agent_id)
    up_to_uuid = UUID(up_to_message_id)

    is_participant = await aweb_db.fetch_one(
        """
        SELECT 1
        FROM {{tables.chat_participants}}
        WHERE session_id = $1 AND did = $2
        """,
        session_id,
        participant_did,
    )
    if not is_participant:
        raise ForbiddenError("Not a participant in this session")

    msg = await aweb_db.fetch_one(
        """
        SELECT created_at
        FROM {{tables.chat_messages}}
        WHERE session_id = $1 AND message_id = $2
        """,
        session_id,
        up_to_uuid,
    )
    if not msg:
        raise NotFoundError("Message not found")

    up_to_time = msg["created_at"]
    read_time = datetime.now(timezone.utc)

    old = await aweb_db.fetch_one(
        """
        SELECT last_read_msg.created_at AS last_read_message_at
        FROM {{tables.chat_read_receipts}}
        LEFT JOIN {{tables.chat_messages}} last_read_msg
          ON last_read_msg.message_id = {{tables.chat_read_receipts}}.last_read_message_id
        WHERE {{tables.chat_read_receipts}}.session_id = $1
          AND {{tables.chat_read_receipts}}.did = $2
        """,
        session_id,
        participant_did,
    )
    old_last_message_at = old["last_read_message_at"] if old else None

    marked = await aweb_db.fetch_value(
        """
        SELECT COUNT(*)::int
        FROM {{tables.chat_messages}}
        WHERE session_id = $1
          AND from_did <> $2
          AND created_at > COALESCE($3::timestamptz, 'epoch'::timestamptz)
          AND created_at <= $4
        """,
        session_id,
        participant_did,
        old_last_message_at,
        up_to_time,
    )

    upserted = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.chat_read_receipts}}
            (session_id, did, agent_id, last_read_message_id, last_read_at)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (session_id, did) DO UPDATE
        SET last_read_message_id = EXCLUDED.last_read_message_id,
            agent_id = EXCLUDED.agent_id,
            last_read_at = EXCLUDED.last_read_at
        WHERE $6 > COALESCE(
            (SELECT created_at FROM {{tables.chat_messages}}
             WHERE message_id = {{tables.chat_read_receipts}}.last_read_message_id),
            'epoch'::timestamptz
        )
        RETURNING 1
        """,
        session_id,
        participant_did,
        participant_agent_uuid,
        up_to_uuid,
        read_time,
        up_to_time,
    )

    return {
        "session_id": str(session_id),
        "messages_marked": int(marked or 0) if upserted else 0,
    }
