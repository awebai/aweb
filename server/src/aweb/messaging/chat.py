from __future__ import annotations

from aweb.human_channels.contract import ContractError
from aweb.human_channels.participants import require_native_participant_input
from aweb.service_errors import ValidationError

from aweb.attachment_service import attachment_transaction

import logging
import uuid as uuid_mod
from datetime import datetime, timezone
import json
from typing import Any
from uuid import UUID

import asyncpg
from pgdbm.errors import QueryError

from aweb.service_errors import ConflictError, NotFoundError, ServiceError, ValidationError
from aweb.messaging.conversations import (
    _equivalent_identity_refs,
    find_active_one_to_one_conversation_between,
)

logger = logging.getLogger(__name__)

HANG_ON_EXTENSION_SECONDS = 300
MAX_CHAT_MARK_READ_IDS = 1000


def _uuid_or_none(value: str | UUID | None) -> UUID | None:
    if value is None:
        return None
    if isinstance(value, UUID):
        return value
    text = str(value).strip()
    if not text:
        return None
    return UUID(text)


def _json_object(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


async def resolve_session_actor_did(db_infra, *, session_id: UUID, actor_dids: list[str]) -> str:
    """Return the caller's participant DID in a chat session, or "" when it is not a participant."""
    if not actor_dids:
        return ""
    aweb_db = db_infra.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT did
        FROM {{tables.chat_participants}}
        WHERE session_id = $1
          AND did = ANY($2::text[])
        ORDER BY CASE WHEN did = $3 THEN 0 ELSE 1 END
        LIMIT 1
        """,
        session_id,
        actor_dids,
        actor_dids[0],
    )
    return (row.get("did") or "").strip() if row else ""


def _participant_did(row: dict[str, Any]) -> str:
    try:
        require_native_participant_input(row)
    except ContractError as error:
        raise ValidationError(str(error)) from error
    return (row.get("did") or row.get("did_aw") or row.get("did_key") or "").strip()


async def get_agent_by_id(db, *, agent_id: str, team_id: str | None = None) -> dict[str, Any] | None:
    aweb_db = db.get_manager("aweb")
    if team_id is None:
        row = await aweb_db.fetch_one(
            """
            SELECT agent_id, team_id, alias, did_key, CASE WHEN did_aw_verified_key = did_key THEN did_aw END AS did_aw, CASE WHEN did_aw_verified_key = did_key THEN address END AS address, identity_scope, (NULLIF(did_aw, '') IS NOT NULL) AS has_global_claim, did_aw AS policy_did_aw, inbound_mode, deleted_at
            FROM {{tables.agents}}
            WHERE agent_id = $1 AND deleted_at IS NULL
            """,
            _uuid_or_none(agent_id),
        )
    else:
        row = await aweb_db.fetch_one(
            """
            SELECT agent_id, team_id, alias, did_key, CASE WHEN did_aw_verified_key = did_key THEN did_aw END AS did_aw, CASE WHEN did_aw_verified_key = did_key THEN address END AS address, identity_scope, (NULLIF(did_aw, '') IS NOT NULL) AS has_global_claim, did_aw AS policy_did_aw, inbound_mode, deleted_at
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
        SELECT agent_id, team_id, alias, did_key, CASE WHEN did_aw_verified_key = did_key THEN did_aw END AS did_aw, CASE WHEN did_aw_verified_key = did_key THEN address END AS address, identity_scope, (NULLIF(did_aw, '') IS NOT NULL) AS has_global_claim, did_aw AS policy_did_aw, inbound_mode, deleted_at
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
        SELECT agent_id, team_id, alias, did_key, CASE WHEN did_aw_verified_key = did_key THEN did_aw END AS did_aw, CASE WHEN did_aw_verified_key = did_key THEN address END AS address, identity_scope, (NULLIF(did_aw, '') IS NOT NULL) AS has_global_claim, did_aw AS policy_did_aw, inbound_mode, deleted_at
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
        SELECT agent_id, team_id, alias, did_key, CASE WHEN did_aw_verified_key = did_key THEN did_aw END AS did_aw, CASE WHEN did_aw_verified_key = did_key THEN address END AS address, identity_scope, (NULLIF(did_aw, '') IS NOT NULL) AS has_global_claim, did_aw AS policy_did_aw, inbound_mode, deleted_at
        FROM {{tables.agents}}
        WHERE deleted_at IS NULL
          AND ((did_aw = $1 AND did_aw_verified_key = did_key) OR did_key = $1)
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
        # Addresses can be reassigned; they do not establish identity continuity.
        if not (dids_a or agent_ids_a) or not (dids_b or agent_ids_b):
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
              )
              AND (
                    ($4::uuid[] <> '{}'::uuid[] AND pb.agent_id = ANY($4::uuid[]))
                 OR ($4::uuid[] = '{}'::uuid[] AND pb.did = ANY($3::text[]))
              )
              AND pa.did <> pb.did
              AND NOT EXISTS (
                    SELECT 1 FROM {{tables.conversations}} c
                    WHERE c.conversation_id = s.session_id
                  )
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
            dids_b,
            agent_ids_b,
        )
        if not rows:
            return None
        # Legacy chat_sessions has no active/closed status. If more than one
        # pre-conversations session exists for the same 1:1 participants, route
        # to the newest row so chat remains usable; ensure_session will create
        # the canonical conversations row for that session before sending.
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
        """,
        session_id,
        team_id,
        created_by_did,
    )
    for participant in participants:
        await executor.execute(
            """
            INSERT INTO {{tables.conversation_participants}} (
                conversation_id, did, agent_id, alias, address, delivery_origin, current_did_key, transport_hint, role
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            """,
            session_id,
            participant["did"],
            participant["agent_id"],
            participant["alias"],
            participant["address"],
            participant.get("delivery_origin"),
            participant.get("current_did_key"),
            participant["transport_hint"],
            "initiator" if participant["did"] == created_by_did else "participant",
        )


async def validate_session_id(
    db,
    *,
    session_id: UUID,
    actor_dids: list[str],
    actor_agent_id: str | UUID | None = None,
) -> bool:
    """Allow a fresh UUID or an existing chat's active caller; never grant membership."""
    row = await db.get_manager("aweb").fetch_one(
        """
        SELECT s.session_id, c.conversation_type,
               EXISTS (
                   SELECT 1 FROM {{tables.chat_participants}} p
                   WHERE p.session_id = s.session_id AND p.left_at IS NULL
                     AND (p.did = ANY($2::text[]) OR p.agent_id = $3::uuid)
               ) AS caller_participant
        FROM {{tables.conversations}} c
        FULL OUTER JOIN {{tables.chat_sessions}} s ON s.session_id = c.conversation_id
        WHERE COALESCE(c.conversation_id, s.session_id) = $1
        """,
        session_id, actor_dids, _uuid_or_none(actor_agent_id),
    )
    if row is None:
        return False
    if (row["conversation_type"] not in (None, "chat")
            or row["session_id"] is None or not row["caller_participant"]):
        raise ConflictError("session_id is not an existing chat session of the caller")
    return True


async def _backfill_legacy_chat_conversation(db, *, session_id: UUID) -> None:
    # Serialize legacy projection, and copy only stored membership and routes.
    # A create request must never modify an existing session's participants.
    async with db.get_manager("aweb").transaction() as tx:
        session = await tx.fetch_one(
            "SELECT team_id, created_by FROM {{tables.chat_sessions}} WHERE session_id = $1 FOR UPDATE",
            session_id,
        )
        conversation = await tx.fetch_one(
            "SELECT conversation_type FROM {{tables.conversations}} WHERE conversation_id = $1", session_id,
        )
        if conversation is not None:
            if conversation["conversation_type"] != "chat":
                raise ConflictError("session_id is not an existing chat session of the caller")
            return
        participants = await tx.fetch_all(
            """
            SELECT did, agent_id, alias, address, delivery_origin, current_did_key,
                   CASE WHEN delivery_origin IS NULL THEN 'local'
                        ELSE 'federation:' || delivery_origin END AS transport_hint
            FROM {{tables.chat_participants}} WHERE session_id = $1
            """,
            session_id,
        )
        creator = next((p["did"] for p in participants
                        if session["created_by"] in (p["did"], p["alias"])), participants[0]["did"])
        await _ensure_chat_conversation(
            tx, session_id=session_id, team_id=session["team_id"],
            created_by_did=creator, participants=participants,
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
        delivery_origin = (row.get("delivery_origin") or "").strip() or None
        transport_hint = (row.get("transport_hint") or "").strip()
        normalized_participants.append(
            {
                "did": did,
                "did_key": (row.get("did_key") or "").strip() or None,
                "agent_id": _uuid_or_none(row.get("agent_id")),
                "alias": (row.get("alias") or did).strip(),
                "address": (row.get("address") or "").strip() or None,
                "delivery_origin": delivery_origin,
                "current_did_key": (row.get("current_did_key") or row.get("did_key") or "").strip() or None,
                "transport_hint": transport_hint or (
                    "federation:" + delivery_origin if delivery_origin else "local"
                ),
            }
        )
    if len(normalized_participants) < 2:
        raise ServiceError("Chat session requires at least two participants")

    actor = normalized_participants[0]  # Supplied by the authenticated adapter, never by target resolution.
    actor_dids = list(dict.fromkeys(d for d in (actor["did"], actor.get("did_key")) if d))
    if session_id is not None and await validate_session_id(
        db, session_id=session_id, actor_dids=actor_dids, actor_agent_id=actor["agent_id"],
    ):
        await _backfill_legacy_chat_conversation(db, session_id=session_id)
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
            await validate_session_id(
                db, session_id=existing, actor_dids=actor_dids, actor_agent_id=actor["agent_id"],
            )
            await _backfill_legacy_chat_conversation(db, session_id=existing)
            return existing

    try:
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
                    INSERT INTO {{tables.chat_participants}} (session_id, did, agent_id, alias, address, delivery_origin, current_did_key)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                    """,
                    session_id,
                    participant["did"],
                    participant["agent_id"],
                    participant["alias"],
                    participant["address"],
                    participant["delivery_origin"],
                    participant["current_did_key"],
                )
            await _ensure_chat_conversation(
                tx,
                session_id=UUID(str(session_id)),
                team_id=team_id,
                created_by_did=created_by_did,
                participants=normalized_participants,
            )
    except (QueryError, asyncpg.exceptions.UniqueViolationError) as exc:
        cause = exc.__cause__ if isinstance(exc, QueryError) else exc
        if isinstance(cause, asyncpg.exceptions.UniqueViolationError):
            raise ConflictError("session_id already exists") from exc
        raise

    return UUID(str(session_id))


@attachment_transaction("chat")
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
    id_chain: dict[str, Any] | None = None,
    content_mode: str = "legacy_plaintext_v1",
    message_version: int = 1,
    encrypted_envelope: dict[str, Any] | None = None,
    encrypted_metadata: dict[str, Any] | None = None,
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

    # The sender-attested time remains in signed_payload or encrypted_envelope.
    # created_at is when this server received the message for ordering, so the
    # two values intentionally use different clocks and may disagree.
    effective_created_at = datetime.now(timezone.utc)
    effective_message_id = message_id if message_id is not None else uuid_mod.uuid4()
    sender_agent_uuid = _uuid_or_none(sender_agent_id) or participant.get("agent_id")
    encrypted_metadata = encrypted_metadata or {}

    msg_row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.chat_messages}}
            (message_id, session_id, from_agent_id, from_did, from_alias, from_address,
             body, sender_leaving, hang_on, reply_to, signature, signed_payload,
             content_mode, message_version, encrypted_envelope, encrypted_ciphertext,
             encrypted_key_wraps, encrypted_ciphertext_hash, encrypted_ciphertext_size,
             encrypted_key_wraps_hash, encrypted_inner_header_hash, encrypted_suite,
             encrypted_signing_key_id, signed_envelope_hash, created_at, id_chain)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
                $21, $22, $23, $24, $25, $26::jsonb)
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
        content_mode,
        int(message_version or 1),
        json.dumps(encrypted_envelope, sort_keys=True, separators=(",", ":")) if encrypted_envelope is not None else None,
        encrypted_metadata.get("encrypted_ciphertext"),
        json.dumps(encrypted_metadata.get("encrypted_key_wraps"), sort_keys=True, separators=(",", ":")) if encrypted_metadata.get("encrypted_key_wraps") is not None else None,
        encrypted_metadata.get("encrypted_ciphertext_hash"),
        encrypted_metadata.get("encrypted_ciphertext_size"),
        encrypted_metadata.get("encrypted_key_wraps_hash"),
        encrypted_metadata.get("encrypted_inner_header_hash"),
        encrypted_metadata.get("encrypted_suite"),
        encrypted_metadata.get("encrypted_signing_key_id"),
        encrypted_metadata.get("signed_envelope_hash"),
        effective_created_at,
        json.dumps(id_chain) if id_chain is not None else None,
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
    # Materialize the viewer's session set before the per-session work. Keep
    # the existing did-first preference and include departed participants;
    # left_at is not a pending-conversation authorization or unread filter.
    rows = await aweb_db.fetch_all(
        """
        WITH mine AS MATERIALIZED (
            SELECT DISTINCT ON (participant.session_id)
                participant.session_id, participant.did, participant.agent_id
            FROM {{tables.chat_participants}} participant
            WHERE participant.did = $1
               OR ($3::uuid IS NOT NULL AND participant.agent_id = $3)
            ORDER BY participant.session_id,
                     CASE WHEN participant.did = $1 THEN 0 ELSE 1 END
        )
        SELECT
            s.session_id,
            s.team_id,
            participants.aliases AS participants,
            participants.dids AS participant_dids,
            participants.addresses AS participant_addresses,
            CASE WHEN lm.content_mode = 'encrypted_v2' THEN '' ELSE lm.body END AS last_message,
            COALESCE(lm.content_mode, 'legacy_plaintext_v1') AS last_message_content_mode,
            COALESCE(lm.message_version, 1) AS last_message_version,
            lm.encrypted_envelope AS last_encrypted_envelope,
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
        FROM mine p
        JOIN {{tables.chat_sessions}} s ON s.session_id = p.session_id
        CROSS JOIN LATERAL (
            SELECT array_agg(p2.alias ORDER BY p2.alias) AS aliases,
                   array_agg(p2.did ORDER BY p2.alias) AS dids,
                   array_agg(p2.address ORDER BY p2.alias) AS addresses
            FROM {{tables.chat_participants}} p2
            WHERE p2.session_id = p.session_id
        ) participants
        LEFT JOIN LATERAL (
            SELECT body, content_mode, message_version, encrypted_envelope,
                   from_alias, from_address, from_did, from_agent_id, hang_on, created_at
            FROM {{tables.chat_messages}}
            WHERE session_id = s.session_id
            ORDER BY created_at DESC
            LIMIT 1
        ) lm ON TRUE
        LEFT JOIN LATERAL (
            SELECT COUNT(*)::int AS cnt
            FROM {{tables.chat_messages}} m
            WHERE m.session_id = s.session_id
              AND m.from_did <> p.did
              AND NOT EXISTS (
                  SELECT 1
                  FROM {{tables.chat_message_reads}} mr
                  WHERE mr.session_id = m.session_id
                    AND mr.did = p.did
                    AND mr.message_id = m.message_id
              )
        ) unread ON TRUE
        LEFT JOIN LATERAL (
            SELECT COALESCE(SUM($2::int), 0)::int AS total_seconds
            FROM {{tables.chat_messages}} m
            WHERE m.session_id = s.session_id
              AND m.hang_on = TRUE
              AND (s.wait_started_at IS NULL OR m.created_at >= s.wait_started_at)
        ) wait_ext ON TRUE
        WHERE COALESCE(unread.cnt, 0) > 0
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
                    OR lm.from_did <> p.did
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
            "last_message_content_mode": row.get("last_message_content_mode") or "legacy_plaintext_v1",
            "last_message_version": int(row.get("last_message_version") or 1),
            "last_encrypted_envelope": _json_object(row.get("last_encrypted_envelope")),
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
        raise NotFoundError()

    message_uuid = _uuid_or_none(message_id)

    if message_uuid is not None:
        rows = await aweb_db.fetch_all(
            """
            SELECT message_id, from_alias, from_address,
                   CASE WHEN content_mode = 'encrypted_v2' THEN '' ELSE body END AS body,
                   created_at, sender_leaving, from_agent_id, reply_to, from_did,
                   signature, signed_payload, id_chain, content_mode, message_version,
                   encrypted_envelope
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
            SELECT message_id, from_alias, from_address,
                   CASE WHEN content_mode = 'encrypted_v2' THEN '' ELSE body END AS body,
                   created_at, sender_leaving, from_agent_id, reply_to, from_did,
                   signature, signed_payload, id_chain, content_mode, message_version,
                   encrypted_envelope
            FROM {{tables.chat_messages}}
            WHERE session_id = $1
              AND (
                $2::bool IS FALSE
                OR (
                    from_did <> $3
                    AND NOT EXISTS (
                        SELECT 1
                        FROM {{tables.chat_message_reads}} mr
                        WHERE mr.session_id = {{tables.chat_messages}}.session_id
                          AND mr.did = $3
                          AND mr.message_id = {{tables.chat_messages}}.message_id
                    )
                )
              )
            ORDER BY created_at DESC
            LIMIT $4
            """,
            session_id,
            bool(unread_only),
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
            "id_chain": _json_object(row.get("id_chain")),
            "content_mode": row.get("content_mode") or "legacy_plaintext_v1",
            "message_version": int(row.get("message_version") or 1),
            "encrypted_envelope": _json_object(row.get("encrypted_envelope")),
        }
        for row in rows
    ]


async def mark_messages_read(
    db,
    *,
    session_id: UUID,
    participant_did: str,
    message_ids: list[str],
    participant_agent_id: str | None = None,
) -> dict[str, Any]:
    aweb_db = db.get_manager("aweb")
    participant_agent_uuid = _uuid_or_none(participant_agent_id)
    if not message_ids:
        raise ValidationError("message_ids is required")
    if len(message_ids) > MAX_CHAT_MARK_READ_IDS:
        raise ValidationError(f"message_ids cannot exceed {MAX_CHAT_MARK_READ_IDS} items")
    requested_ids = list(dict.fromkeys(UUID(message_id) for message_id in message_ids))

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
        raise NotFoundError()

    presented = await aweb_db.fetch_all(
        """
        SELECT message_id
        FROM {{tables.chat_messages}}
        WHERE session_id = $1 AND message_id = ANY($2::uuid[])
        """,
        session_id,
        requested_ids,
    )
    if len(presented) != len(requested_ids):
        raise NotFoundError("Message not found")

    read_time = datetime.now(timezone.utc)
    async with aweb_db.transaction() as tx:
        marked = await tx.fetch_all(
            """
            INSERT INTO {{tables.chat_message_reads}}
                (session_id, did, message_id, agent_id, read_at)
            SELECT $1, $2, m.message_id, $3, $4
            FROM {{tables.chat_messages}} m
            WHERE m.session_id = $1
              AND m.message_id = ANY($5::uuid[])
              AND m.from_did <> $2
            ON CONFLICT (session_id, did, message_id) DO NOTHING
            RETURNING message_id
            """,
            session_id,
            participant_did,
            participant_agent_uuid,
            read_time,
            requested_ids,
        )
        await tx.execute(
            """
            INSERT INTO {{tables.chat_read_receipts}}
                (session_id, did, agent_id, last_read_message_id, last_read_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (session_id, did) DO UPDATE
            SET last_read_message_id = EXCLUDED.last_read_message_id,
                agent_id = EXCLUDED.agent_id,
                last_read_at = EXCLUDED.last_read_at
            """,
            session_id,
            participant_did,
            participant_agent_uuid,
            requested_ids[-1],
            read_time,
        )

    return {
        "session_id": str(session_id),
        "messages_marked": len(marked),
    }


async def mark_messages_read_up_to(
    db,
    *,
    session_id: UUID,
    participant_did: str,
    up_to_message_id: str,
    participant_agent_id: str | None = None,
) -> dict[str, Any]:
    """Resolve a deployed-client watermark into exact per-message reads."""
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
        raise NotFoundError()

    watermark = await aweb_db.fetch_one(
        """
        SELECT created_at
        FROM {{tables.chat_messages}}
        WHERE session_id = $1 AND message_id = $2
        """,
        session_id,
        up_to_uuid,
    )
    if not watermark:
        raise NotFoundError("Message not found")

    read_time = datetime.now(timezone.utc)
    async with aweb_db.transaction() as tx:
        marked = await tx.fetch_all(
            """
            INSERT INTO {{tables.chat_message_reads}}
                (session_id, did, message_id, agent_id, read_at)
            SELECT $1, $2, m.message_id, $3, $4
            FROM {{tables.chat_messages}} m
            WHERE m.session_id = $1
              AND m.from_did <> $2
              AND m.created_at <= $5
            ON CONFLICT (session_id, did, message_id) DO NOTHING
            RETURNING message_id
            """,
            session_id,
            participant_did,
            participant_agent_uuid,
            read_time,
            watermark["created_at"],
        )
        await tx.execute(
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
                 WHERE session_id = $1
                   AND message_id = {{tables.chat_read_receipts}}.last_read_message_id),
                'epoch'::timestamptz
            )
            """,
            session_id,
            participant_did,
            participant_agent_uuid,
            up_to_uuid,
            read_time,
            watermark["created_at"],
        )

    return {
        "session_id": str(session_id),
        "messages_marked": len(marked),
    }
