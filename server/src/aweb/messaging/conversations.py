from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from uuid import UUID

from aweb.service_errors import ForbiddenError, NotFoundError, ServiceError, ValidationError

ConversationType = Literal["mail", "chat"]
ConversationStatus = Literal["active", "closed", "expired"]
ParticipantRole = Literal["initiator", "participant"]

DEFAULT_CONVERSATION_TTL = timedelta(days=30)


@dataclass(frozen=True)
class ConversationParticipant:
    did: str
    agent_id: str | UUID | None = None
    alias: str | None = None
    address: str | None = None
    transport_hint: str | None = None
    role: ParticipantRole = "participant"


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_uuid(value: str | UUID, *, field_name: str) -> UUID:
    if isinstance(value, UUID):
        return value
    text = str(value or "").strip()
    if not text:
        raise ValidationError(f"Missing {field_name}")
    try:
        return UUID(text)
    except ValueError:
        raise ValidationError(f"Invalid {field_name} format")


def _uuid_or_none(value: str | UUID | None, *, field_name: str) -> UUID | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return _parse_uuid(text, field_name=field_name)


def _normalize_type(value: str) -> ConversationType:
    normalized = str(value or "").strip().lower()
    if normalized not in {"mail", "chat"}:
        raise ValidationError("conversation_type must be mail or chat")
    return normalized  # type: ignore[return-value]


def _normalize_role(value: str | None) -> ParticipantRole:
    normalized = str(value or "participant").strip().lower()
    if normalized not in {"initiator", "participant"}:
        raise ValidationError("participant role must be initiator or participant")
    return normalized  # type: ignore[return-value]


def _normalize_did(value: str, *, field_name: str = "did") -> str:
    did = str(value or "").strip()
    if not did:
        raise ValidationError(f"Missing {field_name}")
    return did


def _participant_from(value: ConversationParticipant | dict[str, Any]) -> ConversationParticipant:
    if isinstance(value, ConversationParticipant):
        return value
    return ConversationParticipant(
        did=str(value.get("did") or value.get("did_aw") or value.get("did_key") or ""),
        agent_id=value.get("agent_id"),
        alias=value.get("alias"),
        address=value.get("address"),
        transport_hint=value.get("transport_hint"),
        role=_normalize_role(value.get("role")),
    )


def _participant_record(value: ConversationParticipant | dict[str, Any], *, role: ParticipantRole | None = None):
    participant = _participant_from(value)
    did = _normalize_did(participant.did)
    participant_role = role or _normalize_role(participant.role)
    alias = str(participant.alias or did).strip()
    return {
        "did": did,
        "agent_id": _uuid_or_none(participant.agent_id, field_name="agent_id"),
        "alias": alias or did,
        "address": str(participant.address or "").strip() or None,
        "transport_hint": str(participant.transport_hint or "").strip() or None,
        "role": participant_role,
    }


def _dedupe_participants(participants: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for participant in participants:
        existing = records.get(participant["did"])
        if existing is None or existing["role"] != "initiator":
            records[participant["did"]] = participant
    return list(records.values())


def _expires_at(now: datetime, ttl: timedelta | None, expires_at: datetime | None) -> datetime | None:
    if expires_at is not None:
        return expires_at
    if ttl is None:
        raise ValidationError("Conversation ttl must not be None")
    return now + ttl


def _conversation_dict(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "conversation_id": str(row["conversation_id"]),
        "conversation_type": row["conversation_type"],
        "status": row["status"],
        "team_id": row.get("team_id"),
        "created_by_did": row["created_by_did"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "closed_at": row.get("closed_at"),
        "expires_at": row.get("expires_at"),
    }


def _participant_dict(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "conversation_id": str(row["conversation_id"]),
        "did": row["did"],
        "agent_id": str(row["agent_id"]) if row.get("agent_id") is not None else None,
        "alias": row["alias"],
        "address": row.get("address"),
        "transport_hint": row.get("transport_hint"),
        "role": row["role"],
        "joined_at": row["joined_at"],
    }


async def _expire_due_conversation(
    db,
    *,
    conversation_id: UUID,
    now: datetime,
) -> dict[str, Any] | None:
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        UPDATE {{tables.conversations}}
        SET status = 'expired',
            updated_at = $2
        WHERE conversation_id = $1
          AND status = 'active'
          AND expires_at IS NOT NULL
          AND expires_at <= $2
        RETURNING conversation_id, conversation_type, status, team_id, created_by_did,
                  created_at, updated_at, closed_at, expires_at
        """,
        conversation_id,
        now,
    )
    return None if not row else _conversation_dict(dict(row))


async def _get_active_conversation(
    db,
    *,
    conversation_id: str | UUID,
    now: datetime | None = None,
) -> dict[str, Any]:
    conversation_uuid = _parse_uuid(conversation_id, field_name="conversation_id")
    effective_now = now or _now_utc()
    expired = await _expire_due_conversation(
        db,
        conversation_id=conversation_uuid,
        now=effective_now,
    )
    if expired is not None:
        raise ForbiddenError("Conversation is expired")

    conversation = await get_conversation(db, conversation_id=conversation_uuid)
    if conversation is None:
        raise NotFoundError("Conversation not found")
    if conversation["status"] == "closed":
        raise ForbiddenError("Conversation is closed")
    if conversation["status"] == "expired":
        raise ForbiddenError("Conversation is expired")
    return conversation


async def create_conversation(
    db,
    *,
    conversation_type: ConversationType,
    created_by_did: str,
    initiator: ConversationParticipant | dict[str, Any],
    recipients: Sequence[ConversationParticipant | dict[str, Any]],
    conversation_id: str | UUID | None = None,
    team_id: str | None = None,
    ttl: timedelta | None = DEFAULT_CONVERSATION_TTL,
    expires_at: datetime | None = None,
) -> dict[str, Any]:
    """Create a conversation and its initial participant set in one transaction."""
    conversation_uuid = _uuid_or_none(conversation_id, field_name="conversation_id")
    normalized_type = _normalize_type(conversation_type)
    creator_did = _normalize_did(created_by_did, field_name="created_by_did")
    initiator_record = _participant_record(initiator, role="initiator")
    if initiator_record["did"] != creator_did:
        initiator_record = {**initiator_record, "did": creator_did}

    participant_records = _dedupe_participants(
        [initiator_record, *[_participant_record(item, role="participant") for item in recipients]]
    )
    if len(participant_records) < 1:
        raise ValidationError("Conversation requires at least one participant")

    now = _now_utc()
    effective_expires_at = _expires_at(now, ttl, expires_at)
    aweb_db = db.get_manager("aweb")
    async with aweb_db.transaction() as tx:
        row = await tx.fetch_one(
            """
            INSERT INTO {{tables.conversations}} (
                conversation_id, conversation_type, team_id, created_by_did,
                created_at, updated_at, expires_at
            )
            VALUES (COALESCE($1::uuid, gen_random_uuid()), $2, $3, $4, $5, $5, $6)
            RETURNING conversation_id, conversation_type, status, team_id, created_by_did,
                      created_at, updated_at, closed_at, expires_at
            """,
            conversation_uuid,
            normalized_type,
            team_id,
            creator_did,
            now,
            effective_expires_at,
        )
        if not row:
            raise ServiceError("Failed to create conversation")
        conversation_id = row["conversation_id"]
        for participant in participant_records:
            await tx.execute(
                """
                INSERT INTO {{tables.conversation_participants}} (
                    conversation_id, did, agent_id, alias, address, transport_hint, role
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (conversation_id, did) DO UPDATE
                SET agent_id = EXCLUDED.agent_id,
                    alias = EXCLUDED.alias,
                    address = EXCLUDED.address,
                    transport_hint = EXCLUDED.transport_hint,
                    role = EXCLUDED.role
                """,
                conversation_id,
                participant["did"],
                participant["agent_id"],
                participant["alias"],
                participant["address"],
                participant["transport_hint"],
                participant["role"],
            )

    conversation = _conversation_dict(dict(row))
    conversation["participants"] = await list_conversation_participants(
        db,
        conversation_id=conversation["conversation_id"],
    )
    return conversation


async def get_conversation(db, *, conversation_id: str | UUID) -> dict[str, Any] | None:
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT conversation_id, conversation_type, status, team_id, created_by_did,
               created_at, updated_at, closed_at, expires_at
        FROM {{tables.conversations}}
        WHERE conversation_id = $1
        """,
        _parse_uuid(conversation_id, field_name="conversation_id"),
    )
    return None if not row else _conversation_dict(dict(row))


async def list_conversation_participants(db, *, conversation_id: str | UUID) -> list[dict[str, Any]]:
    aweb_db = db.get_manager("aweb")
    rows = await aweb_db.fetch_all(
        """
        SELECT conversation_id, did, agent_id, alias, address, transport_hint, role, joined_at
        FROM {{tables.conversation_participants}}
        WHERE conversation_id = $1
        ORDER BY joined_at, alias
        """,
        _parse_uuid(conversation_id, field_name="conversation_id"),
    )
    return [_participant_dict(dict(row)) for row in rows]


async def add_conversation_participant(
    db,
    *,
    conversation_id: str | UUID,
    participant: ConversationParticipant | dict[str, Any],
    role: ParticipantRole = "participant",
) -> dict[str, Any]:
    conversation = await get_conversation(db, conversation_id=conversation_id)
    if conversation is None:
        raise NotFoundError("Conversation not found")
    await _get_active_conversation(db, conversation_id=conversation_id)

    record = _participant_record(participant, role=role)
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.conversation_participants}} (
            conversation_id, did, agent_id, alias, address, transport_hint, role
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (conversation_id, did) DO UPDATE
        SET agent_id = EXCLUDED.agent_id,
            alias = EXCLUDED.alias,
            address = EXCLUDED.address,
            transport_hint = EXCLUDED.transport_hint,
            role = EXCLUDED.role
        RETURNING conversation_id, did, agent_id, alias, address, transport_hint, role, joined_at
        """,
        _parse_uuid(conversation_id, field_name="conversation_id"),
        record["did"],
        record["agent_id"],
        record["alias"],
        record["address"],
        record["transport_hint"],
        record["role"],
    )
    if not row:
        raise ServiceError("Failed to add participant")
    return _participant_dict(dict(row))


async def require_active_conversation_participant(
    db,
    *,
    conversation_id: str | UUID,
    authenticated_did: str,
    equivalent_dids: Iterable[str] = (),
) -> dict[str, Any]:
    """Validate continuation authority without rediscovering the sender through AWID."""
    conversation_uuid = _parse_uuid(conversation_id, field_name="conversation_id")
    primary_did = _normalize_did(authenticated_did, field_name="authenticated_did")
    candidate_dids = [primary_did]
    for did in equivalent_dids:
        normalized = str(did or "").strip()
        if normalized and normalized not in candidate_dids:
            candidate_dids.append(normalized)

    aweb_db = db.get_manager("aweb")
    conversation = await _get_active_conversation(db, conversation_id=conversation_uuid)

    participant_row = await aweb_db.fetch_one(
        """
        SELECT conversation_id, did, agent_id, alias, address, transport_hint, role, joined_at
        FROM {{tables.conversation_participants}}
        WHERE conversation_id = $1
          AND did = ANY($2::text[])
        ORDER BY CASE WHEN did = $3 THEN 0 ELSE 1 END
        LIMIT 1
        """,
        conversation_uuid,
        candidate_dids,
        primary_did,
    )
    if not participant_row:
        raise ForbiddenError("Authenticated identity is not a participant in this conversation")

    return {
        "conversation": conversation,
        "participant": _participant_dict(dict(participant_row)),
    }


async def touch_conversation_activity(
    db,
    *,
    conversation_id: str | UUID,
    ttl: timedelta | None = DEFAULT_CONVERSATION_TTL,
    now: datetime | None = None,
) -> dict[str, Any]:
    conversation_uuid = _parse_uuid(conversation_id, field_name="conversation_id")
    effective_now = now or _now_utc()
    effective_expires_at = _expires_at(effective_now, ttl, None)
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        UPDATE {{tables.conversations}}
        SET updated_at = $2,
            expires_at = $3
        WHERE conversation_id = $1
          AND status = 'active'
          AND (expires_at IS NULL OR expires_at > $2)
        RETURNING conversation_id, conversation_type, status, team_id, created_by_did,
                  created_at, updated_at, closed_at, expires_at
        """,
        conversation_uuid,
        effective_now,
        effective_expires_at,
    )
    if not row:
        await _get_active_conversation(
            db,
            conversation_id=conversation_uuid,
            now=effective_now,
        )
        raise ServiceError("Failed to update conversation activity")
    return _conversation_dict(dict(row))


async def close_conversation(
    db,
    *,
    conversation_id: str | UUID,
    closed_by_did: str | None = None,
    system_close: bool = False,
) -> dict[str, Any]:
    if closed_by_did is None and not system_close:
        raise ValidationError("closed_by_did is required unless system_close is true")
    if closed_by_did is not None:
        await require_active_conversation_participant(
            db,
            conversation_id=conversation_id,
            authenticated_did=closed_by_did,
        )

    conversation_uuid = _parse_uuid(conversation_id, field_name="conversation_id")
    now = _now_utc()
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        UPDATE {{tables.conversations}}
        SET status = 'closed',
            closed_at = COALESCE(closed_at, $2),
            updated_at = $2
        WHERE conversation_id = $1
        RETURNING conversation_id, conversation_type, status, team_id, created_by_did,
                  created_at, updated_at, closed_at, expires_at
        """,
        conversation_uuid,
        now,
    )
    if not row:
        raise NotFoundError("Conversation not found")
    return _conversation_dict(dict(row))


async def expire_conversation(db, *, conversation_id: str | UUID) -> dict[str, Any]:
    conversation_uuid = _parse_uuid(conversation_id, field_name="conversation_id")
    now = _now_utc()
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        UPDATE {{tables.conversations}}
        SET status = 'expired',
            updated_at = $2
        WHERE conversation_id = $1
          AND status != 'expired'
        RETURNING conversation_id, conversation_type, status, team_id, created_by_did,
                  created_at, updated_at, closed_at, expires_at
        """,
        conversation_uuid,
        now,
    )
    if not row:
        existing = await get_conversation(db, conversation_id=conversation_uuid)
        if existing is None:
            raise NotFoundError("Conversation not found")
        return existing
    return _conversation_dict(dict(row))
