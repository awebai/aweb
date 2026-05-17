from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from uuid import UUID

from aweb.service_errors import ConflictError, ForbiddenError, NotFoundError, ServiceError, ValidationError

ConversationType = Literal["mail", "chat"]
ConversationStatus = Literal["active", "closed", "expired"]
ParticipantRole = Literal["initiator", "participant"]

DEFAULT_CONVERSATION_TTL: timedelta | None = timedelta(days=30)


@dataclass(frozen=True)
class ConversationParticipant:
    did: str
    agent_id: str | UUID | None = None
    alias: str | None = None
    address: str | None = None
    delivery_origin: str | None = None
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
        delivery_origin=value.get("delivery_origin"),
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
        "delivery_origin": str(participant.delivery_origin or "").strip() or None,
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
        return None
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
        "delivery_origin": row.get("delivery_origin"),
        "transport_hint": row.get("transport_hint"),
        "role": row["role"],
        "joined_at": row["joined_at"],
    }


async def _get_active_conversation(
    db,
    *,
    conversation_id: str | UUID,
    now: datetime | None = None,
) -> dict[str, Any]:
    effective_now = now or _now_utc()
    conversation_uuid = _parse_uuid(conversation_id, field_name="conversation_id")
    conversation = await get_conversation(db, conversation_id=conversation_uuid)
    if conversation is None:
        raise NotFoundError("Conversation not found")
    if conversation["status"] == "closed":
        raise ForbiddenError("Conversation is closed")
    if conversation["status"] == "expired":
        raise ForbiddenError("Conversation is expired")
    expires_at = conversation.get("expires_at")
    if expires_at is not None and expires_at <= effective_now:
        await expire_conversation(db, conversation_id=conversation_uuid)
        raise ForbiddenError("Conversation is expired")
    return conversation


async def _equivalent_identity_refs(
    db,
    did: str,
    *,
    did_key: str | None = None,
    agent_id: str | UUID | None = None,
) -> tuple[list[str], list[UUID]]:
    """Return all identity refs (did_aw + did_key) and agent_ids equivalent to the input.

    Walking is anchored on did_key when available: the cryptographic key is
    collision-resistant. did_aw is name-stable but can collide across distinct
    cryptographic identities (e.g., post-rotation, adversarial registration);
    we only walk by did_aw when no did_key is reachable from the inputs.
    """
    refs: list[str] = []
    for value in (did, did_key):
        normalized = str(value or "").strip()
        if normalized and normalized not in refs:
            refs.append(normalized)

    agent_ids: list[UUID] = []
    agent_uuid = _uuid_or_none(agent_id, field_name="agent_id")
    if agent_uuid is not None:
        agent_ids.append(agent_uuid)

    if not refs and agent_uuid is None:
        return [], []

    aweb_db = db.get_manager("aweb")

    # Anchor the cryptographic identity. If we have agent_id, fetch its
    # did_key from the agents table so a multi-team agent's other team rows
    # can be found via did_key match below. seed_did_keys gates the strict
    # walk; seed_did_aw is captured for the best-effort walk fallback.
    seed_did_keys: list[str] = []
    input_did_key = (did_key or "").strip()
    if input_did_key:
        seed_did_keys.append(input_did_key)
    seed_did_aws: list[str] = []
    input_did = (did or "").strip()
    if input_did and input_did not in seed_did_keys:
        seed_did_aws.append(input_did)

    if agent_uuid is not None:
        seed_row = await aweb_db.fetch_one(
            """
            SELECT did_aw, did_key
            FROM {{tables.agents}}
            WHERE deleted_at IS NULL
              AND agent_id = $1
            """,
            agent_uuid,
        )
        if seed_row is not None:
            seed_did_key = str(seed_row.get("did_key") or "").strip()
            if seed_did_key and seed_did_key not in seed_did_keys:
                seed_did_keys.append(seed_did_key)
            seed_did_aw = str(seed_row.get("did_aw") or "").strip()
            if seed_did_aw and seed_did_aw not in seed_did_aws and seed_did_aw not in seed_did_keys:
                seed_did_aws.append(seed_did_aw)
            for value in (seed_did_aw, seed_did_key):
                if value and value not in refs:
                    refs.append(value)

    rows: list[dict[str, Any]] = []
    if seed_did_keys:
        # Strict cryptographic walk: only matches rows sharing the did_key.
        # Multi-team agents (same did_key, multiple agent_ids) expand here;
        # did_aw collisions (different did_keys, same did_aw) do not.
        rows = await aweb_db.fetch_all(
            """
            SELECT agent_id, did_aw, did_key
            FROM {{tables.agents}}
            WHERE deleted_at IS NULL
              AND did_key = ANY($1::text[])
            """,
            seed_did_keys,
        )
    elif seed_did_aws:
        # Best-effort name walk for callers without a did_key (external/
        # unauthenticated). This path can conflate did_aw collisions; trust
        # of the input is the caller's responsibility.
        rows = await aweb_db.fetch_all(
            """
            SELECT agent_id, did_aw, did_key
            FROM {{tables.agents}}
            WHERE deleted_at IS NULL
              AND did_aw = ANY($1::text[])
            """,
            seed_did_aws,
        )

    for row in rows:
        row_agent_id = _uuid_or_none(row.get("agent_id"), field_name="agent_id")
        if row_agent_id is not None and row_agent_id not in agent_ids:
            agent_ids.append(row_agent_id)
        for value in (row.get("did_aw"), row.get("did_key")):
            normalized = str(value or "").strip()
            if normalized and normalized not in refs:
                refs.append(normalized)
    return refs, agent_ids


def _identity_address_refs(*values: str | None) -> list[str]:
    refs: list[str] = []
    for value in values:
        normalized = str(value or "").strip()
        if normalized and normalized not in refs:
            refs.append(normalized)
    return refs


async def find_active_one_to_one_conversation_between(
    db,
    *,
    conversation_type: ConversationType,
    did_a: str,
    did_b: str,
    did_key_a: str | None = None,
    did_key_b: str | None = None,
    agent_id_a: str | UUID | None = None,
    agent_id_b: str | UUID | None = None,
    address_a: str | None = None,
    address_b: str | None = None,
) -> dict[str, Any] | None:
    """Return the unique active 1:1 conversation shared by two identities.

    First-contact reachability is enforced before a conversation exists. Once an
    active 1:1 conversation exists, participant membership is the routing
    authority. Ambiguous parallel conversations are surfaced rather than guessed.
    """
    normalized_type = _normalize_type(conversation_type)
    dids_a, agent_ids_a = await _equivalent_identity_refs(
        db,
        did_a,
        did_key=did_key_a,
        agent_id=agent_id_a,
    )
    dids_b, agent_ids_b = await _equivalent_identity_refs(
        db,
        did_b,
        did_key=did_key_b,
        agent_id=agent_id_b,
    )
    addresses_a = _identity_address_refs(address_a)
    addresses_b = _identity_address_refs(address_b)
    if not (dids_a or agent_ids_a or addresses_a) or not (dids_b or agent_ids_b or addresses_b):
        return None

    aweb_db = db.get_manager("aweb")
    # This participation check is intentionally table-authoritative. It must
    # not go through address resolution or resolver caches: once a 1:1 channel
    # exists, the recorded participants are the routing authority for replies.
    rows = await aweb_db.fetch_all(
        """
        SELECT c.conversation_id, c.conversation_type, c.status, c.team_id,
               c.created_by_did, c.created_at, c.updated_at, c.closed_at, c.expires_at
        FROM {{tables.conversations}} c
        JOIN {{tables.conversation_participants}} pa
          ON pa.conversation_id = c.conversation_id
        JOIN {{tables.conversation_participants}} pb
          ON pb.conversation_id = c.conversation_id
        WHERE c.conversation_type = $1
          AND c.status = 'active'
          AND (
                (
                    $3::uuid[] <> '{}'::uuid[]
                    AND (
                        pa.agent_id = ANY($3::uuid[])
                        OR (pa.agent_id IS NULL AND pa.did = ANY($2::text[]))
                    )
                )
             OR (
                    $3::uuid[] = '{}'::uuid[]
                    AND pa.did = ANY($2::text[])
                )
             OR ($4::text[] <> '{}'::text[] AND pa.address = ANY($4::text[]))
          )
          AND (
                (
                    $6::uuid[] <> '{}'::uuid[]
                    AND (
                        pb.agent_id = ANY($6::uuid[])
                        OR (pb.agent_id IS NULL AND pb.did = ANY($5::text[]))
                    )
                )
             OR (
                    $6::uuid[] = '{}'::uuid[]
                    AND pb.did = ANY($5::text[])
                )
             OR ($7::text[] <> '{}'::text[] AND pb.address = ANY($7::text[]))
          )
          AND pa.did <> pb.did
          AND (
                SELECT COUNT(*)::int
                FROM {{tables.conversation_participants}} cp
                WHERE cp.conversation_id = c.conversation_id
              ) = 2
        ORDER BY c.updated_at DESC, c.created_at DESC, c.conversation_id DESC
        LIMIT 2
        """,
        normalized_type,
        dids_a,
        agent_ids_a,
        addresses_a,
        dids_b,
        agent_ids_b,
        addresses_b,
    )
    if len(rows) > 1:
        raise ConflictError("Multiple active conversations match these participants")
    if not rows:
        return None
    return _conversation_dict(dict(rows[0]))


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
                    conversation_id, did, agent_id, alias, address, delivery_origin, transport_hint, role
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                ON CONFLICT (conversation_id, did) DO UPDATE
                SET agent_id = EXCLUDED.agent_id,
                    alias = EXCLUDED.alias,
                    address = EXCLUDED.address,
                    delivery_origin = EXCLUDED.delivery_origin,
                    transport_hint = EXCLUDED.transport_hint,
                    role = EXCLUDED.role
                """,
                conversation_id,
                participant["did"],
                participant["agent_id"],
                participant["alias"],
                participant["address"],
                participant["delivery_origin"],
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
        SELECT conversation_id, did, agent_id, alias, address, delivery_origin, transport_hint, role, joined_at
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
            conversation_id, did, agent_id, alias, address, delivery_origin, transport_hint, role
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (conversation_id, did) DO UPDATE
        SET agent_id = EXCLUDED.agent_id,
            alias = EXCLUDED.alias,
            address = EXCLUDED.address,
            delivery_origin = EXCLUDED.delivery_origin,
            transport_hint = EXCLUDED.transport_hint,
            role = EXCLUDED.role
        RETURNING conversation_id, did, agent_id, alias, address, delivery_origin, transport_hint, role, joined_at
        """,
        _parse_uuid(conversation_id, field_name="conversation_id"),
        record["did"],
        record["agent_id"],
        record["alias"],
        record["address"],
        record["delivery_origin"],
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
        SELECT conversation_id, did, agent_id, alias, address, delivery_origin, transport_hint, role, joined_at
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
            expires_at = COALESCE($3::timestamptz, expires_at)
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
