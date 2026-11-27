"""Shared team room storage. Authentication remains in existing team paths."""

from __future__ import annotations

import base64
import json
import logging
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from awid.signing import VerifyResult, verify_did_key_signature, verify_signature
from pydantic import BaseModel, ConfigDict, Field
from pydantic import ValidationError as ModelError

from aweb.agent_wake import record_agent_wake, team_room_wake_key
from aweb.federation.envelope import (
    FederationEnvelopeError,
    enforce_message_timestamp_skew,
)
from aweb.event_types import MutationEventType
from aweb.hooks import MutationCallback, fire_mutation_callback
from aweb.message_events import RoomMessageSentContext
from aweb.id_chain_auth import stored_id_chain
from aweb.identity_address import require_address_evidence
from aweb.member_team_key import current_member_sql
from aweb.messaging.sender_membership import sender_memberships
from aweb.service_errors import (
    ConflictError,
    CurrentMembershipRefusal,
    ForbiddenError,
    NotFoundError,
    ValidationError,
)

logger = logging.getLogger(__name__)
# Released aw 1.36.x recognizes this exact refusal (cmd/aw/room.go).
ROOM_CURRENT_MEMBERSHIP_REQUIRED_DETAIL = "Room requires current team membership"
ROOM_DISCLOSURE = "Team room posts are readable by the service operator and all current and future team members."
ROOM_POLICY = {
    "confidentiality": "server_readable",
    "history_visibility": "current_and_future_members",
    "notice": ROOM_DISCLOSURE,
}


class RoomPost(BaseModel):
    model_config = ConfigDict(extra="forbid")
    room_id: UUID
    signed_payload: str = Field(min_length=1, max_length=150000)
    signature: str = Field(min_length=1, max_length=128)
    signing_key_id: str
    e2ee: bool = False


class _SignedPost(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    type: Literal["chat"]
    conversation_id: str
    message_id: str
    from_did: str
    from_stable_id: str = ""
    from_label: str = Field(alias="from", min_length=1)
    to: str
    to_did: Literal[""]
    subject: str = Field(max_length=512)
    body: str = Field(min_length=1, max_length=64000)
    timestamp: str


def _uuid(value: str) -> UUID:
    try:
        result = UUID(value)
        if str(result) != value:
            raise ValueError()
        return result
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValidationError("Invalid room message ID") from exc


async def _active_member(tx, actor):
    # Lock the member while doing this operation, so an inactive/deleted row
    # cannot retain access through a previously authenticated context.
    row = await tx.fetch_one(
        f"""
        SELECT a.agent_id FROM {{{{tables.agents}}}} a
        WHERE a.agent_id=$1 AND a.team_id=$2 AND a.did_key=$3
          AND {current_member_sql("a")} FOR SHARE OF a
    """,
        UUID(actor.agent_id),
        actor.team_id,
        actor.did_key,
    )
    if not row:
        logger.warning("Room access refused: actor is not an active team member")
        raise CurrentMembershipRefusal(ROOM_CURRENT_MEMBERSHIP_REQUIRED_DETAIL)


async def _ensure_room(tx, team_id):
    await tx.execute(
        "INSERT INTO {{tables.team_rooms}} (team_id) VALUES ($1) ON CONFLICT (team_id) DO NOTHING",
        team_id,
    )
    return await tx.fetch_one(
        "SELECT room_id,team_id FROM {{tables.team_rooms}} WHERE team_id=$1", team_id
    )


async def room_metadata(db, actor):
    """Return the current team's shared room identity and visibility metadata."""
    async with db.get_manager("aweb").transaction() as tx:
        await _active_member(tx, actor)
        room = await _ensure_room(tx, actor.team_id)
        return {
            "team_id": room["team_id"],
            "room_id": str(room["room_id"]),
            **ROOM_POLICY,
        }


def _post_dict(row, team_id):
    signed = json.loads(row["signed_payload"])
    return {
        "team_id": team_id,
        "room_id": str(row["room_id"]),
        "conversation_id": str(row["room_id"]),
        "message_id": str(row["message_id"]),
        "sequence": row["sequence"],
        "from_did": row["from_did"],
        "from_stable_id": row["from_stable_id"],
        "from_alias": signed["from"],
        "subject": signed["subject"],
        "body": signed["body"],
        "timestamp": signed["timestamp"],
        "signed_payload": row["signed_payload"],
        "signature": row["signature"],
        "signing_key_id": row["signing_key_id"],
        "id_chain": stored_id_chain(row["id_chain"]),
        "created_at": row["created_at"].astimezone(timezone.utc).isoformat(),
        **ROOM_POLICY,
    }


async def present_room(db, request, output):
    """Use the same delivery-team sender evidence as mail/chat readers."""
    items = output.get("messages") if "messages" in output else [output]
    if not items:
        return output
    rows = await db.get_manager("aweb").fetch_all(
        """
        SELECT m.message_id,m.from_agent_id,r.team_id FROM {{tables.room_messages}} m
        JOIN {{tables.team_rooms}} r ON r.room_id=m.room_id
        WHERE m.message_id=ANY($1::uuid[])
    """,
        [UUID(item["message_id"]) for item in items],
    )
    memberships = await sender_memberships(request, db, rows)
    by_id = {str(row["message_id"]): row for row in rows}
    for item in items:
        row = by_id[item["message_id"]]
        item["sender_membership"] = memberships[
            (row["team_id"], str(row["from_agent_id"] or ""))
        ].model_dump()
        item["from_address"] = item["from_alias"] if "/" in item["from_alias"] else ""
        try:
            signed = _SignedPost.model_validate_json(item["signed_payload"])
            valid = (
                signed.to == "team-room:" + item["team_id"]
                and signed.conversation_id == item["room_id"] == item["conversation_id"]
                and signed.message_id == item["message_id"]
                and signed.from_did == item["from_did"]
                and signed.from_stable_id == (item["from_stable_id"] or "")
                and item["signing_key_id"] == item["from_did"]
                and verify_signature(
                    item["from_did"], item["signed_payload"].encode(), item["signature"]
                )
                == VerifyResult.VERIFIED
            )
        except ModelError:
            valid = False
        item["verification_status"] = "verified" if valid else "failed"
    return output


def _cursor(room_id, team_id, sequence):
    raw = json.dumps([str(room_id), team_id, sequence], separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _after(cursor, room_id, team_id):
    if cursor is None:
        return 0
    try:
        if not cursor or len(cursor) > 1024:
            raise ValueError()
        value = json.loads(
            base64.b64decode(
                cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True
            )
        )
        if (
            not isinstance(value, list)
            or len(value) != 3
            or value[:2] != [str(room_id), team_id]
        ):
            raise ValueError()
        if type(value[2]) is not int or value[2] < 1:
            raise ValueError()
        return value[2]
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ValidationError("Invalid room cursor") from exc


async def read_room(db, actor, *, after=None, limit=50):
    """Read retained team room posts and clear only notices for the returned page."""
    if not 1 <= limit <= 200:
        raise ValidationError("Room limit must be between 1 and 200")
    async with db.get_manager("aweb").transaction() as tx:
        await _active_member(tx, actor)
        room = await _ensure_room(tx, actor.team_id)
        sequence = _after(after, room["room_id"], actor.team_id)
        rows = await tx.fetch_all(
            "SELECT * FROM {{tables.room_messages}} WHERE room_id=$1 AND sequence>$2 ORDER BY sequence LIMIT $3",
            room["room_id"],
            sequence,
            limit + 1,
        )
        more = len(rows) > limit
        rows = rows[:limit]
        if rows:
            await tx.execute(
                "DELETE FROM {{tables.room_post_notices}} WHERE recipient_agent_id=$1 AND message_id=ANY($2::uuid[])",
                UUID(actor.agent_id),
                [row["message_id"] for row in rows],
            )
        return {
            "team_id": actor.team_id,
            "room_id": str(room["room_id"]),
            **ROOM_POLICY,
            "messages": [_post_dict(row, actor.team_id) for row in rows],
            "has_more": more,
            "next_cursor": (
                _cursor(room["room_id"], actor.team_id, rows[-1]["sequence"])
                if more
                else None
            ),
        }


async def exact_room_message(db, actor, message_id):
    """Read one retained room post without clearing its notice."""
    message_uuid = _uuid(message_id)
    async with db.get_manager("aweb").transaction() as tx:
        await _active_member(tx, actor)
        row = await tx.fetch_one(
            """
            SELECT m.* FROM {{tables.room_messages}} m
            JOIN {{tables.team_rooms}} r ON r.room_id=m.room_id
            WHERE m.message_id=$1 AND r.team_id=$2
        """,
            message_uuid,
            actor.team_id,
        )
        if not row:
            raise NotFoundError()
        return _post_dict(row, actor.team_id)


async def post_room_message(
    db,
    actor,
    post: RoomPost,
    *,
    id_chain=None,
    on_mutation: MutationCallback | None = None,
):
    """Verify and commit a signed team room post, emitting one callback only for a new commit."""
    require_address_evidence(actor)
    if post.e2ee:
        raise ValidationError("room_e2ee_unsupported")
    # Authenticate the preserved bytes before trusting any claims in them.
    try:
        verify_did_key_signature(
            did_key=actor.did_key,
            payload=post.signed_payload.encode(),
            signature_b64=post.signature,
        )
    except ValueError as exc:
        logger.warning("Room post signature verification failed")
        raise ForbiddenError("Invalid room post signature") from exc
    try:
        signed = _SignedPost.model_validate_json(post.signed_payload)
    except ModelError as exc:
        logger.warning(
            "Invalid signed room post fields: %s",
            [(e["loc"], e["type"]) for e in exc.errors()],
        )
        raise ValidationError("Invalid signed room post") from exc
    message_id = _uuid(signed.message_id)
    if (
        post.signing_key_id != actor.did_key
        or signed.from_did != actor.did_key
        or signed.from_stable_id != (actor.did_aw or "")
        or signed.from_label
        not in {actor.alias, actor.address, actor.did_key, actor.did_aw}
        or signed.to != "team-room:" + actor.team_id
        or signed.conversation_id != str(post.room_id)
    ):
        logger.warning("Room post signed sender or target binding mismatch")
        raise ValidationError("Signed room post binding mismatch")
    # docs/aw-hooks-sot.md:92: build metadata before commit; emit only a new post.
    context = RoomMessageSentContext(
        team_id=actor.team_id,
        room_id=str(post.room_id),
        message_id=str(message_id),
        from_agent_id=actor.agent_id,
        from_did=actor.did_key,
        from_did_aw=actor.did_aw,
        from_alias=actor.alias or actor.did_key,
    ).to_context()
    async with db.get_manager("aweb").transaction() as tx:
        await _active_member(tx, actor)
        # Serializing room appends makes sequence order also commit order;
        # pagination cannot skip a lower sequence committed after its cursor.
        room = await tx.fetch_one(
            "SELECT room_id FROM {{tables.team_rooms}} WHERE team_id=$1 FOR UPDATE",
            actor.team_id,
        )
        if not room or room["room_id"] != post.room_id:
            raise ValidationError("Signed room post binding mismatch")
        existing = await tx.fetch_one(
            "SELECT * FROM {{tables.room_messages}} WHERE message_id=$1", message_id
        )
        if existing:
            if (
                existing["room_id"] == post.room_id
                and existing["signed_payload"] == post.signed_payload
                and existing["signature"] == post.signature
            ):
                return _post_dict(existing, actor.team_id)
            logger.warning("Room message ID conflicts with an existing signed post")
            raise ConflictError("Room message ID already used")
        try:
            timestamp = datetime.fromisoformat(signed.timestamp.replace("Z", "+00:00"))
            if timestamp.tzinfo is None or timestamp.microsecond:
                raise ValueError()
            enforce_message_timestamp_skew(timestamp)
        except (ValueError, FederationEnvelopeError) as exc:
            logger.warning(
                "Room post timestamp is invalid or outside the shared skew bound"
            )
            raise ValidationError(
                "Invalid room post timestamp or outside accepted skew"
            ) from exc
        row = await tx.fetch_one(
            """
            INSERT INTO {{tables.room_messages}}
            (message_id,room_id,from_did,from_stable_id,signed_payload,signature,signing_key_id,id_chain,from_agent_id)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9)
            ON CONFLICT (message_id) DO NOTHING RETURNING *
        """,
            message_id,
            post.room_id,
            actor.did_key,
            actor.did_aw or None,
            post.signed_payload,
            post.signature,
            post.signing_key_id,
            json.dumps(id_chain) if id_chain is not None else None,
            UUID(actor.agent_id),
        )
        if row is None:
            # A concurrent append to another team's room won this global ID.
            raise ConflictError("Room message ID already used")
        await tx.execute(
            """WITH recipients AS (
                SELECT a.agent_id FROM {{tables.agents}} a
                WHERE a.team_id=$2 AND a.agent_id<>$3 AND """
            + current_member_sql("a")
            + """
                ORDER BY a.agent_id FOR SHARE OF a
            )
            INSERT INTO {{tables.room_post_notices}} (message_id, recipient_agent_id)
            SELECT $1, agent_id FROM recipients
            ON CONFLICT DO NOTHING""",
            message_id,
            actor.team_id,
            UUID(actor.agent_id),
        )
        record_agent_wake(team_room_wake_key(actor.team_id), "room")
        output = _post_dict(row, actor.team_id)
    await fire_mutation_callback(
        on_mutation, MutationEventType.ROOM_MESSAGE_SENT.value, context
    )
    return output
