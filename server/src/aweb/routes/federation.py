from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request

from awid.log import canonical_server_origin

from aweb.awid_error_handling import (
    AWID_DEPENDENCY_ERRORS,
    awid_dependency_http_exception,
    awid_registry_not_configured_exception,
)
from aweb.config import get_settings
from aweb.deps import get_db
from aweb.e2ee_messages import encrypted_message_storage_metadata
from aweb.federation.envelope import (
    FederatedDeliveryRequest,
    FederationEnvelope,
    FederationEnvelopeError,
    verify_federation_envelope,
)
from aweb.hooks import fire_mutation_hook
from aweb.messaging.conversations import (
    create_conversation,
    get_conversation,
    list_conversation_participants,
    touch_conversation_activity,
)
from aweb.messaging.chat import ensure_session, send_in_session
from aweb.messaging.messages import (
    deliver_message,
    authorize_message_delivery,
    resolve_agent_by_did,
    utc_iso,
)
from aweb.service_errors import ForbiddenError, NotFoundError, ValidationError

router = APIRouter(prefix="/v1/federation", tags=["aweb-federation"])


def _public_origins(request: Request) -> set[str]:
    origins = {
        canonical_server_origin(value)
        for value in getattr(request.app.state, "federation_public_origins", [])
        if str(value or "").strip()
    }
    configured = str(getattr(request.app.state, "public_origin", "") or "").strip()
    if configured:
        origins.add(canonical_server_origin(configured))
    if not origins:
        origins.add(get_settings().public_origin)
    return origins


def _parse_timestamp(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception as exc:
        raise HTTPException(status_code=422, detail="Invalid federation timestamp") from exc


def _split_address(address: str) -> tuple[str, str]:
    if "/" not in address:
        raise HTTPException(status_code=422, detail="Federation target_address must be domain/name")
    domain, name = address.split("/", 1)
    if not domain.strip() or not name.strip():
        raise HTTPException(status_code=422, detail="Federation target_address must be domain/name")
    return domain.strip(), name.strip()


def _participant_alias_from_address(address: str | None, fallback: str) -> str:
    if address and "/" in address:
        _, name = address.split("/", 1)
        if name.strip():
            return name.strip()
    return fallback


def _federated_transport_hint(origin: str | None) -> str:
    if not origin:
        return "federation"
    return f"federation:{canonical_server_origin(origin)}"


def _is_local_did_key(value: str | None) -> bool:
    return str(value or "").strip().startswith("did:key:")


async def _backfill_federated_sender_current_key(db, envelope: FederationEnvelope, *, chat_session: bool = False) -> None:
    sender_did_aw = str(envelope.sender_did_aw or "").strip()
    current_did_key = str(envelope.sender_current_did_key or "").strip()
    if not sender_did_aw.startswith("did:aw:") or not current_did_key.startswith("did:key:"):
        return
    if not envelope.conversation_id:
        return
    conversation_id = UUID(envelope.conversation_id)
    aweb_db = db.get_manager("aweb")
    await aweb_db.execute(
        """
        UPDATE {{tables.conversation_participants}}
        SET current_did_key = $3
        WHERE conversation_id = $1 AND did = $2
        """,
        conversation_id,
        sender_did_aw,
        current_did_key,
    )
    if chat_session:
        await aweb_db.execute(
            """
            UPDATE {{tables.chat_participants}}
            SET current_did_key = $3
            WHERE session_id = $1 AND did = $2
            """,
            conversation_id,
            sender_did_aw,
            current_did_key,
        )




async def _verify_sender_current_key(registry_client, envelope: FederationEnvelope) -> None:
    if envelope.sender_did_aw.startswith("did:key:"):
        if envelope.sender_current_did_key != envelope.sender_did_aw:
            raise HTTPException(status_code=422, detail="Federation sender local key mismatch")
        return
    try:
        resolution = await registry_client.resolve_key(envelope.sender_did_aw)
        if (
            resolution
            and resolution.current_did_key != envelope.sender_current_did_key
            and hasattr(registry_client, "resolve_key_fresh")
        ):
            resolution = await registry_client.resolve_key_fresh(envelope.sender_did_aw)
    except AWID_DEPENDENCY_ERRORS as exc:
        raise awid_dependency_http_exception(exc, operation="AWID federation sender key verification") from exc
    except Exception as exc:
        raise awid_dependency_http_exception(exc, operation="AWID federation sender key verification") from exc
    if not resolution or resolution.current_did_key != envelope.sender_current_did_key:
        raise HTTPException(status_code=422, detail="Federation sender current key mismatch")


async def _resolve_target_identity(
    registry_client,
    envelope: FederationEnvelope,
    *,
    stored_route_continuation: bool = False,
):
    if stored_route_continuation:
        return None
    if "/" not in envelope.target_address:
        raise HTTPException(status_code=422, detail="Federation first-contact target_address must be domain/name")
    try:
        domain, name = _split_address(envelope.target_address)
        resolved = await registry_client.resolve_address(domain, name)
    except HTTPException:
        raise
    except AWID_DEPENDENCY_ERRORS as exc:
        raise awid_dependency_http_exception(exc, operation="AWID federation target identity resolution") from exc
    except Exception as exc:
        raise awid_dependency_http_exception(exc, operation="AWID federation target identity resolution") from exc
    if resolved is None:
        raise HTTPException(status_code=404, detail="Federation target identity not found")
    if resolved.did_aw != envelope.target_did_aw:
        raise HTTPException(status_code=422, detail="Federation target did:aw mismatch")
    if resolved.current_did_key != envelope.target_current_did_key:
        raise HTTPException(status_code=422, detail="Federation target current key mismatch")
    delivery = getattr(resolved, "delivery", None)
    try:
        resolved_origin = canonical_server_origin(
            str(getattr(delivery, "origin", "") or "").strip()
        )
    except Exception as exc:
        raise HTTPException(status_code=424, detail="Federation target address has no delivery origin") from exc
    if resolved_origin != envelope.target_delivery_origin:
        raise HTTPException(status_code=422, detail="Federation target delivery origin mismatch")
    return resolved




def _require_target_origin_here(request: Request, envelope: FederationEnvelope) -> None:
    if envelope.target_delivery_origin not in _public_origins(request):
        raise HTTPException(status_code=421, detail="Federation message is addressed to a different delivery origin")


def _delivery_response(envelope: FederationEnvelope, *, message_id: str, conversation_id: str, created_at: datetime) -> dict:
    response = {
        "message_id": message_id,
        "conversation_id": conversation_id,
        "status": "delivered",
        "delivered_at": utc_iso(created_at),
    }
    if envelope.type == "chat":
        response["session_id"] = conversation_id
    return response


def _envelope_is_encrypted_v2(envelope: FederationEnvelope) -> bool:
    return (
        envelope.content_mode == "encrypted_v2"
        or envelope.message_version == 2
        or envelope.encrypted_envelope is not None
    )


async def _idempotent_existing_message(db, envelope: FederationEnvelope) -> tuple[str, datetime] | None:
    aweb_db = db.get_manager("aweb")
    if _envelope_is_encrypted_v2(envelope):
        row = await aweb_db.fetch_one(
            """
            SELECT message_id, conversation_id, from_did, to_did, from_address, content_mode,
                   signed_envelope_hash, created_at
            FROM {{tables.messages}}
            WHERE message_id = $1
            """,
            UUID(envelope.message_id),
        )
    else:
        row = await aweb_db.fetch_one(
            """
            SELECT message_id, conversation_id, from_did, to_did, from_address, subject,
                   body, priority, created_at
            FROM {{tables.messages}}
            WHERE message_id = $1
            """,
            UUID(envelope.message_id),
        )
    if row is None:
        return None
    if _envelope_is_encrypted_v2(envelope):
        expected = encrypted_message_storage_metadata(envelope.encrypted_envelope or {}).get("signed_envelope_hash")
        if (
            str(row["conversation_id"]) != str(envelope.conversation_id)
            or row["from_did"] != envelope.sender_did_aw
            or row["to_did"] != envelope.target_did_aw
            or (row.get("from_address") or "") != (envelope.sender_address or "")
            or row["content_mode"] != "encrypted_v2"
            or row["signed_envelope_hash"] != expected
        ):
            raise HTTPException(status_code=409, detail="Federation message_id already exists with different encrypted envelope")
        return str(row["conversation_id"]), row["created_at"]
    if (
        str(row["conversation_id"]) != str(envelope.conversation_id)
        or row["from_did"] != envelope.sender_did_aw
        or row["to_did"] != envelope.target_did_aw
        or (row.get("from_address") or "") != (envelope.sender_address or "")
        or row["subject"] != (envelope.subject or "")
        or row["body"] != envelope.body
        or row["priority"] != (envelope.priority or "normal")
    ):
        raise HTTPException(status_code=409, detail="Federation message_id already exists with different content")
    return str(row["conversation_id"]), row["created_at"]


async def _idempotent_existing_chat_message(db, envelope: FederationEnvelope) -> tuple[str, datetime] | None:
    aweb_db = db.get_manager("aweb")
    if _envelope_is_encrypted_v2(envelope):
        row = await aweb_db.fetch_one(
            """
            SELECT message_id, session_id, from_did, from_address, content_mode,
                   signed_envelope_hash, sender_leaving, hang_on, reply_to, created_at
            FROM {{tables.chat_messages}}
            WHERE message_id = $1
            """,
            UUID(envelope.message_id),
        )
    else:
        row = await aweb_db.fetch_one(
            """
            SELECT message_id, session_id, from_did, from_address, body, sender_leaving,
                   hang_on, reply_to, created_at
            FROM {{tables.chat_messages}}
            WHERE message_id = $1
            """,
            UUID(envelope.message_id),
        )
    if row is None:
        return None
    if _envelope_is_encrypted_v2(envelope):
        expected = encrypted_message_storage_metadata(envelope.encrypted_envelope or {}).get("signed_envelope_hash")
        if (
            str(row["session_id"]) != str(envelope.conversation_id)
            or row["from_did"] != envelope.sender_did_aw
            or (row.get("from_address") or "") != (envelope.sender_address or "")
            or row["content_mode"] != "encrypted_v2"
            or row["signed_envelope_hash"] != expected
            or bool(row["sender_leaving"]) != envelope.sender_leaving
            or bool(row["hang_on"]) != envelope.hang_on
            or (str(row["reply_to"]) if row.get("reply_to") else None) != envelope.reply_to
        ):
            raise HTTPException(status_code=409, detail="Federation message_id already exists with different encrypted envelope")
        return str(row["session_id"]), row["created_at"]
    if (
        str(row["session_id"]) != str(envelope.conversation_id)
        or row["from_did"] != envelope.sender_did_aw
        or (row.get("from_address") or "") != (envelope.sender_address or "")
        or row["body"] != envelope.body
        or bool(row["sender_leaving"]) != envelope.sender_leaving
        or bool(row["hang_on"]) != envelope.hang_on
        or (str(row["reply_to"]) if row.get("reply_to") else None) != envelope.reply_to
    ):
        raise HTTPException(status_code=409, detail="Federation message_id already exists with different content")
    return str(row["session_id"]), row["created_at"]


async def _claim_federated_delivery(db, envelope: FederationEnvelope) -> bool:
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.federated_message_deliveries}} (
            message_type, sender_did_aw, target_did_aw, message_id, conversation_id
        )
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (message_type, sender_did_aw, target_did_aw, message_id) DO NOTHING
        RETURNING message_id
        """,
        envelope.type,
        envelope.sender_did_aw,
        envelope.target_did_aw,
        UUID(envelope.message_id),
        UUID(envelope.conversation_id) if envelope.conversation_id else None,
    )
    return row is not None


async def _release_federated_delivery_claim(db, envelope: FederationEnvelope) -> None:
    aweb_db = db.get_manager("aweb")
    await aweb_db.execute(
        """
        DELETE FROM {{tables.federated_message_deliveries}}
        WHERE message_type = $1
          AND sender_did_aw = $2
          AND target_did_aw = $3
          AND message_id = $4
        """,
        envelope.type,
        envelope.sender_did_aw,
        envelope.target_did_aw,
        UUID(envelope.message_id),
    )


async def _ensure_federated_mail_conversation(db, envelope: FederationEnvelope, recipient: dict) -> str:
    if not envelope.conversation_id:
        raise HTTPException(status_code=422, detail="Federated mail requires conversation_id")

    conversation = await get_conversation(db, conversation_id=envelope.conversation_id)
    if conversation is not None:
        if conversation["conversation_type"] != "mail":
            raise HTTPException(status_code=422, detail="Federation conversation is not mail")
        if conversation["status"] != "active":
            raise HTTPException(status_code=403, detail="Federation conversation is not active")
        participants = await list_conversation_participants(db, conversation_id=envelope.conversation_id)
        dids = {item["did"] for item in participants}
        if envelope.sender_did_aw not in dids or envelope.target_did_aw not in dids:
            raise HTTPException(status_code=403, detail="Federation conversation participants mismatch")
        await _backfill_federated_sender_current_key(db, envelope)
        return envelope.conversation_id

    if _is_local_did_key(envelope.target_did_aw):
        raise HTTPException(status_code=404, detail="Local did:key target requires an existing conversation")

    conversation = await create_conversation(
        db,
        conversation_type="mail",
        conversation_id=envelope.conversation_id,
        created_by_did=envelope.sender_did_aw,
        initiator={
            "did": envelope.sender_did_aw,
            "agent_id": None,
            "alias": _participant_alias_from_address(
                envelope.sender_address,
                envelope.sender_did_aw,
            ),
            "address": envelope.sender_address,
            "delivery_origin": envelope.sender_delivery_origin,
            "current_did_key": envelope.sender_current_did_key,
            "transport_hint": _federated_transport_hint(envelope.sender_delivery_origin),
        },
        recipients=[
            {
                "did": envelope.target_did_aw,
                "agent_id": recipient.get("agent_id"),
                "alias": recipient.get("alias") or _participant_alias_from_address(
                    envelope.target_address,
                    envelope.target_did_aw,
                ),
                "address": envelope.target_address,
                "current_did_key": envelope.target_current_did_key,
                "transport_hint": "local",
            }
        ],
        team_id=recipient.get("team_id"),
    )
    return conversation["conversation_id"]


def _validate_stored_target_current_key(*, envelope: FederationEnvelope, participant: dict | None) -> None:
    target_did = str(envelope.target_did_aw or "").strip()
    target_key = str(envelope.target_current_did_key or "").strip()
    if _is_local_did_key(target_did):
        if target_key != target_did:
            raise HTTPException(status_code=422, detail="Federation target current key mismatch")
        return
    stored_key = str((participant or {}).get("current_did_key") or "").strip()
    if stored_key and stored_key != target_key:
        raise HTTPException(status_code=422, detail="Federation target current key mismatch")


async def _federated_stored_route_continuation_exists(db, envelope: FederationEnvelope) -> bool:
    if not envelope.conversation_id:
        return False
    conversation = await get_conversation(db, conversation_id=envelope.conversation_id)
    if conversation is None or conversation.get("status") != "active":
        return False
    if conversation.get("conversation_type") != envelope.type:
        return False
    participants = await list_conversation_participants(db, conversation_id=envelope.conversation_id)
    by_did = {item["did"]: item for item in participants}
    if envelope.sender_did_aw not in by_did or envelope.target_did_aw not in by_did:
        return False
    _validate_stored_target_current_key(envelope=envelope, participant=by_did.get(envelope.target_did_aw))

    if envelope.type == "chat":
        aweb_db = db.get_manager("aweb")
        existing_session = await aweb_db.fetch_one(
            "SELECT session_id FROM {{tables.chat_sessions}} WHERE session_id = $1",
            UUID(envelope.conversation_id),
        )
        if existing_session is None:
            return False
        session_participants = await aweb_db.fetch_all(
            """
            SELECT did, current_did_key
            FROM {{tables.chat_participants}}
            WHERE session_id = $1
              AND did = ANY($2::text[])
            """,
            UUID(envelope.conversation_id),
            [envelope.sender_did_aw, envelope.target_did_aw],
        )
        session_by_did = {item["did"]: item for item in session_participants}
        if envelope.sender_did_aw not in session_by_did or envelope.target_did_aw not in session_by_did:
            raise HTTPException(status_code=403, detail="Federation chat session participants mismatch")
        _validate_stored_target_current_key(envelope=envelope, participant=session_by_did.get(envelope.target_did_aw))

    return True


async def _ensure_federated_chat_session(db, envelope: FederationEnvelope, recipient: dict) -> str:
    if not envelope.conversation_id:
        raise HTTPException(status_code=422, detail="Federated chat requires conversation_id")

    conversation = await get_conversation(db, conversation_id=envelope.conversation_id)
    if conversation is not None:
        if conversation["conversation_type"] != "chat":
            raise HTTPException(status_code=422, detail="Federation conversation is not chat")
        if conversation["status"] != "active":
            raise HTTPException(status_code=403, detail="Federation conversation is not active")
        participants = await list_conversation_participants(db, conversation_id=envelope.conversation_id)
        dids = {item["did"] for item in participants}
        if envelope.sender_did_aw not in dids or envelope.target_did_aw not in dids:
            raise HTTPException(status_code=403, detail="Federation conversation participants mismatch")
        if _is_local_did_key(envelope.target_did_aw):
            aweb_db = db.get_manager("aweb")
            existing_session = await aweb_db.fetch_one(
                "SELECT session_id FROM {{tables.chat_sessions}} WHERE session_id = $1",
                UUID(envelope.conversation_id),
            )
            if existing_session is None:
                raise HTTPException(status_code=404, detail="Local did:key target requires an existing session")
            session_participants = await aweb_db.fetch_all(
                """
                SELECT did
                FROM {{tables.chat_participants}}
                WHERE session_id = $1
                  AND did = ANY($2::text[])
                """,
                UUID(envelope.conversation_id),
                [envelope.sender_did_aw, envelope.target_did_aw],
            )
            session_dids = {item["did"] for item in session_participants}
            if {envelope.sender_did_aw, envelope.target_did_aw} - session_dids:
                raise HTTPException(status_code=403, detail="Federation chat session participants mismatch")
            await _backfill_federated_sender_current_key(db, envelope, chat_session=True)
            return envelope.conversation_id

    if _is_local_did_key(envelope.target_did_aw):
        raise HTTPException(status_code=404, detail="Local did:key target requires an existing session")

    session_id = await ensure_session(
        db,
        team_id=recipient.get("team_id"),
        participant_rows=[
            {
                "did": envelope.sender_did_aw,
                "agent_id": None,
                "alias": _participant_alias_from_address(
                    envelope.sender_address,
                    envelope.sender_did_aw,
                ),
                "address": envelope.sender_address,
                "delivery_origin": envelope.sender_delivery_origin,
                "current_did_key": envelope.sender_current_did_key,
            },
            {
                "did": envelope.target_did_aw,
                "agent_id": recipient.get("agent_id"),
                "alias": recipient.get("alias") or _participant_alias_from_address(
                    envelope.target_address,
                    envelope.target_did_aw,
                ),
                "address": envelope.target_address,
                "delivery_origin": None,
                "current_did_key": envelope.target_current_did_key,
            },
        ],
        created_by=envelope.sender_did_aw,
        session_id=UUID(envelope.conversation_id),
    )
    return str(session_id)


@router.post("/messages")
async def receive_federated_message(
    request: Request,
    payload: FederatedDeliveryRequest,
    db=Depends(get_db),
):
    if payload.envelope.type not in {"mail", "chat"}:
        raise HTTPException(status_code=422, detail="Federation endpoint accepts mail or chat")
    registry_client = getattr(request.app.state, "awid_registry_client", None)
    if registry_client is None:
        raise awid_registry_not_configured_exception(operation="AWID federation receive registry lookup")

    try:
        envelope = verify_federation_envelope(
            payload.envelope,
            payload.signature,
            expected={
                "type": payload.envelope.type,
                "target_address": payload.envelope.target_address,
                "target_did_aw": payload.envelope.target_did_aw,
                "target_current_did_key": payload.envelope.target_current_did_key,
                "target_delivery_origin": payload.envelope.target_delivery_origin,
                "message_id": payload.envelope.message_id,
                "conversation_id": payload.envelope.conversation_id,
            },
        )
    except FederationEnvelopeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    _require_target_origin_here(request, envelope)
    await _verify_sender_current_key(registry_client, envelope)
    stored_route_continuation = await _federated_stored_route_continuation_exists(db, envelope)
    await _resolve_target_identity(
        registry_client,
        envelope,
        stored_route_continuation=stored_route_continuation,
    )

    recipient = await resolve_agent_by_did(db, envelope.target_did_aw)
    if recipient is None:
        recipient = await resolve_agent_by_did(db, envelope.target_current_did_key)
    if recipient is None:
        raise HTTPException(status_code=404, detail="Federation recipient agent not found")
    recipient_did_key = str(recipient.get("did_key") or "").strip()
    if recipient_did_key and recipient_did_key != envelope.target_current_did_key:
        raise HTTPException(status_code=422, detail="Federation target current key mismatch")

    if _is_local_did_key(envelope.target_did_aw) and not stored_route_continuation:
        detail = "Local did:key target requires an existing session" if envelope.type == "chat" else "Local did:key target requires an existing conversation"
        raise HTTPException(status_code=404, detail=detail)
    try:
        await authorize_message_delivery(
            db,
            recipient_agent=recipient,
            sender_did=envelope.sender_did_aw,
            sender_address=envelope.sender_address,
            stored_route_continuation=stored_route_continuation,
        )
    except ForbiddenError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    existing = (
        await _idempotent_existing_message(db, envelope)
        if envelope.type == "mail"
        else await _idempotent_existing_chat_message(db, envelope)
    )
    if existing is not None:
        conversation_id, created_at = existing
        return _delivery_response(
            envelope,
            message_id=envelope.message_id,
            conversation_id=conversation_id,
            created_at=created_at,
        )
    if not await _claim_federated_delivery(db, envelope):
        raise HTTPException(status_code=409, detail="Federated message delivery is already in progress")

    try:
        if envelope.type == "mail":
            conversation_id = await _ensure_federated_mail_conversation(db, envelope, recipient)
            encrypted_metadata = (
                encrypted_message_storage_metadata(envelope.encrypted_envelope or {})
                if _envelope_is_encrypted_v2(envelope)
                else None
            )
            message_id, created_at = await deliver_message(
                db,
                registry_client=registry_client,
                recipient_agent=recipient,
                from_did=envelope.sender_did_aw,
                to_did=envelope.target_did_aw,
                from_alias=_participant_alias_from_address(
                    envelope.sender_address,
                    envelope.sender_did_aw,
                ),
                to_alias=recipient.get("alias") or _participant_alias_from_address(
                    envelope.target_address,
                    envelope.target_did_aw,
                ),
                subject="" if encrypted_metadata is not None else (envelope.subject or ""),
                body="" if encrypted_metadata is not None else envelope.body,
                priority=envelope.priority or "normal",
                sender_address=envelope.sender_address,
                team_id=recipient.get("team_id"),
                from_agent_id=None,
                to_agent_id=recipient.get("agent_id"),
                signature=None if encrypted_metadata is not None else payload.signature,
                signed_payload=None if encrypted_metadata is not None else envelope.signed_payload,
                content_mode=envelope.content_mode or "legacy_plaintext_v1",
                message_version=envelope.message_version or 1,
                encrypted_envelope=envelope.encrypted_envelope,
                encrypted_metadata=encrypted_metadata,
                created_at=_parse_timestamp(envelope.timestamp),
                message_id=UUID(envelope.message_id),
                conversation_id=conversation_id,
                skip_policy_check=True,
            )
            await touch_conversation_activity(db, conversation_id=conversation_id)
        else:
            conversation_id = await _ensure_federated_chat_session(db, envelope, recipient)
            encrypted_metadata = (
                encrypted_message_storage_metadata(envelope.encrypted_envelope or {})
                if _envelope_is_encrypted_v2(envelope)
                else None
            )
            msg_row = await send_in_session(
                db,
                session_id=UUID(conversation_id),
                sender_did=envelope.sender_did_aw,
                sender_agent_id=None,
                sender_address=envelope.sender_address,
                body="" if encrypted_metadata is not None else envelope.body,
                reply_to=UUID(envelope.reply_to) if envelope.reply_to else None,
                leaving=envelope.sender_leaving,
                hang_on=envelope.hang_on,
                signature=None if encrypted_metadata is not None else payload.signature,
                signed_payload=None if encrypted_metadata is not None else envelope.signed_payload,
                content_mode=envelope.content_mode or "legacy_plaintext_v1",
                message_version=envelope.message_version or 1,
                encrypted_envelope=envelope.encrypted_envelope,
                encrypted_metadata=encrypted_metadata,
                created_at=_parse_timestamp(envelope.timestamp),
                message_id=UUID(envelope.message_id),
            )
            if msg_row is None:
                raise HTTPException(status_code=500, detail="Failed to store federated chat message")
            message_id = msg_row["message_id"]
            created_at = msg_row["created_at"]
    except (ValidationError, NotFoundError, ForbiddenError) as exc:
        await _release_federated_delivery_claim(db, envelope)
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    except Exception:
        await _release_federated_delivery_claim(db, envelope)
        raise

    await fire_mutation_hook(
        request,
        "message.sent" if envelope.type == "mail" else "chat.message_sent",
        {
            "team_id": recipient.get("team_id"),
            "from_agent_id": None,
            "from_did": envelope.sender_current_did_key,
            "from_did_aw": envelope.sender_did_aw,
            "to_agent_id": recipient.get("agent_id"),
            "from_alias": _participant_alias_from_address(envelope.sender_address, envelope.sender_did_aw),
            "message_id": str(message_id),
            "conversation_id": conversation_id,
            "session_id": conversation_id if envelope.type == "chat" else None,
            "to_alias": recipient.get("alias"),
            "subject": envelope.subject or "",
            "priority": envelope.priority or "normal",
            "content_mode": envelope.content_mode or "legacy_plaintext_v1",
            "federated": True,
        },
    )

    return _delivery_response(
        envelope,
        message_id=str(message_id),
        conversation_id=conversation_id,
        created_at=created_at,
    )
