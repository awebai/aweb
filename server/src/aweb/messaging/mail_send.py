"""Mail sends over a stored conversation route or to another server, for every adapter."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from uuid import UUID

import asyncpg
from fastapi import HTTPException
from pgdbm.errors import QueryError

from awid.registry import RegistryError
from aweb.agent_wake import agent_wake_scope
from aweb.attachment_service import refuse_remote_attachments
from aweb.e2ee_messages import (
    E2EEEnvelopeError,
    encrypted_message_storage_metadata,
    validate_e2ee_mail_envelope,
)
from aweb.federation.envelope import (
    FederationEnvelope,
    FederationEnvelopeError,
    enforce_message_timestamp_skew,
    verify_federation_envelope,
)
from aweb.federation.mail import FederatedMailDeliveryError, deliver_federated_message
from aweb.hooks import fire_mutation_callback
from aweb.identity_auth_deps import MessagingAuth, auth_dids, participant_dids
from aweb.identity_binding import observe_current_identity_binding
from aweb.messaging.address_auth import local_recipient_for_own_route, verified_signed_payload_json
from aweb.messaging.contacts import (
    resolve_local_namespace_controller_did,
    upsert_successful_identity_contact,
)
from aweb.messaging.conversations import create_conversation, touch_conversation_activity
from aweb.messaging.encryption_custody import require_non_custodial_recipients
from aweb.messaging.mail_routing import (
    MailContinuationContext,
    mail_continuation_context,
    participant_is_remote,
    recipient_for_conversation_participant,
    remote_recipient_from_participant,
)
from aweb.messaging.messages import (
    MessagePriority,
    admit_message_delivery,
    deliver_message,
    utc_iso as _utc_iso,
)
from aweb.messaging.participant_succession import predecessor_target_for_mail
from aweb.messaging.runtime import MessagingRuntime
from aweb.messaging.signatures import (
    MessageSignatureShapeError,
    validate_ed25519_message_signature,
)
from aweb.service_errors import ConflictError, ForbiddenError, NotFoundError, ServiceError, ValidationError

if TYPE_CHECKING:
    from aweb.routes.messages import SendMessageRequest


@dataclass(frozen=True)
class SentMail:
    """A stored mail send, as its sender is told of it."""

    message_id: str
    conversation_id: str | None
    status: str
    delivered_at: str


def _parse_signed_timestamp(value: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid timestamp format")
    if dt.tzinfo is None:
        raise HTTPException(status_code=422, detail="timestamp must be timezone-aware")
    dt = dt.astimezone(timezone.utc)
    if dt.microsecond != 0:
        raise HTTPException(status_code=422, detail="timestamp must be second precision")
    try:
        enforce_message_timestamp_skew(dt)
    except FederationEnvelopeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return dt


def _validate_signed_mail_payload(
    *,
    signature: str,
    signed_payload: str | None,
    recipient: dict | None,
    to_agent_id: str | None,
    to_alias: str | None,
    requested_to_alias: str | None,
    from_alias: str | None,
    from_address: str | None,
    from_stable_id: str | None,
    priority: MessagePriority,
    subject: str,
    body: str,
    from_did: str,
    message_id: str,
    timestamp: str,
    conversation_id: str | None = None,
) -> None:
    if signed_payload is None:
        raise HTTPException(status_code=422, detail="signed_payload is required when signature is provided")
    try:
        payload = json.loads(signed_payload)
    except Exception:
        raise HTTPException(status_code=422, detail="signed_payload must be valid JSON")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="signed_payload must be a JSON object")
    if payload.get("type") != "mail":
        raise HTTPException(status_code=422, detail="signed_payload type must be mail")
    allowed_from_values = {
        value
        for value in (
            str(from_alias or "").strip(),
            str(from_address or "").strip(),
            str(from_did or "").strip(),
            str(from_stable_id or "").strip(),
        )
        if value
    }
    signed_from = str(payload.get("from") or "").strip()
    if signed_from and signed_from not in allowed_from_values:
        raise HTTPException(status_code=422, detail="signed_payload from must match the authenticated sender")
    recipient_alias = (recipient or {}).get("alias") or ""
    recipient_address = (recipient or {}).get("address") or ""
    recipient_stable_id = (recipient or {}).get("did_aw") or ""
    recipient_current_did = (recipient or {}).get("did_key") or ""
    alias_values = (
        ()
        if "~" in str(requested_to_alias or "")
        else (str(to_alias or "").strip(), str(recipient_alias).strip())
    )
    allowed_to_values = {
        value
        for value in (
            str(to_agent_id or "").strip(),
            str(requested_to_alias or "").strip(),
            str(recipient_address).strip(),
            str(recipient_stable_id).strip(),
            str(recipient_current_did).strip(),
            *alias_values,
        )
        if value
    }
    signed_to = str(payload.get("to") or "").strip()
    if signed_to and signed_to not in allowed_to_values:
        raise HTTPException(status_code=422, detail="signed_payload recipient must match the mail recipient")
    signed_to_did = str(payload.get("to_did") or "").strip()
    if signed_to_did and signed_to_did not in {
        str(recipient_stable_id).strip(),
        str(recipient_current_did).strip(),
    }:
        raise HTTPException(status_code=422, detail="signed_payload recipient must match the mail recipient")
    signed_to_stable_id = str(payload.get("to_stable_id") or "").strip()
    if signed_to_stable_id and signed_to_stable_id != str(recipient_stable_id).strip():
        raise HTTPException(status_code=422, detail="signed_payload recipient must match the mail recipient")
    if (payload.get("priority") or "normal") != priority:
        raise HTTPException(status_code=422, detail="signed_payload priority must match the mail message")
    if payload.get("subject", "") != subject:
        raise HTTPException(status_code=422, detail="signed_payload subject must match the mail subject")
    if payload.get("body") != body:
        raise HTTPException(status_code=422, detail="signed_payload body must match the mail body")
    if payload.get("from_did") != from_did:
        raise HTTPException(status_code=422, detail="signed_payload from_did must match the authenticated sender")
    signed_from_stable_id = str(payload.get("from_stable_id") or "").strip()
    if signed_from_stable_id and signed_from_stable_id != str(from_stable_id or "").strip():
        raise HTTPException(
            status_code=422,
            detail="signed_payload from_stable_id must match the authenticated sender",
        )
    if payload.get("message_id") != message_id:
        raise HTTPException(status_code=422, detail="signed_payload message_id must match the mail message")
    if payload.get("timestamp") != timestamp:
        raise HTTPException(status_code=422, detail="signed_payload timestamp must match the mail message")
    signed_conversation_id = str(payload.get("conversation_id") or "").strip()
    if conversation_id is not None:
        if not signed_conversation_id:
            raise HTTPException(status_code=422, detail="signed_payload conversation_id is required")
        if signed_conversation_id != conversation_id:
            raise HTTPException(status_code=422, detail="signed_payload conversation_id must match")
    elif signed_conversation_id:
        raise HTTPException(status_code=422, detail="signed_payload conversation_id must match")
    try:
        validate_ed25519_message_signature(signature)
    except MessageSignatureShapeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _recipient_envelope_address(recipient: dict | None, payload: SendMessageRequest) -> str | None:
    address = str((recipient or {}).get("address") or "").strip()
    if address:
        return address
    requested_address = str(payload.to_address or "").strip()
    return requested_address or None


def _require_remote_mail_signature(payload: SendMessageRequest) -> None:
    if not payload.signature or not payload.signed_payload:
        raise HTTPException(
            status_code=422,
            detail="Federated mail delivery requires a sender-signed payload",
        )
    if not payload.from_did or not payload.from_did.strip():
        raise HTTPException(
            status_code=422,
            detail="from_did is required for federated mail delivery",
        )
    if not payload.message_id or not payload.timestamp or not payload.conversation_id:
        raise HTTPException(
            status_code=422,
            detail="message_id, timestamp, and conversation_id are required for federated mail delivery",
        )


def _validate_encrypted_payload(
    payload: SendMessageRequest,
    *,
    auth: MessagingAuth,
    sender_did: str,
    recipient: dict | None,
    recipient_did: str,
) -> dict | None:
    if payload.content_mode != "encrypted_v2":
        return None
    if payload.message_id is None or payload.conversation_id is None:
        raise HTTPException(
            status_code=422,
            detail="message_id and conversation_id are required for encrypted mail",
        )
    expected_recipient_did = str((recipient or {}).get("did_key") or recipient_did).strip()
    recipient_stable_id = str((recipient or {}).get("did_aw") or "").strip()
    recipient_address = _recipient_envelope_address(recipient, payload)
    if expected_recipient_did.startswith("did:key:") and not recipient_stable_id.startswith("did:aw:"):
        # For remote local-only participants, any stored address is a transport
        # hint. It is not an AWID address authority and must not be required in
        # the encrypted recipient binding.
        recipient_address = None
        recipient_stable_id = ""
    try:
        validate_e2ee_mail_envelope(
            payload.encrypted_envelope or {},
            message_id=payload.message_id,
            conversation_id=payload.conversation_id,
            sender_did=(auth.did_key or sender_did).strip(),
            sender_stable_id=(auth.did_aw or "").strip() or None,
            recipient_did=expected_recipient_did,
            recipient_stable_id=recipient_stable_id or None,
            recipient_address=recipient_address,
        )
    except E2EEEnvelopeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return encrypted_message_storage_metadata(payload.encrypted_envelope or {})


def _remote_delivery_origin(recipient: dict | None) -> str:
    return str((recipient or {}).get("delivery_origin") or "").strip()


def _concrete_contact_address(recipient: dict | None) -> str:
    address = str((recipient or {}).get("address") or "").strip()
    return address if "/" in address else ""


async def record_successful_contact_side_effect(
    db,
    *,
    owner_did: str,
    sender_team_id: str | None,
    recipient: dict | None,
    registry_client=None,
) -> bool:
    recipient_address = _concrete_contact_address(recipient)
    if not recipient_address:
        return False
    recipient_team_id = str((recipient or {}).get("team_id") or "").strip()
    sender_team = str(sender_team_id or "").strip()
    if sender_team and recipient_team_id and sender_team == recipient_team_id:
        return False
    controller_did = str(
        (recipient or {}).get("authority_controller_did") or ""
    ).strip()
    if not controller_did and (recipient or {}).get(
        "requires_local_address_authority"
    ):
        controller_did = (
            await resolve_local_namespace_controller_did(
                registry_client,
                contact_address=recipient_address,
                contact_did_aw=str((recipient or {}).get("did_aw") or ""),
                contact_current_did_key=str(
                    (recipient or {}).get("did_key") or ""
                ),
            )
            or ""
        )
    return await upsert_successful_identity_contact(
        db,
        owner_did=owner_did,
        contact_address=recipient_address,
        contact_did_aw=str((recipient or {}).get("did_aw") or "").strip() or None,
        binding_controller_did=controller_did or None,
        label=str((recipient or {}).get("alias") or recipient_address),
    )


async def deliver_remote_mail_and_project_locally(
    runtime: MessagingRuntime,
    payload: SendMessageRequest,
    db,
    *,
    auth: MessagingAuth,
    registry_client,
    sender_address: str | None,
    sender_did: str,
    id_chain: dict | None,
    recipient: dict,
    recipient_did: str,
    to_agent_id: str | None,
    to_alias: str | None,
    msg_uuid: UUID | None,
) -> SentMail:
    refuse_remote_attachments()
    delivery_origin = _remote_delivery_origin(recipient)
    if not delivery_origin:
        raise HTTPException(
            status_code=424,
            detail="Recipient address has no federated delivery origin",
        )
    local = await local_recipient_for_own_route(db, recipient, runtime)
    if local is not None:
        return await send_mail_conversation_continuation(
            runtime, payload, db, auth=auth, registry_client=registry_client,
            sender_address=sender_address, sender_did=sender_did, id_chain=id_chain,
            conversation_id=payload.conversation_id, local_recipient=local,
        )
    encrypted_metadata = _validate_encrypted_payload(
        payload,
        auth=auth,
        sender_did=sender_did,
        recipient=recipient,
        recipient_did=recipient_did,
    )
    if encrypted_metadata is not None:
        await require_non_custodial_recipients(
            db, payload.encrypted_envelope or {}, [recipient] if recipient else [], sender=auth,
        )
    is_encrypted = payload.content_mode == "encrypted_v2"
    if not is_encrypted:
        _require_remote_mail_signature(payload)
    federation_signature = (
        str((payload.encrypted_envelope or {}).get("signature") or "").strip()
        if is_encrypted
        else str(payload.signature or "").strip()
    )
    sender_routing_did = (auth.did_aw or auth.did_key or "").strip()
    if not sender_routing_did:
        raise HTTPException(
            status_code=422,
            detail="Federated mail delivery requires a sender identity",
        )
    sender_current_did = (
        ((payload.encrypted_envelope or {}).get("from") or {}).get("did")
        if is_encrypted
        else payload.from_did
    ) or sender_did
    sender_current_did = str(sender_current_did).strip()
    if sender_current_did not in set(auth_dids(auth)):
        raise HTTPException(status_code=422, detail="from_did must match the authenticated sender")
    target_current_did = str(recipient.get("did_key") or "").strip()
    target_stable_id = str(recipient.get("did_aw") or recipient_did or "").strip()
    target_address = str(recipient.get("address") or payload.to_address or target_stable_id or "").strip()
    if not target_current_did or not target_stable_id or not target_address:
        raise HTTPException(
            status_code=422,
            detail="Federated mail delivery requires a resolved target identity",
        )
    try:
        envelope = FederationEnvelope(
            type="mail",
            sender_did_aw=sender_routing_did,
            sender_current_did_key=sender_current_did,
            sender_address=sender_address,
            sender_delivery_origin=runtime.public_origin,
            target_address=target_address,
            target_did_aw=target_stable_id,
            target_current_did_key=target_current_did,
            target_delivery_origin=delivery_origin,
            body="" if is_encrypted else payload.body,
            message_id=payload.message_id,
            timestamp=payload.timestamp or ((payload.encrypted_envelope or {}).get("created_at") if is_encrypted else None),
            signed_payload=payload.signed_payload if not is_encrypted else None,
            conversation_id=payload.conversation_id,
            subject="" if is_encrypted else payload.subject,
            priority=payload.priority,
            content_mode=payload.content_mode,
            message_version=payload.message_version,
            encrypted_envelope=payload.encrypted_envelope,
        )
        verify_federation_envelope(
            envelope,
            federation_signature,
            expected={
                "type": "mail",
                "target_address": target_address,
                "target_did_aw": target_stable_id,
                "target_current_did_key": target_current_did,
                "target_delivery_origin": envelope.target_delivery_origin,
                "message_id": payload.message_id,
                "conversation_id": payload.conversation_id,
            },
        )
    except FederationEnvelopeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    try:
        remote = await deliver_federated_message(
            delivery_origin=delivery_origin,
            envelope=envelope,
            signature=federation_signature,
            id_chain=id_chain,
            transport=runtime.mail_transport,
            own_origins=runtime.public_origins,
        )
    except FederatedMailDeliveryError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc

    conversation_id = str(remote.get("conversation_id") or payload.conversation_id or "").strip()
    message_id = str(remote.get("message_id") or payload.message_id or "").strip()
    delivered_at = str(remote.get("delivered_at") or (payload.timestamp or "")).strip()
    if conversation_id != payload.conversation_id:
        raise HTTPException(status_code=502, detail="Federated mail response conversation_id mismatch")
    if message_id != payload.message_id:
        raise HTTPException(status_code=502, detail="Federated mail response message_id mismatch")

    aweb_db = db.get_manager("aweb")
    existing_projection = await aweb_db.fetch_one(
        """
        SELECT message_id, conversation_id, created_at
        FROM {{tables.messages}}
        WHERE message_id = $1
        """,
        msg_uuid,
    ) if msg_uuid is not None else None
    if existing_projection:
        return SentMail(
            message_id=str(existing_projection["message_id"]),
            conversation_id=str(existing_projection["conversation_id"]),
            status=str(remote.get("status") or "delivered"),
            delivered_at=delivered_at or _utc_iso(existing_projection["created_at"]),
        )

    try:
        existing_conversation = await aweb_db.fetch_one(
            """
            SELECT conversation_id
            FROM {{tables.conversations}}
            WHERE conversation_id = $1
            """,
            UUID(conversation_id),
        )
        if existing_conversation:
            conversation = {"conversation_id": str(existing_conversation["conversation_id"])}
        else:
            conversation = await _create_mail_conversation(
                db,
                conversation_type="mail",
                created_by_did=sender_did,
                conversation_id=conversation_id,
                initiator={
                    "did": sender_did,
                    "agent_id": auth.agent_id,
                    "alias": auth.alias or sender_address or sender_did,
                    "address": sender_address,
                    "current_did_key": sender_current_did,
                    "transport_hint": "local",
                },
                recipients=[
                    {
                        "did": recipient_did,
                        "agent_id": to_agent_id,
                        "alias": to_alias or recipient.get("alias") or recipient_did,
                        "address": target_address,
                        "delivery_origin": delivery_origin,
                        "current_did_key": target_current_did,
                        "transport_hint": "federation:" + delivery_origin,
                    }
                ],
                team_id=auth.team_id,
            )
        with agent_wake_scope(runtime.agent_wake_publisher):
            local_message_id, local_created_at = await deliver_message(
                db,
                id_chain=id_chain,
                registry_client=registry_client,
                recipient_agent=recipient,
                team_id=auth.team_id,
                from_agent_id=auth.agent_id,
                from_alias=auth.alias,
                to_agent_id=to_agent_id,
                to_alias=to_alias,
                from_did=sender_did,
                to_did=recipient_did,
                sender_address=sender_address,
                subject="" if is_encrypted else payload.subject,
                body="" if is_encrypted else payload.body,
                priority=payload.priority,
                signature=None if is_encrypted else payload.signature,
                signed_payload=None if is_encrypted else payload.signed_payload,
                content_mode=payload.content_mode or "legacy_plaintext_v1",
                message_version=payload.message_version or 1,
                encrypted_envelope=payload.encrypted_envelope,
                encrypted_metadata=encrypted_metadata,
                message_id=msg_uuid,
                conversation_id=conversation["conversation_id"],
                skip_policy_check=True,
            )
    except (ValidationError, NotFoundError, ForbiddenError) as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    await record_successful_contact_side_effect(
        db,
        owner_did=sender_routing_did,
        sender_team_id=auth.team_id,
        recipient=recipient,
        registry_client=registry_client,
    )

    await fire_mutation_callback(
        runtime.on_mutation,
        "message.sent",
        {
            "team_id": auth.team_id,
            "from_agent_id": auth.agent_id,
            "from_did": sender_did,
            "from_did_aw": sender_routing_did if sender_routing_did.startswith("did:aw:") else None,
            "to_agent_id": to_agent_id,
            "from_alias": auth.alias or sender_did,
            "message_id": message_id or str(local_message_id),
            "conversation_id": conversation_id or conversation["conversation_id"],
            "to_alias": to_alias,
            "subject": payload.subject,
            "priority": payload.priority,
            "content_mode": payload.content_mode or "legacy_plaintext_v1",
            "federated": True,
        },
    )

    return SentMail(
        message_id=message_id or str(local_message_id),
        conversation_id=conversation_id or conversation["conversation_id"],
        status=str(remote.get("status") or "delivered"),
        delivered_at=delivered_at or _utc_iso(local_created_at),
    )


def _lost_send_race(exc: BaseException) -> bool:
    """A concurrent send claimed this message_id or conversation_id and committed first."""
    if isinstance(exc, HTTPException):
        return exc.status_code == 409 and exc.detail == "conversation_exists"
    cause = exc.__cause__ if isinstance(exc, QueryError) else exc
    return isinstance(cause, asyncpg.exceptions.UniqueViolationError)


async def _stored_exact_send(db, *, payload, sender_did: str) -> tuple[SentMail | None, bool]:
    """What an exact retry of this send already stored, before any new effect.

    Returns the stored send when payload.message_id names a message this
    sender sent with the identical signed payload (or encrypted envelope), and
    whether no message with that id exists. A message_id stored with other
    content is left to the ordinary path, which refuses it as a conflict.
    """
    if not payload.message_id:
        return None, False
    try:
        message_uuid = UUID(payload.message_id)
    except ValueError:
        return None, False
    row = await db.get_manager("aweb").fetch_one(
        """
        SELECT message_id, conversation_id, created_at, content_mode, from_did,
               signed_payload, encrypted_envelope
        FROM {{tables.messages}}
        WHERE message_id = $1
        """,
        message_uuid,
    )
    if row is None:
        return None, True
    if row["from_did"] != sender_did:
        return None, False
    if (payload.content_mode or "legacy_plaintext_v1") == "encrypted_v2":
        stored_envelope = row["encrypted_envelope"]
        if isinstance(stored_envelope, str):
            stored_envelope = json.loads(stored_envelope)
        same = (
            row["content_mode"] == "encrypted_v2"
            and payload.encrypted_envelope is not None
            and stored_envelope == payload.encrypted_envelope
        )
    else:
        same = (
            row["content_mode"] == "legacy_plaintext_v1"
            and bool(payload.signed_payload)
            and row["signed_payload"] == payload.signed_payload
        )
    if not same:
        return None, False
    return SentMail(
        message_id=str(row["message_id"]),
        conversation_id=str(row["conversation_id"]) if row["conversation_id"] else None,
        status="delivered",
        delivered_at=_utc_iso(row["created_at"]),
    ), False


async def _create_mail_conversation(db, **kwargs):
    try:
        return await create_conversation(db, **kwargs)
    except (QueryError, asyncpg.exceptions.UniqueViolationError) as exc:
        # The preflight read cannot exclude a concurrent insertion. Creation is
        # transactional: losing that race must refuse rather than reuse or 500.
        cause = exc.__cause__ if isinstance(exc, QueryError) else exc
        if isinstance(cause, asyncpg.exceptions.UniqueViolationError):
            raise HTTPException(status_code=409, detail="conversation_exists") from exc
        raise


async def _continuation_signature_recipient(
    runtime: MessagingRuntime,
    *,
    participant: dict,
    recipient: dict,
    payload: SendMessageRequest,
    sender_did_key: str,
) -> dict:
    """Validate a signed stored-route recipient without changing its routing facts."""
    signed = verified_signed_payload_json(
        signed_payload=payload.signed_payload,
        signature=payload.signature,
        did_key=sender_did_key,
    )
    if signed is None:
        raise HTTPException(status_code=403, detail="Invalid message signature")
    stable = str(participant.get("did") or "")
    signed_stable = signed.get("to_stable_id") or ""
    signed_key = signed.get("to_did") or ""
    signed_to = signed.get("to") or ""
    if not signed_stable and isinstance(signed_key, str) and signed_key.startswith("did:aw:"):
        signed_stable, signed_key = signed_key, ""
    if not signed_stable and isinstance(signed_to, str) and signed_to.startswith("did:aw:"):
        signed_stable = signed_to
    if not stable.startswith("did:aw:") or signed_stable != stable:
        raise HTTPException(status_code=403, detail="identity_binding_mismatch")
    address = str(participant.get("address") or "")
    signed_address = signed_to if isinstance(signed_to, str) and "/" in signed_to else ""
    if signed_address and signed_address != address:
        raise HTTPException(status_code=403, detail="identity_binding_mismatch")
    if not signed_key and isinstance(signed_to, str) and signed_to.startswith("did:key:"):
        signed_key = signed_to
    if not signed_key:
        # Released clients may sign only the stable DID on a stored route.
        # Discover its current key solely for validation, never for delivery.
        try:
            resolved = await runtime.registry_client.resolve_key_fresh(stable)
            signed_key = resolved.current_did_key
        except RegistryError as exc:
            if exc.status_code != 404:
                logging.getLogger(__name__).warning("Stored mail signature binding dependency failed", exc_info=True)
            detail = "identity_binding_mismatch" if exc.status_code == 404 else "identity_binding_unavailable"
            raise HTTPException(status_code=403 if exc.status_code == 404 else 503, detail=detail) from exc
        except Exception as exc:
            logging.getLogger(__name__).warning("Stored mail signature binding dependency failed", exc_info=True)
            raise HTTPException(status_code=503, detail="identity_binding_unavailable") from exc
    if not isinstance(signed_key, str) or not signed_key.startswith("did:key:"):
        raise HTTPException(status_code=403, detail="identity_binding_mismatch")
    await observe_current_identity_binding(
        runtime.registry_client, runtime.identity_binding_cache,
        did_key=signed_key, did_aw=stable, address=signed_address,
    )
    # This copy is passed only to the payload validator. The original recipient,
    # participant agent_id, policy rows and all projection markers stay intact.
    return {**recipient, "did_aw": stable, "did_key": signed_key, "address": address}


async def send_mail_conversation_continuation(
    runtime: MessagingRuntime,
    payload: SendMessageRequest,
    db,
    *,
    auth: MessagingAuth,
    registry_client,
    sender_address: str | None,
    sender_did: str,
    id_chain: dict | None,
    conversation_id: str,
    local_recipient: dict | None = None,
) -> SentMail:
    msg_uuid = UUID(payload.message_id) if payload.message_id else None

    try:
        continuation = await mail_continuation_context(
            db,
            conversation_id=conversation_id,
            sender_did=sender_did,
            equivalent_dids=participant_dids(auth),
        )
        recipient_participant = continuation.recipient_participant
        if local_recipient is None and participant_is_remote(recipient_participant):
            return await send_federated_mail_conversation_continuation(
                runtime,
                payload,
                db,
                auth=auth,
                registry_client=registry_client,
                sender_address=sender_address,
                sender_did=sender_did,
                id_chain=id_chain,
                continuation=continuation,
            )
        recipient = local_recipient or await recipient_for_conversation_participant(db, recipient_participant)
        historical_target = None
        if payload.signature is not None:
            if payload.from_did is None or not payload.from_did.strip():
                raise HTTPException(status_code=422, detail="from_did is required when signature is provided")
            from_did = payload.from_did.strip()
            if from_did not in set(auth_dids(auth)):
                raise HTTPException(status_code=422, detail="from_did must match the authenticated sender")
            if payload.message_id is None or payload.timestamp is None:
                raise HTTPException(
                    status_code=422,
                    detail="message_id and timestamp are required when signature is provided",
                )
            validation = dict(
                signature=payload.signature,
                signed_payload=payload.signed_payload,
                recipient=recipient,
                to_agent_id=payload.to_agent_id,
                to_alias=recipient_participant.get("alias"),
                requested_to_alias=payload.to_alias,
                from_alias=auth.alias,
                from_address=sender_address,
                from_stable_id=auth.did_aw,
                priority=payload.priority,
                subject=payload.subject,
                body=payload.body,
                from_did=from_did,
                message_id=payload.message_id,
                timestamp=payload.timestamp,
                conversation_id=conversation_id,
            )
            # Historical target evidence is restricted to this recorded local
            # mail thread. It never supplies sender or current-key authority.
            signed = verified_signed_payload_json(
                signed_payload=payload.signed_payload,
                signature=payload.signature,
                did_key=auth.did_key,
            )
            if signed is not None and payload.encrypted_envelope is None:
                historical_target = await predecessor_target_for_mail(
                    db, conversation_id=conversation_id,
                    successor_did=recipient_participant["did"], signed=signed,
                )
            if historical_target is not None:
                validation["recipient"] = historical_target
                validation["to_alias"] = historical_target["alias"]
            elif recipient.get("did_aw") and not recipient.get("did_key"):
                # A canonical stored participant can outlive its key projection.
                # Even a stable-only signed target needs current key evidence.
                validation["recipient"] = await _continuation_signature_recipient(
                    runtime, participant=recipient_participant, recipient=recipient,
                    payload=payload, sender_did_key=auth.did_key,
                )
            try:
                _validate_signed_mail_payload(**validation)
            except HTTPException as exc:
                if exc.status_code != 422 or exc.detail != "signed_payload recipient must match the mail recipient":
                    raise
                validation["recipient"] = await _continuation_signature_recipient(
                    runtime, participant=recipient_participant, recipient=recipient,
                    payload=payload, sender_did_key=auth.did_key,
                )
                _validate_signed_mail_payload(**validation)
            # payload.timestamp is the sender's attestation retained in
            # signed_payload; deliver_message separately assigns server receipt
            # time for ordering, so the two values may disagree.
            _parse_signed_timestamp(payload.timestamp)
        encrypted_metadata = _validate_encrypted_payload(
            payload,
            auth=auth,
            sender_did=sender_did,
            recipient=recipient,
            recipient_did=recipient_participant["did"],
        )
        if encrypted_metadata is not None:
            await require_non_custodial_recipients(
                db, payload.encrypted_envelope or {}, [recipient] if recipient else [], sender=auth,
            )
        # Admission comes before any replay, as for any send.
        await admit_message_delivery(
            db,
            recipient=recipient,
            recipient_did=recipient_participant["did"],
            to_agent_id=recipient.get("agent_id"),
            sender_did=sender_did,
            sender_address=sender_address,
            team_id=continuation.conversation.get("team_id") or auth.team_id,
            sender_verified_team_id=auth.verified_team_id,
            sender_verified_dids=auth_dids(auth),
            stored_route_continuation=True,
        )
        stored, message_is_new = await _stored_exact_send(db, payload=payload, sender_did=sender_did)
        if stored is not None:
            return stored
        try:
            with agent_wake_scope(runtime.agent_wake_publisher):
                message_id, server_received_at = await deliver_message(
                    db,
                    id_chain=id_chain,
                    registry_client=registry_client,
                    recipient_agent=recipient,
                    team_id=continuation.conversation.get("team_id") or auth.team_id,
                    from_agent_id=auth.agent_id,
                    from_alias=auth.alias,
                    to_agent_id=recipient.get("agent_id"),
                    to_alias=recipient_participant.get("alias"),
                    from_did=sender_did,
                    to_did=recipient_participant["did"],
                    sender_address=sender_address,
                    subject=payload.subject,
                    body=payload.body,
                    priority=payload.priority,
                    signature=payload.signature,
                    signed_payload=payload.signed_payload,
                    content_mode=payload.content_mode or "legacy_plaintext_v1",
                    message_version=payload.message_version or 1,
                    encrypted_envelope=payload.encrypted_envelope,
                    encrypted_metadata=encrypted_metadata,
                    message_id=msg_uuid,
                    conversation_id=conversation_id,
                    sender_verified_team_id=auth.verified_team_id,
                    sender_verified_dids=auth_dids(auth),
                    stored_route_continuation=True,
                    signed_recipient_did=historical_target["signed_did"]
                    if historical_target is not None else None,
                    known_new=message_is_new,
                    skip_policy_check=True,
                )
        except Exception as exc:
            if not _lost_send_race(exc):
                raise
            stored, _ = await _stored_exact_send(db, payload=payload, sender_did=sender_did)
            if stored is None:
                raise
            return stored
        await touch_conversation_activity(db, conversation_id=conversation_id)
    except (ValidationError, NotFoundError, ForbiddenError, ConflictError) as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    await fire_mutation_callback(
        runtime.on_mutation,
        "message.sent",
        {
            "team_id": auth.team_id,
            "from_agent_id": auth.agent_id,
            "from_did": sender_did,
            "from_did_aw": (auth.did_aw or "").strip() or None,
            "to_agent_id": recipient_participant.get("agent_id"),
            "from_alias": auth.alias or sender_did,
            "message_id": str(message_id),
            "conversation_id": conversation_id,
            "to_alias": recipient_participant.get("alias"),
            "subject": payload.subject,
            "priority": payload.priority,
            "content_mode": payload.content_mode or "legacy_plaintext_v1",
        },
    )

    return SentMail(
        message_id=str(message_id),
        conversation_id=conversation_id,
        status="delivered",
        delivered_at=_utc_iso(server_received_at),
    )


async def send_federated_mail_conversation_continuation(
    runtime: MessagingRuntime,
    payload: SendMessageRequest,
    db,
    *,
    auth: MessagingAuth,
    registry_client,
    sender_address: str | None,
    sender_did: str,
    id_chain: dict | None,
    continuation: MailContinuationContext,
) -> SentMail:
    refuse_remote_attachments()
    recipient_participant = continuation.recipient_participant
    try:
        recipient = await remote_recipient_from_participant(registry_client, recipient_participant)
    except (ValidationError, ServiceError) as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    msg_uuid = UUID(payload.message_id) if payload.message_id else None
    if payload.timestamp:
        _parse_signed_timestamp(payload.timestamp)
    return await deliver_remote_mail_and_project_locally(
        runtime,
        payload,
        db,
        auth=auth,
        registry_client=registry_client,
        sender_address=sender_address,
        sender_did=sender_did,
        id_chain=id_chain,
        recipient=recipient,
        recipient_did=recipient_participant["did"],
        to_agent_id=None,
        to_alias=recipient_participant.get("alias"),
        msg_uuid=msg_uuid,
    )
