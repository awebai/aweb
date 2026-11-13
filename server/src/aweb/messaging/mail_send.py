"""Mail recipient resolution and sends, for every adapter."""

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

from awid.federation_errors import FederationAuthorityError
from awid.registry import RegistryError
from aweb.agent_wake import agent_wake_scope
from aweb.attachment_service import refuse_remote_attachments
from aweb.awid_error_handling import AWID_DEPENDENCY_ERRORS, awid_registry_not_configured_exception
from aweb.db import TransactionInfra
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
from aweb.messaging.address_auth import (
    identity_recipient,
    local_recipient_for_address_binding,
    local_recipient_for_own_route,
    local_recipient_visible_to_auth,
    namespace_uses_home_registry,
    refuse_same_origin_nonresident,
    requires_registry_address_binding,
    verified_signed_payload_json,
)
from aweb.messaging.alias_targets import (
    AmbiguousLocalAddressError,
    derive_team_address,
    get_agent_by_namespace_alias,
    namespace_exists,
    resolve_alias_target,
    team_exists,
)
from aweb.messaging.contacts import (
    resolve_local_namespace_controller_did,
    upsert_successful_identity_contact,
)
from aweb.messaging.conversations import create_conversation, get_conversation, touch_conversation_activity
from aweb.messaging.encryption_custody import require_non_custodial_recipients
from aweb.messaging.mail_routing import (
    MailContinuationContext,
    explicit_mail_target_matches_participant,
    mail_continuation_context,
    participant_is_remote,
    recipient_for_conversation_participant,
    remote_recipient_from_participant,
)
from aweb.messaging.messages import (
    MessagePriority,
    admit_message_delivery,
    authorize_message_delivery,
    deliver_message,
    get_agent_by_id,
    resolve_agent_by_did,
    utc_iso as _utc_iso,
)
from aweb.messaging.participant_succession import predecessor_target_for_mail
from aweb.messaging.participants import messaging_participant_by_alias
from aweb.messaging.runtime import MessagingRuntime
from aweb.messaging.sender_address import sender_address as _sender_address
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
    continuation: MailContinuationContext | None = None,
) -> SentMail:
    msg_uuid = UUID(payload.message_id) if payload.message_id else None

    try:
        if continuation is None:
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


async def _resolve_message_alias(db, auth: MessagingAuth, raw_alias: str, registry_client=None) -> dict | None:
    target = resolve_alias_target(auth.team_id, raw_alias, field="to_alias")
    if "~" in str(raw_alias or "") and not await team_exists(db, target.team_id):
        raise HTTPException(status_code=404, detail=f"Unknown team: {target.team_id}")
    return await messaging_participant_by_alias(db, team_id=target.team_id, alias=target.alias,
                                              selected_team_id=auth.team_id, registry_client=registry_client)


def _external_recipient_from_address(address: str, resolution) -> dict:
    _, name = address.split("/", 1)
    delivery = getattr(resolution, "delivery", None)
    delivery_origin = (
        getattr(resolution, "delivery_origin", None)
        or getattr(delivery, "origin", "")
        or ""
    )
    return {
        "agent_id": None,
        "team_id": None,
        "alias": name,
        "address": address,
        "did_aw": resolution.did_aw.strip(),
        "did_key": (getattr(resolution, "current_did_key", "") or "").strip(),
        "delivery_origin": str(delivery_origin).strip(),
        "authority_controller_did": str(
            getattr(resolution, "controller_did", "") or ""
        ).strip(),
        "external": True,
    }


def _raise_bare_did_first_contact_unsupported() -> None:
    raise HTTPException(
        status_code=422,
        detail="Bare did:aw first-contact is unsupported; use to_address=domain/name or continue an existing conversation",
    )


def _recipient_conversation_address(recipient: dict | None, payload: SendMessageRequest) -> str | None:
    address = str((recipient or {}).get("address") or "").strip()
    if address:
        return address
    requested_address = str(payload.to_address or "").strip()
    if requested_address:
        return requested_address
    return derive_team_address(
        str((recipient or {}).get("team_id") or ""),
        str((recipient or {}).get("alias") or ""),
    ) or None


async def _local_recipient_from_address(db, *, domain: str, name: str) -> dict | None:
    try:
        return await get_agent_by_namespace_alias(db, namespace=domain, alias=name)
    except AmbiguousLocalAddressError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _recipient_identity_matches(left: dict | None, right: dict | None) -> bool:
    if left is None or right is None:
        return False
    left_did = str(left.get("did_aw") or left.get("did_key") or "").strip()
    right_did = str(right.get("did_aw") or right.get("did_key") or "").strip()
    return bool(left_did and right_did and left_did == right_did)


def _signed_payload_matches_address_binding(
    payload: dict | None,
    *,
    address: str,
    recipient: dict,
) -> bool:
    if not isinstance(payload, dict) or payload.get("type") != "mail":
        return False
    signed_to = str(payload.get("to") or "").strip()
    if signed_to and signed_to != address:
        return False
    recipient_stable_id = str(recipient.get("did_aw") or "").strip()
    recipient_current_did = str(recipient.get("did_key") or "").strip()
    signed_to_did = str(payload.get("to_did") or "").strip()
    signed_to_stable_id = str(payload.get("to_stable_id") or "").strip()
    if not signed_to_did and not signed_to_stable_id:
        return False
    if signed_to_did and signed_to_did not in {recipient_stable_id, recipient_current_did}:
        return False
    if signed_to_stable_id and signed_to_stable_id != recipient_stable_id:
        return False
    return bool(recipient_stable_id or recipient_current_did)


async def _bound_recipient_from_address(
    db,
    *,
    registry_client,
    auth: MessagingAuth,
    address: str,
    expected_recipient: dict | None = None,
    signed_payload: str | None = None,
    signature: str | None = None,
) -> dict | None:
    if "/" not in address:
        raise HTTPException(status_code=422, detail="to_address must be domain/name")
    domain, name = address.split("/", 1)
    if registry_client is not None:
        resolved = await registry_client.resolve_address(domain, name, did_key=auth.did_key)
        if resolved is not None and resolved.did_aw:
            bound_recipient = await resolve_agent_by_did(db, resolved.did_aw)
            if bound_recipient is not None:
                return bound_recipient
    local_recipient = await _local_recipient_from_address(db, domain=domain, name=name)
    if requires_registry_address_binding(local_recipient):
        if local_recipient_visible_to_auth(local_recipient, auth):
            return local_recipient
        if registry_client is None:
            return local_recipient
        if (
            expected_recipient is not None
            and _recipient_identity_matches(local_recipient, expected_recipient)
            and _signed_payload_matches_address_binding(
                verified_signed_payload_json(
                    signed_payload=signed_payload,
                    signature=signature,
                    did_key=auth.did_key,
                ),
                address=address,
                recipient=local_recipient,
            )
        ):
            return local_recipient
        raise HTTPException(status_code=404, detail="Recipient address not found")
    return local_recipient


@dataclass(frozen=True)
class MailTarget:
    """Where a mail send goes: the recipient of a first message, or the stored conversation it continues."""

    recipient: dict | None = None
    recipient_did: str = ""
    to_agent_id: str | None = None
    to_alias: str | None = None
    continuation: MailContinuationContext | None = None


async def resolve_mail_target(
    db, auth: MessagingAuth, payload: SendMessageRequest, runtime: MessagingRuntime, source: str,
) -> MailTarget:
    """Resolve whom a send names, before any of it is stored.

    ``payload`` supplies the recipient fields, the conversation id and any
    signature the sender made over the recipient binding. ``source`` keys the
    federation authority's rate bucket for this caller.
    """
    registry_client = runtime.registry_client
    sender_did = (auth.did_aw or auth.did_key or "").strip()
    if not sender_did:
        raise HTTPException(status_code=401, detail="Authenticated identity is missing a routing DID")

    has_explicit_recipient = any(
        value is not None
        for value in (
            payload.to_agent_id,
            payload.to_alias,
            payload.to_did,
            payload.to_stable_id,
            payload.to_address,
        )
    )

    if payload.conversation_id is not None and not has_explicit_recipient:
        try:
            return MailTarget(continuation=await mail_continuation_context(
                db,
                conversation_id=payload.conversation_id,
                sender_did=sender_did,
                equivalent_dids=participant_dids(auth),
            ))
        except (ValidationError, NotFoundError, ForbiddenError, ConflictError) as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    if has_explicit_recipient and payload.conversation_id is not None:
        requested_conversation = await get_conversation(db, conversation_id=payload.conversation_id)
        if requested_conversation is not None:
            try:
                requested_continuation = await mail_continuation_context(
                    db,
                    conversation_id=payload.conversation_id,
                    sender_did=sender_did,
                    equivalent_dids=participant_dids(auth),
                )
            except (ValidationError, NotFoundError, ForbiddenError, ConflictError) as exc:
                raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
            target_matches = await explicit_mail_target_matches_participant(
                db, requested_continuation.recipient_participant,
                to_agent_id=payload.to_agent_id,
                to_alias=payload.to_alias,
                to_did=payload.to_did,
                to_stable_id=payload.to_stable_id,
                to_address=payload.to_address,
            )
            if (not target_matches and payload.encrypted_envelope is None
                    and payload.to_agent_id is None and payload.to_alias is None
                    and payload.to_address is None):
                signed = verified_signed_payload_json(
                    signed_payload=payload.signed_payload, signature=payload.signature,
                    did_key=auth.did_key,
                )
                historical = await predecessor_target_for_mail(
                    db, conversation_id=payload.conversation_id,
                    successor_did=requested_continuation.recipient_participant["did"],
                    signed=signed,
                ) if signed is not None else None
                if historical is not None:
                    identities = {historical["did_key"], historical["did_aw"]} - {None}
                    target_matches = all(
                        value is None or value in identities
                        for value in (payload.to_did, payload.to_stable_id)
                    )
            if not target_matches:
                raise HTTPException(
                    status_code=409,
                    detail="conversation_id recipient does not match the requested recipient",
                )
            return MailTarget(continuation=requested_continuation)

    recipient = None
    recipient_did: str | None = None
    to_agent_id: str | None = payload.to_agent_id
    to_alias: str | None = None

    if payload.to_address is None and payload.to_stable_id is not None:
        recipient_did = payload.to_stable_id.strip()
        recipient = await resolve_agent_by_did(db, recipient_did)
        if recipient is not None:
            recipient = identity_recipient(recipient)
        if recipient is None:
            if recipient_did.startswith("did:aw:"):
                _raise_bare_did_first_contact_unsupported()
            raise HTTPException(status_code=404, detail="Recipient agent not found")
        if payload.to_did is not None and payload.to_did.strip():
            bound_recipient = await resolve_agent_by_did(db, payload.to_did.strip())
            if not _recipient_identity_matches(bound_recipient, recipient):
                raise HTTPException(status_code=422, detail="to_did must match the to_stable_id recipient")
        if payload.to_agent_id is not None and payload.to_agent_id.strip():
            if payload.to_agent_id.strip() != str(recipient["agent_id"]):
                raise HTTPException(status_code=422, detail="to_agent_id must match the to_stable_id recipient")
        if payload.to_alias is not None and payload.to_alias.strip():
            bound_recipient = await _resolve_message_alias(db, auth, payload.to_alias.strip(), registry_client=registry_client)
            if not _recipient_identity_matches(bound_recipient, recipient):
                raise HTTPException(status_code=422, detail="to_alias must match the to_stable_id recipient")
        if payload.to_address is not None and payload.to_address.strip():
            address = payload.to_address.strip()
            bound_recipient = await _bound_recipient_from_address(
                db,
                registry_client=registry_client,
                auth=auth,
                address=address,
                expected_recipient=recipient,
                signed_payload=payload.signed_payload,
                signature=payload.signature,
            )
            if not _recipient_identity_matches(bound_recipient, recipient):
                raise HTTPException(status_code=422, detail="to_address must match the to_stable_id recipient")
            recipient = identity_recipient(recipient, address)
        to_agent_id = str(recipient["agent_id"]) if recipient.get("agent_id") else None
        to_alias = recipient.get("alias")
    elif payload.to_address is None and payload.to_did is not None:
        requested_recipient_did = payload.to_did.strip()
        recipient = await resolve_agent_by_did(db, requested_recipient_did)
        if recipient is not None:
            recipient = identity_recipient(recipient)
        if recipient is None:
            if requested_recipient_did.startswith("did:aw:"):
                _raise_bare_did_first_contact_unsupported()
            raise HTTPException(status_code=404, detail="Recipient agent not found")
        if payload.to_alias is not None and payload.to_alias.strip():
            bound_recipient = await _resolve_message_alias(db, auth, payload.to_alias.strip(), registry_client=registry_client)
            if not _recipient_identity_matches(bound_recipient, recipient):
                raise HTTPException(status_code=422, detail="to_alias must match the to_did recipient")
        if payload.to_agent_id is not None and payload.to_agent_id.strip():
            if payload.to_agent_id.strip() != str(recipient["agent_id"]):
                raise HTTPException(status_code=422, detail="to_agent_id must match the to_did recipient")
        if payload.to_address is not None and payload.to_address.strip():
            address = payload.to_address.strip()
            bound_recipient = await _bound_recipient_from_address(
                db,
                registry_client=registry_client,
                auth=auth,
                address=address,
                expected_recipient=recipient,
                signed_payload=payload.signed_payload,
                signature=payload.signature,
            )
            if not _recipient_identity_matches(bound_recipient, recipient):
                raise HTTPException(status_code=422, detail="to_address must match the to_did recipient")
            recipient = identity_recipient(recipient, address)
        recipient_did = (recipient.get("did_aw") or recipient.get("did_key") or requested_recipient_did).strip()
        to_agent_id = str(recipient["agent_id"]) if recipient.get("agent_id") else None
        to_alias = recipient.get("alias")
    elif payload.to_address is not None:
        address = payload.to_address.strip()
        if "/" not in address:
            raise HTTPException(status_code=422, detail="to_address must be domain/name")
        domain, name = address.split("/", 1)
        local_candidate = await _local_recipient_from_address(db, domain=domain, name=name)
        if local_candidate is not None:
            signed = verified_signed_payload_json(
                signed_payload=payload.signed_payload, signature=payload.signature, did_key=auth.did_key,
            )
            signed_binding = _signed_payload_matches_address_binding(
                signed, address=address, recipient=local_candidate,
            )
            # Preserve already admitted local sends. A signed current-key claim
            # that contradicts the projection must instead use registry evidence.
            needs_current_binding = (
                requires_registry_address_binding(local_candidate) and signed is not None
                and bool(signed.get("to_did") or signed.get("to_stable_id")) and not signed_binding
            )
            if signed_binding or (local_recipient_visible_to_auth(local_candidate, auth) and not needs_current_binding):
                recipient_did = str(
                    local_candidate.get("did_aw") or local_candidate.get("did_key") or ""
                ).strip()
                recipient = identity_recipient(local_candidate, address)
                recipient["requires_local_address_authority"] = True

        strict_authority = runtime.federation_authority
        home_namespace = recipient is None and await namespace_uses_home_registry(db, registry_client, domain)
        if home_namespace:
            try:
                resolved = await registry_client.resolve_address(domain, name, did_key=auth.did_key)
            except AWID_DEPENDENCY_ERRORS as exc:
                logging.getLogger(__name__).warning("Mail home address lookup unavailable for %s", address, exc_info=True)
                raise FederationAuthorityError("sender_registry_unavailable") from exc
            if resolved is not None and resolved.did_aw:
                recipient_did = resolved.did_aw
                recipient = await local_recipient_for_address_binding(db, resolved, address)
                if recipient is None:
                    recipient = _external_recipient_from_address(address, resolved)
        elif recipient is None and strict_authority is not None:
            try:
                resolved = await strict_authority.resolve_contact(
                    address,
                    source_ip=source,
                )
            except FederationAuthorityError as exc:
                if exc.reason != "recipient_identity_not_found":
                    raise
                resolved = None
            if resolved is not None and resolved.did_aw:
                recipient_did = resolved.did_aw
                recipient = await local_recipient_for_address_binding(db, resolved, address)
                if recipient is None:
                    recipient = _external_recipient_from_address(address, resolved)
                else:
                    recipient["authority_controller_did"] = str(
                        getattr(resolved, "controller_did", "") or ""
                    ).strip()
        elif recipient is None and registry_client is not None:
            resolved = await registry_client.resolve_address(domain, name, did_key=auth.did_key)
            if resolved is not None and resolved.did_aw:
                recipient_did = resolved.did_aw
                recipient = await local_recipient_for_address_binding(db, resolved, address)
                if recipient is None:
                    recipient = _external_recipient_from_address(address, resolved)

        if recipient is not None and recipient.get("external"):
            refuse_same_origin_nonresident(
                recipient["delivery_origin"], origins=runtime.public_origins,
            )

        if recipient is None:
            recipient = await _local_recipient_from_address(db, domain=domain, name=name)
            if recipient is None:
                if await namespace_exists(db, domain):
                    raise FederationAuthorityError("recipient_identity_not_found")
                if registry_client is None:
                    raise awid_registry_not_configured_exception(operation="AWID mail recipient address lookup")
                raise HTTPException(status_code=404, detail="Recipient address not found")
            if registry_client is not None and requires_registry_address_binding(recipient):
                if not (
                    local_recipient_visible_to_auth(recipient, auth)
                    or _signed_payload_matches_address_binding(
                        verified_signed_payload_json(
                            signed_payload=payload.signed_payload,
                            signature=payload.signature,
                            did_key=auth.did_key,
                        ),
                        address=address,
                        recipient=recipient,
                    )
                ):
                    raise HTTPException(status_code=404, detail="Recipient address not found")
            recipient = identity_recipient(recipient, address)
            recipient_did = (recipient.get("did_aw") or recipient.get("did_key") or "").strip()
            if not recipient_did:
                raise HTTPException(status_code=404, detail="Recipient agent not found")
        if payload.to_alias is not None and payload.to_alias.strip():
            if recipient.get("external"):
                if payload.to_alias.strip() != recipient["alias"]:
                    raise HTTPException(status_code=422, detail="to_alias must match the to_address recipient")
            else:
                bound_recipient = await _resolve_message_alias(db, auth, payload.to_alias.strip(), registry_client=registry_client)
                if not _recipient_identity_matches(bound_recipient, recipient):
                    raise HTTPException(status_code=422, detail="to_alias must match the to_address recipient")
        if payload.to_agent_id is not None and payload.to_agent_id.strip():
            if recipient.get("external") or payload.to_agent_id.strip() != str(recipient["agent_id"]):
                raise HTTPException(status_code=422, detail="to_agent_id must match the to_address recipient")
        if payload.to_stable_id is not None and payload.to_stable_id.strip():
            if payload.to_stable_id.strip() != str(recipient.get("did_aw") or "").strip():
                raise HTTPException(status_code=422, detail="to_stable_id must match the to_address recipient")
        if payload.to_did is not None and payload.to_did.strip():
            candidate_dids = {
                str(recipient.get("did_aw") or "").strip(),
                str(recipient.get("did_key") or "").strip(),
            }
            if payload.to_did.strip() not in candidate_dids:
                raise HTTPException(status_code=422, detail="to_did must match the to_address recipient")
        to_agent_id = str(recipient["agent_id"]) if recipient.get("agent_id") else None
        to_alias = recipient.get("alias") or address
    elif to_agent_id is not None:
        recipient = await get_agent_by_id(
            db, team_id=auth.team_id, agent_id=to_agent_id,
        ) if auth.team_id else await get_agent_by_id(db, agent_id=to_agent_id)
        if recipient is None:
            raise HTTPException(status_code=404, detail="Recipient agent not found")
        if payload.to_alias is not None and payload.to_alias.strip():
            bound_recipient = await _resolve_message_alias(db, auth, payload.to_alias.strip(), registry_client=registry_client)
            if not _recipient_identity_matches(bound_recipient, recipient):
                raise HTTPException(status_code=422, detail="to_alias must match the to_agent_id recipient")
        recipient_did = (recipient.get("did_aw") or recipient.get("did_key") or "").strip()
        to_alias = recipient.get("alias")
    elif payload.to_alias is not None:
        recipient = await _resolve_message_alias(db, auth, payload.to_alias, registry_client=registry_client)
        if recipient is None:
            raise HTTPException(status_code=404, detail="Recipient agent not found")
        recipient_did = (recipient.get("did_aw") or recipient.get("did_key") or "").strip()
        to_agent_id = str(recipient["agent_id"])
        to_alias = recipient["alias"]
    else:
        raise HTTPException(status_code=422, detail="Must provide to_did, to_address, to_agent_id, or to_alias")

    return MailTarget(
        recipient=recipient,
        recipient_did=recipient_did or "",
        to_agent_id=to_agent_id,
        to_alias=to_alias,
    )


async def send_mail(
    db, auth: MessagingAuth, target: MailTarget, payload: SendMessageRequest, runtime: MessagingRuntime,
) -> SentMail:
    """Store and deliver the signed or encrypted ``payload`` to a resolved target."""
    registry_client = runtime.registry_client
    id_chain = auth.id_chain
    sender_address = _sender_address(auth)
    sender_did = (auth.did_aw or auth.did_key or "").strip()
    if target.continuation is not None:
        if participant_is_remote(target.continuation.recipient_participant):
            return await send_federated_mail_conversation_continuation(
                runtime,
                payload,
                db,
                auth=auth,
                registry_client=registry_client,
                sender_address=sender_address,
                sender_did=sender_did,
                id_chain=id_chain,
                continuation=target.continuation,
            )
        return await send_mail_conversation_continuation(
            runtime,
            payload,
            db,
            auth=auth,
            registry_client=registry_client,
            sender_address=sender_address,
            sender_did=sender_did,
            id_chain=id_chain,
            conversation_id=payload.conversation_id,
            continuation=target.continuation,
        )
    recipient = target.recipient
    recipient_did = target.recipient_did
    to_agent_id = target.to_agent_id
    to_alias = target.to_alias

    msg_uuid = UUID(payload.message_id) if payload.message_id else None
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
        _validate_signed_mail_payload(
            signature=payload.signature,
            signed_payload=payload.signed_payload,
            recipient=recipient,
            to_agent_id=to_agent_id,
            to_alias=to_alias,
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
            conversation_id=payload.conversation_id,
        )
        # payload.timestamp is the sender's attestation retained in
        # signed_payload; deliver_message separately assigns server receipt
        # time for ordering, so the two values may disagree.
        _parse_signed_timestamp(payload.timestamp)

    if (recipient or {}).get("external"):
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
            recipient_did=recipient_did or "",
            to_agent_id=to_agent_id,
            to_alias=to_alias,
            msg_uuid=msg_uuid,
        )

    try:
        if not (recipient or {}).get("external"):
            await authorize_message_delivery(
                db,
                recipient_agent=recipient,
                sender_did=sender_did,
                sender_address=sender_address,
                sender_team_id=auth.team_id,
                sender_verified_team_id=auth.verified_team_id,
                sender_verified_dids=auth_dids(auth),
            )
        encrypted_metadata = _validate_encrypted_payload(
            payload,
            auth=auth,
            sender_did=sender_did,
            recipient=recipient,
            recipient_did=recipient_did or "",
        )
        if encrypted_metadata is not None:
            await require_non_custodial_recipients(
                db, payload.encrypted_envelope or {}, [recipient] if recipient else [], sender=auth,
            )
        stored, message_is_new = await _stored_exact_send(db, payload=payload, sender_did=sender_did)
        if stored is not None:
            return stored
        try:
            with agent_wake_scope(runtime.agent_wake_publisher):
                # The conversation and its first message commit together: a refused
                # delivery leaves no conversation behind.
                async with db.get_manager("aweb").transaction() as tx:
                    send_db = TransactionInfra(db, tx)
                    # If an explicit recipient is present, conversation_id is a caller-chosen
                    # initial id. Continuations use conversation_id without recipient fields.
                    conversation = await _create_mail_conversation(
                        send_db,
                        conversation_type="mail",
                        created_by_did=sender_did,
                        conversation_id=payload.conversation_id,
                        initiator={
                            "did": sender_did,
                            "agent_id": auth.agent_id,
                            "alias": auth.alias or sender_address or sender_did,
                            "address": sender_address,
                            "current_did_key": (auth.did_key or "").strip() or None,
                            "transport_hint": "local",
                        },
                        recipients=[
                            {
                                "did": recipient_did or "",
                                "agent_id": to_agent_id,
                                "alias": to_alias or (recipient or {}).get("alias") or recipient_did or "",
                                "address": _recipient_conversation_address(recipient, payload),
                                "current_did_key": (recipient or {}).get("did_key"),
                                "transport_hint": "local",
                            }
                        ],
                        team_id=auth.team_id,
                    )
                    message_id, server_received_at = await deliver_message(
                        send_db,
                        id_chain=id_chain,
                        registry_client=registry_client,
                        recipient_agent=recipient,
                        team_id=auth.team_id,
                        from_agent_id=auth.agent_id,
                        from_alias=auth.alias,
                        to_agent_id=to_agent_id,
                        to_alias=to_alias,
                        from_did=sender_did,
                        to_did=recipient_did or "",
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
                        conversation_id=conversation["conversation_id"],
                        skip_policy_check=True,
                        known_new=message_is_new,
                    )
        except Exception as exc:
            # An identical send that ran concurrently committed first; its
            # rollback here leaves nothing of this attempt behind.
            if not _lost_send_race(exc):
                raise
            stored, _ = await _stored_exact_send(db, payload=payload, sender_did=sender_did)
            if stored is None:
                raise
            return stored
    except (ValidationError, NotFoundError, ForbiddenError, ConflictError) as exc:
        if (isinstance(exc, ForbiddenError) and payload.to_address
                and recipient.get("identity_scope") == "local"
                and not recipient.get("has_global_claim") and not recipient.get("did_aw")):
            raise FederationAuthorityError("local_recipient_route_missing") from exc
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    await record_successful_contact_side_effect(
        db,
        owner_did=(auth.did_aw or sender_did).strip(),
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
            "from_did_aw": (auth.did_aw or "").strip() or None,
            "to_agent_id": to_agent_id,
            "from_alias": auth.alias or sender_did,
            "message_id": str(message_id),
            "conversation_id": conversation["conversation_id"],
            "to_alias": to_alias,
            "subject": payload.subject,
            "priority": payload.priority,
            "content_mode": payload.content_mode or "legacy_plaintext_v1",
        },
    )

    return SentMail(
        message_id=str(message_id),
        conversation_id=conversation["conversation_id"],
        status="delivered",
        delivered_at=_utc_iso(server_received_at),
    )
