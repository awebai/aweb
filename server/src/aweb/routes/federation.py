from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request

from awid.log import canonical_server_origin
from awid.team_ids import parse_team_id

from aweb.config import get_settings
from aweb.deps import get_db
from aweb.federation.envelope import (
    FederatedDeliveryRequest,
    FederationEnvelope,
    FederationEnvelopeError,
    require_team_certificate_for_non_public_reachability,
    verify_federation_envelope,
)
from aweb.hooks import fire_mutation_hook
from aweb.messaging.conversations import (
    create_conversation,
    get_conversation,
    list_conversation_participants,
    touch_conversation_activity,
)
from aweb.messaging.messages import (
    deliver_message,
    evaluate_messaging_policy,
    resolve_agent_by_did,
    utc_iso,
)
from aweb.service_errors import ForbiddenError, NotFoundError, ValidationError
from aweb.team_auth import parse_and_verify_certificate

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


def _certificate_header_from_dict(certificate: dict | None) -> str | None:
    if certificate is None:
        return None
    return base64.b64encode(json.dumps(certificate).encode()).decode()


async def _verify_sender_current_key(registry_client, envelope: FederationEnvelope) -> None:
    try:
        resolution = await registry_client.resolve_key(envelope.sender_did_aw)
        if (
            resolution
            and resolution.current_did_key != envelope.sender_current_did_key
            and hasattr(registry_client, "resolve_key_fresh")
        ):
            resolution = await registry_client.resolve_key_fresh(envelope.sender_did_aw)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="AWID registry unavailable") from exc
    if not resolution or resolution.current_did_key != envelope.sender_current_did_key:
        raise HTTPException(status_code=422, detail="Federation sender current key mismatch")


async def _resolve_target_address(registry_client, envelope: FederationEnvelope):
    domain, name = _split_address(envelope.target_address)
    try:
        resolved = await registry_client.resolve_address(domain, name)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="AWID registry unavailable") from exc
    if resolved is None:
        raise HTTPException(status_code=404, detail="Federation target address not found")
    if resolved.did_aw != envelope.target_did_aw:
        raise HTTPException(status_code=422, detail="Federation target did:aw mismatch")
    if resolved.current_did_key != envelope.target_current_did_key:
        raise HTTPException(status_code=422, detail="Federation target current key mismatch")
    try:
        resolved_origin = canonical_server_origin((resolved.delivery.origin or "").strip())
    except Exception as exc:
        raise HTTPException(status_code=424, detail="Federation target address has no delivery origin") from exc
    if resolved_origin != envelope.target_delivery_origin:
        raise HTTPException(status_code=422, detail="Federation target delivery origin mismatch")
    return resolved


async def _verify_team_certificate(registry_client, envelope: FederationEnvelope) -> None:
    if envelope.sender_team_certificate is None:
        return
    cert_header = _certificate_header_from_dict(envelope.sender_team_certificate)
    if cert_header is None:
        return

    async def _team_key(team_id: str) -> str:
        domain, name = parse_team_id(team_id)
        key = await registry_client.get_team_public_key(domain, name)
        if not key:
            raise ValueError("Unknown team")
        return key

    async def _revoked(team_id: str) -> set[str]:
        domain, name = parse_team_id(team_id)
        return await registry_client.get_team_revocations(domain, name)

    try:
        team_id = str(envelope.sender_team_certificate.get("team_id") or "")
        if envelope.sender_active_team_id and team_id != envelope.sender_active_team_id:
            raise ValueError("Certificate team_id mismatch")
        team_did_key = await _team_key(team_id)
        revoked = await _revoked(team_id)
        cert_info = parse_and_verify_certificate(
            cert_header,
            request_did_key=envelope.sender_current_did_key,
            team_public_key_resolver=lambda _team_id: team_did_key,
            revocation_checker=lambda _team_id, certificate_id: certificate_id in revoked,
        )
    except Exception as exc:
        raise HTTPException(status_code=403, detail="Invalid federation team certificate") from exc

    cert_did_aw = (cert_info.get("member_did_aw") or "").strip()
    if cert_did_aw and cert_did_aw != envelope.sender_did_aw:
        raise HTTPException(status_code=403, detail="Federation team certificate identity mismatch")
    cert_address = (cert_info.get("member_address") or "").strip()
    if cert_address and envelope.sender_address and cert_address != envelope.sender_address:
        raise HTTPException(status_code=403, detail="Federation team certificate address mismatch")
    _verify_certificate_time(envelope)


def _verify_certificate_time(envelope: FederationEnvelope) -> None:
    cert = envelope.sender_team_certificate or {}
    issued_at = str(cert.get("issued_at") or "").strip()
    if not issued_at:
        raise HTTPException(status_code=403, detail="Federation team certificate missing issued_at")
    try:
        issued = datetime.fromisoformat(issued_at.replace("Z", "+00:00")).astimezone(timezone.utc)
        message_time = _parse_timestamp(envelope.timestamp)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=403, detail="Federation team certificate has invalid issued_at") from exc
    if issued > message_time:
        raise HTTPException(status_code=403, detail="Federation team certificate was issued after message timestamp")


def _require_target_origin_here(request: Request, envelope: FederationEnvelope) -> None:
    if envelope.target_delivery_origin not in _public_origins(request):
        raise HTTPException(status_code=421, detail="Federation message is addressed to a different delivery origin")


async def _idempotent_existing_message(db, envelope: FederationEnvelope) -> tuple[str, datetime] | None:
    aweb_db = db.get_manager("aweb")
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
        return envelope.conversation_id

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
                "transport_hint": "local",
            }
        ],
        team_id=recipient.get("team_id"),
    )
    return conversation["conversation_id"]


@router.post("/messages")
async def receive_federated_message(
    request: Request,
    payload: FederatedDeliveryRequest,
    db=Depends(get_db),
):
    if payload.envelope.type != "mail":
        raise HTTPException(status_code=422, detail="Federation endpoint currently accepts mail only")
    registry_client = getattr(request.app.state, "awid_registry_client", None)
    if registry_client is None:
        raise HTTPException(status_code=503, detail="AWID registry unavailable")

    try:
        envelope = verify_federation_envelope(
            payload.envelope,
            payload.signature,
            expected={
                "type": "mail",
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
    resolved = await _resolve_target_address(registry_client, envelope)
    try:
        require_team_certificate_for_non_public_reachability(
            envelope,
            reachability=resolved.reachability,
        )
    except FederationEnvelopeError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    await _verify_team_certificate(registry_client, envelope)

    recipient = await resolve_agent_by_did(db, envelope.target_did_aw)
    if recipient is None:
        recipient = await resolve_agent_by_did(db, envelope.target_current_did_key)
    if recipient is None:
        raise HTTPException(status_code=404, detail="Federation recipient agent not found")

    try:
        await evaluate_messaging_policy(
            db,
            registry_client=registry_client,
            recipient_agent=recipient,
            sender_did=envelope.sender_did_aw,
            sender_address=envelope.sender_address,
        )
    except ForbiddenError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    existing = await _idempotent_existing_message(db, envelope)
    if existing is not None:
        conversation_id, created_at = existing
        return {
            "message_id": envelope.message_id,
            "conversation_id": conversation_id,
            "status": "delivered",
            "delivered_at": utc_iso(created_at),
        }

    try:
        conversation_id = await _ensure_federated_mail_conversation(db, envelope, recipient)
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
            subject=envelope.subject or "",
            body=envelope.body,
            priority=envelope.priority or "normal",
            sender_address=envelope.sender_address,
            team_id=recipient.get("team_id"),
            from_agent_id=None,
            to_agent_id=recipient.get("agent_id"),
            signature=payload.signature,
            signed_payload=envelope.signed_payload,
            created_at=_parse_timestamp(envelope.timestamp),
            message_id=UUID(envelope.message_id),
            conversation_id=conversation_id,
            skip_policy_check=True,
        )
        await touch_conversation_activity(db, conversation_id=conversation_id)
    except (ValidationError, NotFoundError, ForbiddenError) as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    await fire_mutation_hook(
        request,
        "message.sent",
        {
            "team_id": recipient.get("team_id"),
            "from_agent_id": None,
            "from_did": envelope.sender_current_did_key,
            "from_did_aw": envelope.sender_did_aw,
            "to_agent_id": recipient.get("agent_id"),
            "from_alias": _participant_alias_from_address(envelope.sender_address, envelope.sender_did_aw),
            "message_id": str(message_id),
            "conversation_id": conversation_id,
            "to_alias": recipient.get("alias"),
            "subject": envelope.subject or "",
            "priority": envelope.priority or "normal",
            "federated": True,
        },
    )

    return {
        "message_id": str(message_id),
        "conversation_id": conversation_id,
        "status": "delivered",
        "delivered_at": utc_iso(created_at),
    }
