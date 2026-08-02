from __future__ import annotations

import json
import logging
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from awid.federation_errors import FederationAuthorityError
from awid.log import canonical_server_origin

from aweb.awid_error_handling import AWID_DEPENDENCY_ERRORS
from aweb.config import get_settings
from aweb.deps import get_db
from aweb.federation.authority import AuthorityClaim
from aweb.federation.delivery import (
    deliver_federated_phase_b,
    federation_envelope_hash,
    replay_federation_mutation_outbox,
)
from aweb.federation.envelope import (
    FederatedDeliveryRequest,
    FederationEnvelope,
    FederationEnvelopeError,
    verify_federation_envelope,
)
from aweb.federation.errors import authority_error_body
from aweb.messaging.messages import resolve_agent_by_did

logger = logging.getLogger(__name__)

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


def _split_address(address: str) -> tuple[str, str]:
    if address.count("/") != 1:
        raise FederationAuthorityError("federation_envelope_invalid")
    domain, name = address.split("/", 1)
    if not domain.strip() or not name.strip():
        raise FederationAuthorityError("federation_envelope_invalid")
    return domain.strip(), name.strip()


def _is_local_did_key(value: str | None) -> bool:
    return str(value or "").strip().startswith("did:key:")


def _validate_stored_current_key(
    *,
    did_aw: str,
    current_did_key: str,
    participant: dict | None,
    mismatch_reason: str,
) -> None:
    stable_did = str(did_aw or "").strip()
    expected_key = str(current_did_key or "").strip()
    if _is_local_did_key(stable_did):
        if expected_key != stable_did:
            raise FederationAuthorityError(mismatch_reason)
        return
    stored_key = str((participant or {}).get("current_did_key") or "").strip()
    if not stored_key or stored_key != expected_key:
        raise FederationAuthorityError(mismatch_reason)


def _validate_stored_current_keys(
    envelope: FederationEnvelope, participants: dict[str, dict]
) -> None:
    _validate_stored_current_key(
        did_aw=envelope.sender_did_aw,
        current_did_key=envelope.sender_current_did_key,
        participant=participants.get(envelope.sender_did_aw),
        mismatch_reason="sender_current_key_mismatch",
    )
    _validate_stored_current_key(
        did_aw=envelope.target_did_aw,
        current_did_key=envelope.target_current_did_key,
        participant=participants.get(envelope.target_did_aw),
        mismatch_reason="recipient_current_key_mismatch",
    )


async def _stored_route_participants(
    db, envelope: FederationEnvelope
) -> dict[str, dict] | None:
    if not envelope.conversation_id:
        return None
    manager = db.get_manager("aweb")
    conversation = await manager.fetch_one(
        """
        SELECT conversation_type, status
        FROM {{tables.conversations}}
        WHERE conversation_id = $1
        """,
        UUID(envelope.conversation_id),
    )
    if conversation is None:
        return None
    if (
        conversation["conversation_type"] != envelope.type
        or conversation["status"] != "active"
    ):
        raise FederationAuthorityError("federation_conversation_invalid")
    rows = await manager.fetch_all(
        """
        SELECT did, address, delivery_origin, current_did_key, transport_hint
        FROM {{tables.conversation_participants}}
        WHERE conversation_id = $1
          AND did = ANY($2::text[])
        """,
        UUID(envelope.conversation_id),
        [envelope.sender_did_aw, envelope.target_did_aw],
    )
    by_did = {row["did"]: dict(row) for row in rows}
    if set(by_did) != {envelope.sender_did_aw, envelope.target_did_aw}:
        raise FederationAuthorityError("federation_conversation_invalid")
    _validate_stored_current_keys(envelope, by_did)
    if envelope.type == "chat":
        session = await manager.fetch_one(
            "SELECT 1 FROM {{tables.chat_sessions}} WHERE session_id = $1",
            UUID(envelope.conversation_id),
        )
        if session is None:
            raise FederationAuthorityError("federation_conversation_invalid")
        chat_rows = await manager.fetch_all(
            """
            SELECT did, address, delivery_origin, current_did_key
            FROM {{tables.chat_participants}}
            WHERE session_id = $1 AND did = ANY($2::text[])
            """,
            UUID(envelope.conversation_id),
            [envelope.sender_did_aw, envelope.target_did_aw],
        )
        chat_by_did = {row["did"]: dict(row) for row in chat_rows}
        if set(chat_by_did) != {envelope.sender_did_aw, envelope.target_did_aw}:
            raise FederationAuthorityError("federation_conversation_invalid")
        _validate_stored_current_keys(envelope, chat_by_did)
    else:
        chat_by_did = None
    return {"conversation": by_did, "chat": chat_by_did}


async def _resolve_target_identity(
    registry_client,
    envelope: FederationEnvelope,
    *,
    stored_route_continuation: bool,
) -> None:
    if stored_route_continuation:
        return
    domain, name = _split_address(envelope.target_address)
    try:
        resolved = await registry_client.resolve_address(domain, name)
    except AWID_DEPENDENCY_ERRORS as exc:
        logger.warning(
            "AWID registry dependency failed for federation target identity resolution",
            exc_info=True,
        )
        raise FederationAuthorityError(
            "federation_authority_coordination_unavailable"
        ) from exc
    except Exception as exc:
        logger.exception(
            "Unexpected AWID registry dependency error for federation target identity resolution"
        )
        raise FederationAuthorityError(
            "federation_authority_coordination_unavailable"
        ) from exc
    if resolved is None:
        raise FederationAuthorityError("recipient_identity_not_found")
    if resolved.did_aw != envelope.target_did_aw:
        raise FederationAuthorityError("recipient_address_did_mismatch")
    if resolved.current_did_key != envelope.target_current_did_key:
        raise FederationAuthorityError("recipient_current_key_mismatch")
    delivery = getattr(resolved, "delivery", None)
    try:
        origin = canonical_server_origin(str(getattr(delivery, "origin", "") or ""))
    except Exception as exc:
        raise FederationAuthorityError("recipient_route_missing") from exc
    if origin != envelope.target_delivery_origin:
        raise FederationAuthorityError("recipient_route_mismatch")


async def _established_replay_receipt(
    db,
    *,
    envelope: FederationEnvelope,
    envelope_hash: str,
) -> dict | None:
    try:
        row = await db.get_manager("aweb").fetch_one(
            """
            SELECT envelope_hash, canonical_metadata, storage_kind,
                   legacy_unreplayable, established_result
            FROM {{tables.message_ingress_receipts}}
            WHERE message_id = $1
            """,
            UUID(envelope.message_id),
        )
    except Exception as exc:
        raise FederationAuthorityError(
            "federation_authority_coordination_unavailable"
        ) from exc
    if row is None:
        return None
    if (
        row["legacy_unreplayable"]
        or row["envelope_hash"] != envelope_hash
        or row["storage_kind"] != envelope.type
        or row["established_result"] is None
    ):
        raise FederationAuthorityError("federation_message_replay_conflict")
    metadata = row["canonical_metadata"]
    result = row["established_result"]
    try:
        if isinstance(metadata, str):
            metadata = json.loads(metadata)
        if isinstance(result, str):
            result = json.loads(result)
    except (TypeError, ValueError) as exc:
        raise FederationAuthorityError(
            "federation_message_replay_conflict"
        ) from exc
    if not isinstance(metadata, dict) or not isinstance(result, dict):
        raise FederationAuthorityError("federation_message_replay_conflict")
    return {"metadata": metadata, "result": result}


def _stable_envelope_error(exc: FederationEnvelopeError) -> FederationAuthorityError:
    detail = str(exc).lower()
    if any(
        marker in detail
        for marker in (
            "timestamp",
            "skew",
            "expired",
            "expiration",
            "created_at",
            "too far in the future",
        )
    ):
        return FederationAuthorityError("federation_timestamp_invalid")
    if "signature" in detail:
        return FederationAuthorityError("federation_signature_invalid")
    if "sender address" in detail or "signed_payload from does not match" in detail:
        return FederationAuthorityError("sender_address_wrapper_mismatch")
    return FederationAuthorityError("federation_envelope_invalid")


def _stable_error_response(
    request: Request, error: FederationAuthorityError
) -> JSONResponse:
    correlation_id = request.headers.get("X-Correlation-ID") or str(uuid4())
    headers = {"Retry-After": "1"} if error.retry_after_required else None
    return JSONResponse(
        status_code=error.http_status,
        content=authority_error_body(error, correlation_id=correlation_id),
        headers=headers,
    )


@router.post("/messages")
async def receive_federated_message(
    request: Request,
    payload: FederatedDeliveryRequest,
    db=Depends(get_db),
):
    try:
        registry_client = getattr(request.app.state, "awid_registry_client", None)
        if registry_client is None:
            raise FederationAuthorityError(
                "federation_authority_coordination_unavailable"
            )
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
            raise _stable_envelope_error(exc) from exc
        if envelope.target_delivery_origin not in _public_origins(request):
            raise FederationAuthorityError("target_route_mismatch")

        ingress_envelope_hash = federation_envelope_hash(
            envelope, payload.signature
        )
        established_replay = await _established_replay_receipt(
            db,
            envelope=envelope,
            envelope_hash=ingress_envelope_hash,
        )
        if established_replay is not None:
            metadata = established_replay["metadata"]
            envelope = envelope.model_copy(
                update={
                    "sender_address": metadata.get("sender_address"),
                    "sender_delivery_origin": metadata.get(
                        "sender_delivery_origin"
                    ),
                    "target_address": metadata.get("target_address")
                    or envelope.target_address,
                }
            )
            stored_participants = None
        else:
            stored_route_snapshot = await _stored_route_participants(db, envelope)
        if established_replay is not None:
            stored_route_snapshot = None
        stored_participants = (
            stored_route_snapshot["conversation"]
            if stored_route_snapshot is not None
            else None
        )
        stored_route = stored_route_snapshot is not None
        sender_participant = (
            stored_participants.get(envelope.sender_did_aw)
            if stored_participants is not None
            else None
        )
        if stored_participants is not None:
            target_participant = stored_participants[envelope.target_did_aw]
            stored_target_address = str(
                target_participant.get("address") or ""
            ).strip()
            if not stored_target_address:
                raise FederationAuthorityError("recipient_route_missing")
            if envelope.target_address not in {
                stored_target_address,
                envelope.target_did_aw,
            }:
                raise FederationAuthorityError("recipient_route_mismatch")
            envelope = envelope.model_copy(
                update={"target_address": stored_target_address}
            )
        authority_token = None
        if envelope.sender_did_aw.startswith("did:aw:"):
            sender_address = envelope.sender_address or str(
                (sender_participant or {}).get("address") or ""
            ).strip()
            if not sender_address:
                raise FederationAuthorityError("sender_address_required")
            sender_origin = envelope.sender_delivery_origin
            if sender_origin is None and sender_participant is not None:
                sender_origin = str(
                    sender_participant.get("delivery_origin") or ""
                ).strip() or None
            authority = getattr(request.app.state, "federation_authority", None)
            if authority is None:
                raise FederationAuthorityError(
                    "federation_authority_coordination_unavailable"
                )
            authorized = await authority.authorize(
                AuthorityClaim(
                    canonical_address=sender_address,
                    did_aw=envelope.sender_did_aw,
                    current_did_key=envelope.sender_current_did_key,
                    delivery_origin=sender_origin or "",
                ),
                source_ip=str(request.client.host if request.client else "unknown"),
            )
            authority_token = getattr(authorized, "token", authorized)
            envelope = envelope.model_copy(
                update={
                    "sender_address": getattr(
                        authorized, "canonical_address", sender_address
                    ),
                    "sender_delivery_origin": getattr(
                        authorized, "delivery_origin", sender_origin
                    ),
                }
            )
        else:
            if envelope.sender_current_did_key != envelope.sender_did_aw:
                raise FederationAuthorityError("local_sender_route_mismatch")
            if established_replay is None:
                if not stored_route or sender_participant is None:
                    raise FederationAuthorityError("local_sender_route_mismatch")
                for actual, stored in (
                    (envelope.sender_address, sender_participant.get("address")),
                    (
                        envelope.sender_delivery_origin,
                        sender_participant.get("delivery_origin"),
                    ),
                ):
                    if actual is not None and str(actual) != str(stored or ""):
                        raise FederationAuthorityError("local_sender_route_mismatch")
                envelope = envelope.model_copy(
                    update={
                        "sender_address": str(
                            sender_participant.get("address") or ""
                        ).strip()
                        or None,
                        "sender_delivery_origin": str(
                            sender_participant.get("delivery_origin") or ""
                        ).strip()
                        or None,
                    }
                )

        if established_replay is not None:
            result = await deliver_federated_phase_b(
                db,
                envelope=envelope,
                signature=payload.signature,
                recipient={},
                authority_token=authority_token,
                envelope_hash_override=ingress_envelope_hash,
            )
            return result

        await _resolve_target_identity(
            registry_client,
            envelope,
            stored_route_continuation=stored_route,
        )
        recipient = await resolve_agent_by_did(db, envelope.target_did_aw)
        if recipient is None:
            recipient = await resolve_agent_by_did(
                db, envelope.target_current_did_key
            )
        if recipient is None:
            raise FederationAuthorityError("recipient_identity_not_found")
        if (
            str(recipient.get("did_key") or "").strip()
            and str(recipient.get("did_key")).strip()
            != envelope.target_current_did_key
        ):
            raise FederationAuthorityError("recipient_current_key_mismatch")
        if _is_local_did_key(envelope.target_did_aw) and not stored_route:
            raise FederationAuthorityError("local_recipient_route_missing")
        result = await deliver_federated_phase_b(
            db,
            envelope=envelope,
            signature=payload.signature,
            recipient=recipient,
            authority_token=authority_token,
            stored_route_continuation=stored_route,
            stored_route_snapshot=stored_route_snapshot,
            envelope_hash_override=ingress_envelope_hash,
        )
        try:
            await replay_federation_mutation_outbox(
                request.app,
                db.get_manager("aweb"),
                limit=100,
            )
        except Exception:
            logger.exception(
                "Federation delivery committed but immediate mutation outbox replay failed"
            )
        return result
    except FederationAuthorityError as exc:
        return _stable_error_response(request, exc)
