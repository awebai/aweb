from __future__ import annotations

import json
from typing import Any, Literal

from awid.signing import VerifyResult, verify_signature

from aweb.service_errors import ForbiddenError

VerificationStatus = Literal["verified", "verified_legacy", "unverified", "failed"]

LEGACY_CONVERSATION_CONTINUATION_DETAIL = (
    "Conversation cannot be continued because the latest signed message does not bind conversation_id"
)


def message_verification_status(row: dict[str, Any]) -> VerificationStatus:
    signed_payload = str(row.get("signed_payload") or "")
    signature = str(row.get("signature") or "")
    if not signed_payload or not signature:
        return "unverified"

    try:
        payload = json.loads(signed_payload)
    except Exception:
        return "failed"
    if not isinstance(payload, dict):
        return "failed"

    from_did = str(payload.get("from_did") or row.get("from_did") or "")
    if not from_did:
        return "unverified"

    result = verify_signature(from_did, signed_payload.encode("utf-8"), signature)
    if result == VerifyResult.UNVERIFIED:
        return "unverified"
    if result != VerifyResult.VERIFIED:
        return "failed"

    # Continuation enforcement is row-authoritative: persisted conversation_id
    # must be populated at write time for signed conversation binding to matter.
    conversation_id = str(row.get("conversation_id") or "").strip()
    if not conversation_id:
        return "verified"

    signed_conversation_id = str(payload.get("conversation_id") or "").strip()
    if signed_conversation_id == conversation_id:
        return "verified"
    if not signed_conversation_id:
        return "verified_legacy"
    return "failed"


async def latest_message_verification_status(
    db,
    *,
    conversation_id: str,
    conversation_type: Literal["mail", "chat"] | None = None,
) -> VerificationStatus | None:
    latest = await _latest_message_verification_candidate(
        db,
        conversation_id=conversation_id,
        conversation_type=conversation_type,
    )
    if not latest:
        return None
    return message_verification_status(latest)


async def _latest_message_verification_candidate(
    db,
    *,
    conversation_id: str,
    conversation_type: Literal["mail", "chat"] | None = None,
) -> dict[str, Any] | None:
    aweb_db = db.get_manager("aweb")
    candidates: list[dict[str, Any]] = []
    if conversation_type in (None, "mail"):
        row = await aweb_db.fetch_one(
            """
            SELECT message_id, conversation_id, from_did, signature, signed_payload, created_at
            FROM {{tables.messages}}
            WHERE conversation_id = $1::uuid
            ORDER BY created_at DESC, message_id DESC
            LIMIT 1
            """,
            conversation_id,
        )
        if row:
            candidates.append(dict(row))
    if conversation_type in (None, "chat"):
        row = await aweb_db.fetch_one(
            """
            SELECT message_id, session_id AS conversation_id, from_did, signature, signed_payload, created_at
            FROM {{tables.chat_messages}}
            WHERE session_id = $1::uuid
            ORDER BY created_at DESC, message_id DESC
            LIMIT 1
            """,
            conversation_id,
        )
        if row:
            candidates.append(dict(row))
    if not candidates:
        return None
    latest = max(candidates, key=lambda row: (row["created_at"], str(row["message_id"])))
    return latest


async def _is_first_mail_message(
    db,
    *,
    conversation_id: str,
    message_id: str,
) -> bool:
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT message_id
        FROM {{tables.messages}}
        WHERE conversation_id = $1::uuid
        ORDER BY created_at ASC, message_id ASC
        LIMIT 1
        """,
        conversation_id,
    )
    return bool(row and str(row["message_id"]) == str(message_id))


async def require_conversation_not_legacy_bound(
    db,
    *,
    conversation_id: str,
    conversation_type: Literal["mail", "chat"] | None = None,
) -> None:
    latest = await _latest_message_verification_candidate(
        db,
        conversation_id=conversation_id,
        conversation_type=conversation_type,
    )
    if not latest:
        return
    status = message_verification_status(latest)
    if status == "verified_legacy":
        # Pre-conversation-id clients could seed a valid signed first-contact
        # mail. Allow exactly that bootstrap reply; later legacy signed messages
        # still fail closed because they would make the current thread ambiguous.
        if conversation_type == "mail" and await _is_first_mail_message(
            db,
            conversation_id=conversation_id,
            message_id=str(latest["message_id"]),
        ):
            return
        raise ForbiddenError(LEGACY_CONVERSATION_CONTINUATION_DETAIL)
