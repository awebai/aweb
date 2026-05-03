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

    conversation_id = str(row.get("conversation_id") or "").strip()
    if not conversation_id:
        return "verified"

    signed_conversation_id = str(payload.get("conversation_id") or "").strip()
    if signed_conversation_id == conversation_id:
        return "verified"
    if not signed_conversation_id:
        return "verified_legacy"
    return "failed"


async def latest_message_verification_status(db, *, conversation_id: str) -> VerificationStatus | None:
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT message_id, conversation_id, from_did, signature, signed_payload
        FROM {{tables.messages}}
        WHERE conversation_id = $1::uuid
        ORDER BY created_at DESC, message_id DESC
        LIMIT 1
        """,
        conversation_id,
    )
    if not row:
        return None
    return message_verification_status(dict(row))


async def require_conversation_not_legacy_bound(db, *, conversation_id: str) -> None:
    status = await latest_message_verification_status(db, conversation_id=conversation_id)
    if status == "verified_legacy":
        raise ForbiddenError(LEGACY_CONVERSATION_CONTINUATION_DETAIL)
