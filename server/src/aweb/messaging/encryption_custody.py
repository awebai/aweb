"""Separate explicit client encryption from verified hosted managed encryption."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from uuid import UUID

from awid.e2ee_keys import validate_encryption_key_assertion
from awid.federation_errors import FederationAuthorityError

if TYPE_CHECKING:
    from aweb.identity_auth_deps import MessagingAuth

logger = logging.getLogger(__name__)


async def _verified_hosted_key(db, *, agent_id, did, stable_id, key_id, invalid_reason):
    if not agent_id:
        return False
    row = await db.get_manager("aweb").fetch_one(
        """SELECT assertion_canonical, assertion_signature
           FROM {{tables.agent_encryption_keys}}
           WHERE agent_id=$1 AND encryption_key_id=$2 AND revoked_at IS NULL""",
        UUID(str(agent_id)), key_id,
    )
    if row is None:
        return False
    try:
        assertion = json.loads(row["assertion_canonical"])
        if not isinstance(assertion, dict) or assertion.get("custody") != "hosted_custodial":
            return False
        assertion["signature"] = row["assertion_signature"]
        validate_encryption_key_assertion(
            assertion, current_did_key=did, stable_id=stable_id or None,
            now=datetime.now(timezone.utc),
        )
        if assertion["encryption_key_id"] != key_id:
            raise ValueError("stored assertion does not bind the targeted key")
    except (ValueError, TypeError) as exc:
        logger.warning("Invalid encryption-key assertion for actor %s", agent_id, exc_info=True)
        raise FederationAuthorityError(invalid_reason) from exc
    return True


async def require_non_custodial_recipients(
    db, envelope: dict, recipients: list[dict], *, sender: MessagingAuth,
) -> None:
    """Only a verified hosted sender key exempts managed encrypted-v2 sends.

    Missing/null custody remains a client send, never proof of managed custody.
    Remote recipients without an assertion in hand remain the sending client's
    responsibility; federation ingress and MCP managed paths do not call here.
    """
    wraps = envelope.get("key_wraps")
    if isinstance(wraps, list) and wraps:
        keys = [wrap.get("sender_encryption_key_id") if isinstance(wrap, dict) else None for wrap in wraps]
        if any(not isinstance(key, str) or not key for key in keys) or len(set(keys)) != 1:
            raise FederationAuthorityError("federation_envelope_invalid")
        sender_ref = envelope.get("from")
        if not isinstance(sender_ref, dict) or sender_ref.get("encryption_key_id") != keys[0]:
            raise FederationAuthorityError("federation_envelope_invalid")
        if await _verified_hosted_key(
            db, agent_id=sender.agent_id, did=sender.did_key,
            stable_id=(sender.did_aw or "").strip(), key_id=keys[0],
            invalid_reason="federation_envelope_invalid",
        ):
            return

    references = envelope.get("recipients")
    if not isinstance(references, list):
        return  # Malformed envelopes still go through the shared validator.
    for recipient in recipients:
        if not recipient.get("agent_id"):
            continue
        did = str(recipient.get("did_key") or recipient.get("current_did_key") or "").strip()
        reference = next((item for item in references if isinstance(item, dict) and item.get("did") == did), None)
        if not reference:
            continue
        key_id = reference.get("encryption_key_id")
        if not isinstance(key_id, str) or not key_id:
            continue
        if await _verified_hosted_key(
            db, agent_id=recipient["agent_id"], did=did,
            stable_id=str(recipient.get("did_aw") or "").strip(), key_id=key_id,
            invalid_reason="recipient_encryption_assertion_invalid_or_stale",
        ):
            raise FederationAuthorityError("recipient_custodial_no_e2ee")
