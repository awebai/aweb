"""Refuse hosted decryption custody from the exact verified delivery key."""

import json
import logging
from datetime import datetime, timezone
from uuid import UUID

from awid.e2ee_keys import validate_encryption_key_assertion
from awid.federation_errors import FederationAuthorityError

logger = logging.getLogger(__name__)


async def require_non_custodial_recipients(db, envelope: dict, recipients: list[dict]) -> None:
    """Absent assertions retain legacy behavior; absence is no custody fact.

    Remote recipients without an assertion already in hand remain the sending
    client's responsibility. Ingress and managed hosted sends cannot establish
    user E2EE intent. Check a local recipient's exact delivered key, never its
    latest unrelated key or an unverified projection of its custody field.
    """
    references = envelope.get("recipients")
    if not isinstance(references, list):
        return  # Malformed envelopes still go through the shared validator.
    for recipient in recipients:
        if not recipient.get("agent_id"):
            continue
        did = str(recipient.get("did_key") or recipient.get("current_did_key") or "").strip()
        reference = next((item for item in references if isinstance(item, dict) and item.get("did") == did), None)
        if not reference:
            continue  # Envelope binding validation remains the caller's job.
        key_id = reference.get("encryption_key_id")
        if not isinstance(key_id, str) or not key_id:
            continue
        row = await db.get_manager("aweb").fetch_one(
            """SELECT assertion_canonical, assertion_signature
               FROM {{tables.agent_encryption_keys}}
               WHERE agent_id=$1 AND encryption_key_id=$2 AND revoked_at IS NULL""",
            UUID(str(recipient["agent_id"])), key_id,
        )
        if row is None:
            continue
        try:
            assertion = json.loads(row["assertion_canonical"])
            if not isinstance(assertion, dict) or assertion.get("custody") != "hosted_custodial":
                continue
            assertion["signature"] = row["assertion_signature"]
            validate_encryption_key_assertion(
                assertion, current_did_key=did,
                stable_id=str(recipient.get("did_aw") or "").strip() or None,
                now=datetime.now(timezone.utc),
            )
        except (ValueError, TypeError) as exc:
            logger.warning("Invalid delivery-key assertion for recipient %s", recipient["agent_id"], exc_info=True)
            raise FederationAuthorityError("recipient_encryption_assertion_invalid_or_stale") from exc
        raise FederationAuthorityError("recipient_custodial_no_e2ee")
