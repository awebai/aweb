"""Refuse hosted decryption custody from the exact verified delivery key."""

import json
import logging
from datetime import datetime, timezone
from uuid import UUID

from awid.e2ee_keys import validate_encryption_key_assertion
from awid.federation_errors import FederationAuthorityError

logger = logging.getLogger(__name__)


def require_non_custodial_assertion(assertion: dict) -> None:
    """Call only after signature and current recipient binding verification."""
    if assertion.get("custody") == "hosted_custodial":
        raise FederationAuthorityError("recipient_custodial_no_e2ee")


async def require_non_custodial_recipients(db, envelope: dict, recipients: list[dict]) -> None:
    """Absent assertions retain legacy behavior; absence is no custody fact.

    Remote recipients are checked by their receiving server's Phase B. A local
    recipient's exact delivered key is checked, never its latest unrelated key
    or an unverified projection of the assertion's custody field.
    """
    for recipient in recipients:
        if not recipient.get("agent_id"):
            continue
        did = str(recipient.get("did_key") or recipient.get("current_did_key") or "").strip()
        reference = next((item for item in envelope.get("recipients", []) if item.get("did") == did), None)
        if not reference:
            continue  # Envelope binding validation remains the caller's job.
        row = await db.get_manager("aweb").fetch_one(
            """SELECT assertion_canonical, assertion_signature
               FROM {{tables.agent_encryption_keys}}
               WHERE agent_id=$1 AND encryption_key_id=$2 AND revoked_at IS NULL""",
            UUID(str(recipient["agent_id"])), reference["encryption_key_id"],
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
        require_non_custodial_assertion(assertion)
