"""Immutable message admission facts; current membership is separate information."""
from __future__ import annotations

import json
from typing import Literal

from pydantic import BaseModel, ValidationError

from aweb.messaging.verification import message_verification_status


class SenderAdmission(BaseModel):
    outcome: Literal["verified", "verified_legacy", "unverified", "failed", "unrecorded", "unknown"]
    message_id: str | None = None
    did_key: str | None = None
    team_id: str | None = None
    certificate_id: str | None = None
    did_aw: str | None = None
    address: str | None = None


def capture_sender_admission(auth, row: dict) -> str | None:
    """Use authenticated facts only (acki), never projected agent-row claims.

    Identity-only or federated authentication may have no team/certificate; NULL
    records that absence, rather than inventing a membership assertion. The JSON
    is inserted together with the message, with no separate write or backfill.
    """
    if auth is None:
        return None
    did_key = (auth.did_key or "").strip()
    outcome = message_verification_status(row)
    # A valid signature by somebody else must not inherit this request's facts.
    try:
        if row.get("content_mode") == "encrypted_v2":
            signed_key = row["encrypted_envelope"]["from"]["did"]
        else:
            signed_key = json.loads(row.get("signed_payload") or "{}").get("from_did")
    except (ValueError, KeyError, TypeError):
        signed_key = None
    if outcome in ("verified", "verified_legacy") and signed_key != did_key:
        outcome = "failed"
    return SenderAdmission(
        outcome=outcome, message_id=str(row["message_id"]), did_key=did_key,
        team_id=auth.team_id, certificate_id=auth.certificate_id,
        did_aw=auth.did_aw or None, address=auth.address or None,
    ).model_dump_json()


def stored_sender_admission(row) -> SenderAdmission:
    raw = row.get("sender_admission")
    if raw is None:
        return SenderAdmission(outcome="unrecorded")
    try:
        parsed = SenderAdmission.model_validate_json(raw) if isinstance(raw, str) else SenderAdmission.model_validate(raw)
    except (ValidationError, TypeError):
        return SenderAdmission(outcome="unknown")
    if parsed.message_id != str(row.get("message_id")):
        return SenderAdmission(outcome="unknown")
    return parsed
