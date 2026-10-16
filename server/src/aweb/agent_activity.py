"""Signed agent activity events (docs/agent-activity.md)."""

from __future__ import annotations

from datetime import datetime, timedelta
import re
from typing import Any

from awid.signing import VerifyResult, verify_signature

from aweb.signed_document import (
    SignedDocumentError,
    decode_payload,
    is_safe_positive_integer,
    parse_json_object,
    parse_timestamp,
    require_canonical,
)

ACTIVITY_TYPE = "agent_activity"
ACTIVITY_VERSION = 1
MAX_EVENT_BYTES = 1024
SUMMARY_MAX_BYTES = 120
IDENTIFIER_MAX_BYTES = 64
MAX_VALIDITY = timedelta(seconds=60)
CLOCK_SKEW = timedelta(minutes=5)

PHASES = frozenset({"turn_started", "thinking", "tool", "waiting_permission", "writing", "turn_ended"})

_FIELDS = frozenset(
    {
        "v",
        "type",
        "from_did",
        "from_stable_id",
        "team_id",
        "session_id",
        "turn_id",
        "seq",
        "phase",
        "tool",
        "summary",
        "timestamp",
        "expires_at",
    }
)
_REQUIRED = (
    "v",
    "type",
    "from_did",
    "team_id",
    "session_id",
    "turn_id",
    "seq",
    "phase",
    "timestamp",
    "expires_at",
)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]+$")
_SESSION_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_CONTROL = re.compile("[\u0000-\u001f\u007f-\u009f]")


class ActivityEventError(SignedDocumentError):
    """An activity event refused with one of the contract's error codes."""


def _is_identifier(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value.encode("utf-8")) <= IDENTIFIER_MAX_BYTES
        and _IDENTIFIER.match(value) is not None
    )


def _check_fields(event: dict[str, Any]) -> None:
    unknown = sorted(set(event) - _FIELDS)
    if unknown:
        raise ActivityEventError("unknown_field", f"unknown field {unknown[0]}")
    missing = [name for name in _REQUIRED if name not in event]
    if event.get("phase") == "tool" and "tool" not in event:
        missing.append("tool")
    if missing:
        raise ActivityEventError("missing_field", f"missing field {missing[0]}")


def _check_values(event: dict[str, Any]) -> tuple[datetime, datetime]:
    version = event["v"]
    if not isinstance(version, int) or isinstance(version, bool) or version != ACTIVITY_VERSION:
        raise ActivityEventError("invalid_value", f"v must be {ACTIVITY_VERSION}")
    if not isinstance(event["from_did"], str) or not event["from_did"].startswith("did:key:z"):
        raise ActivityEventError("invalid_value", "from_did must be a did:key")
    if "from_stable_id" in event and (
        not isinstance(event["from_stable_id"], str) or not event["from_stable_id"].startswith("did:aw:")
    ):
        raise ActivityEventError("invalid_value", "from_stable_id must be a did:aw")
    if not isinstance(event["team_id"], str) or not event["team_id"]:
        raise ActivityEventError("invalid_value", "team_id must be a non-empty string")
    session_id = event["session_id"]
    if session_id is not None and (not isinstance(session_id, str) or not _SESSION_ID.match(session_id)):
        raise ActivityEventError("invalid_value", "session_id must be null or a lowercase UUID")
    if not _is_identifier(event["turn_id"]):
        raise ActivityEventError("invalid_value", "turn_id must be 1 to 64 bytes of [A-Za-z0-9_.:-]")
    if not is_safe_positive_integer(event["seq"]):
        raise ActivityEventError("invalid_value", "seq must be an integer from 1 to 2^53-1")
    if not isinstance(event["phase"], str) or event["phase"] not in PHASES:
        raise ActivityEventError("invalid_value", "phase is not a known activity phase")
    if "tool" in event and not _is_identifier(event["tool"]):
        raise ActivityEventError("invalid_value", "tool must be 1 to 64 bytes of [A-Za-z0-9_.:-]")
    if "summary" in event:
        summary = event["summary"]
        if not isinstance(summary, str) or not summary:
            raise ActivityEventError("invalid_value", "summary must be a non-empty string")
        if len(summary.encode("utf-8")) > SUMMARY_MAX_BYTES:
            raise ActivityEventError("text_too_long", f"summary exceeds {SUMMARY_MAX_BYTES} bytes")
        if _CONTROL.search(summary):
            raise ActivityEventError("control_character", "summary must be one line without control characters")
    timestamp = parse_timestamp("timestamp", event["timestamp"], error=ActivityEventError)
    expires_at = parse_timestamp("expires_at", event["expires_at"], error=ActivityEventError)
    return timestamp, expires_at


def verify_activity_event(
    signed_payload: str,
    signature: str,
    *,
    signer_did: str,
    team_id: str,
    stable_id: str | None,
    now: datetime,
) -> dict[str, Any]:
    """Return the verified activity event, or raise ActivityEventError.

    signer_did is the key that signed the request: the agent's did:key, or the
    grant session key for a grant caller. team_id and stable_id are the
    authenticated team and the identity the caller is attributed to. Session
    participation and rate limiting belong to the route.
    """
    raw = decode_payload(signed_payload, max_bytes=MAX_EVENT_BYTES, error=ActivityEventError)
    event = parse_json_object(raw, error=ActivityEventError)
    require_canonical(event, raw, error=ActivityEventError)
    if verify_signature(signer_did, raw, signature) is not VerifyResult.VERIFIED:
        raise ActivityEventError("bad_signature", "the signature does not verify for the caller's key")
    if event.get("type") != ACTIVITY_TYPE:
        raise ActivityEventError("wrong_type", f"type must be {ACTIVITY_TYPE}")
    _check_fields(event)
    timestamp, expires_at = _check_values(event)
    if event["from_did"] != signer_did:
        raise ActivityEventError("signer_mismatch", "from_did is not the key that signed the request")
    if event["team_id"] != team_id:
        raise ActivityEventError("team_mismatch", "team_id is not the authenticated team")
    if "from_stable_id" in event and event["from_stable_id"] != stable_id:
        raise ActivityEventError("stable_id_mismatch", "from_stable_id is not the caller's stable id")
    if not timestamp < expires_at <= timestamp + MAX_VALIDITY:
        raise ActivityEventError("validity_window", "expires_at must be after timestamp and at most 60 seconds later")
    if abs(now - timestamp) > CLOCK_SKEW:
        raise ActivityEventError("clock_skew", "timestamp is more than 5 minutes from the server clock")
    if now >= expires_at:
        raise ActivityEventError("expired", "expires_at has passed")
    return event
