"""Signed agent status documents (docs/agent-health.md)."""

from __future__ import annotations

from datetime import datetime, timedelta
import json
import re
from typing import Any
import unicodedata

from awid.signing import VerifyResult, verify_signature

from aweb.signed_document import (
    SignedDocumentError,
    decode_payload,
    is_safe_positive_integer,
    parse_json_object,
    parse_timestamp,
    require_canonical,
)

STATUS_TYPE = "agent_status"
STATUS_VERSION = 1
MAX_DOCUMENT_BYTES = 2048
REASON_TEXT_MAX_BYTES = 160
FIXING_TEXT_MAX_BYTES = 120
REASON_CODE_MAX_BYTES = 64
MAX_VALIDITY = timedelta(minutes=15)
CLOCK_SKEW = timedelta(minutes=5)

REACHABLE_VALUES = frozenset({"yes", "degraded", "no", "unknown"})
FIXING_BY_VALUES = frozenset({"automatic", "operator", "nobody", "unknown"})

_TOP_LEVEL_FIELDS = frozenset(
    {
        "v",
        "type",
        "team_id",
        "agent",
        "publisher_did",
        "seq",
        "reachable",
        "reason",
        "fixing",
        "observed_at",
        "valid_until",
    }
)
_ALWAYS_REQUIRED = (
    "v",
    "type",
    "team_id",
    "agent",
    "publisher_did",
    "seq",
    "reachable",
    "observed_at",
    "valid_until",
)
_REASON_FIELDS = frozenset({"code", "text"})
_FIXING_FIELDS = frozenset({"by", "text"})
_REASON_CODE = re.compile(r"^[a-z][a-z0-9]*\.[a-z0-9_]+$")


class StatusDocumentError(SignedDocumentError):
    """A status document refused with one of the contract's error codes."""


def _refuse(code: str, message: str) -> StatusDocumentError:
    return StatusDocumentError(code, message)


def _decode_payload(signed_payload: str) -> bytes:
    return decode_payload(signed_payload, max_bytes=MAX_DOCUMENT_BYTES, error=StatusDocumentError)


def _parse_canonical(raw: bytes) -> dict[str, Any]:
    document = parse_json_object(raw, error=StatusDocumentError)
    require_canonical(document, raw, error=StatusDocumentError)
    return document


def _check_field_names(document: dict[str, Any]) -> None:
    unknown = sorted(set(document) - _TOP_LEVEL_FIELDS)
    for name, allowed in (("reason", _REASON_FIELDS), ("fixing", _FIXING_FIELDS)):
        value = document.get(name)
        if isinstance(value, dict):
            unknown.extend(f"{name}.{key}" for key in sorted(set(value) - allowed))
    if unknown:
        raise _refuse("unknown_field", f"unknown field {unknown[0]}")


def _check_required(document: dict[str, Any]) -> None:
    missing = [name for name in _ALWAYS_REQUIRED if name not in document]
    if document.get("reachable") != "yes":
        missing.extend(name for name in ("reason", "fixing") if name not in document)
    for name, required in (("reason", ("code", "text")), ("fixing", ("by",))):
        value = document.get(name)
        if isinstance(value, dict):
            missing.extend(f"{name}.{key}" for key in required if key not in value)
    if missing:
        raise _refuse("missing_field", f"missing field {missing[0]}")


def _check_values(document: dict[str, Any]) -> tuple[datetime, datetime]:
    version = document["v"]
    if not isinstance(version, int) or isinstance(version, bool) or version != STATUS_VERSION:
        raise _refuse("invalid_value", f"v must be {STATUS_VERSION}")
    for name in ("team_id", "agent", "publisher_did"):
        if not isinstance(document[name], str) or not document[name]:
            raise _refuse("invalid_value", f"{name} must be a non-empty string")
    if not document["agent"].startswith(("did:aw:", "did:key:z")):
        raise _refuse("invalid_value", "agent must be a did:aw or did:key")
    if not document["publisher_did"].startswith("did:key:z"):
        raise _refuse("invalid_value", "publisher_did must be a did:key")
    if not is_safe_positive_integer(document["seq"]):
        raise _refuse("invalid_value", "seq must be an integer from 1 to 2^53-1")
    if not isinstance(document["reachable"], str) or document["reachable"] not in REACHABLE_VALUES:
        raise _refuse("invalid_value", "reachable must be yes, degraded, no or unknown")
    if "reason" in document:
        reason = document["reason"]
        if not isinstance(reason, dict):
            raise _refuse("invalid_value", "reason must be an object")
        code = reason["code"]
        if (
            not isinstance(code, str)
            or len(code.encode("utf-8")) > REASON_CODE_MAX_BYTES
            or not _REASON_CODE.match(code)
        ):
            raise _refuse("invalid_value", "reason.code must be a namespaced code of at most 64 bytes")
        if not isinstance(reason["text"], str):
            raise _refuse("invalid_value", "reason.text must be a string")
    if "fixing" in document:
        fixing = document["fixing"]
        if not isinstance(fixing, dict):
            raise _refuse("invalid_value", "fixing must be an object")
        if not isinstance(fixing["by"], str) or fixing["by"] not in FIXING_BY_VALUES:
            raise _refuse("invalid_value", "fixing.by must be automatic, operator, nobody or unknown")
        if "text" in fixing and not isinstance(fixing["text"], str):
            raise _refuse("invalid_value", "fixing.text must be a string")
    observed_at = parse_timestamp("observed_at", document["observed_at"], error=StatusDocumentError)
    valid_until = parse_timestamp("valid_until", document["valid_until"], error=StatusDocumentError)
    return observed_at, valid_until


def _texts(document: dict[str, Any]) -> list[tuple[str, str, int]]:
    texts = []
    reason = document.get("reason")
    if isinstance(reason, dict):
        texts.append(("reason.text", reason["text"], REASON_TEXT_MAX_BYTES))
    fixing = document.get("fixing")
    if isinstance(fixing, dict) and "text" in fixing:
        texts.append(("fixing.text", fixing["text"], FIXING_TEXT_MAX_BYTES))
    return texts


def _check_texts(document: dict[str, Any]) -> None:
    for name, text, limit in _texts(document):
        if len(text.encode("utf-8")) > limit:
            raise _refuse("text_too_long", f"{name} exceeds {limit} bytes")
    for name, text, _ in _texts(document):
        if any(unicodedata.category(char) in {"Cc", "Zl", "Zp"} for char in text):
            raise _refuse("control_character", f"{name} must be one line without control characters")


def stored_status_document(signed_payload: str) -> dict[str, Any]:
    """Decode a status document that was verified when it was stored."""
    return json.loads(_decode_payload(signed_payload).decode("utf-8"))


def verify_status_document(
    signed_payload: str,
    signature: str,
    *,
    signer_did: str,
    now: datetime,
) -> dict[str, Any]:
    """Return the verified status document, or raise StatusDocumentError.

    The signature is verified with signer_did, the publisher's authenticated
    did:key. Team, agent, authority and seq checks belong to the caller.
    """
    raw = _decode_payload(signed_payload)
    document = _parse_canonical(raw)
    if document.get("type") != STATUS_TYPE:
        raise _refuse("wrong_type", f"type must be {STATUS_TYPE}")
    _check_field_names(document)
    _check_required(document)
    observed_at, valid_until = _check_values(document)
    _check_texts(document)
    if document["publisher_did"] != signer_did:
        raise _refuse("publisher_mismatch", "publisher_did is not the authenticated signer")
    if verify_signature(signer_did, raw, signature) is not VerifyResult.VERIFIED:
        raise _refuse("bad_signature", "the signature does not verify for the publisher")
    if not observed_at < valid_until <= observed_at + MAX_VALIDITY:
        raise _refuse("validity_window", "valid_until must be after observed_at and at most 15 minutes later")
    if abs(now - observed_at) > CLOCK_SKEW:
        raise _refuse("clock_skew", "observed_at is more than 5 minutes from the server clock")
    if now > valid_until:
        raise _refuse("expired", "valid_until has passed")
    return document
