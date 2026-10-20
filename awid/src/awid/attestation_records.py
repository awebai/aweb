"""Principal-attestation records: signed bytes, strict parsing and signatures.

The contract is docs/principal-attestation.md and docs/member-person.md. Each
artifact is signed over ``"<type>/1\\n" || canonical_json(payload)``. The
three AWID records are signed with the team key; the attestation is signed by
a custodian issuer key and travels in one request header.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from datetime import datetime, timezone
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from awid.did import public_key_from_did
from awid.signing import canonical_json_bytes
from awid.team_ids import parse_team_id

TEAM_CUSTODIAN = "aweb.team-custodian"
MEMBER_CUSTODY = "aweb.member-custody"
MEMBER_PERSON = "aweb.member-person"
PRINCIPAL_ATTESTATION = "aweb.principal-attestation"

ATTESTATION_HEADER = "X-AWEB-Principal-Attestation"
ATTESTATION_HEADER_MAX_BYTES = 4096
ATTESTATION_MAX_LIFETIME_SECONDS = 300
CHANNELS = frozenset({"mcp_l2", "dashboard", "api"})

_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_CUSTODIAN_ID = re.compile(r"^[a-z0-9.-]{1,128}$")
_CERTIFICATE_ID = re.compile(r"^[A-Za-z0-9-]{1,128}$")
_HANDLE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")


class RecordError(ValueError):
    """A team-signed AWID record is malformed or its signature does not verify."""


class AttestationError(ValueError):
    """A principal attestation is malformed or its signature does not verify."""


def signing_bytes(payload: dict[str, Any]) -> bytes:
    """The exact bytes signed for any of the four artifacts."""
    return f"{payload['type']}/1\n".encode("ascii") + canonical_json_bytes(payload)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _from_b64url(value: str, error: type[ValueError]) -> bytes:
    """Decode base64url without padding, accepting exactly one encoding per value."""
    if not isinstance(value, str) or not _B64URL.fullmatch(value):
        raise error("invalid base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError) as exc:
        raise error("invalid base64url") from exc
    if _b64url(decoded) != value:
        raise error("non-canonical base64url")
    return decoded


def sign_record(signing_key: bytes, payload: dict[str, Any]) -> str:
    """Sign a record or attestation payload; returns base64url without padding."""
    return _b64url(SigningKey(signing_key).sign(signing_bytes(payload)).signature)


def _verify(did_key: str, payload: dict[str, Any], signature: bytes, error: type[ValueError]) -> None:
    try:
        VerifyKey(public_key_from_did(did_key)).verify(signing_bytes(payload), signature)
    except (BadSignatureError, ValueError) as exc:
        raise error("signature does not verify") from exc


def _parse_timestamp(value: Any, error: type[ValueError]) -> datetime:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise error("timestamp must be RFC 3339 UTC with Z and second precision")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise error("invalid timestamp") from exc


def _require_did_key(value: Any, error: type[ValueError]) -> None:
    if not isinstance(value, str) or not value.startswith("did:key:z"):
        raise error("expected a did:key")
    try:
        public_key_from_did(value)
    except Exception as exc:
        raise error("invalid did:key") from exc


def _require_keys(payload: Any, required: set[str], optional: set[str], error: type[ValueError]) -> None:
    if not isinstance(payload, dict):
        raise error("expected an object")
    keys = set(payload)
    if not required <= keys or not keys <= required | optional:
        raise error("unexpected or missing fields")


def _require_common(record: dict[str, Any], record_type: str) -> None:
    if record.get("v") != 1 or type(record.get("v")) is not int or record.get("type") != record_type:
        raise RecordError("wrong record type or version")
    team_id = record.get("team_id")
    try:
        parse_team_id(team_id)
    except Exception as exc:
        raise RecordError("invalid team_id") from exc
    _require_did_key(record.get("team_did_key"), RecordError)
    _parse_timestamp(record.get("issued_at"), RecordError)


def _require_member(record: dict[str, Any]) -> None:
    certificate_id = record.get("certificate_id")
    if not isinstance(certificate_id, str) or not _CERTIFICATE_ID.fullmatch(certificate_id):
        raise RecordError("invalid certificate_id")
    _require_did_key(record.get("member_did_key"), RecordError)


def _require_custodian_id(value: Any, error: type[ValueError]) -> None:
    if not isinstance(value, str) or not _CUSTODIAN_ID.fullmatch(value):
        raise error("invalid custodian_id")


_COMMON = {"v", "type", "team_id", "team_did_key", "issued_at"}


def validate_team_custodian(record: Any) -> None:
    _require_keys(record, _COMMON | {"custodian_id", "issuer_did_keys"}, set(), RecordError)
    _require_common(record, TEAM_CUSTODIAN)
    _require_custodian_id(record["custodian_id"], RecordError)
    keys = record["issuer_did_keys"]
    if not isinstance(keys, list) or len(keys) > 2 or len(set(map(str, keys))) != len(keys):
        raise RecordError("issuer_did_keys must hold zero to two distinct keys")
    for key in keys:
        _require_did_key(key, RecordError)


def validate_member_custody(record: Any) -> None:
    _require_keys(record, _COMMON | {"certificate_id", "member_did_key", "custodian_id"}, set(), RecordError)
    _require_common(record, MEMBER_CUSTODY)
    _require_member(record)
    _require_custodian_id(record["custodian_id"], RecordError)


def validate_member_person(record: Any) -> None:
    _require_keys(record, _COMMON | {"certificate_id", "member_did_key", "single_person"}, set(), RecordError)
    _require_common(record, MEMBER_PERSON)
    _require_member(record)
    if not isinstance(record["single_person"], bool):
        raise RecordError("single_person must be a boolean")


_RECORD_VALIDATORS = {
    TEAM_CUSTODIAN: validate_team_custodian,
    MEMBER_CUSTODY: validate_member_custody,
    MEMBER_PERSON: validate_member_person,
}


def validate_record(record: Any) -> None:
    """Validate any of the three team-signed records by its declared type."""
    validator = _RECORD_VALIDATORS.get(record.get("type") if isinstance(record, dict) else None)
    if validator is None:
        raise RecordError("unknown record type")
    validator(record)


def verify_record(record: Any, signature: str, *, team_did_key: str) -> None:
    """Validate a record, require it to name ``team_did_key`` and verify its signature."""
    validate_record(record)
    if record["team_did_key"] != team_did_key:
        raise RecordError("record is not signed for this team key")
    raw = _from_b64url(signature, RecordError)
    if len(raw) != 64:
        raise RecordError("invalid signature length")
    _verify(team_did_key, record, raw, RecordError)


def validate_attestation(payload: Any) -> None:
    required = {
        "v", "type", "team_id", "certificate_id", "member_did_key", "custody",
        "custodian_id", "issuer_did_key", "channel", "session_id", "iat", "exp",
        "request_binding",
    }
    _require_keys(payload, required, {"human_principal"}, AttestationError)
    if payload["v"] != 1 or type(payload["v"]) is not int or payload["type"] != PRINCIPAL_ATTESTATION:
        raise AttestationError("wrong attestation type or version")
    try:
        parse_team_id(payload["team_id"])
    except Exception as exc:
        raise AttestationError("invalid team_id") from exc
    if not isinstance(payload["certificate_id"], str) or not _CERTIFICATE_ID.fullmatch(payload["certificate_id"]):
        raise AttestationError("invalid certificate_id")
    _require_did_key(payload["member_did_key"], AttestationError)
    _require_did_key(payload["issuer_did_key"], AttestationError)
    if payload["custody"] != "custodial":
        raise AttestationError("custody must be custodial")
    _require_custodian_id(payload["custodian_id"], AttestationError)
    if payload["channel"] not in CHANNELS:
        raise AttestationError("unknown channel")
    for field in ("session_id", "human_principal"):
        if field in payload and (not isinstance(payload[field], str) or not _HANDLE.fullmatch(payload[field])):
            raise AttestationError(f"invalid {field}")
    # The lifetime rule is a time check (attestation_expired), made by the verifier.
    _parse_timestamp(payload["iat"], AttestationError)
    _parse_timestamp(payload["exp"], AttestationError)
    if not isinstance(payload["request_binding"], str) or not _SHA256_HEX.fullmatch(payload["request_binding"]):
        raise AttestationError("request_binding must be 64 lowercase hex")


def _strict_object(raw: bytes) -> dict[str, Any]:
    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise AttestationError("duplicate key")
            result[key] = value
        return result

    def no_float(value):
        raise AttestationError("floats are not allowed")

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=no_duplicates,
            parse_float=no_float,
            parse_constant=no_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AttestationError("payload is not JSON") from exc
    if not isinstance(value, dict):
        raise AttestationError("payload is not an object")
    try:
        canonical = canonical_json_bytes(value)
    except UnicodeEncodeError as exc:
        raise AttestationError("payload is not valid Unicode") from exc
    if canonical != raw:
        raise AttestationError("payload bytes are not canonical")
    return value


def encode_attestation_header(issuer_key: bytes, payload: dict[str, Any]) -> str:
    """Build the header value ``base64url(payload).base64url(signature)``."""
    validate_attestation(payload)
    signature = SigningKey(issuer_key).sign(signing_bytes(payload)).signature
    return f"{_b64url(canonical_json_bytes(payload))}.{_b64url(signature)}"


def decode_attestation_header(value: str) -> tuple[dict[str, Any], bytes]:
    """Parse a header value strictly; returns the payload and the raw signature.

    The signature is not verified here: :func:`verify_attestation_signature`
    does that, so a caller can order the checks as the contract requires.
    """
    if not isinstance(value, str) or len(value.encode("utf-8")) > ATTESTATION_HEADER_MAX_BYTES:
        raise AttestationError("attestation header is too large")
    parts = value.split(".")
    if len(parts) != 2:
        raise AttestationError("attestation header must be payload.signature")
    raw = _from_b64url(parts[0], AttestationError)
    signature = _from_b64url(parts[1], AttestationError)
    if len(signature) != 64:
        raise AttestationError("invalid signature length")
    payload = _strict_object(raw)
    validate_attestation(payload)
    return payload, signature


def parse_attestation_time(value: str) -> datetime:
    """An attestation's ``iat`` or ``exp`` as an aware UTC datetime."""
    return _parse_timestamp(value, AttestationError)


def verify_attestation_signature(payload: dict[str, Any], signature: bytes) -> None:
    """Verify the attestation against its own ``issuer_did_key``."""
    _verify(payload["issuer_did_key"], payload, signature, AttestationError)
