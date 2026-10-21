"""Capability-link requests (docs/page-links.md §2-§3).

A link's secret is stored only as its verifier. After the one-time exchange,
every request a link holder makes is an ``aweb.link-request/1`` signed by the
session's browser key. This module computes the verifier and builds and
checks those signed bytes, as the contract's conformance vectors freeze them.
Nonce replay, Origin and the link's lifecycle are the serving app's stateful
checks.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from awid.did import did_from_public_key, public_key_from_did
from awid.signing import canonical_json_bytes
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

LINK_REQUEST_PREFIX = b"aweb.link-request/1\n"
LINK_REQUEST_TYPE = "aweb.link-request"
MAX_SKEW_SECONDS = 60
LINK_REQUEST_BINDINGS = frozenset({"link_id", "session_id", "method", "path", "body_sha256"})

_FIELDS = frozenset(
    {
        "v",
        "type",
        "link_id",
        "session_id",
        "method",
        "path",
        "body_sha256",
        "nonce",
        "issued_at",
    }
)
_ID = re.compile(r"[A-Za-z0-9._-]{1,128}")
_METHOD = re.compile(r"[A-Z]{3,7}")
_PATH = re.compile(r"/[\x21-\x7e]{0,2047}")
_HEX_DIGEST = re.compile(r"[0-9a-f]{64}")
_NONCE = re.compile(r"[0-9a-f]{32}")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


class LinkRequestRefused(ValueError):
    """A link request failed; ``code`` is the contract's error code."""

    def __init__(self, code: str, reason: str) -> None:
        super().__init__(f"{code}: {reason}")
        self.code = code


def secret_verifier(secret: str) -> str:
    """The stored form of a link secret: bare hex SHA-256 of its UTF-8 bytes."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def check_session_did_key(did_key: object) -> None:
    """An exchange accepts only a canonical Ed25519 did:key (422 otherwise)."""
    try:
        if (
            not isinstance(did_key, str)
            or did_from_public_key(public_key_from_did(did_key)) != did_key
        ):
            raise LinkRequestRefused("schema_invalid", "session_did_key")
    except ValueError as exc:
        if isinstance(exc, LinkRequestRefused):
            raise
        raise LinkRequestRefused("schema_invalid", "session_did_key") from exc


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LinkRequestRefused("signature_invalid", "duplicate key")
        result[key] = value
    return result


def _no_number(text: str) -> Any:
    raise LinkRequestRefused("signature_invalid", "non-integer number")


def _decode_signed_payload(signed_payload: object) -> tuple[bytes, Mapping[str, Any]]:
    def bad(reason: str) -> LinkRequestRefused:
        return LinkRequestRefused("signature_invalid", reason)

    if not isinstance(signed_payload, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", signed_payload):
        raise bad("signed payload encoding")
    try:
        raw = base64.urlsafe_b64decode(signed_payload + "=" * (-len(signed_payload) % 4))
    except (binascii.Error, ValueError) as exc:
        raise bad("signed payload encoding") from exc
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != signed_payload:
        raise bad("signed payload encoding")
    try:
        parsed = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_no_duplicates,
            parse_float=_no_number,
            parse_constant=_no_number,
        )
    except LinkRequestRefused:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise bad("signed payload is not JSON") from exc
    if not isinstance(parsed, dict):
        raise bad("signed payload is not an object")
    try:
        canonical = canonical_json_bytes(parsed)
    except (UnicodeEncodeError, ValueError, TypeError) as exc:
        raise bad("signed payload has no canonical form") from exc
    if canonical != raw:
        raise bad("signed payload is not canonical")
    return raw, parsed


def link_request_signing_bytes(payload: Mapping[str, Any]) -> bytes:
    return LINK_REQUEST_PREFIX + canonical_json_bytes(dict(payload))


def _matches(pattern: re.Pattern[str], value: object) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _issued_at(payload: object) -> datetime:
    def bad(reason: str) -> LinkRequestRefused:
        return LinkRequestRefused("signature_invalid", reason)

    if not isinstance(payload, Mapping) or set(payload) != _FIELDS:
        raise bad("payload fields")
    version = payload["v"]
    if not isinstance(version, int) or isinstance(version, bool) or version != 1:
        raise bad("v")
    if payload["type"] != LINK_REQUEST_TYPE:
        raise bad("v or type")
    for field in ("link_id", "session_id"):
        if not _matches(_ID, payload[field]):
            raise bad(field)
    if not _matches(_METHOD, payload["method"]) or not _matches(_PATH, payload["path"]):
        raise bad("method or path")
    if not _matches(_HEX_DIGEST, payload["body_sha256"]):
        raise bad("body_sha256")
    if not _matches(_NONCE, payload["nonce"]):
        raise bad("nonce")
    if not _matches(_TIMESTAMP, payload["issued_at"]):
        raise bad("issued_at")
    try:
        return datetime.fromisoformat(payload["issued_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise bad("issued_at") from exc


def sign_link_request(payload: Mapping[str, Any], signing_key: SigningKey) -> str:
    """The session key's signature, base64url without padding."""
    _issued_at(payload)
    signature = signing_key.sign(link_request_signing_bytes(payload)).signature
    return base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")


def _signature_bytes(signature: object) -> bytes:
    if not isinstance(signature, str) or not re.fullmatch(r"[A-Za-z0-9_-]{86}", signature):
        raise LinkRequestRefused("signature_invalid", "signature encoding")
    raw = base64.urlsafe_b64decode(signature + "==")
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != signature:
        raise LinkRequestRefused("signature_invalid", "signature encoding")
    return raw


def verify_link_request(
    payload: Mapping[str, Any],
    signature: str,
    *,
    session_did_key: str,
    expected: Mapping[str, Any],
    now: datetime,
) -> None:
    """Verify a link request: shape and signature, then binding, then time.

    ``session_did_key`` is the key the session was created with. ``expected``
    holds exactly LINK_REQUEST_BINDINGS: the live session's link and session
    IDs and the actual request's method, raw path with query and body digest.
    A missing or extra key is a ValueError, never a skipped check.
    """
    if set(expected) != LINK_REQUEST_BINDINGS:
        raise ValueError(f"expected must hold exactly the bindings {sorted(LINK_REQUEST_BINDINGS)}")
    issued = _issued_at(payload)
    raw = _signature_bytes(signature)
    try:
        if did_from_public_key(public_key_from_did(session_did_key)) != session_did_key:
            raise ValueError("session key is not a canonical did:key")
        VerifyKey(public_key_from_did(session_did_key)).verify(
            link_request_signing_bytes(payload), raw
        )
    except BadSignatureError as exc:
        raise LinkRequestRefused("signature_invalid", "signature does not verify") from exc
    for field in sorted(LINK_REQUEST_BINDINGS):
        if payload[field] != expected[field]:
            raise LinkRequestRefused("signature_invalid", field)
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if abs((issued - now.astimezone(UTC)).total_seconds()) > MAX_SKEW_SECONDS:
        raise LinkRequestRefused("authorization_expired", "outside the time window")


def verify_link_request_bytes(
    signed_payload: str,
    signature: str,
    *,
    session_did_key: str,
    expected: Mapping[str, Any],
    now: datetime,
) -> Mapping[str, Any]:
    """Verify a link request as received: the X-AWEB-Signed-Payload header.

    The bytes must be the one base64url encoding of canonical JSON with no
    duplicate keys, so that every reader of the request sees the same fields;
    then the checks of verify_link_request run. This is the serving app's
    entry point. Returns the verified payload.
    """
    _, parsed = _decode_signed_payload(signed_payload)
    verify_link_request(
        parsed, signature, session_did_key=session_did_key, expected=expected, now=now
    )
    return parsed
