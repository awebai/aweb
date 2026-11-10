"""Request binding shared by handoff collection and key-bound console sessions.

These signatures reuse v2 primitives, never team-auth admission or its headers.
No credential/session authority follows from parsing an unverified payload.
"""

import base64
import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any

from awid.signing import canonical_json_bytes, verify_did_key_signature
from fastapi import Request

from aweb_naapp.runtime.team_auth import raw_request_target

_KEY = "X-Console-Key"
_SIGNATURE = "X-Console-Signature"
_TIMESTAMP = "X-Console-Timestamp"
_PAYLOAD = "X-Console-Signed-Payload"
CONSOLE_SIGNATURE_HEADERS = (_KEY, _SIGNATURE, _TIMESTAMP, _PAYLOAD)
_LOOPBACK = re.compile(r"http://(?:127\.0\.0\.1|\[::1\]):([1-9][0-9]{0,4})(/[A-Za-z0-9._~/-]*)")
_NONCE = re.compile(r"[0-9a-f]{32}")
_UTC_SECOND = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_B64URL = re.compile(r"[A-Za-z0-9_-]+")
_SIGNATURE64 = re.compile(r"[A-Za-z0-9+/]{86}")


class HandoffWireRefused(ValueError):
    """A fixed refusal; never includes a token, key, body or signature."""


def loopback_redirect(value: Any) -> str:
    match = _LOOPBACK.fullmatch(value) if isinstance(value, str) else None
    if match is None or int(match[1]) > 65535:
        raise HandoffWireRefused("redirect_uri_refused")
    return value


def _single_header(request: Request, name: str) -> str:
    values = request.headers.getlist(name)
    if len(values) != 1 or not values[0]:
        raise HandoffWireRefused("console_signature_refused")
    return values[0]


def console_payload(request: Request) -> dict[str, Any]:
    """Unverified lookup material ONLY; call verify_console_request before use."""
    encoded = _single_header(request, _PAYLOAD)
    if len(encoded) > 8192 or _B64URL.fullmatch(encoded) is None:
        raise HandoffWireRefused("console_signature_refused")
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != encoded:
            raise ValueError()
        payload = json.loads(raw)
        if not isinstance(payload, dict) or canonical_json_bytes(payload) != raw:
            raise ValueError()
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise HandoffWireRefused("console_signature_refused") from exc
    return payload


async def verify_console_request(
    request: Request,
    *,
    origin: str,
    client_key: str,
    domain: str,
    subject_field: str,
    subject: str,
    now: datetime,
) -> str:
    """Verify the stored key, exact canonical request bytes and signed nonce.

    The caller must check this nonce once, atomically with its session/result
    operation. Neither this function nor the caller accepts team certificates.
    """
    try:
        if (domain, subject_field) not in (
            ("handoff-result", "handoff_id"),
            ("handoff-session", "session_id"),
        ):
            raise ValueError()
        payload = console_payload(request)
        timestamp = _single_header(request, _TIMESTAMP)
        signature = _single_header(request, _SIGNATURE)
        if _single_header(request, _KEY) != client_key:
            raise ValueError()
        if _UTC_SECOND.fullmatch(timestamp) is None or _SIGNATURE64.fullmatch(signature) is None:
            raise ValueError()
        signature_bytes = base64.b64decode(signature + "==", validate=True)
        if base64.b64encode(signature_bytes).rstrip(b"=").decode() != signature:
            raise ValueError()
        issued = datetime.fromisoformat(timestamp[:-1] + "+00:00")
        if now.tzinfo is None or abs((now.astimezone(UTC) - issued).total_seconds()) > 300:
            raise ValueError()
        nonce = payload.get("nonce")
        if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
            raise ValueError()
        expected = {
            "v": 2,
            "auth": domain,
            "aud": origin,
            "method": request.method.upper(),
            "path": raw_request_target(request),
            subject_field: subject,
            "body_sha256": hashlib.sha256(await request.body()).hexdigest(),
            "timestamp": timestamp,
            "nonce": nonce,
        }
        if type(payload.get("v")) is not int or payload != expected:
            raise ValueError()
        verify_did_key_signature(
            did_key=client_key, payload=canonical_json_bytes(payload), signature_b64=signature
        )
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        raise HandoffWireRefused("console_signature_refused") from exc
    return nonce
