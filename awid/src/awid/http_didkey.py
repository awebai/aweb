"""HTTP request envelope DIDKey auth for FastAPI routes.

Verifies an incoming request carries a DIDKey-signed envelope that binds the
signature to the request body hash, HTTP method, URL path, and timestamp.
This is stronger than signing a payload dict alone: it prevents replay of a
signature against a different endpoint or with a modified body.

For the payload-dict signing convention used by awid-service's DNS and team
routes (where the caller passes structured fields to be signed), see
``awid.dns_auth.verify_signed_json_request``.
"""

from __future__ import annotations

import hashlib

from fastapi import HTTPException, Request

from awid.dns_auth import enforce_timestamp_skew, parse_didkey_auth, require_timestamp
from awid.signing import canonical_json_bytes, verify_did_key_signature


def build_http_didkey_payload(
    *,
    body_bytes: bytes,
    method: str,
    path: str,
    timestamp: str,
) -> bytes:
    """Build the canonical JSON envelope that gets signed.

    The envelope binds the signature to the SHA-256 of the request body, the
    HTTP method (uppercased), the URL path, and the request timestamp. Clients
    must construct the same envelope with the same timestamp they send in the
    ``X-AWEB-Timestamp`` header; any drift in any field invalidates the
    signature.
    """
    return canonical_json_bytes(
        {
            "body_sha256": hashlib.sha256(body_bytes).hexdigest(),
            "method": method.upper(),
            "path": path,
            "timestamp": timestamp,
        }
    )


async def verify_http_didkey_request(request: Request) -> str:
    """Verify a DIDKey-signed HTTP request against its envelope.

    Expects:

    - ``Authorization: DIDKey <did:key> <base64-signature>`` — the signer and
      signature over the canonical JSON envelope.
    - ``X-AWEB-Timestamp: <ISO-8601 UTC>`` — the timestamp that is also baked
      into the signed envelope, used for skew enforcement.

    Returns the verified ``did:key`` on success. Raises ``HTTPException(401)``
    on any verification failure (missing header, malformed auth, stale
    timestamp, signature mismatch).

    This verifier is stateless. Replay protection — if required by the caller's
    threat model — must be implemented on top of this via a nonce cache or a
    one-shot token store, not by this function.
    """
    body_bytes = await request.body()
    did_key, signature = parse_didkey_auth(request.headers.get("Authorization"))
    timestamp = require_timestamp(request)
    enforce_timestamp_skew(timestamp)
    payload = build_http_didkey_payload(
        body_bytes=body_bytes,
        method=request.method,
        path=request.url.path,
        timestamp=timestamp,
    )
    try:
        verify_did_key_signature(did_key=did_key, payload=payload, signature_b64=signature)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid signature") from exc
    return did_key


__all__ = [
    "build_http_didkey_payload",
    "verify_http_didkey_request",
]
