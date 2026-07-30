"""folio's app-emit-credential signer.

Produces output byte-identical to the Go signer (awid/signing.go
SignAppEmitCredential) so the Go signer, this Python emitter, and the core
verifier agree on the wire. It reuses the shared awid canonical-JSON and signing
primitives (the same ones folio's cert-auth path uses) — it does NOT define a
second canonicalization. This is the v1 stopgap app event emit credential; folio
does not emit events yet (forward-looking), this just establishes byte-parity.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from urllib.parse import urlsplit

from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message
from nacl.signing import SigningKey


@dataclass(frozen=True)
class AppEmitCredential:
    did_key: str
    signature_b64: str
    canonical_payload: str
    signed_payload_b64url: str
    body_sha256: str
    headers: dict[str, str]


def _request_target(target: str) -> tuple[str, str]:
    """Split a target URL into (audience, path[?query]) the way the Go signer does."""
    parts = urlsplit(target)
    if not parts.scheme or not parts.netloc:
        raise ValueError("target URL must include a scheme and host")
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    return f"{parts.scheme}://{parts.netloc}", path


def sign_app_emit_credential(
    *,
    private_key: bytes,
    method: str,
    target: str,
    team_id: str,
    app_id: str,
    key_id: str,
    body: bytes,
    timestamp: str,
) -> AppEmitCredential:
    """Sign a v1 app event emit credential.

    ``private_key`` is the 32-byte ed25519 seed. Returns the canonical signed
    payload, body_sha256, the ed25519 signature, and the AWEB-App Authorization
    plus X-AWEB-* headers, byte-identical to the frozen Go vector.
    """
    team_id = team_id.strip()
    app_id = app_id.strip()
    key_id = key_id.strip()
    timestamp = timestamp.strip()
    if not team_id:
        raise ValueError("team_id is required")
    if not app_id:
        raise ValueError("app_id is required")
    if not key_id:
        raise ValueError("key_id is required")
    if not timestamp:
        raise ValueError("timestamp is required")

    audience, path = _request_target(target)
    body_sha256 = hashlib.sha256(body).hexdigest()
    did_key = did_from_public_key(bytes(SigningKey(private_key).verify_key))

    payload = {
        "v": 1,
        "auth": "app-event",
        "aud": audience,
        "method": method.strip().upper(),
        "path": path,
        "team_id": team_id,
        "app_id": app_id,
        "kid": key_id,
        "did_key": did_key,
        "body_sha256": body_sha256,
        "timestamp": timestamp,
    }
    canonical = canonical_json_bytes(payload)
    signature_b64 = sign_message(private_key, canonical)
    signed_payload_b64url = base64.urlsafe_b64encode(canonical).rstrip(b"=").decode("ascii")

    headers = {
        "Authorization": f"AWEB-App DIDKey {did_key} {signature_b64}",
        "X-AWEB-App-ID": app_id,
        "X-AWEB-App-Key-ID": key_id,
        "X-AWEB-Team-ID": team_id,
        "X-AWEB-Timestamp": timestamp,
        "X-AWEB-Signed-Payload": signed_payload_b64url,
    }
    return AppEmitCredential(
        did_key=did_key,
        signature_b64=signature_b64,
        canonical_payload=canonical.decode("utf-8"),
        signed_payload_b64url=signed_payload_b64url,
        body_sha256=body_sha256,
        headers=headers,
    )
