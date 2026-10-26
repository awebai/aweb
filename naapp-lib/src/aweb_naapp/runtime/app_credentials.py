"""Purpose-bound app credentials, signed for one purpose each.

An app signs a request to its team's server with one of its keys under one
purpose. Each purpose has its own Authorization prefix and its own signed
``auth`` value, both of which the server requires to name the purpose, so a
credential signed for one purpose is never accepted for another
(app-team-server-api §2). The headers and the canonical signed payload are
those of the app-event credential, byte-identical to the Go signer for
``app-event`` and to ``test-vectors/app-read-credential-v1.json`` for the read
purposes. Signatures are unpadded standard base64, the one encoding the server
accepts for read purposes. ``app-request`` additionally signs the installation
id and generation (docs/app-task-requests.md §2).
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit

from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message
from nacl.signing import SigningKey

from aweb_naapp.runtime.app_keys import AppKey

APP_CREDENTIAL_VERSION = 1

APP_EVENT = "app-event"
APP_GRANT_READ = "app-grant-read"
APP_REQUEST = "app-request"
HOOK_RESOLVE = "hook-resolve"


@dataclass(frozen=True)
class AppCredentialPurpose:
    auth: str
    prefix: str


PURPOSES: dict[str, AppCredentialPurpose] = {
    APP_EVENT: AppCredentialPurpose(auth=APP_EVENT, prefix="AWEB-App DIDKey "),
    APP_GRANT_READ: AppCredentialPurpose(auth=APP_GRANT_READ, prefix="AWEB-App-Grant-Read DIDKey "),
    APP_REQUEST: AppCredentialPurpose(auth=APP_REQUEST, prefix="AWEB-App-Request DIDKey "),
    HOOK_RESOLVE: AppCredentialPurpose(auth=HOOK_RESOLVE, prefix="AWEB-App-Hook-Resolve DIDKey "),
}


@dataclass(frozen=True)
class AppCredential:
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


def sign_app_credential(
    *,
    purpose: str,
    private_key: bytes,
    method: str,
    target: str,
    team_id: str,
    app_id: str,
    key_id: str,
    body: bytes,
    timestamp: str,
    installation_id: str | None = None,
    installation_generation: int | None = None,
) -> AppCredential:
    """Sign one request with a 32-byte Ed25519 seed.

    ``app-request`` requires a nonempty installation id and a positive integer
    generation. Other purposes keep their existing payload without those fields.
    """
    spec = PURPOSES.get(purpose)
    if spec is None:
        raise ValueError(f"unknown app credential purpose {purpose!r}")
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
    if purpose == APP_REQUEST:
        if not isinstance(installation_id, str) or not installation_id.strip():
            raise ValueError("app-request requires an installation_id")
        if type(installation_generation) is not int or installation_generation <= 0:
            raise ValueError("app-request requires a positive integer installation_generation")

    audience, path = _request_target(target)
    body_sha256 = hashlib.sha256(body).hexdigest()
    did_key = did_from_public_key(bytes(SigningKey(private_key).verify_key))

    payload = {
        "v": APP_CREDENTIAL_VERSION,
        "auth": spec.auth,
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
    if purpose == APP_REQUEST:
        payload["installation_id"] = installation_id
        payload["installation_generation"] = installation_generation
    canonical = canonical_json_bytes(payload)
    signature_b64 = sign_message(private_key, canonical)
    signed_payload_b64url = base64.urlsafe_b64encode(canonical).rstrip(b"=").decode("ascii")

    headers = {
        "Authorization": f"{spec.prefix}{did_key} {signature_b64}",
        "X-AWEB-App-ID": app_id,
        "X-AWEB-App-Key-ID": key_id,
        "X-AWEB-Team-ID": team_id,
        "X-AWEB-Timestamp": timestamp,
        "X-AWEB-Signed-Payload": signed_payload_b64url,
    }
    return AppCredential(
        did_key=did_key,
        signature_b64=signature_b64,
        canonical_payload=canonical.decode("utf-8"),
        signed_payload_b64url=signed_payload_b64url,
        body_sha256=body_sha256,
        headers=headers,
    )


def _utc_seconds_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class AppCredentialSigner:
    """Signs requests for one purpose with one of the app's keys.

    The key comes from :func:`aweb_naapp.runtime.app_keys.load_app_key`, which
    refuses at startup a purpose the manifest does not declare for a
    configured kid.
    """

    def __init__(self, *, app_id: str, key: AppKey, purpose: str) -> None:
        if purpose not in PURPOSES:
            raise ValueError(f"unknown app credential purpose {purpose!r}")
        if did_from_public_key(bytes(key.signing_key.verify_key)) != key.did_key:
            raise ValueError(f"app key {key.kid} is not the key its did:key names")
        self.app_id = app_id
        self.purpose = purpose
        self._key = key

    def __repr__(self) -> str:
        return f"AppCredentialSigner(app_id={self.app_id!r}, kid={self._key.kid!r}, purpose={self.purpose!r})"

    def sign(
        self,
        *,
        method: str,
        target: str,
        team_id: str,
        body: bytes = b"",
        timestamp: str | None = None,
        installation_id: str | None = None,
        installation_generation: int | None = None,
    ) -> AppCredential:
        """Sign a request to ``target``, an absolute URL whose origin is the audience."""
        return sign_app_credential(
            purpose=self.purpose,
            private_key=bytes(self._key.signing_key),
            method=method,
            target=target,
            team_id=team_id,
            app_id=self.app_id,
            key_id=self._key.kid,
            body=body,
            timestamp=_utc_seconds_now() if timestamp is None else timestamp,
            installation_id=installation_id,
            installation_generation=installation_generation,
        )
