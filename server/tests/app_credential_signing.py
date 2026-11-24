"""An app's signed request headers for one credential purpose, built from awid's primitives.

The headers and canonical payload are the app credential family's
(docs/app-events.md, docs/app-registry.md); ``app-request`` also signs the
installation id and generation (docs/app-task-requests.md §2).
test_app_credential_signing.py holds them to the frozen vectors byte for byte.
"""

import base64
import hashlib

from awid.did import did_key_from_signing_key
from awid.signing import canonical_json_bytes, sign_message

from aweb.app_credentials import APP_REQUEST, PURPOSES


def app_credential_headers(
    *,
    purpose: str,
    seed: bytes,
    method: str,
    aud: str,
    path: str,
    team_id: str,
    app_id: str,
    kid: str,
    body: bytes,
    timestamp: str,
    installation_id: str | None = None,
    installation_generation: int | None = None,
) -> dict[str, str]:
    """Headers for one request, signed with the app key's 32-byte Ed25519 seed."""
    spec = PURPOSES[purpose]
    did_key = did_key_from_signing_key(seed)
    payload = {
        "v": 1,
        "auth": spec.auth,
        "aud": aud,
        "method": method.upper(),
        "path": path,
        "team_id": team_id,
        "app_id": app_id,
        "kid": kid,
        "did_key": did_key,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "timestamp": timestamp,
    }
    if purpose == APP_REQUEST:
        payload["installation_id"] = installation_id
        payload["installation_generation"] = installation_generation
    canonical = canonical_json_bytes(payload)
    return {
        "Authorization": f"{spec.prefix}{did_key} {sign_message(seed, canonical)}",
        "X-AWEB-App-ID": app_id,
        "X-AWEB-App-Key-ID": kid,
        "X-AWEB-Team-ID": team_id,
        "X-AWEB-Timestamp": timestamp,
        "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(canonical).rstrip(b"=").decode("ascii"),
    }
