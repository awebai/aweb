"""Purpose-bound app request credentials.

An installed app signs a request with one of its registered keys under one
purpose. Each purpose has its own Authorization prefix, its own exact signed
``auth`` value and its own key source, so a credential signed for one purpose
is never accepted for another, even when one physical key serves several.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from fastapi import HTTPException, Request

from awid.dns_auth import enforce_timestamp_skew, require_timestamp
from awid.log import canonical_server_origin
from awid.signing import canonical_json_bytes, verify_did_key_signature

from aweb.app_registry import get_active_app_emit_key, get_active_app_key, validate_team_id
from aweb.config import get_settings
from aweb.team_auth_envelope import decode_signed_payload_header, raw_request_target

APP_CREDENTIAL_VERSION = 1

APP_EVENT = "app-event"
APP_GRANT_READ = "app-grant-read"
HOOK_RESOLVE = "hook-resolve"

KeyLookup = Callable[..., Awaitable[dict | None]]


@dataclass(frozen=True)
class AppCredentialPurpose:
    auth: str
    prefix: str
    label: str
    key_not_registered: str
    lookup_key: KeyLookup


@dataclass(frozen=True)
class AppCredential:
    purpose: str
    team_id: str
    app_id: str
    kid: str
    did_key: str


async def _emit_key(db, *, purpose: str, team_id: str, app_id: str, kid: str, did_key: str) -> dict | None:
    return await get_active_app_emit_key(db, team_id=team_id, app_id=app_id, kid=kid, did_key=did_key)


async def _app_key(db, *, purpose: str, team_id: str, app_id: str, kid: str, did_key: str) -> dict | None:
    return await get_active_app_key(db, team_id=team_id, app_id=app_id, kid=kid, did_key=did_key, purpose=purpose)


PURPOSES: dict[str, AppCredentialPurpose] = {
    APP_EVENT: AppCredentialPurpose(
        auth=APP_EVENT,
        prefix="AWEB-App DIDKey ",
        label="app event",
        key_not_registered="App emit key is not registered",
        lookup_key=_emit_key,
    ),
    APP_GRANT_READ: AppCredentialPurpose(
        auth=APP_GRANT_READ,
        prefix="AWEB-App-Grant-Read DIDKey ",
        label="app grant read",
        key_not_registered="app_key_not_registered",
        lookup_key=_app_key,
    ),
    HOOK_RESOLVE: AppCredentialPurpose(
        auth=HOOK_RESOLVE,
        prefix="AWEB-App-Hook-Resolve DIDKey ",
        label="hook resolve",
        key_not_registered="app_key_not_registered",
        lookup_key=_app_key,
    ),
}


def _allowed_audiences(request: Request) -> set[str]:
    configured = str(getattr(request.app.state, "public_origin", "") or "").strip()
    return {canonical_server_origin(configured or get_settings().public_origin)}


async def verify_app_credential(request: Request, db, purpose: str) -> AppCredential:
    """Verify an app credential for exactly ``purpose``.

    The Authorization prefix selects nothing: it must be the purpose's own
    prefix, the signed ``auth`` must equal the purpose, and the key must be
    registered for it under the team's installed digest.
    """
    spec = PURPOSES[purpose]
    label = spec.label

    auth = (request.headers.get("Authorization") or "").strip()
    if not auth.startswith(spec.prefix):
        raise HTTPException(status_code=401, detail=f"Missing {label} Authorization header")
    parts = auth[len(spec.prefix):].strip().split()
    if len(parts) != 2:
        raise HTTPException(status_code=401, detail=f"Malformed {label} Authorization header")
    did_key, signature_b64 = parts

    app_id = (request.headers.get("X-AWEB-App-ID") or "").strip().lower()
    kid = (request.headers.get("X-AWEB-App-Key-ID") or "").strip()
    team_id = validate_team_id((request.headers.get("X-AWEB-Team-ID") or "").strip())
    timestamp = require_timestamp(request)
    enforce_timestamp_skew(timestamp)

    body_sha256 = getattr(request.state, "body_sha256", None)
    if body_sha256 is None:
        body_sha256 = hashlib.sha256(getattr(request.state, "cached_body", b"") or b"").hexdigest()

    try:
        canonical = decode_signed_payload_header(str(request.headers.get("X-AWEB-Signed-Payload") or "").strip())
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid {label} signed payload") from exc
    try:
        payload = json.loads(canonical)
    except Exception as exc:
        raise HTTPException(status_code=401, detail=f"Invalid {label} signed payload") from exc
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != canonical:
        raise HTTPException(status_code=401, detail=f"Invalid {label} signed payload")

    expected = {
        "v": APP_CREDENTIAL_VERSION,
        "auth": spec.auth,
        "method": request.method.upper(),
        "path": raw_request_target(request),
        "team_id": team_id,
        "app_id": app_id,
        "kid": kid,
        "did_key": did_key,
        "body_sha256": body_sha256,
        "timestamp": timestamp,
    }
    for field, expected_value in expected.items():
        if payload.get(field) != expected_value:
            raise HTTPException(status_code=401, detail=f"{label.capitalize()} signed payload does not match request")

    aud = str(payload.get("aud") or "").strip()
    try:
        canonical_aud = canonical_server_origin(aud)
    except Exception as exc:
        raise HTTPException(status_code=401, detail=f"{label.capitalize()} signed payload audience is invalid") from exc
    if canonical_aud not in _allowed_audiences(request):
        raise HTTPException(status_code=401, detail=f"{label.capitalize()} signed payload audience is not allowed")

    try:
        verify_did_key_signature(did_key=did_key, payload=canonical, signature_b64=signature_b64)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid {label} signature") from exc

    row = await spec.lookup_key(db, purpose=purpose, team_id=team_id, app_id=app_id, kid=kid, did_key=did_key)
    if row is None:
        raise HTTPException(status_code=403, detail=spec.key_not_registered)

    return AppCredential(purpose=purpose, team_id=team_id, app_id=app_id, kid=kid, did_key=did_key)
