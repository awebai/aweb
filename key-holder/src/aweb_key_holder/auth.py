"""aw's covering identity request profile; possession is not eligibility."""

import hashlib
from dataclasses import dataclass

from awid.did import validate_stable_id
from awid.dns_auth import enforce_timestamp_skew, parse_didkey_auth, require_timestamp
from awid.request_auth import identity_auth_signature_payload
from awid.signing import verify_did_key_signature
from fastapi import HTTPException, Request


@dataclass(frozen=True)
class Caller:
    identity: str
    key: str
    timestamp: str
    body: bytes

    @property
    def descriptor(self):
        return {"kind": "identity", "id": self.identity, "key": self.key}

    def check_time(self):
        enforce_timestamp_skew(self.timestamp)


async def authenticate(request: Request, *, origin: str) -> Caller:
    key, signature = parse_didkey_auth(request.headers.get("Authorization"))
    timestamp = require_timestamp(request)
    enforce_timestamp_skew(timestamp)
    if not request.headers.get("X-AWEB-Signed-Payload"):
        raise HTTPException(status_code=401, detail="covering_request_required")
    identity = request.headers.get("X-AWEB-DID-AW", "").strip()
    body = await request.body()
    enforce_timestamp_skew(timestamp)
    try:
        validate_stable_id(identity)
        envelope = identity_auth_signature_payload(
            request,
            did_aw=identity,
            timestamp=timestamp,
            body_sha256=hashlib.sha256(body).hexdigest(),
            allowed_audiences=[origin],
        )
        if envelope.version != 2:
            raise ValueError("covering_request_required")
        verify_did_key_signature(
            did_key=key, payload=envelope.canonical_payload, signature_b64=signature
        )
    except ValueError as error:
        raise HTTPException(
            status_code=401, detail="request_binding_invalid"
        ) from error
    return Caller(identity, key, timestamp, body)
