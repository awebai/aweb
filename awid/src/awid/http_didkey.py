"""Onboarding HTTP possession proofs; route checks separately confer authority.

The versioned form is governed by docs/team-auth-envelope-v2.md. Released legacy
method/path/body proofs remain accepted and must be measured by the embedding
host before any separately approved cutoff.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Iterable

from fastapi import HTTPException, Request

from awid.dns_auth import enforce_timestamp_skew, parse_didkey_auth, require_timestamp
from awid.request_auth import RequestAuthEnvelope, parse_request_auth_v2
from awid.signing import canonical_json_bytes, verify_did_key_signature


def build_http_didkey_payload(*, body_bytes: bytes, method: str, path: str, timestamp: str) -> bytes:
    """Frozen legacy bytes. New emitters use request_auth.sign_request_credential."""
    return canonical_json_bytes({'body_sha256': hashlib.sha256(body_bytes).hexdigest(),
                                 'method': method.upper(), 'path': path, 'timestamp': timestamp})


@dataclass(frozen=True)
class VerifiedHTTPDIDKeyProof:
    did_key: str
    signature_b64: str
    envelope: RequestAuthEnvelope


async def verify_http_didkey_proof(
    request: Request, *, allowed_audiences: Iterable[str] = (), did_aw: str = '',
    authorization_header: str = 'Authorization', timestamp_header: str = 'X-AWEB-Timestamp',
    signed_payload_header: str = 'X-AWEB-Signed-Payload', legacy_path: str | None = None,
) -> VerifiedHTTPDIDKeyProof:
    """Verify possession only, returning version/nonce for the embedding host.

    After body-DID/current-key/route authority checks, hosts call their shared
    replay admission and count accepted legacy envelopes (version 1). Keep the
    returned envelope: do not infer its version from an unverified header.
    Header arguments are names. legacy_path preserves a host's historical v1
    path spelling only; v2 always verifies the external raw target and query.
    """
    body = await request.body()
    did_key, signature = parse_didkey_auth(request.headers.get(authorization_header))
    timestamp = require_timestamp(request, header_name=timestamp_header)
    enforce_timestamp_skew(timestamp)
    if request.headers.get(signed_payload_header) is None:
        canonical = build_http_didkey_payload(body_bytes=body, method=request.method,
                                             path=request.url.path if legacy_path is None else legacy_path,
                                             timestamp=timestamp)
        envelope = RequestAuthEnvelope(1, canonical, {})
    else:
        try:
            envelope = parse_request_auth_v2(
                request, claims={'did_aw': did_aw}, timestamp=timestamp,
                body_sha256=hashlib.sha256(body).hexdigest(), allowed_audiences=allowed_audiences,
                signed_payload_header=signed_payload_header,
            )
        except ValueError as exc:
            raise HTTPException(401, detail=str(exc)) from exc
    try:
        verify_did_key_signature(did_key=did_key, payload=envelope.canonical_payload, signature_b64=signature)
    except ValueError as exc:
        raise HTTPException(401, detail='Invalid signature') from exc
    return VerifiedHTTPDIDKeyProof(did_key, signature, envelope)


async def verify_http_didkey_request(request: Request) -> str:
    """Existing entry point; a presented malformed v2 never falls back to v1.

    Hosts migrating to v2 must configure their public origins. Hosts needing
    route authority/replay/usage reporting use verify_http_didkey_proof directly.
    """
    allowed = getattr(request.app.state, 'request_auth_public_origins', ())
    if not allowed:
        public_origin = getattr(request.app.state, 'public_origin', '')
        allowed = (public_origin,) if public_origin else ()
    proof = await verify_http_didkey_proof(
        request, allowed_audiences=allowed, did_aw=(request.headers.get('X-AWEB-DID-AW') or '').strip(),
    )
    return proof.did_key


__all__ = ['build_http_didkey_payload', 'verify_http_didkey_request',
           'verify_http_didkey_proof', 'VerifiedHTTPDIDKeyProof']
