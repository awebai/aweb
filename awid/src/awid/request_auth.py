"""Shared root request-auth v2 construction; membership is verified separately."""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import secrets
from typing import Any, Mapping
from urllib.parse import quote, urlsplit

import httpx

from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.log import canonical_server_origin
from awid.signing import canonical_json_bytes, sign_message

REQUEST_AUTH_RESERVED_FIELDS = frozenset({
    'v', 'aud', 'method', 'path', 'body_sha256', 'timestamp', 'team_id', 'did_aw', 'nonce',
})


def validate_request_nonce(payload: Mapping[str, Any]) -> str | None:
    """Absent is compatible; a present nonce has exactly one canonical encoding."""
    if 'nonce' not in payload:
        return None
    value = payload['nonce']
    if not isinstance(value, str) or len(value) != 22:
        raise ValueError('invalid request nonce')
    try:
        raw = base64.b64decode(value + '==', altchars=b'-_', validate=True)
    except (ValueError, UnicodeError) as exc:
        raise ValueError('invalid request nonce') from exc
    if len(raw) != 16 or base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii') != value:
        raise ValueError('invalid request nonce')
    return value


def request_auth_payload(*, method: str, target: str, claim: str, value: str,
                         timestamp: str, body: bytes = b'',
                         custom: Mapping[str, Any] | None = None,
                         nonce: str | None = None) -> bytes:
    """Canonical byte builder, also used by deterministic conformance vectors."""
    if claim not in {'team_id', 'did_aw'}:
        raise ValueError('request auth claim must be team_id or did_aw')
    supplied = dict(custom or {})
    if supplied.keys() & REQUEST_AUTH_RESERVED_FIELDS:
        raise ValueError('custom fields cannot replace request authority')
    url = urlsplit(target)
    audience = canonical_server_origin(f'{url.scheme}://{url.netloc}')
    if url.fragment or url.username is not None or url.password is not None:
        raise ValueError('request auth target cannot contain credentials or a fragment')
    path = httpx.URL(target).raw_path.decode('ascii')
    payload = {**supplied, 'v': 2, 'aud': audience, 'method': method.upper(),
               'path': path, 'body_sha256': hashlib.sha256(body).hexdigest(),
               claim: value, 'timestamp': timestamp}
    if nonce is not None:
        payload['nonce'] = nonce
    validate_request_nonce(payload)
    return canonical_json_bytes(payload)


@dataclass(frozen=True)
class RequestCredential:
    did_key: str
    signature: str
    canonical_payload: bytes
    headers: dict[str, str]


def sign_request_credential(signing_key: bytes, *, method: str, target: str,
                            claim: str, value: str, body: bytes = b'',
                            timestamp: str | None = None,
                            custom: Mapping[str, Any] | None = None) -> RequestCredential:
    """Sign one fresh root request. Deploy nonce-aware verifiers before use."""
    timestamp = timestamp or datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    nonce = base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b'=').decode('ascii')
    canonical = request_auth_payload(method=method, target=target, claim=claim, value=value,
                                     body=body, timestamp=timestamp, custom=custom, nonce=nonce)
    key = SigningKey(signing_key)
    did_key = did_from_public_key(bytes(key.verify_key))
    signature = sign_message(signing_key, canonical)
    headers = {
        'Authorization': f'DIDKey {did_key} {signature}',
        'X-AWEB-Timestamp': timestamp,
        'X-AWEB-Signed-Payload': base64.urlsafe_b64encode(canonical).rstrip(b'=').decode('ascii'),
    }
    if claim == 'did_aw' and value:
        headers['X-AWEB-DID-AW'] = value
    return RequestCredential(did_key, signature, canonical, headers)


@dataclass(frozen=True)
class RequestAuthEnvelope:
    version: int
    canonical_payload: bytes
    payload: dict[str, Any]


def decode_signed_payload_header(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    except Exception as exc:
        raise ValueError('invalid X-AWEB-Signed-Payload header') from exc


def raw_request_target(request) -> str:
    raw = request.scope.get('raw_path')
    if isinstance(raw, bytes):
        path = raw.decode('ascii')
    elif raw:
        path = str(raw)
    else:
        path = quote(str(request.scope.get('path') or request.url.path or '/'), safe='/%')
    root = str(request.scope.get('root_path') or '')
    if root and not path.startswith(root):
        path = quote(root.rstrip('/'), safe='/%') + (path if path.startswith('/') else '/' + path)
    if not path.startswith('/'):
        path = '/' + path
    query = request.scope.get('query_string') or b''
    query = query.decode('ascii') if isinstance(query, bytes) else str(query)
    return path + ('?' + query if query else '')


def parse_request_auth_v2(request, *, claims: Mapping[str, str], timestamp: str,
                          body_sha256: str, allowed_audiences,
                          signed_payload_header: str = 'X-AWEB-Signed-Payload') -> RequestAuthEnvelope:
    """Bind presented canonical bytes; caller still verifies signature/authority."""
    canonical = decode_signed_payload_header(str(request.headers.get(signed_payload_header) or '').strip())
    try:
        payload = json.loads(canonical)
        if not isinstance(payload, dict) or canonical_json_bytes(payload) != canonical:
            raise ValueError('noncanonical payload')
    except (ValueError, UnicodeError, TypeError) as exc:
        raise ValueError('invalid X-AWEB-Signed-Payload header') from exc
    if payload.get('type') == 'aweb.awid-controller-request':
        raise ValueError('wrong request envelope type')
    if payload.get('v') != 2:
        raise ValueError('unsupported team-auth envelope version')
    validate_request_nonce(payload)
    audiences = set()
    for configured in allowed_audiences:
        configured = str(configured or '').strip()
        if configured:
            audiences.add(canonical_server_origin(configured))
    if not audiences:
        raise ValueError('team-auth public audience is not configured')
    expected = {'method': request.method.upper(), 'path': raw_request_target(request),
                **claims, 'body_sha256': body_sha256, 'timestamp': timestamp}
    for field, value in expected.items():
        if field not in payload or str(payload[field]).strip() != value:
            raise ValueError('signed request payload does not match request')
    try:
        audience = canonical_server_origin(str(payload.get('aud') or '').strip())
    except (ValueError, TypeError) as exc:
        raise ValueError('signed request payload audience is invalid') from exc
    if audience not in audiences:
        raise ValueError('signed request payload audience is not allowed')
    return RequestAuthEnvelope(2, canonical, payload)
