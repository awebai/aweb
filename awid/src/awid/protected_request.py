"""Covering-v2 possession proofs for protected-service request adapters.

This authenticates a key only. The embedding must resolve the selected
identity's current key in its configured registry and authorize the operation
against its provisioned scope/policy before disclosing or executing anything.
These labels confer no AWID controller authority and have no legacy form.
"""
from __future__ import annotations

import base64
import hashlib
import re
from typing import Any

from fastapi import HTTPException, Request

from awid.controller_request import raw_controller_request_target
from awid.dns_auth import enforce_timestamp_skew, parse_didkey_auth, require_timestamp
from awid.id_tree_requests import CONTROLLER_REQUEST_TYPE
from awid.log import require_canonical_server_origin
from awid.signing import canonical_json_bytes, verify_did_key_signature


_METHODS = {
    'protected_operation_prepare': 'POST',
    'protected_operation_receipt': 'GET',
    'protected_operation_execute': 'POST',
    'protected_handoff_start': 'POST',
    'protected_admission_policy_read': 'GET',
}


async def verify_protected_request(
    request: Request, *, operation: str, request_origin: str,
    service_id: str, domain: str, scope: dict[str, Any],
) -> str:
    """Verify the exact request and return its signing did:key.

    All keyword arguments are selected by the embedding, never copied from the
    unverified envelope. ``scope`` is the canonical typed scope: retained scope
    for receipts/execution, validated explicit scope for prepare, or exactly
    ``{service_id, team_id}`` for policy reads. Origin comes from trusted server
    configuration, never Host/forwarded headers. No key material is accepted.
    """
    if operation not in _METHODS:
        raise ValueError('unregistered protected-service operation')
    require_canonical_server_origin(request_origin)
    if not service_id or not domain or not isinstance(scope, dict) or not scope:
        raise ValueError('protected-service binding is not configured')

    did, signature = parse_didkey_auth(request.headers.get('Authorization'))
    timestamp = require_timestamp(request)
    enforce_timestamp_skew(timestamp)
    if request.method != _METHODS[operation]:
        raise HTTPException(status_code=401, detail='Protected request method does not match operation')
    body = await request.body()
    if request.method == 'GET' and body:
        raise HTTPException(status_code=401, detail='Protected GET requests require an empty body')

    # Reconstruct rather than parse attacker-selected JSON. Exact canonical
    # encoding equality rejects duplicate/extra fields, alternate encodings and
    # absent covering headers without falling back to legacy controller auth.
    raw = canonical_json_bytes({
        'v': 2, 'type': CONTROLLER_REQUEST_TYPE, 'aud': request_origin,
        'operation': operation, 'domain': domain, 'timestamp': timestamp,
        'method': request.method, 'path': raw_controller_request_target(request),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'service_id': service_id,
        'scope_sha256': hashlib.sha256(canonical_json_bytes(scope)).hexdigest(),
    })
    encoded = base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')
    if request.headers.get('X-AWEB-Signed-Payload') != encoded:
        raise HTTPException(status_code=401, detail='Protected envelope does not match request')
    # The protected wire specifies unpadded standard base64, unlike permissive
    # legacy consumers of verify_did_key_signature.
    if not re.fullmatch(r'[A-Za-z0-9+/]{86}', signature):
        raise HTTPException(status_code=401, detail='Invalid protected request signature encoding')
    try:
        verify_did_key_signature(did_key=did, payload=raw, signature_b64=signature)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail='Invalid protected request signature') from exc
    return did
