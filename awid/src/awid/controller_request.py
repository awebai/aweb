"""Covering controller HTTP envelopes; legacy acceptance is rollout-only."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
from urllib.parse import quote

from fastapi import HTTPException, Request
from fastapi.routing import APIRoute

from awid.dns_auth import enforce_timestamp_skew, parse_didkey_auth, require_timestamp, verify_signed_json_request
from awid.log import canonical_server_origin
from awid.signing import canonical_json_bytes, verify_did_key_signature

CONTROLLER_REQUEST_TYPE = 'aweb.awid-controller-request'
CONTROLLER_OPERATIONS = frozenset({
    'register', 'update_namespace', 'rotate_controller', 'delete_namespace',
    'authorize_subdomain_registration', 'authorize_subdomain_rotation',
    'create_team', 'delete_team', 'rotate_team_key', 'set_team_visibility',
    'register_certificate', 'revoke_certificate',
    'publish_team_custodian', 'publish_member_custody', 'publish_member_person',
    'register_address', 'update_address', 'delete_address', 'reassign_address',
    'register_id_certificate', 'revoke_id_certificate', 'rotate_namespace_controller',
    'read_id_certificate_status',
})
logger = logging.getLogger(__name__)


def raw_controller_request_target(request: Request) -> str:
    raw = request.scope.get('raw_path')
    path = raw.decode('ascii') if isinstance(raw, bytes) else quote(request.scope.get('path', '/'), safe='/%')
    root = quote(str(request.scope.get('root_path') or '').rstrip('/'), safe='/%')
    if root and path != root and not path.startswith(root + '/'):
        path = root + ('/' if not path.startswith('/') else '') + path
    query = request.scope.get('query_string', b'')
    if query:
        path += '?' + (query.decode('ascii') if isinstance(query, bytes) else query)
    return path


async def verify_controller_json_request(
    request: Request, *, payload_dict: dict[str, str],
    authorization_header: str = 'Authorization', timestamp_header: str = 'X-AWEB-Timestamp',
    signed_payload_header: str = 'X-AWEB-Signed-Payload',
) -> str:
    """Verify exact covering bytes, or the separately measured legacy form.

    Route helpers supply the closed operation and its existing contextual
    claims. Only the route's success records usage; proof alone is not authority.
    """
    operation = payload_dict['operation']
    if operation not in CONTROLLER_OPERATIONS:
        raise ValueError('unregistered controller operation')
    supplied = request.headers.get(signed_payload_header)
    if supplied is None:
        did = verify_signed_json_request(
            request, payload_dict=payload_dict, authorization_header=authorization_header,
            timestamp_header=timestamp_header,
        )
        pending = getattr(request.state, 'legacy_controller_operations', None)
        if pending is None:
            pending = set()
            request.state.legacy_controller_operations = pending
        pending.add(operation)
        return did

    did, signature = parse_didkey_auth(request.headers.get(authorization_header))
    timestamp = require_timestamp(request, header_name=timestamp_header)
    enforce_timestamp_skew(timestamp)
    try:
        if len(supplied) > 16384 or not re.fullmatch(r'[A-Za-z0-9_-]+={0,2}', supplied):
            raise ValueError('invalid encoding')
        raw = base64.b64decode(supplied + '=' * (-len(supplied) % 4), altchars=b'-_', validate=True)
        payload = json.loads(raw)
        if not isinstance(payload, dict) or not isinstance(payload.get('aud'), str):
            raise ValueError('invalid envelope')
        audience = canonical_server_origin(payload['aud'])
    except (ValueError, TypeError, UnicodeError) as exc:
        raise HTTPException(status_code=401, detail='Invalid AWID controller envelope') from exc

    origins = getattr(request.app.state, 'awid_public_origins', ())
    allowed = {canonical_server_origin(value) for value in origins}
    if not allowed:
        raise HTTPException(status_code=503, detail='AWID controller public origins are not configured')
    if audience not in allowed:
        raise HTTPException(status_code=401, detail='AWID controller audience is not allowed')
    body = await request.body()
    expected = {
        **payload_dict, 'timestamp': timestamp, 'v': 2, 'type': CONTROLLER_REQUEST_TYPE,
        'aud': audience, 'method': request.method.upper(),
        'path': raw_controller_request_target(request), 'body_sha256': hashlib.sha256(body).hexdigest(),
    }
    if raw != canonical_json_bytes(expected):
        raise HTTPException(status_code=401, detail='AWID controller envelope does not match request')
    try:
        verify_did_key_signature(did_key=did, payload=raw, signature_b64=signature)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail='Invalid signature') from exc
    return did


class ControllerAuthRoute(APIRoute):
    """Count successful legacy controller operations, never raw identifiers.

    The existing AWID metric convention is a per-process aggregate, reported at
    one and powers of two. Embedding operators ingest these structured metrics;
    this adds no public metrics endpoint or telemetry dependency.
    """
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def measured(request: Request):
            response = await handler(request)
            if response.status_code < 400:
                counts = getattr(request.app.state, 'legacy_controller_auth_counts', None)
                if counts is None:
                    counts = {}
                    request.app.state.legacy_controller_auth_counts = counts
                for operation in getattr(request.state, 'legacy_controller_operations', ()):
                    count = counts.get(operation, 0) + 1
                    counts[operation] = count
                    if count == 1 or count & (count - 1) == 0:
                        logger.info('event=awid_legacy_controller_auth_accepted metric=awid_legacy_controller_auth_accepted value=%s operation=%s', count, operation)
            return response
        return measured
