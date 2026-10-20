"""The public AWID controller request schema, canonicalizer and client signer."""
from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from urllib.parse import urlsplit

import httpx
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.log import canonical_server_origin
from awid.signing import canonical_json_bytes, sign_message, verify_did_key_signature

CONTROLLER_REQUEST_TYPE = 'aweb.awid-controller-request'
# Required and optional route claims, excluding the separately typed operation.
_ROUTE_CLAIMS = {
    'register': ({'domain'}, {'default_delivery_origin'}),
    'update_namespace': ({'domain', 'default_delivery_origin'}, set()),
    'rotate_controller': ({'domain', 'new_controller_did'}, set()),
    'delete_namespace': ({'domain'}, set()),
    'authorize_subdomain_registration': ({'domain', 'child_domain', 'controller_did'}, set()),
    'authorize_subdomain_rotation': ({'domain', 'child_domain', 'new_controller_did'}, set()),
    'create_team': ({'domain', 'name'}, set()),
    'delete_team': ({'domain', 'team_name'}, set()),
    'rotate_team_key': ({'domain', 'name', 'new_team_did_key'}, set()),
    'set_team_visibility': ({'domain', 'team_name', 'visibility'}, set()),
    'register_certificate': ({'domain', 'team_name', 'certificate_id'}, set()),
    'revoke_certificate': ({'domain', 'team_name', 'certificate_id'}, set()),
    'register_address': ({'domain', 'name'}, set()),
    'update_address': ({'domain', 'name'}, set()),
    'delete_address': ({'domain', 'name'}, {'expected_address_id', 'expected_did_aw', 'expected_current_did_key'}),
    'reassign_address': ({'domain', 'name'}, set()),
    'publish_team_custodian': ({'domain', 'team_name', 'custodian_id'}, set()),
    'publish_member_custody': ({'domain', 'team_name', 'certificate_id'}, set()),
    'publish_member_person': ({'domain', 'team_name', 'certificate_id'}, set()),
}
CONTROLLER_OPERATIONS = frozenset(_ROUTE_CLAIMS)
_FIXED = {'v', 'type', 'operation', 'aud', 'method', 'path', 'body_sha256', 'timestamp'}


@dataclass(frozen=True)
class ControllerRequest:
    operation: str
    aud: str
    method: str
    path: str
    body_sha256: str
    timestamp: str
    route_claims: Mapping[str, str]
    v: int = 2
    type: str = CONTROLLER_REQUEST_TYPE

    def __post_init__(self):
        object.__setattr__(self, 'route_claims', MappingProxyType(dict(self.route_claims)))


def build_controller_payload(request: ControllerRequest) -> bytes:
    """Validate typed fields and derive the one canonical controller payload.

    This checks the protocol, not a signing service's authority policy. Such a
    service must also constrain audience, operation, namespace/team and freshness.
    """
    if type(request.v) is not int or request.v != 2 or request.type != CONTROLLER_REQUEST_TYPE:
        raise ValueError('invalid controller envelope type or version')
    if any(not isinstance(getattr(request, name), str) for name in _FIXED - {'v'}):
        raise ValueError('invalid controller field type')
    if request.operation not in _ROUTE_CLAIMS:
        raise ValueError('unknown controller operation')
    required, optional = _ROUTE_CLAIMS[request.operation]
    claims = dict(request.route_claims)
    if not required <= claims.keys() or claims.keys() - required - optional:
        raise ValueError('unknown or missing controller route claims')
    if any(not isinstance(value, str) for value in claims.values()) or not claims['domain']:
        raise ValueError('invalid controller route claims')
    if canonical_server_origin(request.aud) != request.aud:
        raise ValueError('noncanonical controller audience')
    if request.method not in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        raise ValueError('invalid controller mutation method')
    if not isinstance(request.path, str) or not request.path.startswith('/') or '#' in request.path:
        raise ValueError('invalid controller target')
    request.path.encode('ascii')
    if any(ord(char) <= 32 or ord(char) == 127 for char in request.path):
        raise ValueError('invalid controller target')
    if not isinstance(request.body_sha256, str) or not re.fullmatch('[0-9a-f]{64}', request.body_sha256):
        raise ValueError('invalid controller body commitment')
    if not isinstance(request.timestamp, str) or datetime.fromisoformat(request.timestamp).tzinfo is None:
        raise ValueError('invalid controller timestamp')
    payload = dict(claims, operation=request.operation, v=request.v, type=request.type,
                   aud=request.aud, method=request.method, path=request.path,
                   body_sha256=request.body_sha256, timestamp=request.timestamp)
    return canonical_json_bytes(payload)


def parse_controller_request(canonical_payload: bytes) -> ControllerRequest:
    """Refuse unknown fields, protocol confusion and noncanonical JSON bytes."""
    if not isinstance(canonical_payload, bytes) or len(canonical_payload) > 12288:
        raise ValueError('invalid controller payload')
    try:
        fields = json.loads(canonical_payload)
        if not isinstance(fields, dict) or not _FIXED <= fields.keys():
            raise ValueError('missing controller fields')
        fixed = {key: fields[key] for key in _FIXED}
        parsed = ControllerRequest(**fixed, route_claims={k: v for k, v in fields.items() if k not in _FIXED})
        if build_controller_payload(parsed) != canonical_payload:
            raise ValueError('noncanonical controller payload')
        return parsed
    except (TypeError, UnicodeError, OverflowError) as exc:
        raise ValueError('invalid controller payload') from exc


@dataclass(frozen=True)
class ControllerSigningRequest:
    controller_did_key: str
    operation: str
    canonical_payload: bytes

    def __post_init__(self):
        if parse_controller_request(self.canonical_payload).operation != self.operation:
            raise ValueError('controller signing operation mismatch')


ControllerSigner = Callable[[ControllerSigningRequest], Awaitable[str]]


def _payload(request: httpx.Request, claims: dict[str, str], timestamp: str | None) -> bytes:
    origin = urlsplit(str(request.url))
    return build_controller_payload(ControllerRequest(
        operation=claims['operation'], route_claims={k: v for k, v in claims.items() if k != 'operation'},
        aud=canonical_server_origin(f'{origin.scheme}://{origin.netloc}'), method=request.method,
        path=request.url.raw_path.decode('ascii'), body_sha256=hashlib.sha256(request.content).hexdigest(),
        timestamp=timestamp or datetime.now(timezone.utc).isoformat(),
    ))


def _headers(payload: bytes, did: str, signature: str, parent: bool) -> dict[str, str]:
    verify_did_key_signature(did_key=did, payload=payload, signature_b64=signature)
    prefix = 'X-AWEB-Parent-' if parent else 'X-AWEB-'
    return {
        'X-AWEB-Parent-Authorization' if parent else 'Authorization': f'DIDKey {did} {signature}',
        prefix + 'Timestamp': parse_controller_request(payload).timestamp,
        prefix + 'Signed-Payload': base64.urlsafe_b64encode(payload).rstrip(b'=').decode('ascii'),
    }


def controller_request_headers(
    request: httpx.Request, *, signing_key: bytes, claims: dict[str, str],
    timestamp: str | None = None, parent: bool = False,
) -> dict[str, str]:
    """Sign an already serialized request using a locally held controller key."""
    payload = _payload(request, claims, timestamp)
    did = did_from_public_key(bytes(SigningKey(signing_key).verify_key))
    return _headers(payload, did, sign_message(signing_key, payload), parent)


async def sign_controller_request(
    request: httpx.Request, *, controller_did_key: str, signer: ControllerSigner,
    claims: dict[str, str], parent: bool = False,
) -> dict[str, str]:
    """Call an external signer after serialization, then verify before sending.

    The signer must parse, apply its key policy, rebuild and sign with this SDK.
    It must not treat the supplied bytes as an arbitrary signing oracle.
    """
    payload = _payload(request, claims, None)
    signature = await signer(ControllerSigningRequest(controller_did_key, claims['operation'], payload))
    return _headers(payload, controller_did_key, signature, parent)
