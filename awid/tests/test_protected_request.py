"""Protected-service requester possession, without controller or human authority."""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI, HTTPException
from starlette.requests import Request

from awid.did import did_from_public_key, generate_keypair
from awid.controller_request import verify_controller_json_request
from awid.protected_request import verify_protected_request
from awid.signing import canonical_json_bytes, sign_message


ORIGIN = 'https://signer.customer.example'
SERVICE = 'customer-signer'
DOMAIN = 'customer.example'
SCOPE = {'service_id': SERVICE, 'team_id': 'engineering:customer.example'}
OPERATIONS = (
    ('protected_operation_prepare', 'POST'),
    ('protected_operation_receipt', 'GET'),
    ('protected_operation_execute', 'POST'),
    ('protected_handoff_start', 'POST'),
    ('protected_admission_policy_read', 'GET'),
)


def signed_request(*, operation=OPERATIONS[0][0], method='POST', body=b'{}',
                   overrides=None, raw_payload=None, timestamp=None):
    private, public = generate_keypair()
    did = did_from_public_key(public)
    timestamp = timestamp or datetime.now(timezone.utc).isoformat()
    fields = {
        'v': 2, 'type': 'aweb.awid-controller-request',
        'aud': ORIGIN, 'domain': DOMAIN, 'operation': operation,
        'method': method, 'path': '/protected/protected-operations?team=a%3Ab',
        'body_sha256': hashlib.sha256(body).hexdigest(), 'timestamp': timestamp,
        'service_id': SERVICE,
        'scope_sha256': hashlib.sha256(canonical_json_bytes(SCOPE)).hexdigest(),
    }
    fields.update(overrides or {})
    raw = raw_payload if raw_payload is not None else canonical_json_bytes(fields)
    headers = {
        'Authorization': f'DIDKey {did} {sign_message(private, raw)}',
        'X-AWEB-Timestamp': timestamp,
        'X-AWEB-Signed-Payload': base64.urlsafe_b64encode(raw).rstrip(b'=').decode(),
    }
    return did, headers, body


def request(headers, body, *, method='POST', path=b'/protected-operations',
            query=b'team=a%3Ab', root_path='/protected'):
    async def receive():
        return {'type': 'http.request', 'body': body, 'more_body': False}

    return Request({
        'type': 'http', 'method': method, 'path': path.decode(), 'raw_path': path,
        'root_path': root_path, 'query_string': query,
        'headers': [(k.lower().encode(), v.encode()) for k, v in headers.items()],
    }, receive)


async def verify(req, *, operation=OPERATIONS[0][0], **kwargs):
    return await verify_protected_request(
        req, operation=operation, request_origin=ORIGIN, service_id=SERVICE,
        domain=DOMAIN, scope=SCOPE, **kwargs,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize('operation,method', OPERATIONS)
async def test_covering_request_authenticates_only_the_signing_key(operation, method):
    did, headers, body = signed_request(operation=operation, method=method,
                                        body=b'' if method == 'GET' else b'{}')
    assert await verify(request(headers, body, method=method), operation=operation) == did


@pytest.mark.asyncio
@pytest.mark.parametrize('overrides', [
    {'aud': 'https://app.aweb.ai'}, {'domain': 'other.example'},
    {'operation': 'register_certificate'}, {'method': 'GET'},
    {'path': '/protected-operations?team=a%3Ab'},
    {'path': '/protected/protected-operations?team=a:b'},
    {'body_sha256': hashlib.sha256(b'{"kind":"human"}').hexdigest()},
    {'service_id': 'other-service'}, {'scope_sha256': '0' * 64},
    {'v': 1}, {'type': 'aweb.team-auth'}, {'extra': 'ignored?'},
])
async def test_valid_signature_cannot_substitute_any_bound_field(overrides):
    _, headers, body = signed_request(overrides=overrides)
    with pytest.raises(HTTPException) as exc:
        await verify(request(headers, body))
    assert exc.value.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize('credential', ['Bearer worker-token', 'AWEB-Grant worker-grant',
                                      'DIDKey raw-key', ''])
async def test_legacy_tokens_and_plain_key_are_not_requester_proofs(credential):
    _, headers, body = signed_request()
    headers['Authorization'] = credential
    with pytest.raises(HTTPException) as exc:
        await verify(request(headers, body))
    assert exc.value.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize('field,value', [
    ('X-AWEB-Signed-Payload', None), ('X-AWEB-Signed-Payload', ''),
    ('X-AWEB-Signed-Payload', 'not+url/base64'), ('X-AWEB-Timestamp', None),
    ('X-AWEB-Timestamp', '2026-11-11T00:00:00'),
])
async def test_missing_or_malformed_covering_headers_never_fall_back(field, value):
    _, headers, body = signed_request()
    if value is None:
        headers.pop(field)
    else:
        headers[field] = value
    with pytest.raises(HTTPException) as exc:
        await verify(request(headers, body))
    assert exc.value.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize('seconds', [-301, 301])
async def test_stale_or_future_proofs_refuse(seconds):
    timestamp = (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()
    _, headers, body = signed_request(timestamp=timestamp)
    with pytest.raises(HTTPException) as exc:
        await verify(request(headers, body))
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_duplicate_fields_refuse_even_if_correctly_signed():
    _, headers, body = signed_request(raw_payload=b'{"v":2,"v":2}')
    with pytest.raises(HTTPException) as exc:
        await verify(request(headers, body))
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_another_key_cannot_sign_as_the_named_key():
    _, headers, body = signed_request()
    _, another, _ = signed_request()
    parts = headers['Authorization'].split()
    parts[1] = another['Authorization'].split()[1]
    headers['Authorization'] = ' '.join(parts)
    with pytest.raises(HTTPException) as exc:
        await verify(request(headers, body))
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_external_mount_prefix_is_not_added_twice():
    did, headers, body = signed_request()
    assert await verify(request(headers, body, path=b'/protected/protected-operations')) == did


@pytest.mark.asyncio
async def test_unknown_operation_is_a_configuration_error():
    _, headers, body = signed_request()
    with pytest.raises(ValueError, match='operation'):
        await verify(request(headers, body), operation='arbitrary_sign')


@pytest.mark.asyncio
async def test_get_proof_cannot_carry_a_body_even_when_correctly_signed():
    operation = 'protected_operation_receipt'
    _, headers, body = signed_request(operation=operation, method='GET', body=b'{}')
    with pytest.raises(HTTPException) as exc:
        await verify(request(headers, body, method='GET'), operation=operation)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize('field', ['signature', 'payload'])
async def test_padded_wire_encodings_refuse(field):
    _, headers, body = signed_request()
    name = 'Authorization' if field == 'signature' else 'X-AWEB-Signed-Payload'
    headers[name] += '='
    with pytest.raises(HTTPException) as exc:
        await verify(request(headers, body))
    assert exc.value.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize('registry_origin', [ORIGIN, 'https://registry.customer.example'])
async def test_protected_proof_cannot_authorize_an_awid_controller_operation(registry_origin):
    _, headers, body = signed_request()
    req = request(headers, body)
    req.scope['app'] = app = FastAPI()
    app.state.awid_public_origins = (registry_origin,)
    with pytest.raises(HTTPException) as exc:
        await verify_controller_json_request(
            req, payload_dict={'domain': DOMAIN, 'operation': 'create_team', 'name': 'engineering'},
        )
    assert exc.value.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize('registry_origin', [ORIGIN, 'https://registry.customer.example'])
async def test_awid_controller_proof_cannot_prepare_a_protected_operation(registry_origin):
    private, public = generate_keypair()
    did = did_from_public_key(public)
    timestamp = datetime.now(timezone.utc).isoformat()
    body = b'{}'
    raw = canonical_json_bytes({
        'v': 2, 'type': 'aweb.awid-controller-request', 'aud': registry_origin,
        'domain': DOMAIN, 'operation': 'create_team', 'name': 'engineering',
        'timestamp': timestamp, 'method': 'POST',
        'path': '/protected/protected-operations?team=a%3Ab',
        'body_sha256': hashlib.sha256(body).hexdigest(),
    })
    headers = {
        'Authorization': f'DIDKey {did} {sign_message(private, raw)}',
        'X-AWEB-Timestamp': timestamp,
        'X-AWEB-Signed-Payload': base64.urlsafe_b64encode(raw).rstrip(b'=').decode(),
    }
    req = request(headers, body)
    req.scope['app'] = app = FastAPI()
    app.state.awid_public_origins = (registry_origin,)
    # The neighboring operation really is accepted by AWID's verifier with
    # this exact signature, including the shared-origin embedding.
    assert await verify_controller_json_request(
        req, payload_dict={'domain': DOMAIN, 'operation': 'create_team', 'name': 'engineering'},
    ) == did
    with pytest.raises(HTTPException) as exc:
        await verify(req)
    assert exc.value.status_code == 401
