"""Published Python/Go clients against real AWID, PostgreSQL and Redis.

The forwarding middleware changes a signed target for refusal tests. It never
synthesizes an AWID response, substitutes authority, or disables the limiter.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
from pathlib import Path
import socket
import subprocess
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio
import uvicorn

from awid.attestation_records import sign_record
from awid.controller_signing import controller_request_headers
from awid.registry import RegistryClient, RegistryError
from test_attestation_record_routes import _custodian, _custody, _person, publish_custodian, register_certificate
from test_certificates import _register_identity
from test_controller_request_v2_http import certificate_body, controller_app, keypair, send  # noqa: F401

ROOT = Path(__file__).resolve().parents[2]
OPERATIONS = (
    'register', 'update_namespace', 'rotate_controller', 'delete_namespace',
    'rotate_team_key', 'create_team', 'set_team_visibility', 'delete_team', 'register_certificate', 'revoke_certificate',
    'register_address', 'update_address', 'delete_address', 'conditional_delete_address', 'reassign_address',
    'publish_team_custodian', 'publish_member_custody', 'publish_member_person',
)
GO_OPERATIONS = tuple(x for x in OPERATIONS if x not in {'rotate_controller'})


@pytest.fixture(scope='session')
def controller_driver(tmp_path_factory):
    binary = tmp_path_factory.mktemp('controller-driver') / ('driver.exe' if os.name == 'nt' else 'driver')
    subprocess.run(['go', 'build', '-o', str(binary), str(ROOT / 'cli/tests/awid_controller_driver.go')],
                   cwd=ROOT / 'cli/go', check=True, capture_output=True, text=True, timeout=120)
    return binary


@pytest_asyncio.fixture
async def network_registry(controller_app):
    env = controller_app
    state = SimpleNamespace(tamper=False, mutations=[], status=[])
    async def forwarded(scope, receive, send_response):
        if scope['type'] == 'http':
            scope = dict(scope, client=env.client._transport.client)
            if scope['method'] not in {'GET', 'HEAD', 'OPTIONS'}:
                state.mutations.append(dict(scope))
                if state.tamper:
                    scope['query_string'] = scope.get('query_string', b'') + b'&tampered=1'
                async def observed(message):
                    if message['type'] == 'http.response.start':
                        state.status.append(message['status'])
                    await send_response(message)
                await env.app(scope, receive, observed)
                return
        await env.app(scope, receive, send_response)
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    origin = f'http://127.0.0.1:{sock.getsockname()[1]}'
    env.app.state.awid_public_origins = (origin, 'http://registry.test')
    server = uvicorn.Server(uvicorn.Config(forwarded, lifespan='off', log_level='error'))
    serving = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        for _ in range(100):
            if server.started:
                break
            await asyncio.sleep(.02)
        assert server.started
        yield env, state, origin
    finally:
        server.should_exit = True
        await serving
        sock.close()


async def scenario(env, operation):
    """Prepare real prerequisites; return one public client mutation."""
    body = certificate_body(env)
    member_key, member_did = keypair()
    member_stable = await _register_identity(env.client, member_key, member_did)
    config = dict(Action=operation, TeamDID=env.team[1], MemberDID=member_did, MemberStableID=member_stable,
                  Certificate=body['certificate'], Key=base64.b64encode(env.controller[0]).decode(), Claims={})
    namespace_key = env.controller[0]
    team_key = env.team[0]
    claims = {'domain': 'local', 'operation': operation}
    path = '/v1/namespaces/local/teams/base'
    if operation in {'set_team_visibility', 'register_certificate', 'revoke_certificate'} or operation.startswith('publish_'):
        config['Key'] = base64.b64encode(team_key).decode()
    if operation == 'register':
        deleted = await send(env, 'DELETE', '/v1/namespaces/local', dict(domain='local', operation='delete_namespace'))
        assert deleted.status_code == 200, deleted.text
        return config, lambda r: r.register_namespace('local', env.controller[1], namespace_key)
    if operation == 'update_namespace':
        return config, lambda r: r.update_namespace_delivery_origin('local', namespace_key, 'https://delivery.example')
    if operation == 'rotate_controller':
        new_key, new_did = keypair()
        return config, lambda r: r.rotate_namespace_controller('local', new_did, new_key)
    if operation == 'delete_namespace':
        return config, lambda r: r.delete_namespace('local', namespace_key)
    if operation == 'rotate_team_key':
        new_did = keypair()[1]
        claims.update(name='base', new_team_did_key=new_did)
        payload = dict(new_team_did_key=new_did)
        config.update(Method='POST', Path=path + '/rotate', Claims=claims, Body=payload)
        return config, lambda r: r.controller_request('POST', path + '/rotate', signing_key=namespace_key, claims=claims, body=payload)
    if operation == 'create_team':
        return config, lambda r: r.register_team(domain='local', name='new', display_name='Review — <safe>',
            team_did_key=env.team[1], visibility='private', namespace_controller_signing_key=namespace_key)
    if operation == 'set_team_visibility':
        return config, lambda r: r.set_team_visibility('local', 'base', 'private', team_key)
    if operation == 'delete_team':
        return config, lambda r: r.delete_team('local', 'base', namespace_key)
    if operation == 'register_certificate':
        return config, lambda r: r.register_team_certificate('local', 'base', team_controller_signing_key=team_key, **body)
    if operation == 'revoke_certificate':
        response = await send(env, 'POST', path + '/certificates',
            dict(claims, operation='register_certificate', team_name='base', certificate_id=body['certificate_id']), body, signer=env.team)
        assert response.status_code == 200, response.text
        config['Claims'] = {'certificate_id': body['certificate_id']}
        return config, lambda r: r.revoke_team_certificate('local', 'base', team_controller_signing_key=team_key, certificate_id=body['certificate_id'])
    if operation in {'register_address', 'update_address', 'delete_address', 'conditional_delete_address', 'reassign_address'}:
        address_body = dict(name='member', did_aw=member_stable, current_did_key=member_did)
        if operation != 'register_address':
            response = await send(env, 'POST', '/v1/namespaces/local/addresses',
                dict(claims, operation='register_address', name='member'), address_body)
            assert response.status_code == 200, response.text
            config['Claims'] = dict(expected_address_id=response.json()['address_id'],
                                    expected_did_aw=member_stable, expected_current_did_key=member_did)
        if operation == 'register_address':
            return config, lambda r: r.register_address('local', 'member', member_stable, namespace_key)
        if operation == 'update_address':
            config.update(Method='PUT', Path='/v1/namespaces/local/addresses/member', Body={}, Claims=dict(claims, name='member'))
            return config, lambda r: r.update_address('local', 'member', namespace_key)
        if operation == 'reassign_address':
            new_key, new_did = keypair()
            new_stable = await _register_identity(env.client, new_key, new_did)
            config.update(Method='POST', Path='/v1/namespaces/local/addresses/member/reassign',
                          Body=dict(did_aw=new_stable, current_did_key=new_did), Claims=dict(claims, name='member'))
            return config, lambda r: r.reassign_address('local', 'member', new_stable, namespace_key)
        if operation == 'conditional_delete_address':
            preconditions = config['Claims']
            return config, lambda r: r.controller_request('DELETE', '/v1/namespaces/local/addresses/member',
                signing_key=namespace_key, claims=dict(claims, operation='delete_address', name='member', **preconditions), body=preconditions)
        return config, lambda r: r.delete_address('local', 'member', namespace_key)
    if operation.startswith('publish_'):
        claims['team_name'] = 'base'
        if operation == 'publish_team_custodian':
            record = _custodian(env)
            claims['custodian_id'] = record['custodian_id']
            path += '/custodians/' + record['custodian_id']
        else:
            cert = await register_certificate(env)
            custodian = await publish_custodian(env, _custodian(env))
            assert custodian.status_code == 200, custodian.text
            claims['certificate_id'] = cert['certificate_id']
            record = _custody(env, cert) if operation == 'publish_member_custody' else _person(env, cert)
            path += f'/certificates/{cert["certificate_id"]}/' + ('custody' if operation == 'publish_member_custody' else 'person')
        payload = dict(record=record, signature=sign_record(team_key, record))
        config.update(Method='PUT', Path=path, Claims=claims, Body=payload)
        return config, lambda r: r.controller_request('PUT', path, signing_key=team_key, claims=claims, body=payload)
    raise AssertionError(operation)


@pytest.mark.asyncio
@pytest.mark.parametrize('operation', OPERATIONS)
@pytest.mark.parametrize('family', ['python', 'go'])
async def test_clients_refuse_tampering_then_apply_original_once(network_registry, controller_driver, operation, family):
    if family == 'go' and operation not in GO_OPERATIONS:
        pytest.skip('Go does not emit namespace rotation')
    env, state, origin = network_registry
    config, call = await scenario(env, operation)
    config['URL'] = origin
    client = RegistryClient(registry_url=origin)
    async def invoke():
        if family == 'python':
            try:
                await call(client)
                return 200
            except RegistryError as exc:
                return exc.status_code
        process = await asyncio.create_subprocess_exec(str(controller_driver), stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(process.communicate(json.dumps(config).encode()), 15)
        assert process.returncode == 0, stderr.decode()
        return json.loads(stdout)['status']
    async def snapshot():
        result = []
        for table in ('dns_namespaces', 'teams', 'team_certificates', 'dns_addresses', 'team_custodians', 'member_custody', 'member_person'):
            rows = await env.db.fetch_all('SELECT row_to_json(t)::text AS row FROM {{tables.' + table + '}} t ORDER BY row_to_json(t)::text')
            result.append([row['row'] for row in rows])
        return result
    try:
        before = await snapshot()
        state.tamper = True
        assert await invoke() == 401
        assert len(state.mutations) == 1, 'covering refusal must not trigger another request'
        assert state.status == [401]
        assert await snapshot() == before
        state.tamper = False
        assert await invoke() == 200
        assert len(state.mutations) == 2
        assert state.status == [401, 200]
        assert all(b'x-aweb-signed-payload' in dict(row['headers']) for row in state.mutations)
    finally:
        await client.aclose()


def test_python_signer_matches_published_vector():
    vector = json.loads((ROOT / 'docs/vectors/awid-controller-request-v2.json').read_text())
    request = httpx.Request('POST', 'http://registry.test/v1/namespaces/local/teams', content=vector['body_utf8'].encode())
    signed = controller_request_headers(request, signing_key=bytes.fromhex(vector['seed_hex']),
        claims=dict(domain='local', operation='create_team', name='vector'), timestamp=vector['payload']['timestamp'])
    assert base64.urlsafe_b64decode(signed['X-AWEB-Signed-Payload'] + '==').decode() == vector['canonical_payload']
    assert signed['Authorization'] == f'DIDKey {vector["did_key"]} {vector["signature_b64"]}'


@pytest.mark.asyncio
async def test_empty_certificate_refused_before_any_python_network_request(network_registry):
    env, state, origin = network_registry
    body = certificate_body(env)
    registry = RegistryClient(registry_url=origin)
    try:
        for value in (None, '', '  '):
            body['certificate'] = value
            with pytest.raises(ValueError):
                await registry.register_team_certificate('local', 'base', team_controller_signing_key=env.team[0], **body)
        assert state.mutations == []
    finally:
        await registry.aclose()


def test_signer_parser_rebuilder_refuses_protocol_confusion_and_unknown_fields():
    from awid.controller_signing import ControllerSigningRequest, build_controller_payload, parse_controller_request
    from awid.signing import canonical_json_bytes
    vector = json.loads((ROOT / 'docs/vectors/awid-controller-request-v2.json').read_text())
    raw = vector['canonical_payload'].encode()
    parsed = parse_controller_request(raw)
    assert build_controller_payload(parsed) == raw
    assert parsed.route_claims == dict(domain='local', name='vector')
    variants = [b' ' + raw, raw[:-1] + b',"v":2}',
                canonical_json_bytes(dict(vector['payload'], type='aweb.team-auth-request')),
                canonical_json_bytes(dict(vector['payload'], v=1)),
                canonical_json_bytes(dict(vector['payload'], unsupported='value'))]
    missing = dict(vector['payload'])
    missing.pop('name')
    variants.append(canonical_json_bytes(missing))
    for invalid in variants:
        with pytest.raises(ValueError):
            parse_controller_request(invalid)
    with pytest.raises(ValueError):
        ControllerSigningRequest(vector['did_key'], 'delete_team', raw)
    with pytest.raises(TypeError):
        parsed.route_claims['domain'] = 'other'


@pytest.mark.asyncio
async def test_public_external_signer_verifies_before_send_and_separates_parent(network_registry):
    from awid.controller_signing import build_controller_payload, parse_controller_request
    from awid.signing import sign_message
    env, state, origin = network_registry
    child_key, child_did = keypair()
    calls = []
    async def child_signer(request):
        parsed = parse_controller_request(request.canonical_payload)
        assert parsed.operation == request.operation == 'register'
        assert request.controller_did_key == child_did
        calls.append(parsed.operation)
        return sign_message(child_key, build_controller_payload(parsed))
    async def parent_signer(request):
        parsed = parse_controller_request(request.canonical_payload)
        assert parsed.operation == request.operation == 'authorize_subdomain_registration'
        assert request.controller_did_key == env.controller[1]
        calls.append(parsed.operation)
        return sign_message(env.controller[0], build_controller_payload(parsed))
    registry = RegistryClient(registry_url=origin)
    body = dict(domain='child.local', controller_did=child_did)
    try:
        await registry.controller_request('POST', '/v1/namespaces', claims=dict(domain='child.local', operation='register'),
            body=body, controller_did_key=child_did, signer=child_signer,
            parent_claims=dict(domain='child.local', child_domain='child.local', controller_did=child_did, operation='authorize_subdomain_registration'),
            parent_controller_did_key=env.controller[1], parent_signer=parent_signer)
        assert calls == ['register', 'authorize_subdomain_registration']
        assert state.status == [200]
        assert b'x-aweb-parent-signed-payload' in dict(state.mutations[0]['headers'])
        async def wrong_key(request):
            return sign_message(env.team[0], request.canonical_payload)
        with pytest.raises(ValueError):
            await registry.controller_request('POST', '/v1/namespaces', claims=dict(domain='child.local', operation='register'),
                body=body, controller_did_key=child_did, signer=wrong_key)
        assert len(state.mutations) == 1
    finally:
        await registry.aclose()
