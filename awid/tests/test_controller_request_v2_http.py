"""Controller mutation binding through AWID, real PostgreSQL and real Redis."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from redis.asyncio import Redis

from awid.did import did_from_public_key, generate_keypair
from awid.signing import canonical_json_bytes, sign_message
from awid_service.main import create_app
from test_certificates import _register_identity, _signed_certificate_blob

ORIGIN = 'http://registry.test'
TYPE = 'aweb.awid-controller-request'


def keypair():
    key, public = generate_keypair()
    return key, did_from_public_key(public)


def headers(key, did, claims, method, path, body=b'', *, covering=True, overrides=None, parent=False):
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = {**claims, 'timestamp': timestamp}
    if covering:
        payload.update(v=2, type=TYPE, aud=ORIGIN, method=method, path=path, body_sha256=hashlib.sha256(body).hexdigest())
    payload.update(overrides or {})
    canonical = canonical_json_bytes(payload)
    prefix = 'X-AWEB-Parent-' if parent else 'X-AWEB-'
    result = {
        'X-AWEB-Parent-Authorization' if parent else 'Authorization': f'DIDKey {did} {sign_message(key, canonical)}',
        prefix + 'Timestamp': timestamp,
    }
    if covering:
        result[prefix + 'Signed-Payload'] = base64.urlsafe_b64encode(canonical).rstrip(b'=').decode()
    return result


async def send(env, method, path, claims, body=None, *, signer=None, covering=True, overrides=None):
    content = json.dumps(body, separators=(',', ':'), ensure_ascii=False).encode() if body is not None else b''
    key, did = signer or env.controller
    signed = headers(key, did, claims, method, path, content, covering=covering, overrides=overrides)
    return await env.client.request(method, path, content=content, headers={**signed, 'Content-Type': 'application/json'})


@pytest_asyncio.fixture
async def controller_app(awid_db_infra):
    # Real limiter and isolated client-IP bucket; remove only this fixture's keys.
    ip = '127.' + '.'.join(str(n) for n in os.urandom(3))
    async with Redis.from_url(os.environ.get('REDIS_URL', 'redis://localhost:6379/0'), decode_responses=True) as redis:
        await redis.ping()
        app = create_app(db_infra=awid_db_infra, redis=redis)
        app.state.awid_public_origins = (ORIGIN,)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=(ip, 12345)), base_url=ORIGIN) as client:
                env = SimpleNamespace(app=app, client=client, db=awid_db_infra.get_manager(), controller=keypair(), team=keypair())
                response = await send(env, 'POST', '/v1/namespaces', {'domain': 'local', 'operation': 'register'}, {'domain': 'local'}, covering=False)
                assert response.status_code == 200, response.text
                response = await send(env, 'POST', '/v1/namespaces/local/teams', {'domain': 'local', 'operation': 'create_team', 'name': 'base'}, {'name': 'base', 'team_did_key': env.team[1], 'visibility': 'public'}, covering=False)
                assert response.status_code == 200, response.text
                try:
                    yield env
                finally:
                    owned = [key async for key in redis.scan_iter(match=f'aweb:rl:*:{ip}:*')]
                    if owned:
                        await redis.delete(*owned)


def certificate_body(env, *, alias='member'):
    member = keypair()
    cert_id = str(uuid4())
    body = dict(certificate_id=cert_id, member_did_key=member[1], member_did_aw=None, member_address=None, alias=alias, identity_scope='local')
    body['certificate'] = _signed_certificate_blob(env.team[0], certificate_id=cert_id, team_id='base:local', team_did_key=env.team[1], member_did_key=member[1], alias=alias, lifetime='local')
    return body


@pytest.mark.asyncio
async def test_new_certificate_requires_blob_even_with_legacy_controller_signature(controller_app):
    env = controller_app
    body = certificate_body(env)
    body.pop('certificate')
    response = await send(env, 'POST', '/v1/namespaces/local/teams/base/certificates', {'domain': 'local', 'operation': 'register_certificate', 'team_name': 'base', 'certificate_id': body['certificate_id']}, body, signer=env.team, covering=False)
    assert response.status_code == 422, response.text
    assert await env.db.fetch_value('SELECT count(*) FROM {{tables.team_certificates}}') == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('field', ['team_did_key', 'visibility', 'display_name'])
async def test_covering_create_refuses_swapped_written_fields(controller_app, field):
    env = controller_app
    path = '/v1/namespaces/local/teams'
    body = dict(name='bound', team_did_key=keypair()[1], visibility='private', display_name='Original')
    content = json.dumps(body).encode()
    signed = headers(*env.controller, {'domain': 'local', 'operation': 'create_team', 'name': 'bound'}, 'POST', path, content)
    body[field] = keypair()[1] if field == 'team_did_key' else ('public' if field == 'visibility' else 'Changed')
    rejected = await env.client.post(path, content=json.dumps(body).encode(), headers={**signed, 'Content-Type': 'application/json'})
    assert rejected.status_code == 401, rejected.text
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.teams}} WHERE name='bound'") == 0
    accepted = await env.client.post(path, content=content, headers={**signed, 'Content-Type': 'application/json'})
    assert accepted.status_code == 200, accepted.text
    row = await env.db.fetch_one("SELECT team_did_key,visibility,display_name FROM {{tables.teams}} WHERE name='bound'")
    assert dict(row) == {k: json.loads(content)[k] for k in row.keys()}


@pytest.mark.asyncio
@pytest.mark.parametrize('override', [
    {'method': 'DELETE'}, {'path': '/v1/namespaces/local/teams?extra=1'},
    {'body_sha256': '0'*64}, {'operation': 'delete_team'}, {'domain': 'other.local'},
    {'aud': 'https://other-registry.test'}, {'type': 'aweb.team-auth-request'}, {'v': 1},
])
async def test_covering_envelope_requires_target_audience_and_protocol_type(controller_app, override):
    env = controller_app
    body = {'name': 'bound', 'team_did_key': keypair()[1]}
    response = await send(env, 'POST', '/v1/namespaces/local/teams', {'domain': 'local', 'operation': 'create_team', 'name': 'bound'}, body, overrides=override)
    assert response.status_code == 401, response.text
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.teams}} WHERE name='bound'") == 0


@pytest.mark.asyncio
async def test_covering_header_never_falls_back_to_valid_legacy_signature(controller_app):
    env = controller_app
    path = '/v1/namespaces/local/teams'
    body = {'name': 'bound', 'team_did_key': keypair()[1]}
    content = json.dumps(body).encode()
    signed = headers(*env.controller, {'domain': 'local', 'operation': 'create_team', 'name': 'bound'}, 'POST', path, content, covering=False)
    signed['X-AWEB-Signed-Payload'] = 'invalid'
    response = await env.client.post(path, content=content, headers={**signed, 'Content-Type': 'application/json'})
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_reassign_binds_both_identity_and_current_key(controller_app):
    env = controller_app
    first, second = keypair(), keypair()
    first_aw = await _register_identity(env.client, *first)
    second_aw = await _register_identity(env.client, *second)
    response = await send(env, 'POST', '/v1/namespaces/local/addresses', {'domain': 'local', 'name': 'agent', 'operation': 'register_address'}, {'name': 'agent', 'did_aw': first_aw, 'current_did_key': first[1]})
    assert response.status_code == 200, response.text
    path = '/v1/namespaces/local/addresses/agent/reassign'
    body = {'did_aw': second_aw, 'current_did_key': second[1]}
    content = json.dumps(body).encode()
    signed = headers(*env.controller, {'domain': 'local', 'name': 'agent', 'operation': 'reassign_address'}, 'POST', path, content)
    response = await env.client.post(path, content=json.dumps({'did_aw': first_aw, 'current_did_key': first[1]}).encode(), headers={**signed, 'Content-Type': 'application/json'})
    assert response.status_code == 401, response.text
    assert await env.db.fetch_value("SELECT did_aw FROM {{tables.public_addresses}} WHERE name='agent'") == first_aw
    response = await env.client.post(path, content=content, headers={**signed, 'Content-Type': 'application/json'})
    assert response.status_code == 200, response.text
    assert response.json()['did_aw'] == second_aw


@pytest.mark.asyncio
@pytest.mark.parametrize('field', ['member_did_key', 'member_did_aw', 'alias', 'member_address', 'identity_scope'])
async def test_registration_refuses_fields_that_disagree_with_signed_blob(controller_app, field):
    env = controller_app
    body = certificate_body(env)
    if field == 'member_did_key':
        body[field] = keypair()[1]
    elif field in ('member_did_aw', 'member_address'):
        member = keypair()
        stable = await _register_identity(env.client, *member)
        assert (await send(env, 'POST', '/v1/namespaces/local/addresses', {'domain': 'local', 'name': 'other', 'operation': 'register_address'}, {'name': 'other', 'did_aw': stable, 'current_did_key': member[1]})).status_code == 200
        body['member_did_aw'], body['member_address'] = stable, 'local/other'
        body['identity_scope'] = 'global'
    else:
        body[field] = 'global' if field == 'identity_scope' else 'different'
    response = await send(env, 'POST', '/v1/namespaces/local/teams/base/certificates', {'domain': 'local', 'operation': 'register_certificate', 'team_name': 'base', 'certificate_id': body['certificate_id']}, body, signer=env.team)
    assert response.status_code == 422, response.text
    assert await env.db.fetch_value('SELECT count(*) FROM {{tables.team_certificates}}') == 0


@pytest.mark.asyncio
async def test_covering_team_lifecycle_and_legacy_metric(controller_app):
    env = controller_app
    before = dict(env.app.state.legacy_controller_auth_counts)
    body = certificate_body(env)
    claims = {'domain': 'local', 'team_name': 'base', 'operation': 'register_certificate', 'certificate_id': body['certificate_id']}
    result = await send(env, 'POST', '/v1/namespaces/local/teams/base/certificates', claims, body, signer=env.team)
    assert result.status_code == 200, result.text
    changed = await send(env, 'PATCH', '/v1/namespaces/local/teams/base', {'domain': 'local', 'team_name': 'base', 'operation': 'set_team_visibility', 'visibility': 'private'}, {'visibility': 'private'}, signer=env.team)
    assert changed.status_code == 200, changed.text
    revoked = await send(env, 'POST', '/v1/namespaces/local/teams/base/certificates/revoke', {**claims, 'operation': 'revoke_certificate'}, {'certificate_id': body['certificate_id']}, signer=env.team)
    assert revoked.status_code == 200, revoked.text
    removed = await send(env, 'DELETE', '/v1/namespaces/local/teams/base', {'domain': 'local', 'operation': 'delete_team', 'team_name': 'base'})
    assert removed.status_code == 200, removed.text
    assert env.app.state.legacy_controller_auth_counts == before
    legacy = await send(env, 'POST', '/v1/namespaces/local/teams', {'domain': 'local', 'operation': 'create_team', 'name': 'legacy'}, {'name': 'legacy', 'team_did_key': keypair()[1]}, covering=False)
    assert legacy.status_code == 200, legacy.text
    assert env.app.state.legacy_controller_auth_counts['create_team'] == before['create_team'] + 1
