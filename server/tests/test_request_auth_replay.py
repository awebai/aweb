"""Nonce admission through the real aweb/AWID/PostgreSQL/Redis HTTP stack."""
import asyncio
import base64
from datetime import datetime, timezone
import hashlib
import secrets
import socket

import httpx
import pytest
import pytest_asyncio
from uuid import uuid4
from redis.asyncio import Redis
from starlette.requests import Request

from awid.did import stable_id_from_did_key
from awid.signing import canonical_json_bytes, sign_message
from test_addressless_sender_cli import _registry_http
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401


ABSENT = object()


@pytest_asyncio.fixture(autouse=True)
async def isolated_replay_store(privacy_app):
    from aweb.request_auth_replay import RedisRequestReplayStore
    prefix = f'aweb:test:request-replay:{uuid4().hex}:'
    privacy_app.app.state.request_auth_replay_store = RedisRequestReplayStore(
        privacy_app.redis, key_prefix=prefix)
    try:
        yield
    finally:
        keys = [key async for key in privacy_app.redis.scan_iter(match=prefix + '*')]
        if keys:
            await privacy_app.redis.delete(*keys)


async def _headers(env, family, *, nonce=ABSENT, timestamp=None):
    actor = env.actors['alice']
    claim = {'did_aw': ''}
    headers = {'User-Agent': 'aw/1.36.45'}
    if family == 'certificate':
        claim = {'team_id': TEAM}
        headers['X-AWID-Team-Certificate'] = actor.certificate
    elif family == 'identity-global':
        await env.app.state.awid_registry_client.register_did(actor.did, actor.sk)
        stable = stable_id_from_did_key(actor.did)
        claim = {'did_aw': stable}
        headers['X-AWEB-DID-AW'] = stable
    timestamp = timestamp or datetime.now(timezone.utc).isoformat()
    payload = dict(v=2, aud=str(env.client.base_url).rstrip('/'), method='GET',
                   path='/v1/messages/inbox', body_sha256=hashlib.sha256(b'').hexdigest(),
                   timestamp=timestamp, **claim)
    if nonce is not ABSENT:
        payload['nonce'] = nonce
    canonical = canonical_json_bytes(payload)
    headers.update({'Authorization': f'DIDKey {actor.did} {sign_message(actor.sk, canonical)}',
                    'X-AWEB-Timestamp': timestamp,
                    'X-AWEB-Signed-Payload': base64.urlsafe_b64encode(canonical).rstrip(b'=').decode()})
    env.app.state.public_origin = str(env.client.base_url).rstrip('/')
    return headers


def _nonce():
    return base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b'=').decode()


@pytest.mark.asyncio
@pytest.mark.parametrize('family', ['certificate', 'identity-local', 'identity-global'])
async def test_nonce_request_is_accepted_once(privacy_app, family):
    env = privacy_app
    headers = await _headers(env, family, nonce=_nonce())
    first = await env.client.get('/v1/messages/inbox', headers=headers)
    assert first.status_code == 200, first.text
    replay = await env.client.get('/v1/messages/inbox', headers=headers)
    assert replay.status_code == 401, replay.text
    assert replay.json()['detail']['code'] == 'request_replayed'


@pytest.mark.asyncio
async def test_two_fresh_nonces_in_same_second_both_pass(privacy_app):
    env = privacy_app
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    for _ in range(2):
        headers = await _headers(env, 'identity-local', nonce=_nonce(), timestamp=timestamp)
        response = await env.client.get('/v1/messages/inbox', headers=headers)
        assert response.status_code == 200, response.text


@pytest.mark.asyncio
@pytest.mark.parametrize('nonce', ['', None, 1, 'AAAAAAAAAAAAAAAAAAAAAA==', 'AA',
                                   'AAAAAAAAAAAAAAAAAAAAAB', '/////////////////////w'])
async def test_signed_malformed_nonce_is_refused(privacy_app, nonce):
    headers = await _headers(privacy_app, 'identity-local', nonce=nonce)
    response = await privacy_app.client.get('/v1/messages/inbox', headers=headers)
    assert response.status_code == 401, response.text


@pytest.mark.asyncio
async def test_nonce_free_duplicate_is_accepted_and_measured(privacy_app):
    from aweb.auth_metrics import NONCE_FREE_REQUEST_AUTH_ACCEPTED, REQUEST_AUTH_REPLAY_DETECTED
    env = privacy_app
    labels = ('identity', 'GET', '/v1/messages/inbox', '1.36.45')
    usage = NONCE_FREE_REQUEST_AUTH_ACCEPTED.labels(*labels)
    duplicates = REQUEST_AUTH_REPLAY_DETECTED.labels(*labels, 'nonce_free')
    before = usage._value.get(), duplicates._value.get()
    headers = await _headers(env, 'identity-local')
    for _ in range(2):
        response = await env.client.get('/v1/messages/inbox', headers=headers)
        assert response.status_code == 200, response.text
    assert usage._value.get() == before[0] + 2
    assert duplicates._value.get() == before[1] + 1


@pytest.mark.asyncio
async def test_store_unavailable_refuses_nonce_but_preserves_old_client(privacy_app):
    from aweb.request_auth_replay import RedisRequestReplayStore
    env = privacy_app
    # A real TCP connection failure, not a simulated store/auth response.
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    async with Redis.from_url(f'redis://127.0.0.1:{port}', socket_connect_timeout=.1) as unavailable:
        env.app.state.request_auth_replay_store = RedisRequestReplayStore(unavailable)
        try:
            headers = await _headers(env, 'identity-local', nonce=_nonce())
            response = await env.client.get('/v1/messages/inbox', headers=headers)
            assert response.status_code == 503, response.text
            assert response.json()['detail']['code'] == 'request_auth_replay_unavailable'
            headers = await _headers(env, 'identity-local')
            response = await env.client.get('/v1/messages/inbox', headers=headers)
            assert response.status_code == 200, response.text
        finally:
            del env.app.state.request_auth_replay_store


@pytest.mark.asyncio
async def test_simultaneous_identical_requests_have_one_winner(privacy_app):
    env = privacy_app
    headers = await _headers(env, 'identity-local', nonce=_nonce())
    responses = await asyncio.gather(*(env.client.get('/v1/messages/inbox', headers=headers) for _ in range(2)))
    assert sorted(r.status_code for r in responses) == [200, 401]


@pytest.mark.asyncio
async def test_bridge_and_dependency_share_one_incoming_claim(privacy_app):
    from aweb.team_auth_deps import verify_request_certificate
    env = privacy_app

    async def bridge(scope, receive, send):
        if scope['type'] == 'http':
            scope['app'] = env.app
            request = Request(scope)
            request.state.body_sha256 = hashlib.sha256(b'').hexdigest()
            await verify_request_certificate(request, env.infra)
        await env.app(scope, receive, send)

    async with _registry_http(bridge) as (url, _):
        async with httpx.AsyncClient(base_url=url) as client:
            original = env.client
            env.client = client
            try:
                headers = await _headers(env, 'certificate', nonce=_nonce())
                response = await client.get('/v1/messages/inbox', headers=headers)
                assert response.status_code == 200, response.text
                # A second request bypassing the outer bridge must still refuse.
                replay = await original.get('/v1/messages/inbox', headers=headers)
                assert replay.status_code == 401, replay.text
            finally:
                env.client = original


@pytest.mark.asyncio
async def test_alternate_signature_encoding_is_the_same_replay(privacy_app):
    env = privacy_app
    headers = await _headers(env, 'identity-local', nonce=_nonce())
    first = await env.client.get('/v1/messages/inbox', headers=headers)
    assert first.status_code == 200, first.text
    scheme, did, signature = headers['Authorization'].split(' ')
    alternate = signature.replace('+', '-').replace('/', '_') + '=='
    headers['Authorization'] = f'{scheme} {did} {alternate}'
    replay = await env.client.get('/v1/messages/inbox', headers=headers)
    assert replay.status_code == 401, replay.text
    assert replay.json()['detail']['code'] == 'request_replayed'
