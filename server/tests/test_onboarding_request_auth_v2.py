"""Onboarding proof API through real HTTP; no substituted verification/store."""
import base64
from datetime import datetime, timezone
import hashlib
import json
import secrets

from fastapi import HTTPException, Request
import pytest

from awid.signing import canonical_json_bytes, sign_message
from test_dashboard_privacy import privacy_app  # noqa: F401


@pytest.mark.asyncio
@pytest.mark.parametrize('side_headers', [False, True])
async def test_versioned_onboarding_proof_bound_to_target_and_side_header(side_headers, privacy_app):
    from awid.http_didkey import verify_http_didkey_proof
    from aweb.request_auth_replay import admit_verified_request, RedisRequestReplayStore
    from uuid import uuid4
    env = privacy_app
    prefix = f'aweb:test:onboarding:{uuid4().hex}:'
    env.app.state.request_auth_replay_store = RedisRequestReplayStore(env.redis, key_prefix=prefix)
    env.app.state.public_origin = str(env.client.base_url).rstrip('/')
    actor = env.actors['alice']

    @env.app.post('/onboarding-proof')
    async def endpoint(request: Request):
        proof = await verify_http_didkey_proof(
            request, allowed_audiences=[env.app.state.public_origin], did_aw='',
            authorization_header='X-AWEB-DIDKey-Signature' if side_headers else 'Authorization',
            timestamp_header='X-AWEB-DIDKey-Timestamp' if side_headers else 'X-AWEB-Timestamp',
            signed_payload_header='X-AWEB-DIDKey-Signed-Payload' if side_headers else 'X-AWEB-Signed-Payload')
        if (await request.json())['did_key'] != proof.did_key:
            raise HTTPException(401, detail='body signer mismatch')
        await admit_verified_request(request, envelope=proof.envelope, did_key=proof.did_key,
                                     signature_b64=proof.signature_b64, family='onboarding')
        return {'did_key': proof.did_key, 'version': proof.envelope.version}

    timestamp = datetime.now(timezone.utc).isoformat()
    body = json.dumps({'did_key': actor.did}).encode()
    fields = dict(v=2, aud=env.app.state.public_origin, method='POST',
                  path='/onboarding-proof?q=a%2Fb', did_aw='', timestamp=timestamp,
                  body_sha256=hashlib.sha256(body).hexdigest(),
                  nonce=base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b'=').decode())
    canonical = canonical_json_bytes(fields)
    headers = {'Content-Type': 'application/json'}
    auth = 'X-AWEB-DIDKey-Signature' if side_headers else 'Authorization'
    clock = 'X-AWEB-DIDKey-Timestamp' if side_headers else 'X-AWEB-Timestamp'
    payload = 'X-AWEB-DIDKey-Signed-Payload' if side_headers else 'X-AWEB-Signed-Payload'
    headers.update({auth: f'DIDKey {actor.did} {sign_message(actor.sk, canonical)}', clock: timestamp,
                    payload: base64.urlsafe_b64encode(canonical).rstrip(b'=').decode()})
    if side_headers:
        headers['Authorization'] = 'Bearer separate-authority-is-not-the-key-proof'
    try:
        valid = await env.client.post('/onboarding-proof?q=a%2Fb', content=body, headers=headers)
        assert valid.status_code == 200, valid.text
        assert valid.json() == {'did_key': actor.did, 'version': 2}
        retargeted = await env.client.post('/onboarding-proof?q=changed', content=body, headers=headers)
        assert retargeted.status_code == 401, retargeted.text
        bad_payload = dict(fields, nonce='not-a-valid-nonce')
        headers[payload] = base64.urlsafe_b64encode(canonical_json_bytes(bad_payload)).rstrip(b'=').decode()
        bad = await env.client.post('/onboarding-proof?q=a%2Fb', content=body, headers=headers)
        assert bad.status_code == 401, bad.text
        # A valid OLD signature plus a malformed presented v2 must not fall back.
        old = canonical_json_bytes(dict(body_sha256=hashlib.sha256(body).hexdigest(),
                                       method='POST', path='/onboarding-proof', timestamp=timestamp))
        headers[auth] = f'DIDKey {actor.did} {sign_message(actor.sk, old)}'
        headers[payload] = 'malformed'
        refused = await env.client.post('/onboarding-proof', content=body, headers=headers)
        assert refused.status_code == 401, refused.text
        del headers[payload]
        legacy = await env.client.post('/onboarding-proof', content=body, headers=headers)
        assert legacy.status_code == 200, legacy.text
        assert legacy.json()['version'] == 1
    finally:
        keys = [key async for key in env.redis.scan_iter(match=prefix + '*')]
        if keys:
            await env.redis.delete(*keys)


@pytest.mark.asyncio
async def test_existing_onboarding_verifier_never_ignores_present_v2(privacy_app):
    from awid.http_didkey import verify_http_didkey_request
    env = privacy_app
    actor = env.actors['alice']

    @env.app.post('/onboarding-old-entry')
    async def endpoint(request: Request):
        return {'did_key': await verify_http_didkey_request(request)}

    body = b'{}'
    timestamp = datetime.now(timezone.utc).isoformat()
    old = canonical_json_bytes(dict(body_sha256=hashlib.sha256(body).hexdigest(),
                                   method='POST', path='/onboarding-old-entry', timestamp=timestamp))
    headers = {'Authorization': f'DIDKey {actor.did} {sign_message(actor.sk, old)}',
               'X-AWEB-Timestamp': timestamp, 'X-AWEB-Signed-Payload': 'malformed',
               'Content-Type': 'application/json'}
    response = await env.client.post('/onboarding-old-entry', content=body, headers=headers)
    assert response.status_code == 401, response.text
    del headers['X-AWEB-Signed-Payload']
    accepted = await env.client.post('/onboarding-old-entry', content=body, headers=headers)
    assert accepted.status_code == 200, accepted.text


@pytest.mark.asyncio
@pytest.mark.parametrize('legacy_path', [None, '/onboarding-compat'])
@pytest.mark.parametrize('side_headers', [False, True])
async def test_onboarding_legacy_path_override_never_rewrites_v2(privacy_app, legacy_path, side_headers):
    from awid.http_didkey import build_http_didkey_payload, verify_http_didkey_proof
    env = privacy_app
    actor = env.actors['alice']
    origin = str(env.client.base_url).rstrip('/')
    auth = 'X-AWEB-DIDKey-Signature' if side_headers else 'Authorization'
    clock = 'X-AWEB-DIDKey-Timestamp' if side_headers else 'X-AWEB-Timestamp'
    payload = 'X-AWEB-DIDKey-Signed-Payload' if side_headers else 'X-AWEB-Signed-Payload'

    @env.app.post('/onboarding-compat/')
    async def endpoint(request: Request):
        proof = await verify_http_didkey_proof(
            request, allowed_audiences=[origin], legacy_path=legacy_path,
            authorization_header=auth, timestamp_header=clock, signed_payload_header=payload)
        return {'did_key': proof.did_key, 'version': proof.envelope.version}

    body = b'{}'
    timestamp = datetime.now(timezone.utc).isoformat()
    headers = {'Content-Type': 'application/json', clock: timestamp}
    if side_headers:
        headers['Authorization'] = 'Bearer separate-route-authority'

    def sign(canonical):
        headers[auth] = f'DIDKey {actor.did} {sign_message(actor.sk, canonical)}'

    def legacy(path):
        return build_http_didkey_payload(body_bytes=body, method='POST', path=path, timestamp=timestamp)

    sign(legacy(legacy_path if legacy_path is not None else '/onboarding-compat/'))
    accepted = await env.client.post('/onboarding-compat/?q=ignored-by-legacy', content=body, headers=headers)
    assert accepted.status_code == 200, accepted.text
    assert accepted.json() == {'did_key': actor.did, 'version': 1}
    sign(legacy('/onboarding-compat/' if legacy_path is not None else '/onboarding-compat'))
    refused = await env.client.post('/onboarding-compat/', content=body, headers=headers)
    assert refused.status_code == 401, refused.text

    fields = dict(v=2, aud=origin, method='POST', path='/onboarding-compat/?q=a%2Fb',
                  did_aw='', timestamp=timestamp, body_sha256=hashlib.sha256(body).hexdigest())
    canonical = canonical_json_bytes(fields)
    sign(canonical)
    headers[payload] = base64.urlsafe_b64encode(canonical).rstrip(b'=').decode()
    accepted = await env.client.post('/onboarding-compat/?q=a%2Fb', content=body, headers=headers)
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()['version'] == 2
    retargeted = await env.client.post('/onboarding-compat/?q=changed', content=body, headers=headers)
    assert retargeted.status_code == 401, retargeted.text
    canonical = canonical_json_bytes(dict(fields, path='/onboarding-compat'))
    sign(canonical)
    headers[payload] = base64.urlsafe_b64encode(canonical).rstrip(b'=').decode()
    rewritten = await env.client.post('/onboarding-compat/', content=body, headers=headers)
    assert rewritten.status_code == 401, rewritten.text
