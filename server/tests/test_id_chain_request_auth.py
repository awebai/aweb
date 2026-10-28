"""S4 enrollment carrier and identity-lane request decisions.

Unit tests pin the binding/cache seam; the omission regression drives the real
AWID and aweb services, PostgreSQL, Redis and public registration clients.
"""
from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI, HTTPException, Request

from awid.dns_verify import DomainAuthority
from awid.id_certificates import id_certificate_signing_bytes
from awid.registry import CachedRegistryClient, IDTreeEnrollment
from awid_service.deps import get_domain_verifier
from aweb.api import _build_awid_registry_client
from aweb.identity_binding import IdentityBinding, verify_identity_binding
from test_awid_registry_client import _FakeRedis
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import privacy_app  # noqa: F401
from test_messages_http import _signed_identity_headers

VECTORS = json.loads((Path(__file__).resolve().parents[2] / 'docs/vectors/id-certificates-v1.json').read_text())
ALICE = VECTORS['keys']['alice']
ROOT = VECTORS['keys']['root']
DOMAIN = 'example.com'


def request(app, headers=None):
    return Request({'type': 'http', 'method': 'GET', 'path': '/', 'query_string': b'',
                    'headers': [(key.lower().encode(), value.encode()) for key, value in (headers or {}).items()],
                    'app': app, 'state': {}})


@pytest.mark.asyncio
@pytest.mark.parametrize('wire, expected', [
    ({'id_tree': {'enrolled': True, 'domain': DOMAIN}}, IDTreeEnrollment(True, DOMAIN)),
    ({'id_tree': {'enrolled': False}}, IDTreeEnrollment(False, None)),
    ({}, None),
], ids=['enrolled', 'not-enrolled', 'unknown'])
async def test_binding_uses_fresh_resolution_and_preserves_the_sixty_second_boundary(monkeypatch, wire, expected):
    calls = []

    async def answer(req):
        calls.append(req.url.path)
        return httpx.Response(200, json={'did_aw': ALICE['did_aw'], 'current_did_key': ALICE['did_key'], **wire})

    client = CachedRegistryClient('https://registry.example', _FakeRedis(), transport=httpx.MockTransport(answer))
    app = FastAPI()
    app.state.awid_registry_client = client
    async def forbidden_plain_resolve(self, did_aw):
        pytest.fail('binding used plain resolve_key')

    monkeypatch.setattr(CachedRegistryClient, 'resolve_key', forbidden_plain_resolve)
    now = [100.0]
    monkeypatch.setattr('aweb.identity_binding.monotonic', lambda: now[0])

    async def bind():
        return await verify_identity_binding(request(app), did_key=ALICE['did_key'], did_aw=ALICE['did_aw'])

    try:
        first = await bind()
        assert first.id_tree == expected
        assert len(calls) == 1
        now[0] = 159.0
        second = await bind()
        assert second.id_tree == expected
        assert len(calls) == (2 if expected is None else 1)
        now[0] = 220.0
        assert (await bind()).id_tree == expected
        assert len(calls) == (3 if expected is None else 2)
    finally:
        await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize('redis_present', [False, True], ids=['plain-factory', 'cached-factory'])
async def test_factory_without_cached_evidence_never_fetches_a_tree(monkeypatch, redis_present):
    from aweb.id_chain_auth import authenticate_id_chain

    monkeypatch.setenv('AWID_REGISTRY_URL', 'https://registry.example')
    monkeypatch.setenv('AWEB_DATABASE_URL', 'postgresql://unused/test')
    app = FastAPI()
    client = _build_awid_registry_client(app, redis=_FakeRedis() if redis_present else None,
                                       transport=httpx.MockTransport(lambda req: pytest.fail('chainless local did network work')))
    app.state.awid_registry_client = client
    try:
        result = await authenticate_id_chain(request(app), IdentityBinding(did_key=ALICE['did_key']))
        assert result['reason'] == 'legacy_no_chain'
        if not redis_present:
            with pytest.raises(HTTPException) as refused:
                await authenticate_id_chain(request(app), IdentityBinding(
                    did_aw=ALICE['did_aw'], did_key=ALICE['did_key'], id_tree=IDTreeEnrollment(True, DOMAIN)))
            assert refused.value.status_code == 503
            assert refused.value.detail == 'evidence_unavailable'
    finally:
        await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize('enrollment, reason', [
    (None, 'evidence_unavailable'),
    (IDTreeEnrollment(True, 'other.example'), 'domain_mismatch'),
], ids=['unknown-is-not-legacy', 'presented-domain-must-match-enrollment'])
async def test_enrollment_controls_domain_before_any_tree_fetch(enrollment, reason):
    from awid.id_certificates import encode_id_chain_header
    from aweb.id_chain_auth import authenticate_id_chain

    class NoTreeRead:
        async def id_chain_evidence(self, *args, **kwargs):
            pytest.fail('unselected or conflicting domain caused a tree read')

    app = FastAPI()
    app.state.awid_registry_client = NoTreeRead()
    bundle = {'v': 1, 'type': 'aweb.id-chain', 'certificates': [VECTORS['certificates']['alice']['signed']]}
    req = request(app, {'X-AWID-ID-Chain': encode_id_chain_header(bundle)})
    with pytest.raises(HTTPException) as refused:
        await authenticate_id_chain(req, IdentityBinding(
            did_aw=ALICE['did_aw'], did_key=ALICE['did_key'], id_tree=enrollment))
    assert refused.value.detail == reason
    assert refused.value.status_code == (503 if enrollment is None else 403)


@pytest.mark.asyncio
@pytest.mark.parametrize('revoked', [False, True], ids=['live-neighbor', 'enroll-then-revoke'])
async def test_stale_not_enrolled_does_not_hide_enrollment_or_revocation(privacy_app, monkeypatch, revoked):
    env = privacy_app
    # A distinct domain prevents another case's valid 60s tree cache from
    # legitimately masking this case's newly witnessed revocation.
    domain = f'awtest-s4-{uuid4().hex}.test'
    actor = env.actors['bob']
    actor.sk, actor.did = bytes.fromhex(ALICE['seed_hex']), ALICE['did_key']
    await env.db.execute('UPDATE {{tables.agents}} SET did_key=$1 WHERE agent_id=$2', actor.did, actor.id)
    async with registry_listener(env) as (writer, origin):
        env.registry_app.state.awid_public_origins = (origin,)
        selected_domain = domain

        async def exact_dns(domain):
            assert domain == selected_domain
            return DomainAuthority(ROOT['did_key'], origin, '_awid.' + selected_domain)

        env.registry_app.dependency_overrides[get_domain_verifier] = lambda: exact_dns
        # Use the production factory and its actual Redis cache. Only DNS is
        # fixture evidence; all key, enrollment, status and revoke reads/writes
        # run through real HTTP services.
        monkeypatch.setenv('AWID_REGISTRY_URL', origin)
        monkeypatch.setenv('AWEB_DATABASE_URL', 'postgresql://unused/test')
        cached = _build_awid_registry_client(env.app, redis=env.redis)
        object.__setattr__(cached, '_domain_verifier', exact_dns)
        env.app.state.awid_registry_client = cached
        try:
            stable = (await writer.register_did(actor.did, actor.sk)).did_aw
            await writer.register_namespace(domain, ROOT['did_key'], bytes.fromhex(ROOT['seed_hex']))
            assert (await cached.resolve_key(stable)).id_tree == IDTreeEnrollment(False, None)
            warmed_at = time.monotonic()
            from nacl.signing import SigningKey
            fields = VECTORS['certificates']['alice']['signed']['certificate'] | {
                'domain': domain, 'parent': {'kind': 'namespace', 'id': domain}}
            signature = SigningKey(bytes.fromhex(ROOT['seed_hex'])).sign(id_certificate_signing_bytes(fields)).signature
            signed = {'certificate': fields, 'signature': base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}
            bundle = {'v': 1, 'type': 'aweb.id-chain', 'certificates': [signed]}

            def signer(seed, did):
                from nacl.signing import SigningKey
                return lambda payload: (did, SigningKey(seed).sign(payload).signature)

            receipt = await writer.register_id_certificate(bundle, signer=signer(actor.sk, actor.did),
                                                           expected_head=None, invitation_id=None)
            if revoked:
                await writer.revoke_id_certificate(domain, stable,
                    signer=signer(bytes.fromhex(ROOT['seed_hex']), ROOT['did_key']),
                    expected_head=receipt['certificate_id'])
            # The ordinary SDK cache still says legacy inside its five-minute
            # TTL. Original authentication MUST resolve fresh instead.
            assert (await cached.resolve_key(stable)).id_tree == IDTreeEnrollment(False, None)

            async def forbidden_plain_resolve(self, did_aw):
                pytest.fail('omission used plain resolve_key instead of the 60s binding path')

            monkeypatch.setattr(CachedRegistryClient, 'resolve_key', forbidden_plain_resolve)
            payload = {'to_did': env.actors['carol'].did, 'subject': 'must refuse', 'body': 'must not deliver'}
            body = json.dumps(payload).encode()
            before = await env.db.fetch_val('SELECT count(*) FROM {{tables.messages}}')
            response = await env.client.post('/v1/messages', content=body, headers={
                **_signed_identity_headers(actor.sk, actor.did, stable, body), 'Content-Type': 'application/json'})
            assert time.monotonic() - warmed_at < 300
            assert response.status_code == (403 if revoked else 200), response.text
            if revoked:
                assert response.json()['detail'] == 'revoked'
            assert await env.db.fetch_val('SELECT count(*) FROM {{tables.messages}}') == before + (0 if revoked else 1)
        finally:
            env.app.state.awid_registry_client = writer
            await cached.aclose()


def _signed_fixture_certificate(template, *, domain, identity, parent, issuer):
    from nacl.signing import SigningKey

    fields = VECTORS['certificates'][template]['signed']['certificate'] | {
        'domain': domain, 'id': identity, 'parent': parent}
    seed = bytes.fromhex(VECTORS['keys'][issuer]['seed_hex'])
    signature = SigningKey(seed).sign(id_certificate_signing_bytes(fields)).signature
    return {'certificate': fields, 'signature': base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}


def _fixture_signer(name):
    from nacl.signing import SigningKey

    key = VECTORS['keys'][name]
    return lambda payload: (key['did_key'], SigningKey(bytes.fromhex(key['seed_hex'])).sign(payload).signature)


@pytest.mark.asyncio
@pytest.mark.parametrize('presentation, reason', [
    ('revoked', 'revoked'),
    ('root-replaced', 'root_replaced'),
    ('malformed', 'invalid_encoding'),
    ('two-headers', 'invalid_shape'),
    ('chainless', None),
])
async def test_did_key_only_requests_enforce_presented_chain(privacy_app, monkeypatch, presentation, reason):
    from awid.id_certificates import encode_id_chain_header

    env = privacy_app
    actor = env.actors['bob']
    domain = f'awtest-local-{uuid4().hex}.test'
    async with registry_listener(env) as (writer, origin):
        env.registry_app.state.awid_public_origins = (origin,)
        controller = [ROOT]

        async def exact_dns(selected):
            assert selected == domain
            return DomainAuthority(controller[0]['did_key'], origin, '_awid.' + domain)

        env.registry_app.dependency_overrides[get_domain_verifier] = lambda: exact_dns
        monkeypatch.setenv('AWID_REGISTRY_URL', origin)
        monkeypatch.setenv('AWEB_DATABASE_URL', 'postgresql://unused/test')
        cached = _build_awid_registry_client(env.app, redis=env.redis)
        object.__setattr__(cached, '_domain_verifier', exact_dns)
        env.app.state.awid_registry_client = cached
        try:
            root_local = _signed_fixture_certificate('root-agent', domain=domain, identity=actor.did,
                parent={'kind': 'namespace', 'id': domain}, issuer='root')
            bundle = {'v': 1, 'type': 'aweb.id-chain', 'certificates': [root_local]}
            if presentation in ('revoked', 'root-replaced'):
                await writer.register_namespace(domain, ROOT['did_key'], bytes.fromhex(ROOT['seed_hex']))
                await writer.register_did(ALICE['did_key'], bytes.fromhex(ALICE['seed_hex']))
                human = _signed_fixture_certificate('alice', domain=domain, identity=ALICE['did_aw'],
                    parent={'kind': 'namespace', 'id': domain}, issuer='root')
                receipt = await writer.register_id_certificate(
                    {'v': 1, 'type': 'aweb.id-chain', 'certificates': [human]},
                    signer=_fixture_signer('alice'), expected_head=None, invitation_id=None)
                local = _signed_fixture_certificate('coordinator', domain=domain, identity=actor.did,
                    parent={'kind': 'identity', 'id': ALICE['did_aw']}, issuer='alice')
                bundle['certificates'] = [human, local]
                if presentation == 'revoked':
                    await writer.revoke_id_certificate(domain, ALICE['did_aw'], signer=_fixture_signer('root'),
                                                       expected_head=receipt['certificate_id'])
                else:
                    controller[0] = VECTORS['keys']['root_rotated']
                    await writer.rotate_namespace_controller(domain, controller[0]['did_key'],
                                                              bytes.fromhex(controller[0]['seed_hex']))
            else:
                async def no_tree_read(self, *args, **kwargs):
                    pytest.fail('chainless or syntactically refused local request fetched a tree')
                monkeypatch.setattr(CachedRegistryClient, 'id_chain_evidence', no_tree_read)

            body = json.dumps({'to_did': env.actors['carol'].did, 'subject': 'local', 'body': 'local'}).encode()
            headers = list(_signed_identity_headers(actor.sk, actor.did, '', body).items())
            headers.append(('Content-Type', 'application/json'))
            if presentation != 'chainless':
                value = '!' if presentation == 'malformed' else encode_id_chain_header(bundle)
                headers.append(('X-AWID-ID-Chain', value))
                if presentation == 'two-headers':
                    headers.append(('X-AWID-ID-Chain', value))
            before = await env.db.fetch_val('SELECT count(*) FROM {{tables.messages}}')
            response = await env.client.post('/v1/messages', content=body, headers=headers)
            assert response.status_code == (200 if reason is None else 403), response.text
            if reason:
                assert response.json()['detail'] == reason
            assert await env.db.fetch_val('SELECT count(*) FROM {{tables.messages}}') == before + (reason is None)
        finally:
            env.app.state.awid_registry_client = writer
            await cached.aclose()
