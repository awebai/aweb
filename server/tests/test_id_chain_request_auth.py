"""S4 enrollment carrier and identity-lane request decisions.

Unit tests pin the binding/cache seam; the omission regression drives the real
AWID and aweb services, PostgreSQL, Redis and public registration clients.
"""
from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI, HTTPException, Request

from awid.dns_verify import DomainAuthority
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
async def test_binding_preserves_enrollment_and_the_sixty_second_boundary(monkeypatch, wire, expected):
    calls = []

    async def answer(req):
        calls.append(req.url.path)
        return httpx.Response(200, json={'did_aw': ALICE['did_aw'], 'current_did_key': ALICE['did_key'], **wire})

    client = CachedRegistryClient('https://registry.example', _FakeRedis(), transport=httpx.MockTransport(answer))
    app = FastAPI()
    app.state.awid_registry_client = client
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
async def test_cached_not_enrolled_then_enroll_revoke_and_omit_refuses(privacy_app, monkeypatch):
    env = privacy_app
    actor = env.actors['bob']
    actor.sk, actor.did = bytes.fromhex(ALICE['seed_hex']), ALICE['did_key']
    await env.db.execute('UPDATE {{tables.agents}} SET did_key=$1 WHERE agent_id=$2', actor.did, actor.id)
    async with registry_listener(env) as (writer, origin):
        async def exact_dns(domain):
            assert domain == DOMAIN
            return DomainAuthority(ROOT['did_key'], origin, '_awid.' + DOMAIN)

        env.registry_app.dependency_overrides[get_domain_verifier] = lambda: exact_dns
        # Use the production factory and its actual Redis cache. Only DNS is
        # fixture evidence; all key, enrollment, status and revoke reads/writes
        # run through real HTTP services.
        monkeypatch.setenv('AWID_REGISTRY_URL', origin)
        cached = _build_awid_registry_client(env.app, redis=env.redis)
        object.__setattr__(cached, '_domain_verifier', exact_dns)
        env.app.state.awid_registry_client = cached
        try:
            stable = (await writer.register_did(actor.did, actor.sk)).did_aw
            await writer.register_namespace(DOMAIN, ROOT['did_key'], bytes.fromhex(ROOT['seed_hex']))
            assert (await cached.resolve_key(stable)).id_tree == IDTreeEnrollment(False, None)
            bundle = {'v': 1, 'type': 'aweb.id-chain', 'certificates': [VECTORS['certificates']['alice']['signed']]}

            def signer(seed, did):
                from nacl.signing import SigningKey
                return lambda payload: (did, SigningKey(seed).sign(payload).signature)

            receipt = await writer.register_id_certificate(bundle, signer=signer(actor.sk, actor.did),
                                                           expected_head=None, invitation_id=None)
            await writer.revoke_id_certificate(DOMAIN, stable,
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
            assert response.status_code == 403, response.text
            assert response.json()['detail'] == 'revoked'
            assert await env.db.fetch_val('SELECT count(*) FROM {{tables.messages}}') == before
        finally:
            env.app.state.awid_registry_client = writer
            await cached.aclose()
