"""Own certificate kind, not the connect payload, controls human treatment.

Real request auth, public registry, chain verifier, PostgreSQL and messaging.
Only DNS is fixture authority. Both cases deliberately send the same human claim.
"""
import json
from uuid import UUID, uuid4

import pytest

from awid.dns_verify import DomainAuthority
from awid_service.deps import get_domain_verifier
from aweb.api import _build_awid_registry_client
from test_dashboard_privacy import privacy_app, TEAM  # noqa: F401
from test_cli_never_grants import registry_listener
from test_id_chain_request_auth import ALICE, ROOT, _signed_fixture_certificate, _fixture_signer
from test_messages_http import _encode_certificate, _make_certificate, _signed_team_headers


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['agent', 'human'])
async def test_connect_own_verified_kind_controls_chat_mail_and_roster(privacy_app, monkeypatch, kind):
    env = privacy_app
    domain = f'awtest-kind-{uuid4().hex}.test'
    async with registry_listener(env) as (writer, origin):
        env.registry_app.state.awid_public_origins = (origin,)

        async def exact_dns(selected):
            assert selected == domain
            return DomainAuthority(ROOT['did_key'], origin, '_awid.' + domain)

        env.registry_app.dependency_overrides[get_domain_verifier] = lambda: exact_dns
        monkeypatch.setenv('AWID_REGISTRY_URL', origin)
        monkeypatch.setenv('AWEB_DATABASE_URL', 'postgresql://unused/test')
        cached = _build_awid_registry_client(env.app, redis=env.redis)
        object.__setattr__(cached, '_domain_verifier', exact_dns)
        env.app.state.awid_registry_client = cached
        try:
            await writer.register_did(ALICE['did_key'], bytes.fromhex(ALICE['seed_hex']))
            await writer.register_namespace(domain, ROOT['did_key'], bytes.fromhex(ROOT['seed_hex']))
            signed = _signed_fixture_certificate('alice' if kind == 'human' else 'root-agent',
                domain=domain, identity=ALICE['did_aw'], parent={'kind': 'namespace', 'id': domain}, issuer='root')
            bundle = {'v': 1, 'type': 'aweb.id-chain', 'certificates': [signed]}
            await writer.register_id_certificate(bundle, signer=_fixture_signer('alice'),
                                                  expected_head=None, invitation_id=None)
            cert = _encode_certificate(_make_certificate(env.team_sk, env.team_did, ALICE['did_key'],
                team_id=TEAM, alias='subject', member_did_aw=ALICE['did_aw'], certificate_id='kind-subject'))
            body = json.dumps({'agent_type': 'human'}).encode()
            response = await env.client.post('/v1/connect', content=body, headers={
                **_signed_team_headers(bytes.fromhex(ALICE['seed_hex']), ALICE['did_key'], TEAM, cert, body),
                'Content-Type': 'application/json'})
            assert response.status_code == 200, response.text
            row = await env.db.fetch_one('SELECT * FROM {{tables.agents}} WHERE agent_id=$1',
                                        UUID(response.json()['agent_id']))
            # This assertion reproduces the released defect before any new API is used.
            assert row['agent_type'] == kind
            sender = env.actors['bob']
            headers = _signed_team_headers(sender.sk, sender.did, TEAM, sender.certificate)
            roster = await env.client.get('/v1/agents', headers=headers)
            assert roster.status_code == 200, roster.text
            assert ('subject' in {r['alias'] for r in roster.json()['agents']}) == (kind == 'agent')
            for path, payload, expected in [
                ('/v1/chat/sessions', {'to_aliases': ['subject'], 'message': 'hello'}, 422 if kind == 'human' else 200),
                ('/v1/messages', {'to_alias': 'subject', 'subject': 'hello', 'body': 'mail works'}, 200),
            ]:
                body = json.dumps(payload).encode()
                response = await env.client.post(path, content=body, headers={
                    **_signed_team_headers(sender.sk, sender.did, TEAM, sender.certificate, body),
                    'Content-Type': 'application/json'})
                assert response.status_code == expected, response.text
        finally:
            env.app.state.awid_registry_client = writer
            await cached.aclose()
