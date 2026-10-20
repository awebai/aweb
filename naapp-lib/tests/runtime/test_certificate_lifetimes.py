"""Signed expiry at a relying app, backed by the actual AWID routes and PG."""
from datetime import UTC, datetime, timedelta
import base64
import json
from uuid import uuid4

import pytest
from awid.registry import RegistryClient
from awid.signing import canonical_json_bytes, sign_message
from aweb_naapp.runtime.certificate_client import TeamCertificateHTTPClient

from tests.runtime.conftest import Member, relying_app, utc_timestamp

ORIGIN = 'https://app.example.com'


@pytest.mark.parametrize('offset,expected', [(-1, 200), (0, 401), (1, 401)])
async def test_signed_certificate_expiry_boundary(registry, offset, expected):
    expires = datetime(2026, 10, 20, 12, tzinfo=UTC)
    member = Member(team_id='ops:example.com', extra_cert_fields={
        'version': 2, 'validity_class': 'member', 'expires_at': utc_timestamp(expires),
    })
    await registry.add_team(member.team_id, member.team_did_key)
    await registry.add_certificate(member.certificate())
    now = expires + timedelta(seconds=offset)
    async with relying_app(registry, public_origin=ORIGIN, now=lambda: now) as (client, _):
        response = await client.get('/v1/items', headers=member.headers(
            aud=ORIGIN, method='GET', path='/v1/items', timestamp=utc_timestamp(now),
        ))
    assert response.status_code == expected, response.text
    if expected == 401:
        assert response.json()['detail']['code'] == 'certificate_expired'


async def test_optional_expiry_does_not_change_default_or_override_revocation(registry):
    member = Member(team_id='ops:example.com', extra_cert_fields={'version': 2, 'validity_class': 'member'})
    await registry.add_team(member.team_id, member.team_did_key)
    await registry.add_certificate(member.certificate())
    async with relying_app(registry, public_origin=ORIGIN) as (client, _):
        response = await client.get('/v1/items', headers=member.headers(aud=ORIGIN, method='GET', path='/v1/items'))
    assert response.status_code == 200, response.text
    await registry.revoke(member.certificate_id)
    async with relying_app(registry, public_origin=ORIGIN) as (client, _):
        response = await client.get('/v1/items', headers=member.headers(aud=ORIGIN, method='GET', path='/v1/items'))
    assert response.status_code == 401 and 'revoked' in response.text.lower(), response.text


async def test_rollover_member_follows_installs_and_retries_once(registry, monkeypatch, tmp_path):
    monkeypatch.setenv('AWID_CERTIFICATE_V2_ISSUANCE_ENABLED', 'true')
    member = Member(team_id='ops:example.com')
    old = member.certificate()
    await registry.add_team(member.team_id, member.team_did_key, visibility='private')
    await registry.add_certificate(old)
    fresh = {key: value for key, value in old.items() if key not in ('signature', 'lifetime')}
    fresh.update(version=2, certificate_id=str(uuid4()), validity_class='member', identity_scope='global')
    fresh['signature'] = sign_message(bytes(member.team_key), canonical_json_bytes(fresh))
    sdk = RegistryClient('https://registry.example', transport=registry.transport)
    try:
        await sdk.rollover_team_certificate('example.com', 'ops', old['certificate_id'], {
            'certificate_id': fresh['certificate_id'], 'member_did_key': member.did_key,
            'alias': member.alias, 'identity_scope': 'global',
            'certificate': base64.b64encode(json.dumps(fresh).encode()).decode(),
        }, signing_key=bytes(member.team_key))
        installed = tmp_path / 'certificate.json'
        async def install(cert):
            installed.write_text(json.dumps(cert))
        async with relying_app(registry, public_origin=ORIGIN) as (http, _):
            refused = await http.get('/v1/items', headers=member.headers(aud=ORIGIN, method='GET', path='/v1/items'))
            assert refused.status_code == 401 and refused.json()['detail']['code'] == 'certificate_replaced'
            client = TeamCertificateHTTPClient(http, origin=ORIGIN, certificate=old,
                member_signing_key=bytes(member.member_key), registry=sdk, install=install)
            response = await client.request('GET', '/v1/items')
            assert response.status_code == 200, response.text
            assert response.json()['certificate_id'] == fresh['certificate_id']
            assert json.loads(installed.read_text()) == fresh
            # Revocation of the replacement is disciplinary, with no recovery.
        await registry.revoke(fresh['certificate_id'])
        async with relying_app(registry, public_origin=ORIGIN) as (http, _):
            client = TeamCertificateHTTPClient(http, origin=ORIGIN, certificate=fresh,
                member_signing_key=bytes(member.member_key), registry=sdk, install=install)
            refused = await client.request('GET', '/v1/items')
            assert refused.status_code == 401
    finally:
        await sdk.aclose()
