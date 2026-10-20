"""Team-controlled grant bounds on the real server, registry, PG and Redis."""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from awid.credential_policy import POLICY_FIELDS, policy_signing_bytes
from awid.signing import canonical_json_bytes, sign_message

from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_messages_http import _make_keypair, _signed_team_headers


async def _policy(env, maximum, revision):
    record = dict(v=1, type='aweb.team-credential-policy', team_id=TEAM, team_did_key=env.team_did,
                  revision=revision, issued_at=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
    record.update(dict.fromkeys(POLICY_FIELDS))
    record['identity_grant'] = maximum
    env.registry_app.state.awid_public_origins = ('http://registry.test',)
    await env.app.state.awid_registry_client.set_team_credential_policy(
        'example.test', TEAM.split(':')[0], record, sign_message(env.team_sk, policy_signing_bytes(record)), signing_key=env.team_sk,
    )


async def _mint(env, ttl='never', scopes=None):
    key, _, did = _make_keypair()
    body = json.dumps({'grant_did_key': did, 'scopes': scopes or ['mail.read'], 'ttl_seconds': ttl}).encode()
    actor = env.actors['alice']
    response = await env.client.post('/v1/identity-grants', content=body, headers={
        **_signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate, body), 'Content-Type': 'application/json',
    })
    assert response.status_code == 200, response.text
    return key, did, response.json()


def _grant_headers(env, key, did, grant, path):
    origin = str(env.client.base_url).rstrip('/')
    env.app.state.public_origin = origin
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = canonical_json_bytes(dict(v=1, auth='identity-grant', method='GET', path=path,
        grant_id=grant['grant_id'], body_sha256=hashlib.sha256(b'').hexdigest(), timestamp=timestamp, aud=origin))
    return {
        'Authorization': f'AWEB-Grant DIDKey {did} {sign_message(key, payload)}',
        'X-AWEB-Grant-ID': grant['grant_id'], 'X-AWEB-Timestamp': timestamp,
        'X-AWEB-Signed-Payload': base64.urlsafe_b64encode(payload).rstrip(b'=').decode(),
    }


async def _read(env, key, did, grant):
    path = '/v1/messages/inbox'
    return await env.client.get(path, headers=_grant_headers(env, key, did, grant, path))


@pytest.mark.asyncio
async def test_no_policy_keeps_never_and_finite_grants(privacy_app):
    env = privacy_app
    for ttl in ('never', 60):
        key, did, grant = await _mint(env, ttl)
        assert (grant['expires_at'] == 'never') == (ttl == 'never')
        assert (await _read(env, key, did, grant)).status_code == 200


@pytest.mark.asyncio
async def test_cap_clamps_mint_and_rechecks_existing_grants(privacy_app):
    env = privacy_app
    old_key, old_did, old = await _mint(env)
    assert (await _read(env, old_key, old_did, old)).status_code == 200
    await _policy(env, 60, 1)
    refused = await _read(env, old_key, old_did, old)
    assert refused.status_code == 401, refused.text
    assert refused.json()['detail']['code'] == 'grant_lifetime_exceeded'
    key, did, grant = await _mint(env)
    assert grant['expires_at'] != 'never'
    issued, expires = (datetime.fromisoformat(grant[field]) for field in ('issued_at', 'expires_at'))
    assert (expires - issued).total_seconds() == 60
    assert (await _read(env, key, did, grant)).status_code == 200
    await _policy(env, 59, 2)
    assert (await _read(env, key, did, grant)).status_code == 401
    await _policy(env, None, 3)
    assert (await _read(env, key, did, grant)).status_code == 200
    # Unsetting a maximum preserves the original finite stored deadline.
    stored = await env.db.fetch_value('SELECT expires_at FROM {{tables.identity_session_grants}} WHERE grant_id=$1', __import__('uuid').UUID(grant['grant_id']))
    assert stored == expires


@pytest.mark.asyncio
async def test_signed_parent_expiry_clamps_never_and_revocation_wins(privacy_app):
    env = privacy_app
    actor = env.actors['alice']
    cert = json.loads(base64.b64decode(actor.certificate))
    cert.pop('signature')
    cert.update(version=2, validity_class='member', expires_at='2090-01-01T00:00:00Z')
    cert['signature'] = sign_message(env.team_sk, canonical_json_bytes(cert))
    actor.certificate = base64.b64encode(json.dumps(cert).encode()).decode()
    key, did, grant = await _mint(env)
    assert datetime.fromisoformat(grant['expires_at']) == datetime(2090, 1, 1, tzinfo=timezone.utc)
    await env.db.execute('UPDATE {{tables.identity_session_grants}} SET revoked_at=NOW() WHERE grant_id=$1', __import__('uuid').UUID(grant['grant_id']))
    response = await _read(env, key, did, grant)
    assert response.status_code == 403 and 'revoked' in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize('ttl', ['never', 3600])
async def test_open_grant_stream_stops_when_team_lifetime_is_lowered(privacy_app, ttl):
    import asyncio
    from datetime import timedelta
    from urllib.parse import urlencode
    env = privacy_app
    key, did, grant = await _mint(env, ttl, ['events.read'])
    path = '/v1/events/stream?' + urlencode(dict(deadline=(datetime.now(timezone.utc) + timedelta(seconds=50)).isoformat()))
    async with env.client.stream('GET', path, headers=_grant_headers(env, key, did, grant, path), timeout=40) as response:
        assert response.status_code == 200, await response.aread()
        await _policy(env, 60, 1)
        async def terminal():
            async for line in response.aiter_lines():
                if line == 'event: grant_lifetime_exceeded':
                    return
            raise AssertionError('stream ended without policy refusal')
        await asyncio.wait_for(terminal(), 35)


@pytest.mark.asyncio
async def test_registered_private_v2_issuer_remains_revocable_without_service_token(privacy_app, monkeypatch):
    from test_credential_rollover_clients_http import _register, _rollover
    env = privacy_app
    monkeypatch.setenv('AWID_CERTIFICATE_V2_ISSUANCE_ENABLED', 'true')
    monkeypatch.setenv('AWEB_REQUIRE_REGISTERED_CERTIFICATES', 'true')
    await env.registry_db.execute("UPDATE {{tables.teams}} SET visibility='private'")
    from test_cli_never_grants import registry_listener
    async with registry_listener(env, service_token=False) as (registry, origin):
        env.registry_app.state.awid_public_origins = (origin,)
        actor = env.actors['alice']
        cert = json.loads(base64.b64decode(actor.certificate))
        cert.pop('signature')
        cert.update(version=2, validity_class='member')
        cert['signature'] = sign_message(env.team_sk, canonical_json_bytes(cert))
        actor.certificate = base64.b64encode(json.dumps(cert).encode()).decode()
        await _register(env, registry, cert)
        key, did, grant = await _mint(env)
        assert (await _read(env, key, did, grant)).status_code == 200
        await _rollover(env, registry, cert)
        refused = await _read(env, key, did, grant)
        assert refused.status_code == 403 and 'issuing certificate revoked' in refused.text, refused.text
