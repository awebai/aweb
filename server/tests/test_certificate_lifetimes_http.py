"""Certificate lifetime enforcement through real HTTP, AWID, PostgreSQL and Redis."""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from awid.signing import canonical_json_bytes, sign_message

from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_messages_http import _encode_certificate, _signed_team_headers


def _certificate(env, *, version=2, expiry="future", validity_class="member"):
    cert = json.loads(base64.b64decode(env.actors['alice'].certificate))
    cert.pop('signature')
    cert['version'] = version
    cert['issued_at'] = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    if version == 2:
        cert['validity_class'] = validity_class
    if expiry != 'none':
        cert['expires_at'] = {
            'future': (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
            'past': (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
            'malformed': 'not-a-timestamp',
            'naive': '2026-01-01T00:00:00',
            'null': None,
        }[expiry]
    cert['signature'] = sign_message(env.team_sk, canonical_json_bytes(cert))
    return cert


async def _get(env, cert):
    actor = env.actors['alice']
    return await env.client.get('/v1/identity-grants', headers=_signed_team_headers(
        actor.sk, actor.did, TEAM, _encode_certificate(cert),
    ))


@pytest.mark.asyncio
@pytest.mark.parametrize('version,expiry', [(1, 'none'), (2, 'none'), (2, 'future')])
async def test_no_expiry_default_and_unexpired_certificate_work(privacy_app, version, expiry):
    response = await _get(privacy_app, _certificate(privacy_app, version=version, expiry=expiry))
    assert response.status_code == 200, response.text


@pytest.mark.asyncio
@pytest.mark.parametrize('expiry,code', [
    ('past', 'certificate_expired'), ('malformed', 'certificate_malformed'),
    ('naive', 'certificate_malformed'), ('null', 'certificate_malformed'),
])
async def test_signed_invalid_deadline_refuses_before_projection_write(privacy_app, expiry, code):
    env = privacy_app
    before = await env.db.fetch_value('SELECT certificate_id FROM {{tables.agents}} WHERE agent_id=$1', env.actors['alice'].id)
    response = await _get(env, _certificate(env, expiry=expiry))
    assert response.status_code == 401, response.text
    assert response.json()['detail']['code'] == code
    assert await env.db.fetch_value('SELECT certificate_id FROM {{tables.agents}} WHERE agent_id=$1', env.actors['alice'].id) == before


@pytest.mark.asyncio
async def test_expiry_is_signed_and_revocation_still_wins(privacy_app):
    env = privacy_app
    cert = _certificate(env, expiry='past')
    cert['expires_at'] = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    response = await _get(env, cert)
    assert response.status_code == 401 and 'signature' in response.text.lower(), response.text

    cert = _certificate(env, expiry='past')
    await env.registry_db.execute(
        'INSERT INTO {{tables.team_certificates}} (team_uuid,certificate_id,member_did_key,alias,revoked_at) '
        'SELECT team_uuid,$2,$3,$4,NOW() FROM {{tables.teams}} WHERE name=$1',
        TEAM.split(':')[0], cert['certificate_id'], cert['member_did_key'], cert['alias'],
    )
    await env.app.state.awid_registry_client.invalidate_team_certificate_cache('example.test', TEAM.split(':')[0])
    response = await _get(env, cert)
    assert response.status_code == 401 and 'revoked' in response.text.lower(), response.text


@pytest.mark.asyncio
async def test_controller_chosen_validity_class_is_required_for_v2(privacy_app):
    response = await _get(privacy_app, _certificate(privacy_app, validity_class='global'))
    assert response.status_code == 401, response.text
    assert response.json()['detail']['code'] == 'certificate_malformed'
