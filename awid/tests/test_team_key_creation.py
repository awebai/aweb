"""Public creation acts bind the key without publishing private team metadata."""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone

import pytest

from awid.registry import RegistryClient
from awid.signing import canonical_json_bytes, sign_message
from awid.team_key_acts import verify_team_key_act
from conftest import controller_request_headers, controller_keypair

PATH = '/v1/namespaces/local/teams'
HEADER = 'X-AWEB-Team-Key-Act'


def creation_header(env, content, **changes):
    body = json.loads(content)
    payload = canonical_json_bytes({
        'v': 1, 'type': 'aweb.team-key-act', 'operation': 'create_team',
        'domain': 'local', 'name': body['name'], 'team_did_key': body['team_did_key'],
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'body_sha256': hashlib.sha256(content).hexdigest(), **changes,
    })
    return json.dumps({
        'signed_payload': base64.urlsafe_b64encode(payload).rstrip(b'=').decode(),
        'signature': sign_message(env.controller[0], payload),
    }, separators=(',', ':'))


async def create(env, *, changes=None, covering=True, act=True):
    body = {'name': 'private', 'display_name': 'PRIVATE METADATA',
            'team_did_key': controller_keypair()[1], 'visibility': 'private'}
    content = canonical_json_bytes(body)
    headers = controller_request_headers(
        *env.controller, {'domain': 'local', 'operation': 'create_team', 'name': body['name']},
        'POST', PATH, content, covering=covering,
    )
    headers['Content-Type'] = 'application/json'
    if act:
        headers[HEADER] = creation_header(env, content, **(changes or {}))
    return body, await env.client.post(PATH, content=content, headers=headers)


@pytest.mark.asyncio
async def test_creation_keeps_a_public_key_act_without_private_metadata(controller_app):
    env = controller_app
    body, response = await create(env)
    assert response.status_code == 200, response.text
    response = await env.client.get(PATH + '/private/key-act')
    assert response.status_code == 200, response.text
    record = response.json()
    act = verify_team_key_act(record, domain='local', name='private', team_did_key=body['team_did_key'])
    assert act.signer_did_key == env.controller[1]
    raw = base64.urlsafe_b64decode(record['signed_payload'] + '==')
    assert b'PRIVATE METADATA' not in raw
    assert b'display_name' not in raw
    assert 'display_name' not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize('changes', [
    {'domain': 'other.example'}, {'name': 'other'}, {'team_did_key': controller_keypair()[1]},
    {'body_sha256': '0' * 64}, {'operation': 'rotate_team_key'},
])
async def test_disagreeing_creation_act_refuses_without_creating_team(controller_app, changes):
    env = controller_app
    _, response = await create(env, changes=changes)
    assert response.status_code == 401, response.text
    assert await env.db.fetch_value("SELECT count(*) FROM {{tables.teams}} WHERE name='private'") == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('covering', [True, False])
async def test_released_creation_without_public_act_remains_accepted(controller_app, covering):
    _, response = await create(controller_app, covering=covering, act=False)
    assert response.status_code == 200, response.text


@pytest.mark.asyncio
async def test_python_creation_client_supplies_the_public_act(controller_app):
    env = controller_app
    sdk = RegistryClient(registry_url=str(env.client.base_url), transport=env.client._transport)
    try:
        key = controller_keypair()[1]
        await sdk.register_team(domain='local', name='sdk', display_name='PRIVATE METADATA',
                                team_did_key=key, visibility='private',
                                namespace_controller_signing_key=env.controller[0])
        record = await sdk.get_team_key_act('local', 'sdk')
        assert record is not None
        assert verify_team_key_act(record, domain='local', name='sdk', team_did_key=key)
    finally:
        await sdk.aclose()


@pytest.mark.asyncio
async def test_same_key_backfill_precondition_cannot_restore_a_stale_inventory_key(controller_app):
    from conftest import send_controller_request
    env = controller_app
    old = env.team[1]
    new = controller_keypair()[1]
    path = '/v1/namespaces/local/teams/base/rotate'
    claims = {'domain': 'local', 'operation': 'rotate_team_key', 'name': 'base', 'new_team_did_key': new}
    assert (await send_controller_request(env, 'POST', path, claims, {'new_team_did_key': new})).status_code == 200
    response = await send_controller_request(env, 'POST', path, {**claims, 'new_team_did_key': old},
                                             {'new_team_did_key': old, 'expected_team_did_key': old})
    assert response.status_code == 409, response.text
    assert await env.db.fetch_value("SELECT team_did_key FROM {{tables.teams}} WHERE name='base'") == new
    assert await env.db.fetch_value('SELECT count(*) FROM {{tables.team_key_acts}}') == 1
