"""Policy and rollover contracts through real AWID, PostgreSQL and Redis."""
from __future__ import annotations

import asyncio
import base64
import json
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import httpx

from awid.credential_policy import POLICY_FIELDS, policy_signing_bytes
from awid.registry import RegistryClient
from awid.signing import canonical_json_bytes, sign_message
from test_controller_request_v2_http import (
    ORIGIN, certificate_body, controller_app, headers, keypair, send,  # noqa: F401
)


def policy_body(env, *, revision=1, **limits):
    record = dict(v=1, type='aweb.team-credential-policy', team_id='base:local',
                  team_did_key=env.team[1], revision=revision,
                  issued_at=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
    record.update(dict.fromkeys(POLICY_FIELDS))
    record.update(limits)
    return {'record': record, 'signature': sign_message(env.team[0], policy_signing_bytes(record))}


async def set_policy(env, body, **kwargs):
    return await send(env, 'POST', '/v1/namespaces/local/teams/base/credential-lifetimes',
                      {'domain': 'local', 'operation': 'set_credential_lifetimes', 'team_name': 'base'},
                      body, signer=kwargs.pop('signer', env.team), **kwargs)


async def register(env, body):
    return await send(env, 'POST', '/v1/namespaces/local/teams/base/certificates',
                      {'domain': 'local', 'operation': 'register_certificate', 'team_name': 'base', 'certificate_id': body['certificate_id']}, body, signer=env.team)


async def rollover(env, old, new, **kwargs):
    return await send(env, 'POST', f'/v1/namespaces/local/teams/base/certificates/{old}/rollover',
                      {'domain': 'local', 'operation': 'rollover_certificate', 'team_name': 'base', 'certificate_id': old,
                       'replacement_certificate_id': new['certificate_id']}, {'replacement': new}, signer=kwargs.pop('signer', env.team), **kwargs)


@pytest.mark.asyncio
async def test_default_absence_and_signed_private_team_policy(controller_app):
    env = controller_app
    assert await env.db.fetch_value('SELECT inet_server_port()') == int(os.environ.get('TEST_DB_PORT', '5432'))
    await env.db.execute("UPDATE {{tables.teams}} SET visibility='private' WHERE name='base'")
    path = '/v1/namespaces/local/teams/base/credential-lifetimes'
    absent = await env.client.get(path)
    assert absent.status_code == 200 and absent.json()['record'] is None
    body = policy_body(env, identity_grant=3600)
    assert (await set_policy(env, body)).status_code == 200
    public = await env.client.get(path)
    assert public.status_code == 200 and public.json()['record'] == body['record']
    client = RegistryClient(ORIGIN, transport=httpx.ASGITransport(app=env.app))
    try:
        verified = await client.get_team_credential_policy('local', 'base')
        assert verified == body['record']
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_policy_controller_authority_covering_binding_and_audit(controller_app):
    env = controller_app
    body = policy_body(env, identity_grant=3600)
    assert (await set_policy(env, body, covering=False)).status_code == 401
    assert (await set_policy(env, body, signer=keypair())).status_code == 403
    assert await env.db.fetch_value('SELECT count(*) FROM {{tables.team_credential_policy_audit}}') == 0
    response = await set_policy(env, body)
    assert response.status_code == 200, response.text
    assert (await set_policy(env, body)).status_code == 200  # Read-only idempotence.
    assert await env.db.fetch_value('SELECT count(*) FROM {{tables.team_credential_policy_audit}}') == 1
    next_body = policy_body(env, revision=2, identity_grant=60)
    assert (await set_policy(env, next_body)).status_code == 200
    audit = await env.db.fetch_one('SELECT old_record_json,new_record_json FROM {{tables.team_credential_policy_audit}} ORDER BY created_at DESC LIMIT 1')
    assert json.loads(audit['old_record_json']) == body['record']
    assert json.loads(audit['new_record_json']) == next_body['record']
    # A signed covering request cannot substitute any written maximum.
    path = '/v1/namespaces/local/teams/base/credential-lifetimes'
    content = canonical_json_bytes(policy_body(env, revision=3))
    signed = headers(*env.team, {'operation': 'set_credential_lifetimes', 'domain': 'local', 'team_name': 'base'}, 'POST', path, content)
    changed = json.loads(content)
    changed['record']['identity_grant'] = 1
    refused = await env.client.post(path, content=canonical_json_bytes(changed), headers={**signed, 'Content-Type': 'application/json'})
    assert refused.status_code == 401, refused.text


@pytest.mark.asyncio
async def test_rollover_atomicity_tombstones_and_idempotence(controller_app):
    env = controller_app
    original = certificate_body(env)
    assert (await register(env, original)).status_code == 200
    replacement = certificate_body(env, member=(None, original['member_did_key']))
    # Preserve membership and use a freshly signed new certificate ID.
    bad = dict(replacement, certificate='not-json')
    refused = await rollover(env, original['certificate_id'], bad)
    assert refused.status_code == 422
    assert await env.db.fetch_value('SELECT revoked_at FROM {{tables.team_certificates}} WHERE certificate_id=$1', original['certificate_id']) is None
    accepted = await rollover(env, original['certificate_id'], replacement)
    assert accepted.status_code == 200, accepted.text
    assert (await rollover(env, original['certificate_id'], replacement)).status_code == 200
    assert await env.db.fetch_value('SELECT count(*) FROM {{tables.team_certificates}}') == 2
    old = await env.db.fetch_one('SELECT revoked_at,replaced_by_certificate_id FROM {{tables.team_certificates}} WHERE certificate_id=$1', original['certificate_id'])
    assert old['revoked_at'] and old['replaced_by_certificate_id'] == replacement['certificate_id']
    delayed = await register(env, original)
    assert delayed.status_code == 409
    status = await env.client.get(f"/v1/namespaces/local/teams/base/certificates/{original['certificate_id']}/status?include_replacement=true")
    assert status.json()['replaced_by_certificate_id'] == replacement['certificate_id']


@pytest.mark.asyncio
async def test_parallel_rollovers_only_one_new_id_wins(controller_app):
    env = controller_app
    old = certificate_body(env)
    assert (await register(env, old)).status_code == 200
    replacements = [certificate_body(env, member=(None, old['member_did_key'])) for _ in range(2)]
    responses = await asyncio.gather(*(rollover(env, old['certificate_id'], new) for new in replacements))
    assert sorted(r.status_code for r in responses) == [200, 409], [r.text for r in responses]
    assert await env.db.fetch_value('SELECT count(*) FROM {{tables.team_certificates}} WHERE revoked_at IS NULL') == 1
    assert await env.db.fetch_value('SELECT count(*) FROM {{tables.team_certificates}}') == 2


@pytest.mark.asyncio
async def test_certificate_policy_adoption_gate_and_exact_maximum(controller_app, monkeypatch):
    env = controller_app
    body = policy_body(env, member_certificate=3600)
    assert (await set_policy(env, body)).status_code == 409
    monkeypatch.setenv('AWID_CERTIFICATE_V2_ISSUANCE_ENABLED', 'true')
    assert (await set_policy(env, body)).status_code == 200
    assert (await register(env, certificate_body(env))).status_code == 422
    for seconds, expected in [(3601, 422), (3600, 200)]:
        request = certificate_body(env)
        cert = json.loads(base64.b64decode(request['certificate']))
        cert.pop('signature')
        issued = datetime.now(timezone.utc).replace(microsecond=0)
        cert.update(version=2, validity_class='member', issued_at=issued.isoformat(),
                    expires_at=(issued + timedelta(seconds=seconds)).isoformat())
        cert['signature'] = sign_message(env.team[0], canonical_json_bytes(cert))
        request['certificate'] = base64.b64encode(json.dumps(cert).encode()).decode()
        response = await register(env, request)
        assert response.status_code == expected, response.text


@pytest.mark.asyncio
async def test_rollover_refuses_foreign_controller_and_changed_membership(controller_app):
    env = controller_app
    old = certificate_body(env)
    assert (await register(env, old)).status_code == 200
    new = certificate_body(env, member=(None, old['member_did_key']))
    assert (await rollover(env, old['certificate_id'], new, signer=keypair())).status_code == 403
    assert (await rollover(env, old['certificate_id'], new, covering=False)).status_code == 401
    different = certificate_body(env)
    assert (await rollover(env, old['certificate_id'], different)).status_code == 409
    assert await env.db.fetch_value('SELECT count(*) FROM {{tables.team_certificates}} WHERE revoked_at IS NULL') == 1


@pytest.mark.asyncio
async def test_policy_is_part_of_atomic_team_key_rotation(controller_app):
    env = controller_app
    record = policy_body(env, identity_grant=3600)
    assert (await set_policy(env, record)).status_code == 200
    next_key = keypair()
    path = '/v1/namespaces/local/teams/base/rotate'
    claims = dict(operation='rotate_team_key', domain='local', name='base', new_team_did_key=next_key[1])
    # Omitting any stored signed record refuses the whole rotation.
    refused = await send(env, 'POST', path, claims, dict(new_team_did_key=next_key[1], resigned_records={}))
    assert refused.status_code == 409, refused.text
    assert refused.json()['detail']['missing']['team_credential_policy'] is True
    assert await env.db.fetch_value("SELECT team_did_key FROM {{tables.teams}} WHERE name='base'") == env.team[1]
    fresh = dict(record['record'], team_did_key=next_key[1],
        issued_at=(datetime.now(timezone.utc) + timedelta(seconds=1)).strftime('%Y-%m-%dT%H:%M:%SZ'))
    signature = sign_message(next_key[0], policy_signing_bytes(fresh))
    changed = dict(fresh, identity_grant=1)
    refused = await send(env, 'POST', path, claims, dict(new_team_did_key=next_key[1], resigned_records={
        'team_credential_policy': dict(record=changed, signature=sign_message(next_key[0], policy_signing_bytes(changed))),
    }))
    assert refused.status_code == 409, refused.text
    accepted = await send(env, 'POST', path, claims, dict(new_team_did_key=next_key[1], resigned_records={
        'team_credential_policy': dict(record=fresh, signature=signature),
    }))
    assert accepted.status_code == 200, accepted.text
    client = RegistryClient(ORIGIN, transport=httpx.ASGITransport(app=env.app))
    try:
        assert await client.get_team_credential_policy('local', 'base') == fresh
    finally:
        await client.aclose()
    assert await env.db.fetch_value('SELECT count(*) FROM {{tables.team_credential_policy_audit}}') == 1


@pytest.mark.asyncio
async def test_policy_cache_refuses_stale_wrong_key_or_unavailable_record(controller_app):
    env = controller_app
    body = policy_body(env, identity_grant=3600)
    assert (await set_policy(env, body)).status_code == 200
    client = RegistryClient(ORIGIN, transport=httpx.ASGITransport(app=env.app))
    try:
        assert await client.get_team_credential_policy('local', 'base') == body['record']
        # A genuine authority failure cannot become an absent-policy fallback.
        await env.db.execute('UPDATE {{tables.team_credential_policies}} SET signature=$1', 'bad-signature')
        assert await client.get_team_credential_policy('local', 'base') == body['record']
        client._credential_policy_cache.clear()  # End this client's bounded reuse.
        with pytest.raises(Exception, match='signature'):
            await client.get_team_credential_policy('local', 'base')
        assert not client._credential_policy_cache
        await env.db.execute('UPDATE {{tables.team_credential_policies}} SET signature=$1', body['signature'])
        await env.db.execute('UPDATE {{tables.teams}} SET team_did_key=$1', keypair()[1])
        with pytest.raises(Exception):
            await client.get_team_credential_policy('local', 'base')
        assert not client._credential_policy_cache
    finally:
        await client.aclose()
