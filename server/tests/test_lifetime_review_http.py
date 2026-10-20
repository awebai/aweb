"""Review boundaries on the real server, registry, PostgreSQL and Redis."""
from __future__ import annotations
import asyncio
import base64
import json
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from awid.signing import canonical_json_bytes, sign_message
from test_dashboard_privacy import TEAM, privacy_app, _request  # noqa: F401
from test_messages_http import _make_keypair, _signed_team_headers
from test_team_credential_policy_http import _mint, _read, _policy, _grant_headers
from test_credential_rollover_clients_http import _register, _rollover


async def parent(env, *, expires_at=None):
    actor = env.actors['alice']
    cert = json.loads(base64.b64decode(actor.certificate))
    cert.pop('signature')
    cert.update(version=2, validity_class='member', issued_at=(datetime.now(timezone.utc)-timedelta(minutes=1)).isoformat())
    if expires_at: cert['expires_at']=expires_at
    cert['signature']=sign_message(env.team_sk, canonical_json_bytes(cert))
    actor.certificate=base64.b64encode(json.dumps(cert).encode()).decode()
    registry=env.app.state.awid_registry_client
    env.registry_app.state.awid_public_origins=('http://registry.test',)
    await _register(env, registry, cert)
    return cert


@pytest.mark.asyncio
@pytest.mark.parametrize('renew', [False, True])
async def test_renewal_keeps_grants_but_disciplinary_revoke_ends_them(privacy_app, monkeypatch, renew):
    env=privacy_app
    monkeypatch.setenv('AWID_CERTIFICATE_V2_ISSUANCE_ENABLED','true')
    cert=await parent(env)
    key,did,grant=await _mint(env)
    registry=env.app.state.awid_registry_client
    assert (await _read(env,key,did,grant)).status_code==200
    fresh=await _rollover(env,registry,cert) if renew else cert
    assert (await _read(env,key,did,grant)).status_code==200
    await registry.revoke_team_certificate('example.test', TEAM.split(':')[0],
        team_controller_signing_key=env.team_sk, certificate_id=fresh['certificate_id'])
    refused=await _read(env,key,did,grant)
    assert refused.status_code==403 and 'issuing certificate revoked' in refused.text
    actor=env.actors['alice']
    old=await env.client.get('/v1/identity-grants',headers=_signed_team_headers(actor.sk,actor.did,TEAM,actor.certificate))
    assert old.status_code==401 and old.json()['detail']['code']=='certificate_revoked'


@pytest.mark.asyncio
async def test_policy_removal_and_rollover_preserve_the_original_grant_deadline(privacy_app, monkeypatch):
    env=privacy_app
    monkeypatch.setenv('AWID_CERTIFICATE_V2_ISSUANCE_ENABLED','true')
    cert=await parent(env)
    await _policy(env,3600,1)
    key,did,grant=await _mint(env)
    await _rollover(env,env.app.state.awid_registry_client,cert)
    await _policy(env,None,2)
    assert (await _read(env,key,did,grant)).status_code==200
    stored=await env.db.fetch_value('SELECT expires_at FROM {{tables.identity_session_grants}} WHERE grant_id=$1', __import__('uuid').UUID(grant['grant_id']))
    assert stored==datetime.fromisoformat(grant['expires_at'])


@pytest.mark.asyncio
async def test_old_certificate_clamp_ends_grant_after_renewal(privacy_app, monkeypatch):
    env=privacy_app
    monkeypatch.setenv('AWID_CERTIFICATE_V2_ISSUANCE_ENABLED','true')
    expiry=datetime.now(timezone.utc)+timedelta(seconds=3)
    cert=await parent(env,expires_at=expiry.isoformat())
    key,did,grant=await _mint(env)
    await _rollover(env,env.app.state.awid_registry_client,cert,
        expires_at=(expiry+timedelta(hours=1)).isoformat())
    assert (await _read(env,key,did,grant)).status_code==200
    await asyncio.sleep(max(0,(expiry-datetime.now(timezone.utc)).total_seconds())+.02)
    refused=await _read(env,key,did,grant)
    assert refused.status_code==401 and refused.json()['detail']['code']=='grant_expired'


@pytest.mark.asyncio
async def test_unbounded_grant_ends_when_finite_replacement_expires(privacy_app, monkeypatch):
    env = privacy_app
    monkeypatch.setenv('AWID_CERTIFICATE_V2_ISSUANCE_ENABLED', 'true')
    cert = await parent(env)
    key, did, grant = await _mint(env)
    assert grant['expires_at'] == 'never'
    expiry = datetime.now(timezone.utc) + timedelta(seconds=3)
    await _rollover(env, env.app.state.awid_registry_client, cert, expires_at=expiry.isoformat())
    # Cache the replacement while it is valid. Its signed deadline must still
    # be checked locally on every verification, including on a cache hit.
    assert (await _read(env, key, did, grant)).status_code == 200
    await asyncio.sleep(max(0, (expiry-datetime.now(timezone.utc)).total_seconds()) + .02)
    refused = await _read(env, key, did, grant)
    assert refused.status_code == 401, refused.text
    assert refused.json()['detail']['code'] == 'grant_expired'


@pytest.mark.asyncio
async def test_replacement_chain_refuses_changed_member_and_cycles(privacy_app, monkeypatch):
    env=privacy_app
    monkeypatch.setenv('AWID_CERTIFICATE_V2_ISSUANCE_ENABLED','true')
    cert=await parent(env)
    key,did,grant=await _mint(env)
    registry=env.app.state.awid_registry_client
    fresh=await _rollover(env,registry,cert)
    bob=json.loads(base64.b64decode(env.actors['bob'].certificate))
    await _register(env,registry,bob)
    await env.registry_db.execute('UPDATE {{tables.team_certificates}} SET replaced_by_certificate_id=$2 WHERE certificate_id=$1',cert['certificate_id'],bob['certificate_id'])
    await registry.invalidate_team_certificate_cache('example.test',TEAM.split(':')[0])
    assert (await _read(env,key,did,grant)).status_code==403
    await env.registry_db.execute('UPDATE {{tables.team_certificates}} SET replaced_by_certificate_id=$2 WHERE certificate_id=$1',cert['certificate_id'],fresh['certificate_id'])
    await env.registry_db.execute('UPDATE {{tables.team_certificates}} SET revoked_at=NOW(),replaced_by_certificate_id=$2 WHERE certificate_id=$1',fresh['certificate_id'],cert['certificate_id'])
    await registry.invalidate_team_certificate_cache('example.test',TEAM.split(':')[0])
    assert (await _read(env,key,did,grant)).status_code==403


@pytest.mark.asyncio
async def test_certificate_streams_close_at_signed_expiry(privacy_app, monkeypatch):
    from contextlib import AsyncExitStack
    from urllib.parse import urlencode
    env=privacy_app
    monkeypatch.setenv('AWID_CERTIFICATE_V2_ISSUANCE_ENABLED','true')
    chat=await _request(env,'alice','POST','/v1/chat/sessions',dict(to_dids=[env.actors['bob'].did],message='expiry boundary'))
    assert chat.status_code==200,chat.text
    expiry=datetime.now(timezone.utc)+timedelta(seconds=3)
    cert=await parent(env,expires_at=expiry.isoformat())
    actor=env.actors['alice']
    query=urlencode(dict(deadline=(expiry+timedelta(minutes=2)).isoformat()))
    paths=['/v1/events/stream?'+query,f"/v1/chat/sessions/{chat.json()['session_id']}/stream?{query}"]
    async with AsyncExitStack() as stack:
        responses=[]
        for path in paths:
            response=await stack.enter_async_context(env.client.stream('GET',path,headers=_signed_team_headers(actor.sk,actor.did,TEAM,actor.certificate),timeout=8))
            assert response.status_code==200,await response.aread()
            responses.append(response)
        await asyncio.wait_for(asyncio.gather(*(response.aread() for response in responses)),5)
    assert datetime.now(timezone.utc)<expiry+timedelta(seconds=2)


@pytest.mark.asyncio
async def test_one_anonymous_verifier_admits_more_than_sixty_distinct_members(privacy_app, monkeypatch):
    from awid.ratelimit import MemoryFixedWindowRateLimiter
    from awid.registry import RegistryClient
    env=privacy_app
    monkeypatch.setenv('AWEB_REQUIRE_REGISTERED_CERTIFICATES','true')
    await env.registry_db.execute("UPDATE {{tables.teams}} SET visibility='private'")
    env.registry_app.state.rate_limiter=MemoryFixedWindowRateLimiter()
    original=env.app.state.awid_registry_client
    registry=RegistryClient(original.registry_url,transport=original.transport)
    env.app.state.awid_registry_client=registry
    calls=[]
    @env.registry_app.middleware('http')
    async def observe_status(request,call_next):
        if request.url.path.endswith('/status'): calls.append(request.url.path)
        return await call_next(request)
    started=time.monotonic()
    try:
        for index in range(72):
            key,_,did=_make_keypair()
            alias='member'+str(index)
            cert=dict(version=2,certificate_id=str(uuid4()),team_id=TEAM,team_did_key=env.team_did,
                member_did_key=did,alias=alias,identity_scope='local',validity_class='member',issued_at=datetime.now(timezone.utc).isoformat())
            cert['signature']=sign_message(env.team_sk,canonical_json_bytes(cert))
            blob=base64.b64encode(json.dumps(cert).encode()).decode()
            await env.registry_db.execute('INSERT INTO {{tables.team_certificates}} (team_uuid,certificate_id,member_did_key,alias,identity_scope,certificate) SELECT team_uuid,$1,$2,$3,\'local\',$4 FROM {{tables.teams}}',cert['certificate_id'],did,alias,blob)
            await env.db.execute('INSERT INTO {{tables.agents}} (agent_id,team_id,did_key,alias,identity_scope) VALUES ($1,$2,$3,$4,\'local\')',uuid4(),TEAM,did,alias)
            response=await env.client.get('/v1/identity-grants',headers=_signed_team_headers(key,did,TEAM,blob))
            assert response.status_code==200,response.text
        assert len(calls)==72 and time.monotonic()-started<60
        # An attacker controls its envelope signer, never the team's signature.
        for _ in range(4):
            rogue,_,did=_make_keypair()
            forged=dict(cert,certificate_id=str(uuid4()),member_did_key=did)
            forged['signature']=sign_message(rogue,canonical_json_bytes({k:v for k,v in forged.items() if k!='signature'}))
            response=await env.client.get('/v1/identity-grants',headers=_signed_team_headers(rogue,did,TEAM,base64.b64encode(json.dumps(forged).encode()).decode()))
            assert response.status_code==401,response.text
        assert len(calls)==72  # Signature refusal precedes every per-ID request.
    finally:
        env.app.state.awid_registry_client=original
        await registry.aclose()


@pytest.mark.asyncio
async def test_replacement_chain_accepts_eight_links_but_refuses_a_ninth(privacy_app, monkeypatch):
    env=privacy_app
    monkeypatch.setenv('AWID_CERTIFICATE_V2_ISSUANCE_ENABLED','true')
    certificate=await parent(env)
    key,did,grant=await _mint(env)
    registry=env.app.state.awid_registry_client
    for _ in range(8):
        certificate=await _rollover(env,registry,certificate)
    assert (await _read(env,key,did,grant)).status_code==200
    await _rollover(env,registry,certificate)
    refused=await _read(env,key,did,grant)
    assert refused.status_code==403 and 'issuing certificate revoked' in refused.text


@pytest.mark.asyncio
async def test_never_grant_streams_close_at_replacement_certificate_expiry(privacy_app, monkeypatch):
    from contextlib import AsyncExitStack
    from urllib.parse import urlencode
    env=privacy_app
    monkeypatch.setenv('AWID_CERTIFICATE_V2_ISSUANCE_ENABLED','true')
    chat=await _request(env,'alice','POST','/v1/chat/sessions',dict(to_dids=[env.actors['bob'].did],message='chain expiry'))
    assert chat.status_code==200,chat.text
    cert=await parent(env)
    key,did,grant=await _mint(env,scopes=['mail.read','events.read','chat.read'])
    assert grant['expires_at']=='never'
    expiry=datetime.now(timezone.utc)+timedelta(seconds=3)
    await _rollover(env,env.app.state.awid_registry_client,cert,expires_at=expiry.isoformat())
    query=urlencode(dict(deadline=(expiry+timedelta(minutes=2)).isoformat()))
    paths=['/v1/events/stream?'+query,f"/v1/chat/sessions/{chat.json()['session_id']}/stream?{query}"]
    async with AsyncExitStack() as stack:
        responses=[]
        for path in paths:
            response=await stack.enter_async_context(env.client.stream('GET',path,headers=_grant_headers(env,key,did,grant,path),timeout=8))
            assert response.status_code==200,await response.aread()
            responses.append(response)
        bodies=await asyncio.wait_for(asyncio.gather(*(response.aread() for response in responses)),5)
    assert datetime.now(timezone.utc)<expiry+timedelta(seconds=2)
    for body in bodies:
        assert b'grant_expired' in body
