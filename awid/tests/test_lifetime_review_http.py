"""Registry membership expiry and status capacity on real routes/resources."""
from __future__ import annotations
import asyncio
import base64
import json
from datetime import datetime,timedelta,timezone
from uuid import uuid4
import httpx
import pytest
from awid.registry import RegistryClient,RegistryError
from awid.signing import canonical_json_bytes,sign_message
from test_controller_request_v2_http import ORIGIN,certificate_body,controller_app,keypair  # noqa: F401
from test_credential_lifetimes_http import register
from test_attestation_record_routes import _person,publish_person


def read_headers(key,did,path):
    timestamp=datetime.now(timezone.utc).isoformat()
    return {'Authorization':f'DIDKey {did} {sign_message(key,(timestamp+chr(10)+"GET"+chr(10)+path).encode())}',
        'X-AWEB-Timestamp':timestamp}


@pytest.mark.asyncio
async def test_expired_members_lose_private_reads_team_listing_and_attestation_authority(controller_app,monkeypatch):
    env=controller_app
    monkeypatch.setenv('AWID_CERTIFICATE_V2_ISSUANCE_ENABLED','true')
    member=keypair()
    body=certificate_body(env,member=member)
    cert=json.loads(base64.b64decode(body['certificate']));cert.pop('signature')
    expiry=datetime.now(timezone.utc)+timedelta(seconds=4)
    cert.update(version=2,validity_class='member',issued_at=(expiry-timedelta(minutes=1)).isoformat(),expires_at=expiry.isoformat())
    cert['signature']=sign_message(env.team[0],canonical_json_bytes(cert))
    body['certificate']=base64.b64encode(json.dumps(cert).encode()).decode()
    response=await register(env,body)
    assert response.status_code==200,response.text
    assert await env.db.fetch_value('SELECT expires_at FROM {{tables.team_certificates}} WHERE certificate_id=$1',body['certificate_id'])==expiry
    await env.db.execute("UPDATE {{tables.teams}} SET visibility='private'")
    base='/v1/namespaces/local/teams/base'
    listing='/v1/namespaces/local/teams'
    assert (await env.client.get(base,headers=read_headers(*member,base))).status_code==200
    assert (await env.client.get(listing,headers=read_headers(*member,listing))).json()['teams']
    record=_person(env,body)
    assert (await publish_person(env,record)).status_code==200
    await asyncio.sleep(max(0,(expiry-datetime.now(timezone.utc)).total_seconds())+.02)
    refused=await env.client.get(base,headers=read_headers(*member,base))
    assert refused.status_code==403,refused.text
    response=await env.client.get(listing,headers=read_headers(*member,listing))
    assert response.status_code==200 and response.json()['teams']==[]
    assert (await publish_person(env,record)).status_code==404
    member_path=base+'/members/'+cert['alias']
    assert (await env.client.get(member_path,headers=read_headers(*member,member_path))).status_code==403


@pytest.mark.asyncio
async def test_negative_status_cache_is_bounded_and_reuses_404(controller_app):
    env=controller_app
    paths=[]
    class RecordingTransport(httpx.ASGITransport):
        async def handle_async_request(self,request):
            if request.url.path.endswith('/status'):paths.append(request.url.path)
            return await super().handle_async_request(request)
    client=RegistryClient(ORIGIN,transport=RecordingTransport(app=env.app))
    try:
        unknown=str(uuid4())
        for _ in range(3):
            with pytest.raises(RegistryError) as error:
                await client.get_team_certificate_status('local','base',unknown)
            assert error.value.status_code==404
        assert len(paths)==1
        client._certificate_status_cache.clear()
        client._certificate_status_cache.update((('old','local','base',str(index)),(0,None)) for index in range(4096))
        with pytest.raises(RegistryError):
            await client.get_team_certificate_status('local','base',str(uuid4()))
        assert len(client._certificate_status_cache)==4096
        assert ('old','local','base','0') not in client._certificate_status_cache
        assert not client._certificate_status_locks
    finally:await client.aclose()
