"""Actual aw user signatures cannot authorize protocol operations."""
import hashlib
import json

import httpx
import pytest

from awid.did import stable_id_from_did_key
from awid.log import identity_state_hash, log_entry_payload
from awid.signing import canonical_json_bytes, sign_message, verify_signature, VerifyResult
from test_cli_human_reply import _cli
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_e2ee_local_sender_read_trust import _local_sender_mail
from test_messages_http import _encode_certificate, _make_keypair, _signed_identity_headers, _signed_team_headers


@pytest.mark.usefixtures('source_cli_binary')
@pytest.mark.asyncio
@pytest.mark.parametrize('family', ['rotate_key', 'team_v1', 'identity_v1', 'controller_v1'])
async def test_user_signature_cannot_authorize_protocol(privacy_app, tmp_path, family):
    env = privacy_app
    async with _local_sender_mail(env, tmp_path, False, False, False) as (
            _, _, binary, cwd, command_env, registry):
        actor = env.actors['bob']
        if family == 'rotate_key':
            await env.app.state.awid_registry_client.register_did(actor.did, actor.sk)
            stable = stable_id_from_did_key(actor.did)
            head = await env.registry_db.fetch_one(
                'SELECT seq,entry_hash FROM {{tables.did_aw_log}} WHERE did_aw=$1 ORDER BY seq DESC LIMIT 1', stable)
            _, _, new_did = _make_keypair()
            claims = json.loads(log_entry_payload(
                did_aw=stable, seq=head['seq'] + 1, operation='rotate_key', previous_did_key=actor.did,
                new_did_key=new_did, prev_entry_hash=head['entry_hash'],
                state_hash=identity_state_hash(did_aw=stable, current_did_key=new_did),
                authorized_by=actor.did, timestamp=''))
            claims.pop('timestamp')
        elif family == 'controller_v1':
            claims = dict(domain='local', operation='register')
        else:
            claims = dict(body_sha256=hashlib.sha256(b'').hexdigest(),
                          **({'team_id': TEAM} if family == 'team_v1' else {'did_aw': ''}))
        signed = await _cli(binary, cwd, command_env, 'id', 'sign', '--payload', json.dumps(claims), '--json')
        timestamp, signature = signed['timestamp'], signed['signature']
        canonical = canonical_json_bytes({**claims, 'timestamp': timestamp})
        headers = {'Authorization': f'DIDKey {actor.did} {signature}', 'X-AWEB-Timestamp': timestamp}
        if family == 'team_v1':
            cert_path = next((tmp_path / '.aw' / 'team-certs').glob('*.pem'))
            headers['X-AWID-Team-Certificate'] = _encode_certificate(json.loads(cert_path.read_text()))
        if family == 'rotate_key':
            body = {k: v for k, v in claims.items() if k not in {'did_aw', 'previous_did_key'}}
            body.update(timestamp=timestamp, signature=signature)
            async with httpx.AsyncClient(base_url=registry.url) as client:
                response = await client.put(f'/v1/did/{stable}', json=body)
                assert response.status_code == 401, response.text
                current = await env.registry_db.fetch_value(
                    'SELECT current_did_key FROM {{tables.did_aw_mappings}} WHERE did_aw=$1', stable)
                assert current == actor.did
                body['signature'] = sign_message(actor.sk, canonical)
                control = await client.put(f'/v1/did/{stable}', json=body)
                assert control.status_code == 200, control.text
        elif family == 'controller_v1':
            async with httpx.AsyncClient(base_url=registry.url) as client:
                response = await client.post('/v1/namespaces', json={'domain': 'local'}, headers=headers)
                assert response.status_code == 401, response.text
                headers['Authorization'] = f'DIDKey {actor.did} {sign_message(actor.sk, canonical)}'
                control = await client.post('/v1/namespaces', json={'domain': 'local'}, headers=headers)
                assert control.status_code == 200, control.text
        else:
            response = await env.client.get('/v1/messages/inbox', headers=headers)
            assert response.status_code == 401, response.text
            if family == 'team_v1':
                control_headers = _signed_team_headers(actor.sk, actor.did, TEAM, headers['X-AWID-Team-Certificate'])
            else:
                control_headers = _signed_identity_headers(actor.sk, actor.did, '')
            control = await env.client.get('/v1/messages/inbox', headers=control_headers)
            assert control.status_code == 200, control.text
        assert verify_signature(actor.did, b'aweb.user-signature/1\n' + canonical, signature) == VerifyResult.VERIFIED
        assert verify_signature(actor.did, canonical, signature) == VerifyResult.FAILED


