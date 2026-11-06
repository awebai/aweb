"""X-E2 experiments; no negotiated profile is enabled by these test-only helpers."""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('hc_e2ee_spike', ROOT / 'scripts/spikes/human_channels_e2ee.py')
spike = importlib.util.module_from_spec(spec)
spec.loader.exec_module(spike)


def test_experimental_group_and_separate_reshare():
    run = spike.experiment()
    assert run['checks'] == ['chain_verified', 'old_key_denied', 'bridge_readable', 'original_preserved', 'authorized_reshare', 'removed_key_denied', 'legacy_refuses_new_profile']


def test_missing_chain_and_wrong_grant_refuse():
    run = spike.experiment()
    fixture = run['fixture']
    with pytest.raises(ValueError):
        spike.verify_chain(fixture['chain'][1:], fixture['owner'], fixture['session_id'])
    for field in ('recipient', 'holder', 'source_hash', 'policy_head'):
        altered = copy.deepcopy(fixture['grant'])
        value = json.loads(altered['signed_payload'])
        value[field] += '-wrong'
        altered = spike.sign(value, fixture['identities']['alice'])
        with pytest.raises(ValueError):
            spike.open_reshare(fixture['original'], fixture['capsule'], altered, fixture['chain'][:2], fixture['identities']['carol'], fixture['owner'], fixture['session_id'])

# Real local OSS/AWID/PG/Redis transport. The new membership/profile operations
# are expected refusals until P4/P5; a native carrier is not room admission.
from datetime import datetime, timezone
import os
import asyncio
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401


@pytest.mark.asyncio
async def test_real_http_native_source_and_authorized_capsule(privacy_app, tmp_path):
    env = privacy_app
    now = datetime.now(timezone.utc)
    ids = {}
    for index, name in enumerate(('alice', 'bob', 'carol'), 1):
        actor = env.actors[name]
        ids[name] = spike.identity(name, index, now, signing_seed=actor.sk, team_id=TEAM)
        # Disposable identity provisioning, never session membership fabrication.
        await env.app.state.awid_registry_client.register_did(actor.did, actor.sk)
        await env.db.execute("UPDATE {{tables.agents}} SET identity_scope='global', did_aw=$1, did_aw_verified_key=did_key, certificate_id=$2 WHERE agent_id=$3",
                             ids[name]['stable_id'], 'privacy-' + name, actor.id)
    fixture = spike.experiment(ids, now=now)['fixture']
    original = fixture['original']
    response = await _request(env, 'alice', 'POST', '/v1/chat/sessions', {
        'session_id': fixture['session_id'], 'to_dids': [ids['bob']['did']], 'message': '',
        'message_id': original['message_id'], 'timestamp': original['created_at'],
        'content_mode': 'encrypted_v2', 'message_version': 2, 'encrypted_envelope': original,
    })
    assert response.status_code == 200, response.text
    history = await _request(env, 'bob', 'GET', f"/v1/chat/sessions/{fixture['session_id']}/messages")
    assert history.status_code == 200, history.text
    stored = next(m['encrypted_envelope'] for m in history.json()['messages'] if m['message_id'] == original['message_id'])
    assert spike.canon(stored) == spike.canon(original)
    fixture['original'] = stored
    assert spike.native.decrypt_e2ee_message(original, spike.decrypt_identity(ids['bob']))['body'] == 'old group content'
    denied = await _request(env, 'carol', 'GET', f"/v1/chat/sessions/{fixture['session_id']}/messages")
    assert denied.status_code in (403, 404), denied.text
    assert 'old group content' not in denied.text
    membership = await _request(env, 'alice', 'POST', f"/v1/chat/sessions/{fixture['session_id']}/membership", fixture['chain'][1])
    assert membership.status_code == 404, membership.text
    experimental = fixture['bridge_epoch']
    refused = await _request(env, 'alice', 'POST', '/v1/chat/sessions', {
        'session_id': fixture['session_id'], 'to_dids': [ids['bob']['did'], ids['carol']['did']], 'message': '',
        'message_id': experimental['message_id'], 'timestamp': experimental['created_at'],
        'content_mode': 'encrypted_v2', 'message_version': 3, 'encrypted_envelope': experimental,
    })
    assert refused.status_code == 422, refused.text
    capsule = fixture['capsule']
    sent = await _request(env, 'bob', 'POST', '/v1/messages', {
        'to_did': ids['carol']['did'], 'message_id': capsule['message_id'], 'conversation_id': capsule['conversation_id'],
        'content_mode': 'encrypted_v2', 'message_version': 2, 'encrypted_envelope': capsule,
    })
    assert sent.status_code == 200, sent.text
    received = await _request(env, 'carol', 'GET', '/v1/messages/' + capsule['message_id'])
    assert received.status_code == 200, received.text
    delivered = received.json()['encrypted_envelope']
    fixture['capsule'] = delivered
    assert spike.open_reshare(original, delivered, fixture['grant'], fixture['chain'][:2], ids['carol'], fixture['owner'], fixture['session_id'])['body'] == 'old group content'
    # Explicit history copy did not add the recipient to the original room.
    still_denied = await _request(env, 'carol', 'GET', f"/v1/chat/sessions/{fixture['session_id']}/messages")
    assert still_denied.status_code in (403, 404), still_denied.text
    path = tmp_path / 'real-http-spike.json'
    path.write_text(json.dumps(fixture))
    fixture['base_url'] = str(env.client.base_url).rstrip('/')
    path.write_text(json.dumps(fixture))
    path.chmod(0o600)
    child_env = os.environ.copy()
    child_env['AW_TEST_HC_E2EE_SPIKE_FIXTURE'] = str(path)
    process = await asyncio.create_subprocess_exec('go', 'test', './awid', '-run', '^TestHumanChannelsE2EELiveInput$', '-count=1', cwd=ROOT / 'cli/go', env=child_env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)
    assert process.returncode == 0, stdout.decode() + stderr.decode()


def test_shared_experimental_cross_language_fixture():
    fixture = json.loads((ROOT / 'docs/vectors/human-channels-e2ee-spike.json').read_text())
    spike.verify_chain(fixture['chain'], fixture['owner'], fixture['session_id'])
    assert spike.open_reshare(fixture['original'], fixture['capsule'], fixture['grant'], fixture['chain'][:2], fixture['identities']['carol'], fixture['owner'], fixture['session_id'])['body'] == 'old group content'
    assert spike.open_group(fixture['bridge_epoch'], fixture['chain'][:2], fixture['identities']['bob'], fixture['owner'], fixture['session_id'])['body'] == 'visible to bridge'
    assert spike.open_group(fixture['future'], fixture['chain'], fixture['identities']['carol'], fixture['owner'], fixture['session_id'])['body'] == 'future after removal'


def test_bridge_omission_and_signed_control_failures_refuse():
    fixture = spike.experiment()['fixture']
    chain = fixture['chain']
    for altered in (chain + [chain[1]], chain[:2] + [chain[0]]):
        with pytest.raises(ValueError):
            spike.verify_chain(altered, fixture['owner'], fixture['session_id'])
    for change in ('missing_consent', 'hidden_bridge', 'wrong_owner'):
        intent = json.loads(chain[1]['signed_payload'])
        if change == 'missing_consent':intent['consents'] = []
        if change == 'hidden_bridge':intent['state']['confidentiality'] = 'end_to_end'
        signer = fixture['identities']['bob' if change == 'wrong_owner' else 'alice']
        altered = chain[:1] + [spike.sign(intent, signer)]
        with pytest.raises(ValueError):
            spike.verify_chain(altered, fixture['owner'], fixture['session_id'])
    envelope = copy.deepcopy(fixture['bridge_epoch'])
    envelope['key_wraps'] = [w for w in envelope['key_wraps'] if w.get('recipient_did') != fixture['identities']['bob']['did']]
    envelope['crypto']['key_wraps_hash'] = spike.native._hash_canonical('key_wraps', [spike.native._key_wrap_map(w) for w in envelope['key_wraps']])
    envelope['signature'] = spike.sign_message(spike.un64(fixture['identities']['alice']['signing_seed']), spike.protected(envelope))
    with pytest.raises(ValueError, match='missing recipient wrap'):
        spike.open_group(envelope, chain[:2], fixture['identities']['carol'], fixture['owner'], fixture['session_id'])


def test_removed_holder_cannot_authorize_a_fresh_history_transfer():
    f = spike.experiment()['fixture']
    value = json.loads(f['grant']['signed_payload'])
    value['policy_head'] = spike.head(f['chain'][-1])
    grant = spike.sign(value, f['identities']['alice'])
    with pytest.raises(ValueError, match='inactive holder'):
        spike.open_reshare(f['original'], f['capsule'], grant, f['chain'], f['identities']['carol'], f['owner'], f['session_id'])
