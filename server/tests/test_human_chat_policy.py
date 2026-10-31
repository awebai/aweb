"""D8: authoritative humans use mail; agent/unknown chat remains supported."""
import json
from uuid import UUID

import pytest

from test_dashboard_privacy import privacy_app  # noqa: F401
from test_messages_http import _signed_identity_headers
from test_mcp_mail_conversation_parity import mail_server  # noqa: F401
from test_human_channels_native_send import native_send  # noqa: F401


async def request(env, path, payload):
    sender = env.actors['alice']
    body = json.dumps(payload).encode()
    return await env.client.post(path, content=body, headers={
        'Content-Type': 'application/json',
        **_signed_identity_headers(sender.sk, sender.did, '', body),
    })


@pytest.mark.asyncio
@pytest.mark.parametrize('selector', ['alias', 'did', 'address', 'group'])
async def test_authoritative_team_human_refuses_new_chat_without_effects(privacy_app, selector):
    env = privacy_app
    await env.db.execute("UPDATE {{tables.agents}} SET agent_type='human' WHERE agent_id=$1", env.actors['bob'].id)
    target = {
        'alias': {'to_aliases': ['bob']},
        'did': {'to_dids': [env.actors['bob'].did]},
        'address': {'to_addresses': ['example.test/bob']},
        'group': {'to_aliases': ['carol', 'bob']},
    }[selector]
    response = await request(env, '/v1/chat/sessions', {**target, 'message': 'must not send'})
    assert response.status_code == 422, response.text
    result = response.json()
    assert result['reason'] == 'recipient_human_mail_only', result
    assert result['retryable'] is False
    assert 'aw mail send --to ' in result['detail']
    assert result['correlation_id']
    for table in ('chat_sessions', 'chat_messages', 'conversations'):
        assert await env.db.fetch_val('SELECT count(*) FROM {{tables.' + table + '}}') == 0
    assert env.dispatched == []


@pytest.mark.asyncio
@pytest.mark.parametrize('control', [{}, {'leaving': True}, {'hang_on': True}])
async def test_existing_human_session_refuses_next_send_and_wait_changes(privacy_app, control):
    env = privacy_app
    started = await request(env, '/v1/chat/sessions', {'to_aliases': ['bob'], 'message': 'agent control'})
    assert started.status_code == 200, started.text
    cid = started.json()['session_id']
    await env.db.execute("UPDATE {{tables.agents}} SET agent_type='human' WHERE agent_id=$1", env.actors['bob'].id)
    before = list(env.dispatched)
    response = await request(env, f'/v1/chat/sessions/{cid}/messages', {'body': 'refuse', **control})
    assert response.status_code == 422, response.text
    assert response.json()['reason'] == 'recipient_human_mail_only'
    assert response.json()['retryable'] is False
    assert await env.db.fetch_val('SELECT count(*) FROM {{tables.chat_messages}} WHERE session_id=$1', UUID(cid)) == 1
    assert env.dispatched == before


@pytest.mark.asyncio
@pytest.mark.parametrize('continuation', [False, True])
async def test_mcp_human_chat_refusal_precedes_custody_and_send(mail_server, continuation):
    env = mail_server
    arguments = {'to': 'human'}
    if continuation:
        await env.db.execute("UPDATE {{tables.agents}} SET agent_type='agent' WHERE agent_id=$1", UUID(env.human))
        started = await env.mcp_call('send_chat', message='agent control', plaintext=True, **arguments)
        assert 'error' not in started, started
        arguments = {'conversation_id': started['session_id'], 'hang_on': True}
        await env.db.execute("UPDATE {{tables.agents}} SET agent_type='human' WHERE agent_id=$1", UUID(env.human))
    before = len(env.custody.payloads)
    refused = await env.mcp_call('send_chat', message='must refuse', plaintext=True, **arguments)
    assert refused.get('reason') == 'recipient_human_mail_only', refused
    assert refused['retryable'] is False
    assert 'aw mail send --to ' in refused['error']
    assert len(env.custody.payloads) == before
    assert await env.db.fetch_val('SELECT count(*) FROM {{tables.chat_messages}}') == int(continuation)


@pytest.mark.asyncio
@pytest.mark.parametrize('case_name, expected', [
    ('human-leaf-is-itself', True), ('registered-agent', False),
    ('human-leaf-is-itself-unavailable', False),
    ('human-leaf-is-itself-wrong-key', False),
])
async def test_remote_kind_uses_shared_current_verifier_not_nearest_human(privacy_app, case_name, expected):
    from copy import deepcopy
    from types import SimpleNamespace
    from awid.id_certificates import IDChainEvidence
    from awid.registry import IDTreeEnrollment, KeyResolution
    from aweb.messaging.chat_policy import HumanChatRefused, require_agent_chat
    from test_id_chain_request_auth import VECTORS

    case = next(c for c in VECTORS['verification_cases'] if c['name'] == case_name.split('-unavailable')[0].split('-wrong-key')[0])
    subject = case['subject']
    status = deepcopy(VECTORS['status_fixtures'][case['status']])
    epoch = next(e for e in status['namespace']['epochs'] if e['retired_at'] is None)
    authority = dict(domain=status['domain'], dns_name='_awid.' + status['domain'], inherited=False, controller_key=epoch['did_key'])
    calls = []
    async def resolve(did):
        calls.append(did)
        if case_name.endswith('unavailable'):
            raise TimeoutError('kind unavailable')
        return KeyResolution(did, subject['did_key'], id_tree=IDTreeEnrollment(True, status['domain']))
    async def evidence(bundle, bound, *, domain):
        assert bundle is None
        assert bound == {'id': subject['id'], 'did_key': subject['did_key']}
        assert domain == status['domain']
        return IDChainEvidence(status, authority, 0)
    recipient = dict(did_aw=subject['id'], did_key=subject['did_key'], address='alias.example/person')
    if case_name.endswith('wrong-key'):
        recipient['did_key'] = privacy_app.actors['carol'].did
    client = SimpleNamespace(resolve_key_fresh=resolve, id_chain_evidence=evidence)
    if expected:
        with pytest.raises(HumanChatRefused) as refused:
            await require_agent_chat(privacy_app.infra, [recipient], registry_client=client)
        assert refused.value.reason == 'recipient_human_mail_only'
    else:
        await require_agent_chat(privacy_app.infra, [recipient], registry_client=client)
    assert calls == [subject['id']]


@pytest.mark.asyncio
async def test_native_human_chat_prepare_refuses_without_retaining_or_writing(native_send):
    from aweb.messaging.chat_policy import HumanChatRefused
    with pytest.raises(HumanChatRefused) as refused:
        await native_send['prepared']('chat')
    assert refused.value.reason == 'recipient_human_mail_only'
    assert native_send['service']._preparations == {}
    for table in ('chat_messages', 'chat_sessions', 'human_channel_sends'):
        assert await native_send['db'].fetch_val('SELECT count(*) FROM {{tables.' + table + '}}') == 0


@pytest.mark.asyncio
async def test_federated_ingress_cannot_send_chat_to_authoritative_human(aweb_cloud_db):
    from aweb.messaging.chat_policy import HumanChatRefused
    from aweb.federation.delivery import deliver_federated_phase_b
    from test_federation_activation_delivery import _DB, _envelope, _seed_recipient_and_authority
    db = aweb_cloud_db.aweb_db
    envelope = _envelope(kind='chat')
    recipient, token = await _seed_recipient_and_authority(db, envelope)
    await db.execute("UPDATE {{tables.agents}} SET agent_type='human' WHERE agent_id=$1", recipient['agent_id'])
    with pytest.raises(HumanChatRefused) as refused:
        await deliver_federated_phase_b(_DB(db), envelope=envelope, signature='test', recipient=recipient, authority_token=token)
    assert refused.value.reason == 'recipient_human_mail_only'
    for table in ('chat_messages', 'message_ingress_receipts', 'federation_mutation_outbox'):
        assert await db.fetch_val('SELECT count(*) FROM {{tables.' + table + '}}') == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('existing', [False, True])
async def test_group_refusal_names_only_authoritative_humans_in_stable_order(privacy_app, existing):
    env = privacy_app
    # The requested agent can be in a group with several people. Never label
    # that agent a person merely because the whole send is refused.
    if existing:
        started = await request(env, '/v1/chat/sessions', {
            'to_aliases': ['carol', 'bob'], 'message': 'agent control',
        })
        assert started.status_code == 200, started.text
    await env.db.execute("UPDATE {{tables.agents}} SET agent_type='human' WHERE alias IN ('bob','carol')")
    if existing:
        response = await request(env, '/v1/chat/sessions/' + started.json()['session_id'] + '/messages', {'body': 'no', 'hang_on': True})
    else:
        response = await request(env, '/v1/chat/sessions', {'to_aliases': ['carol', 'bob'], 'message': 'no'})
    assert response.status_code == 422, response.text
    assert response.json()['recipients'] == ['bob', 'carol']
    assert await env.db.fetch_val('SELECT count(*) FROM {{tables.chat_messages}}') == int(existing)


@pytest.mark.asyncio
async def test_refusal_names_exclude_agent_and_unknown_members(privacy_app):
    from aweb.messaging.chat_policy import HumanChatRefused, require_agent_chat
    env = privacy_app
    await env.db.execute("UPDATE {{tables.agents}} SET agent_type='human' WHERE alias='bob'")
    rows = [dict(did_key=env.actors['carol'].did, alias='carol'),
            dict(did_key='did:key:unknown', alias='unknown'),
            dict(did_key=env.actors['bob'].did, alias='bob'),
            dict(did_key=env.actors['bob'].did, alias='bob')]
    with pytest.raises(HumanChatRefused) as refused:
        await require_agent_chat(env.infra, rows)
    assert refused.value.body()['recipients'] == ['bob']
