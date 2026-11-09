"""D8: authoritative humans use mail; agent/unknown chat remains supported."""
import json
from uuid import UUID

import pytest

from test_dashboard_privacy import privacy_app  # noqa: F401
from test_messages_http import _signed_identity_headers
from test_mcp_mail_conversation_parity import mail_server  # noqa: F401
from test_human_channels_native_send import native_send  # noqa: F401

__all__ = ["privacy_app", "mail_server", "native_send"]


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
    await env.db.execute("UPDATE {{tables.agents}} SET agent_type='human', human_verified_key=did_key WHERE agent_id=$1", env.actors['bob'].id)
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
    await env.db.execute("UPDATE {{tables.agents}} SET agent_type='human', human_verified_key=did_key WHERE agent_id=$1", env.actors['bob'].id)
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
        await env.db.execute("UPDATE {{tables.agents}} SET agent_type='human', human_verified_key=did_key WHERE agent_id=$1", UUID(env.human))
    before = len(env.custody.payloads)
    refused = await env.mcp_call('send_chat', message='must refuse', plaintext=True, **arguments)
    assert refused.get('reason') == 'recipient_human_mail_only', refused
    assert refused['retryable'] is False
    assert 'aw mail send --to ' in refused['error']
    assert len(env.custody.payloads) == before
    assert await env.db.fetch_val('SELECT count(*) FROM {{tables.chat_messages}}') == int(continuation)


@pytest.mark.asyncio
@pytest.mark.parametrize('scope', ['local', 'global'])
@pytest.mark.parametrize('projection', ['verified-human', 'raw-human', 'wrong-key', 'agent', 'unknown'])
async def test_chat_preflight_uses_projections_without_any_registry_io(privacy_app, scope, projection):
    import os
    from awid.registry import CachedRegistryClient
    from awid_service.testing import ServiceTransport
    from redis.asyncio import Redis
    from aweb.messaging.chat_policy import HumanChatRefused, require_agent_chat

    env = privacy_app
    actor = env.actors['bob']
    identity = None
    if scope == 'global':
        identity = (await env.app.state.awid_registry_client.register_did(actor.did, actor.sk)).did_aw
    kind = 'agent' if projection == 'agent' else 'human'
    marker = actor.did if projection == 'verified-human' else env.actors['carol'].did if projection == 'wrong-key' else None
    if projection != 'unknown':
        await env.db.execute(
            "UPDATE {{tables.agents}} SET did_aw=$2,did_aw_verified_key=did_key,agent_type=$3,human_verified_key=$4 WHERE agent_id=$1",
            actor.id, identity, kind, marker,
        )
    recipient = dict(did_key=actor.did, did_aw=identity, alias='bob')
    if projection == 'unknown':
        recipient = dict(did_key=env.actors['carol'].did, did_aw=identity, alias='unknown')
    recording = ServiceTransport(env.registry_app)
    redis = Redis.from_url(os.environ.get('REDIS_URL', 'redis://localhost:6379/0'))
    client = CachedRegistryClient('http://registry.test', redis, transport=recording)
    try:
        if projection == 'verified-human':
            with pytest.raises(HumanChatRefused) as refused:
                await require_agent_chat(env.infra, [recipient], registry_client=client)
            assert refused.value.reason == 'recipient_human_mail_only'
        else:
            await require_agent_chat(env.infra, [recipient], registry_client=client)
        assert recording.calls == []
    finally:
        await client.aclose()
        await redis.aclose()


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
    await db.execute("UPDATE {{tables.agents}} SET agent_type='human', human_verified_key=did_key WHERE agent_id=$1", recipient['agent_id'])
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
    await env.db.execute("UPDATE {{tables.agents}} SET agent_type='human', human_verified_key=did_key WHERE alias IN ('bob','carol')")
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
    await env.db.execute("UPDATE {{tables.agents}} SET agent_type='human', human_verified_key=did_key WHERE alias='bob'")
    rows = [dict(did_key=env.actors['carol'].did, alias='carol'),
            dict(did_key='did:key:unknown', alias='unknown'),
            dict(did_key=env.actors['bob'].did, alias='bob'),
            dict(did_key=env.actors['bob'].did, alias='bob')]
    with pytest.raises(HumanChatRefused) as refused:
        await require_agent_chat(env.infra, rows)
    assert refused.value.body()['recipients'] == ['bob']


@pytest.mark.asyncio
@pytest.mark.parametrize('stamp_before_accept', [False, True])
async def test_native_legacy_label_grants_no_human_chat_treatment(native_send, stamp_before_accept):
    from aweb.messaging.chat_policy import HumanChatRefused
    from test_human_channels_native_send import complete

    env = native_send
    await env['db'].execute('UPDATE {{tables.agents}} SET human_verified_key=NULL WHERE agent_id=$1', UUID(env['b']))
    prepared = await env['prepared']('chat')
    if stamp_before_accept:
        await env['db'].execute('UPDATE {{tables.agents}} SET human_verified_key=did_key WHERE agent_id=$1', UUID(env['b']))
        with pytest.raises(HumanChatRefused):
            await complete(env, prepared)
    else:
        await complete(env, prepared)
    assert await env['db'].fetch_val('SELECT count(*) FROM {{tables.chat_messages}}') == (0 if stamp_before_accept else 1)


@pytest.mark.asyncio
async def test_agent_with_verified_human_ancestor_is_allowed_without_registry_io(privacy_app):
    import os
    from copy import deepcopy
    from pathlib import Path
    from awid.id_certificates import IDChainEvidence, verify_id_chain
    from awid.registry import CachedRegistryClient
    from awid_service.testing import ServiceTransport
    from redis.asyncio import Redis
    from aweb.messaging.chat_policy import require_agent_chat

    vectors = json.loads((Path(__file__).resolve().parents[2] / 'docs/vectors/id-certificates-v1.json').read_text())
    case = next(case for case in vectors['verification_cases'] if case['name'] == 'registered-agent')
    status = deepcopy(vectors['status_fixtures'][case['status']])
    epoch = next(epoch for epoch in status['namespace']['epochs'] if epoch['retired_at'] is None)
    authority = dict(domain=status['domain'], dns_name='_awid.' + status['domain'], inherited=False, controller_key=epoch['did_key'])
    bundle = {'v': 1, 'type': 'aweb.id-chain', 'certificates': [deepcopy(vectors['certificates'][name]['signed']) for name in case['chain']]}
    observed = verify_id_chain(bundle, subject=case['subject'], evidence=IDChainEvidence(status, authority, 0), domain=status['domain'])
    assert observed['identity_valid'] is True and observed['kind'] == 'agent'
    assert observed['human_id'] is not None
    env = privacy_app
    subject = case['subject']
    await env.db.execute(
        "UPDATE {{tables.agents}} SET did_key=$2,did_aw=$3,did_aw_verified_key=$2,agent_type='agent',human_verified_key=NULL WHERE agent_id=$1",
        env.actors['bob'].id, subject['did_key'], subject['id'],
    )
    recording = ServiceTransport(env.registry_app)
    redis = Redis.from_url(os.environ.get('REDIS_URL', 'redis://localhost:6379/0'))
    client = CachedRegistryClient('http://registry.test', redis, transport=recording)
    try:
        await require_agent_chat(env.infra, [dict(did_aw=subject['id'], did_key=subject['did_key'], alias='bob')], registry_client=client)
        assert recording.calls == []
    finally:
        await client.aclose()
        await redis.aclose()
