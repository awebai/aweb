"""A global participant is its did:aw, not its signing-key identity."""
import json
from uuid import UUID, uuid4

import pytest

from aweb.messaging.conversations import create_conversation
from test_multi_membership_address import addressed_human  # noqa: F401
from test_dashboard_privacy import privacy_app  # noqa: F401
from test_messages_http import _signed_identity_headers
from test_mcp_mail_conversation_parity import mail_server  # noqa: F401


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['mail', 'chat'])
async def test_global_signing_key_is_not_a_separate_participant_authority(addressed_human, kind):
    env = addressed_human.env
    actor, other = env.actors['bob'], env.actors['carol']
    cid = uuid4()
    await create_conversation(env.infra, conversation_type=kind, conversation_id=str(cid), created_by_did=other.did,
        initiator={'did': other.did, 'alias': 'carol', 'transport_hint': 'local'},
        recipients=[{'did': actor.did, 'alias': 'key-only-identity', 'transport_hint': 'local'}])
    if kind == 'mail':
        await env.db.execute("INSERT INTO {{tables.messages}} (message_id,from_did,to_did,subject,body,conversation_id) VALUES ($1,$2,$3,'private key thread','private',$4)", uuid4(), other.did, actor.did, cid)
        path = f'/v1/messages/conversations/{cid}'
    else:
        await env.db.execute("INSERT INTO {{tables.chat_sessions}} (session_id,created_by) VALUES ($1,$2)", cid, other.did)
        for did in (other.did, actor.did):
            await env.db.execute("INSERT INTO {{tables.chat_participants}} (session_id,did,alias) VALUES ($1,$2,'key participant')", cid, did)
        path = f'/v1/chat/sessions/{cid}/messages'
    # The SAME key proves an enrolled global subject; it is not that subject's
    # separate did:key participant reference. No alias/actor expansion joins them.
    response = await env.client.get(path, headers=_signed_identity_headers(actor.sk, actor.did, env.stable['bob'], b''))
    assert response.status_code == 404, response.text


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['mail', 'chat'])
async def test_hosted_signature_key_does_not_replace_global_thread_participant(mail_server, kind):
    env = mail_server
    if kind == 'chat':
        await env.db.execute("UPDATE {{tables.agents}} SET agent_type='agent' WHERE agent_id=$1", UUID(env.human))
        result = await env.mcp_call('send_chat', to='human', message='new agent chat', plaintext=True)
    else:
        result = await env.mcp_mail(to='human', plaintext=True)
    assert 'error' not in result, result
    cid = UUID(result['conversation_id'])
    participants = await env.db.fetch_all("SELECT did FROM {{tables.conversation_participants}} WHERE conversation_id=$1", cid)
    assert {row['did'] for row in participants} == {'did:aw:pilot', 'did:aw:human'}
    payload = env.custody.payloads[-1]
    assert payload['from_did'] == env.pilot_did
    assert payload['from_stable_id'] == 'did:aw:pilot'
