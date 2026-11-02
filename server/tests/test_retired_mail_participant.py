"""Old identity threads cannot forward to a replacement occupying its alias."""
import json
from uuid import UUID

import pytest

from identity_binding_support import register_global_identity
from test_multi_membership_address import addressed_human  # noqa: F401
from test_messages_http import _signed_identity_headers
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401
from test_mcp_mail_conversation_parity import mail_server  # noqa: F401


@pytest.mark.asyncio
async def test_retired_identity_continuation_refuses_new_alias_mail_reaches_replacement(privacy_app):
    env = privacy_app
    first = await _request(env, 'alice', 'POST', '/v1/messages', {'to_alias': 'bob', 'subject': 'old thread', 'body': 'first'})
    assert first.status_code == 200, first.text
    cid = first.json()['conversation_id']
    await env.db.execute("UPDATE {{tables.agents}} SET deleted_at=NOW(),alias='retired-bob' WHERE agent_id=$1", env.actors['bob'].id)
    await env.db.execute("UPDATE {{tables.agents}} SET alias='bob',agent_type='human' WHERE agent_id=$1", env.actors['carol'].id)
    replacement = env.actors['carol']
    stable = await register_global_identity(env, replacement)
    resolution = await env.app.state.awid_registry_client.resolve_key_fresh(stable)
    assert resolution.current_did_key == replacement.did
    await env.db.execute("UPDATE {{tables.agents}} SET did_aw=$1,did_aw_verified_key=did_key,identity_scope='global' WHERE agent_id=$2", stable, replacement.id)
    before = list(env.dispatched)
    # No registry or hosted forwarding can make the retired identity live.
    registry = env.app.state.awid_registry_client
    env.app.state.awid_registry_client = object()
    try:
        refused = await _request(env, 'alice', 'POST', '/v1/messages', {'conversation_id': cid, 'body': 'must not forward'})
    finally:
        env.app.state.awid_registry_client = registry
    assert refused.status_code == 410, refused.text
    detail = refused.json()['detail']
    assert detail['code'] == 'participant_retired'
    assert detail['message'] == f'bob has moved; start a new mail to bob in {TEAM}'
    assert await env.db.fetch_val('SELECT count(*) FROM {{tables.messages}} WHERE conversation_id=$1', UUID(cid)) == 1
    assert env.dispatched == before
    new = await _request(env, 'alice', 'POST', '/v1/messages', {'to_alias': 'bob', 'subject': 'new thread', 'body': 'to replacement'})
    assert new.status_code == 200, new.text
    assert new.json()['conversation_id'] != cid
    assert await env.db.fetch_val('SELECT to_did FROM {{tables.messages}} WHERE message_id=$1', UUID(new.json()['message_id'])) == stable


@pytest.mark.asyncio
async def test_mcp_retired_continuation_keeps_original_thread_and_does_not_sign(mail_server):
    env = mail_server
    first = await env.mcp_mail(to='human', plaintext=True)
    await env.db.execute("UPDATE {{tables.agents}} SET deleted_at=NOW() WHERE agent_id=$1", UUID(env.human))
    count = len(env.custody.payloads)
    refused = await env.mcp_mail(conversation_id=first['conversation_id'], plaintext=True)
    assert isinstance(refused.get('error'), dict), refused
    assert refused['error']['code'] == 'participant_retired', refused
    assert len(env.custody.payloads) == count
    assert await env.db.fetch_val('SELECT count(*) FROM {{tables.messages}}') == 1


@pytest.mark.asyncio
async def test_deleted_membership_does_not_retire_a_still_live_identity(addressed_human):
    env = addressed_human.env
    actor = env.actors['bob']
    async def send(payload):
        content = json.dumps(payload).encode()
        return await env.client.post('/v1/messages', content=content, headers={
            'Content-Type': 'application/json',
            **_signed_identity_headers(actor.sk, actor.did, env.stable['bob'], content),
        })
    first = await send({'to_did': env.stable['alice'], 'subject': 'identity thread', 'body': 'first'})
    assert first.status_code == 200, first.text
    await env.db.execute("UPDATE {{tables.agents}} SET deleted_at=NOW() WHERE agent_id=$1", env.actors['alice'].id)
    continued = await send({'conversation_id': first.json()['conversation_id'], 'body': 'same identity'})
    assert continued.status_code == 200, continued.text
    assert await env.db.fetch_val('SELECT to_did FROM {{tables.messages}} WHERE message_id=$1', UUID(continued.json()['message_id'])) == env.stable['alice']
