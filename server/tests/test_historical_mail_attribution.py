"""Canonical membership plus this thread's key, never cross-thread equivalence."""
from uuid import UUID, uuid4

import pytest

from test_messages_http import _make_keypair, _signed_identity_headers
from test_mcp_mail_conversation_parity import mail_server  # noqa: F401
from test_participant_identity_migration import apply, seed_thread


@pytest.mark.asyncio
@pytest.mark.parametrize('reader', ['http', 'mcp'])
async def test_normalized_history_inbox_unread_exact_read_and_incoming_ack(mail_server, reader):
    env, db = mail_server, mail_server.db
    cid, messages, _ = await seed_thread(env, 'mail')
    incoming = messages[0]
    # Own historical key, peer's key, and an older rotated key must not become
    # incoming just because all these messages share the caller's thread.
    others = []
    for sender, recipient in [(env.pilot_did, 'did:aw:human'),
                              (env.human_did, env.human_did),
                              (env.human_did, 'did:key:older-rotated')]:
        mid = uuid4()
        await db.execute("""INSERT INTO {{tables.messages}}
            (message_id,conversation_id,from_did,to_did,body) VALUES ($1,$2,$3,$4,'history')""", mid, cid, sender, recipient)
        others.append(mid)
    await apply(db)
    headers = _signed_identity_headers(env.pilot_key, env.pilot_did, 'did:aw:pilot', b'')
    listed = await env.client.get('/v1/conversations?conversation_type=mail', headers=headers)
    assert listed.status_code == 200, listed.text
    assert listed.json()['conversations'][0]['unread_count'] == 1
    counts = await env.client.get('/v1/conversations/unread-counts?participant_did=did:aw:human', headers=headers)
    assert counts.status_code == 200, counts.text
    assert counts.json()['counts'] == [{'participant_did': 'did:aw:human', 'unread_count': 1}]
    for mid in [incoming, *others]:
        exact = await env.client.get(f'/v1/messages/{mid}', headers=headers)
        assert exact.status_code == 200, exact.text
    outsider_key, _, outsider_did = _make_keypair()
    outsider = await env.client.get(f'/v1/messages/{incoming}', headers=_signed_identity_headers(outsider_key, outsider_did, '', b''))
    assert outsider.status_code == 404, outsider.text
    assert await db.fetch_val('SELECT count(*) FROM {{tables.messages}} WHERE read_at IS NOT NULL') == 0
    if reader == 'http':
        inbox = await env.client.get('/v1/messages/inbox', headers=headers)
        assert inbox.status_code == 200, inbox.text
        assert {UUID(m['message_id']) for m in inbox.json()['messages']} == {incoming}
        assert await db.fetch_val('SELECT count(*) FROM {{tables.messages}} WHERE read_at IS NOT NULL') == 0
        ack = await env.client.post(f'/v1/messages/{incoming}/ack', headers=headers)
        assert ack.status_code == 200, ack.text
    else:
        inbox = await env.mcp_call('check_inbox')
        assert {UUID(m['message_id']) for m in inbox['messages']} == {incoming}, inbox
    assert await db.fetch_val('SELECT count(*) FROM {{tables.messages}} WHERE read_at IS NOT NULL') == 1
    for mid in others:
        refused = await env.client.post(f'/v1/messages/{mid}/ack', headers=headers)
        assert refused.status_code == 404, refused.text
    counts = await env.client.get('/v1/conversations/unread-counts?participant_did=did:aw:human', headers=headers)
    assert counts.json()['counts'][0]['unread_count'] == 0
    # Knowledge of a key from some other thread is never attribution here.
    separate, _, _ = await seed_thread(env, 'mail')
    await db.execute('UPDATE {{tables.conversation_participants}} SET did=$1,current_did_key=NULL WHERE conversation_id=$2 AND did=$3', 'did:aw:pilot', separate, env.pilot_did)
    inbox = await env.client.get('/v1/messages/inbox', headers=headers)
    assert inbox.status_code == 200, inbox.text
    assert {UUID(m['message_id']) for m in inbox.json()['messages']} == {incoming}


@pytest.mark.asyncio
async def test_pre_thread_mail_keeps_canonical_only_legacy_behavior(mail_server):
    env, db = mail_server, mail_server.db
    ids = {}
    for recipient in (env.pilot_did, 'did:aw:pilot'):
        mid = uuid4()
        await db.execute("INSERT INTO {{tables.messages}} (message_id,from_did,to_did,body) VALUES ($1,'did:aw:human',$2,'legacy')", mid, recipient)
        ids[recipient] = mid
    headers = _signed_identity_headers(env.pilot_key, env.pilot_did, 'did:aw:pilot', b'')
    for recipient, mid in ids.items():
        exact = await env.client.get(f'/v1/messages/{mid}', headers=headers)
        assert exact.status_code == (200 if recipient == 'did:aw:pilot' else 404), exact.text
    inbox = await env.client.get('/v1/messages/inbox', headers=headers)
    assert {UUID(m['message_id']) for m in inbox.json()['messages']} == {ids['did:aw:pilot']}


@pytest.mark.asyncio
async def test_normalized_chat_excludes_own_old_key_from_pending_unread_and_ack(mail_server):
    from types import SimpleNamespace
    from aweb.messaging.chat import get_message_history, get_pending_conversations, mark_messages_read
    from aweb.identity_auth_deps import MessagingAuth
    from aweb.routes.conversations import list_conversations_for_auth
    env, db = mail_server, mail_server.db
    cid, messages, _ = await seed_thread(env, 'chat')
    own = uuid4()
    await db.execute("INSERT INTO {{tables.chat_messages}} (message_id,session_id,from_did,from_alias,body) VALUES ($1,$2,$3,'pilot','own historical send')", own, cid, env.pilot_did)
    await apply(db)
    infra = SimpleNamespace(get_manager=lambda _: db)
    history = await get_message_history(infra, session_id=cid, participant_did='did:aw:pilot', unread_only=True)
    assert {r['message_id'] for r in history} == {str(messages[1])}
    pending = await get_pending_conversations(infra, participant_did='did:aw:pilot')
    assert len(pending) == 1 and pending[0]['unread_count'] == 1
    listed = await list_conversations_for_auth(infra, MessagingAuth(did_key=env.pilot_did, did_aw='did:aw:pilot', address=None), conversation_type='chat')
    assert listed.conversations[0].unread_count == 1
    await mark_messages_read(infra, session_id=cid, participant_did='did:aw:pilot', message_ids=[str(own), str(messages[1])])
    assert await db.fetch_val('SELECT count(*) FROM {{tables.chat_message_reads}} WHERE message_id=$1', own) == 0
    assert await get_pending_conversations(infra, participant_did='did:aw:pilot') == []
