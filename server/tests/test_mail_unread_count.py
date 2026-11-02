"""One count per incoming unread message, independent of peer multiplicity."""
from uuid import UUID, uuid4

import pytest
from test_messages_http import _make_keypair, _signed_identity_headers
from test_mcp_mail_conversation_parity import mail_server  # noqa: F401
from test_participant_identity_migration import apply, seed_thread


@pytest.mark.asyncio
async def test_total_unread_is_distinct_scoped_historical_and_read_only(mail_server):
    env, db = mail_server, mail_server.db
    cid, mids, _ = await seed_thread(env, 'mail')
    await seed_thread(env, 'mail')
    await apply(db)
    await db.execute("""INSERT INTO {{tables.conversation_participants}}
        (conversation_id,did,alias,transport_hint) VALUES ($1,'did:aw:third','third','local')""", cid)
    await db.execute("""INSERT INTO {{tables.messages}} (from_did,to_did,body,conversation_id)
        VALUES ($1,'did:aw:human','own send',$2),('did:aw:human','did:aw:pilot','already read',$2)""", env.pilot_did, cid)
    await db.execute("UPDATE {{tables.messages}} SET read_at=now() WHERE body='already read'")
    headers = _signed_identity_headers(env.pilot_key, env.pilot_did, 'did:aw:pilot', b'')
    before = [dict(r) for r in await db.fetch_all('SELECT * FROM {{tables.messages}} ORDER BY message_id')]
    count = await env.client.get('/v1/messages/unread-count', headers=headers)
    assert count.status_code == 200, count.text
    assert count.json() == {'unread_count': 2}
    peers = await env.client.get('/v1/conversations/unread-counts?participant_did=did:aw:human&participant_did=did:aw:third', headers=headers)
    assert sum(row['unread_count'] for row in peers.json()['counts']) == 3
    key, _, did = _make_keypair()
    outsider = await env.client.get('/v1/messages/unread-count', headers=_signed_identity_headers(key, did, '', b''))
    assert outsider.status_code == 200 and outsider.json() == {'unread_count': 0}, outsider.text
    assert [dict(r) for r in await db.fetch_all('SELECT * FROM {{tables.messages}} ORDER BY message_id')] == before
    ack = await env.client.post(f'/v1/messages/{mids[0]}/ack', headers=headers)
    assert ack.status_code == 200, ack.text
    after = await env.client.get('/v1/messages/unread-count', headers=headers)
    assert after.json() == {'unread_count': 1}
