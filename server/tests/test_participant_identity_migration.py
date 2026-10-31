"""Upgrade released key-named participants without restoring key authority."""
from datetime import datetime, timedelta, timezone
from importlib.resources import files
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from pgdbm.errors import QueryError

from aweb.identity_auth_deps import MessagingAuth
from aweb.routes.conversations import list_conversations_for_auth
from test_messages_http import _signed_identity_headers
from test_mcp_mail_conversation_parity import mail_server  # noqa: F401

MIGRATION = files('aweb') / 'migrations/aweb/045_canonical_participant_dids.sql'


async def apply(db):
    await db.execute(MIGRATION.read_text())


async def seed_thread(env, kind, *, duplicate=False):
    db, cid = env.db, uuid4()
    await db.execute("""INSERT INTO {{tables.conversations}}
        (conversation_id,conversation_type,team_id,created_by_did)
        VALUES ($1,$2,'ops:acme.com',$3)""", cid, kind, env.pilot_did)
    old = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for did, alias in [(env.pilot_did, 'pilot'), ('did:aw:human', 'human')]:
        await db.execute("""INSERT INTO {{tables.conversation_participants}}
            (conversation_id,did,alias,transport_hint,joined_at,agent_id,role)
            VALUES ($1,$2,$3,'local',$4,$5,$6)""", cid, did, alias, old,
            UUID(env.pilot) if alias == 'pilot' else UUID(env.human),
            'initiator' if alias == 'pilot' else 'participant')
    canonical_id = None
    if duplicate:
        canonical_id = await db.fetch_val("""INSERT INTO {{tables.conversation_participants}}
            (conversation_id,did,alias,transport_hint,joined_at)
            VALUES ($1,'did:aw:pilot','current-label','local',$2) RETURNING participant_id""", cid, old + timedelta(days=1))
    messages = []
    if kind == 'mail':
        mid = uuid4()
        await db.execute("""INSERT INTO {{tables.messages}}
            (message_id,conversation_id,from_did,to_did,from_alias,to_alias,subject,body,signed_payload)
            VALUES ($1,$2,$3,$4,'human','pilot','old title','old body','original signed bytes')""",
            mid, cid, env.human_did, env.pilot_did)
        messages.append(mid)
    else:
        await db.execute("INSERT INTO {{tables.chat_sessions}} (session_id,created_by) VALUES ($1,$2)", cid, env.pilot_did)
        for did, alias in [(env.pilot_did, 'pilot'), ('did:aw:human', 'human')]:
            await db.execute("""INSERT INTO {{tables.chat_participants}}
                (session_id,did,alias,joined_at,agent_id,left_at) VALUES ($1,$2,$3,$4,$5,$6)""",
                cid, did, alias, old, UUID(env.pilot) if alias == 'pilot' else UUID(env.human), old)
        if duplicate:
            await db.execute("""INSERT INTO {{tables.chat_participants}}
                (session_id,did,alias,joined_at) VALUES ($1,'did:aw:pilot','current-label',$2)""", cid, old + timedelta(days=1))
        for day in (1, 2):
            mid = uuid4()
            await db.execute("""INSERT INTO {{tables.chat_messages}}
                (message_id,session_id,from_did,from_alias,body,signed_payload,created_at)
                VALUES ($1,$2,$3,'human','old body','original signed bytes',$4)""", mid, cid, env.human_did, old + timedelta(days=day))
            messages.append(mid)
        await db.execute("""INSERT INTO {{tables.chat_message_reads}} (session_id,did,message_id,read_at,agent_id)
            VALUES ($1,$2,$3,$4,$5)""", cid, env.pilot_did, messages[0], old + timedelta(days=3), UUID(env.pilot))
        await db.execute("""INSERT INTO {{tables.chat_read_receipts}}
            (session_id,did,last_read_message_id,last_read_at,agent_id) VALUES ($1,$2,$3,$4,$5)""",
            cid, env.pilot_did, messages[1], old + timedelta(days=3), UUID(env.pilot))
        if duplicate:
            await db.execute("""INSERT INTO {{tables.chat_message_reads}} (session_id,did,message_id,read_at)
                VALUES ($1,'did:aw:pilot',$2,$3),($1,'did:aw:pilot',$4,$3)""", cid, messages[0], old + timedelta(days=4), messages[1])
            await db.execute("""INSERT INTO {{tables.chat_read_receipts}}
                (session_id,did,last_read_message_id,last_read_at) VALUES ($1,'did:aw:pilot',$2,$3)""",
                cid, messages[0], old + timedelta(days=4))
    return cid, messages, canonical_id


@pytest.mark.asyncio
async def test_upgrade_preserves_threads_duplicate_state_and_signed_message_bytes(mail_server):
    env, db = mail_server, mail_server.db
    # Multiple verified membership rows naming the SAME global identity are OK.
    await db.execute("""INSERT INTO {{tables.teams}} (team_id,namespace,team_name,team_did_key)
        VALUES ('other:else.test','else.test','other','did:key:team')""")
    await db.execute("""INSERT INTO {{tables.agents}} (team_id,alias,did_key,did_aw,did_aw_verified_key)
        VALUES ('other:else.test','pilot',$1,'did:aw:pilot',$1)""", env.pilot_did)
    rows = [(kind, duplicate, await seed_thread(env, kind, duplicate=duplicate))
            for kind in ('mail', 'chat') for duplicate in (False, True)]
    messages_before = [dict(r) for r in await db.fetch_all('SELECT * FROM {{tables.messages}} ORDER BY message_id')]
    chat_before = [dict(r) for r in await db.fetch_all('SELECT * FROM {{tables.chat_messages}} ORDER BY message_id')]
    await apply(db)
    for kind, duplicate, (cid, messages, canonical_id) in rows:
        cp = await db.fetch_all('SELECT * FROM {{tables.conversation_participants}} WHERE conversation_id=$1', cid)
        assert {r['did'] for r in cp} == {'did:aw:pilot', 'did:aw:human'}
        owner = next(r for r in cp if r['did'] == 'did:aw:pilot')
        assert owner['agent_id'] == UUID(env.pilot)
        assert owner['current_did_key'] == env.pilot_did
        assert owner['role'] == 'initiator'
        assert owner['joined_at'] == datetime(2026, 1, 1, tzinfo=timezone.utc)
        if duplicate:
            assert owner['participant_id'] == canonical_id
            assert owner['alias'] == 'current-label'
        if kind == 'mail':
            response = await env.client.get(f'/v1/messages/conversations/{cid}', headers=_signed_identity_headers(env.pilot_key, env.pilot_did, 'did:aw:pilot', b''))
            assert response.status_code == 200, response.text
            assert {UUID(message['message_id']) for message in response.json()['messages']} == set(messages)
        if kind == 'chat':
            peers = await db.fetch_all('SELECT * FROM {{tables.chat_participants}} WHERE session_id=$1', cid)
            assert {r['did'] for r in peers} == {'did:aw:pilot', 'did:aw:human'}
            owner = next(r for r in peers if r['did'] == 'did:aw:pilot')
            assert owner['agent_id'] == UUID(env.pilot)
            assert owner['current_did_key'] == env.pilot_did
            assert (owner['left_at'] is None) == duplicate
            reads = await db.fetch_all('SELECT * FROM {{tables.chat_message_reads}} WHERE session_id=$1', cid)
            assert {r['did'] for r in reads} == {'did:aw:pilot'}
            assert {r['message_id'] for r in reads} == set(messages if duplicate else messages[:1])
            assert next(r for r in reads if r['message_id'] == messages[0])['read_at'].day == (5 if duplicate else 4)
            receipt = await db.fetch_one('SELECT * FROM {{tables.chat_read_receipts}} WHERE session_id=$1', cid)
            assert receipt['did'] == 'did:aw:pilot'
            assert receipt['last_read_message_id'] == messages[1]
            assert receipt['last_read_at'].day == (5 if duplicate else 4)
    auth = MessagingAuth(did_key=env.pilot_did, did_aw='did:aw:pilot', address='acme.com/pilot')
    result = await list_conversations_for_auth(SimpleNamespace(get_manager=lambda _: db), auth)
    assert {item.conversation_id for item in result.conversations} == {str(r[2][0]) for r in rows}
    assert [dict(r) for r in await db.fetch_all('SELECT * FROM {{tables.messages}} ORDER BY message_id')] == messages_before
    assert [dict(r) for r in await db.fetch_all('SELECT * FROM {{tables.chat_messages}} ORDER BY message_id')] == chat_before
    snapshot = [dict(r) for r in await db.fetch_all('SELECT * FROM {{tables.conversation_participants}} ORDER BY conversation_id,did')]
    await apply(db)
    assert [dict(r) for r in await db.fetch_all('SELECT * FROM {{tables.conversation_participants}} ORDER BY conversation_id,did')] == snapshot


@pytest.mark.asyncio
async def test_empty_migration_is_noop_and_local_identity_is_untouched(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    await apply(db)
    await db.execute("INSERT INTO {{tables.teams}} (team_id,namespace,team_name,team_did_key) VALUES ('t:local','local','t','did:key:team')")
    await db.execute("INSERT INTO {{tables.agents}} (team_id,alias,did_key) VALUES ('t:local','local','did:key:local')")
    cid = uuid4()
    await db.execute("INSERT INTO {{tables.conversations}} (conversation_id,conversation_type,created_by_did) VALUES ($1,'mail','did:key:local')", cid)
    await db.execute("INSERT INTO {{tables.conversation_participants}} (conversation_id,did,alias,transport_hint) VALUES ($1,'did:key:local','local','local')", cid)
    before = dict(await db.fetch_one('SELECT * FROM {{tables.conversation_participants}}'))
    await apply(db)
    assert dict(await db.fetch_one('SELECT * FROM {{tables.conversation_participants}}')) == before


@pytest.mark.asyncio
async def test_ambiguous_verified_key_mapping_aborts_without_partial_changes(mail_server):
    env, db = mail_server, mail_server.db
    await seed_thread(env, 'mail')
    await db.execute("INSERT INTO {{tables.teams}} (team_id,namespace,team_name,team_did_key) VALUES ('t:other','other','t','did:key:team')")
    await db.execute("""INSERT INTO {{tables.agents}} (team_id,alias,did_key,did_aw,did_aw_verified_key)
        VALUES ('t:other','other',$1,'did:aw:someoneelse',$1)""", env.pilot_did)
    before = [dict(r) for r in await db.fetch_all('SELECT * FROM {{tables.conversation_participants}} ORDER BY did')]
    with pytest.raises(QueryError, match='ambiguous verified participant'):
        await apply(db)
    assert [dict(r) for r in await db.fetch_all('SELECT * FROM {{tables.conversation_participants}} ORDER BY did')] == before


@pytest.mark.asyncio
@pytest.mark.parametrize('kind,plaintext', [('mail', False), ('mail', True), ('chat', True)])
@pytest.mark.parametrize('selector', ['alias', 'current_key'])
async def test_released_hosted_mcp_writer_stores_global_participant_not_signing_key(mail_server, kind, plaintext, selector):
    env = mail_server
    target = 'human' if selector == 'alias' else env.human_did
    if kind == 'chat':
        await env.db.execute("UPDATE {{tables.agents}} SET agent_type='agent' WHERE agent_id=$1", UUID(env.human))
        sent = await env.mcp_call('send_chat', to=target, message='new', plaintext=plaintext)
        cid = sent.get('session_id')
    else:
        sent = await env.mcp_mail(to=target, plaintext=plaintext)
        cid = sent.get('conversation_id')
    assert 'error' not in sent, sent
    assert cid, sent
    expected = {'did:aw:pilot', 'did:aw:human'}
    assert {r['did'] for r in await env.db.fetch_all('SELECT did FROM {{tables.conversation_participants}} WHERE conversation_id=$1', UUID(cid))} == expected
    if kind == 'chat':
        assert {r['did'] for r in await env.db.fetch_all('SELECT did FROM {{tables.chat_participants}} WHERE session_id=$1', UUID(cid))} == expected


@pytest.mark.asyncio
async def test_http_key_selector_stores_verified_global_participants(mail_server):
    env = mail_server
    sent = await env.human_mail(to_did=env.pilot_did)
    assert {r['did'] for r in await env.db.fetch_all(
        'SELECT did FROM {{tables.conversation_participants}} WHERE conversation_id=$1',
        UUID(sent['conversation_id']))} == {'did:aw:human', 'did:aw:pilot'}
