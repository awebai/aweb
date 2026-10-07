"""Compare the viewer-first query with its released SQL on a real test DB."""
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from aweb.messaging.chat import get_pending_conversations

BASELINE = (Path(__file__).parent / "fixtures/pending_conversations_before_abow.sql").read_text()


async def query_and_args(did, agent):
    captured = []

    async def capture(query, *args):
        captured.append((query, args))
        return []

    db = SimpleNamespace(get_manager=lambda name: SimpleNamespace(fetch_all=capture))
    await get_pending_conversations(db, participant_did=did, participant_agent_id=str(agent) if agent else None)
    return captured[0]


async def seed(db):
    await db.execute("""INSERT INTO {{tables.teams}}
        (team_id, namespace, team_name, team_did_key)
        VALUES ('query:example.test', 'example.test', 'query', 'did:key:team')""")
    agent = uuid4()
    await db.execute("""INSERT INTO {{tables.agents}}
        (agent_id, team_id, did_key, alias, identity_scope)
        VALUES ($1, 'query:example.test', 'did:key:viewer', 'viewer', 'local')""", agent)
    sessions = {}
    for index, kind in enumerate(['dual', 'agent_only', 'left', 'wait', 'encrypted', 'read', 'own_wait', 'expired', 'empty']):
        sid = uuid4()
        sessions[kind] = sid
        await db.execute("""INSERT INTO {{tables.chat_sessions}}
            (session_id, team_id, created_by, wait_seconds, wait_started_at, wait_started_by)
            VALUES ($1, 'query:example.test', 'other', $2,
                    CASE WHEN $2::int IS NULL THEN NULL ELSE NOW() - INTERVAL '100 seconds' END, $3)""",
            sid, 1 if kind in ('wait', 'own_wait', 'expired') else None,
            agent if kind == 'own_wait' else None)
        did = 'did:key:old' if kind == 'agent_only' else 'did:key:viewer'
        await db.execute("""INSERT INTO {{tables.chat_participants}}
            (session_id, did, agent_id, alias, address, left_at)
            VALUES ($1, $2, $3, 'viewer', NULL,
                    CASE WHEN $4::boolean THEN NOW() ELSE NULL END),
                   ($1, 'did:key:other', NULL, 'other', 'example.test/other', NULL)""",
            sid, did, agent, kind == 'left')
        if kind == 'dual':
            await db.execute("""INSERT INTO {{tables.chat_participants}}
                (session_id, did, agent_id, alias) VALUES ($1, 'did:aw:viewer', $2, 'viewer-stable')""", sid, agent)
        if kind == 'empty':
            continue
        mid = uuid4()
        await db.execute("""INSERT INTO {{tables.chat_messages}}
            (message_id, session_id, from_did, from_alias, body, created_at, hang_on,
             content_mode, message_version, encrypted_envelope, encrypted_ciphertext,
             encrypted_key_wraps, encrypted_ciphertext_hash, encrypted_ciphertext_size,
             encrypted_key_wraps_hash, encrypted_inner_header_hash, encrypted_suite,
             encrypted_signing_key_id, signed_envelope_hash)
            VALUES ($1, $2, 'did:key:other', 'other', $3,
                    NOW() + ($4 * INTERVAL '1 second'), $5,
                    $6, $7, $8::jsonb, 'fixture', '{}'::jsonb, 'sha256:fixture', 7,
                    'sha256:fixture', 'sha256:fixture', 'fixture', 'fixture', 'sha256:fixture')""",
            mid, sid, '' if kind == 'encrypted' else kind, index,
            kind in ('wait', 'own_wait'),
            'encrypted_v2' if kind == 'encrypted' else 'legacy_plaintext_v1',
            2 if kind == 'encrypted' else 1,
            json.dumps({'ciphertext': 'fixture'}) if kind == 'encrypted' else None)
        if kind in ('read', 'wait', 'own_wait', 'expired', 'dual'):
            # For dual, only exact key DID has read it: selecting stable DID
            # instead would change unread_count and the returned session set.
            await db.execute("""INSERT INTO {{tables.chat_message_reads}}
                (session_id, did, message_id) VALUES ($1, $2, $3)""", sid, did, mid)
    return agent, sessions


def comparable(rows):
    return sorted([dict(row) for row in rows], key=lambda row: str(row['session_id']))


@pytest.mark.asyncio
async def test_pending_query_semantics_match_released_sql(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    agent, sessions = await seed(db)
    for did, actor in [('did:key:viewer', agent), ('did:aw:viewer', agent),
                       ('did:key:viewer', None), ('did:key:old', None),
                       ('did:key:absent', None)]:
        query, args = await query_and_args(did, actor)
        old = await db.fetch_all(BASELINE, *args)
        new = await db.fetch_all(query, *args)
        assert comparable(new) == comparable(old)
    query, args = await query_and_args('did:key:viewer', agent)
    rows = {row['session_id']: row for row in await db.fetch_all(query, *args)}
    assert set(rows) == {sessions[k] for k in ('agent_only', 'left', 'wait', 'encrypted')}
    assert rows[sessions['wait']]['extended_wait_seconds'] == 300
    assert rows[sessions['wait']]['unread_count'] == 0
    assert rows[sessions['left']]['unread_count'] == 1
    assert rows[sessions['encrypted']]['last_message'] == ''
    assert rows[sessions['encrypted']]['last_message_version'] == 2


def nodes(plan):
    yield plan
    for child in plan.get('Plans', []):
        yield from nodes(child)


@pytest.mark.asyncio
async def test_pending_query_scales_with_viewer_sessions(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    agent, sessions = await seed(db)
    # The old query deliberately leaves ties between non-exact agent matches
    # unspecified. Keep fallback plan comparisons unambiguous; the semantic
    # test above separately proves exact-DID preference with dual rows.
    await db.execute("""UPDATE {{tables.chat_participants}} SET agent_id = NULL
        WHERE session_id = $1""", sessions['dual'])
    # A few viewer sessions amid more unrelated sessions than the observed
    # replica. No global scan prohibition is asserted on tiny tables.
    await db.execute("""INSERT INTO {{tables.chat_sessions}} (session_id, created_by)
        SELECT md5('unrelated-' || n)::uuid, 'other' FROM generate_series(1, 12000) n""")
    await db.execute("""INSERT INTO {{tables.chat_participants}} (session_id, did, alias)
        SELECT md5('unrelated-' || n)::uuid, 'did:key:unrelated-' || n, 'other'
        FROM generate_series(1, 12000) n""")
    await db.execute("""INSERT INTO {{tables.chat_messages}} (session_id, from_did, from_alias, body)
        SELECT md5('unrelated-' || n)::uuid, 'did:key:someone', 'someone', 'unrelated'
        FROM generate_series(1, 12000) n CROSS JOIN generate_series(1, 3) m""")
    await db.execute("""INSERT INTO {{tables.chat_message_reads}} (session_id, did, message_id)
        SELECT DISTINCT ON (m.session_id) m.session_id, p.did, m.message_id
        FROM {{tables.chat_messages}} m
        JOIN {{tables.chat_participants}} p ON p.session_id = m.session_id
        WHERE p.did LIKE 'did:key:unrelated-%'
        ORDER BY m.session_id, m.message_id""")
    print('DATABASE', dict(await db.fetch_one('SELECT version() AS version')))
    for table in ('chat_sessions', 'chat_participants', 'chat_messages', 'chat_message_reads'):
        await db.execute('ANALYZE {{tables.' + table + '}}')
    for did, actor in [('did:key:viewer', None), ('did:key:viewer', agent), ('did:key:absent', agent)]:
        query, args = await query_and_args(did, actor)
        plans = {}
        for name, sql in [('before', BASELINE), ('after', query)]:
            result = await db.fetch_all('EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ' + sql, *args)
            raw = result[0]['QUERY PLAN']
            plans[name] = (json.loads(raw) if isinstance(raw, str) else raw)[0]
        print('PLAN', did, actor is not None, json.dumps(plans))
        after = list(nodes(plans['after']['Plan']))
        assert not [n for n in after if n.get('Node Type') == 'Seq Scan' and
                    n.get('Relation Name') in ('chat_sessions', 'chat_participants', 'chat_messages')]
        assert max(n.get('Actual Loops', 0) for n in after) <= 9
        assert plans['after']['Plan']['Actual Rows'] == plans['before']['Plan']['Actual Rows']
