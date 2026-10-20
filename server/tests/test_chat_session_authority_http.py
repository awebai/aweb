"""Session UUIDs never grant thread membership: real app, PG, Redis and HTTP."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from awid.signing import canonical_json_bytes, sign_message
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401
from test_messages_http import _make_keypair


async def _foreign_actors(env):
    team = f"foreign-{uuid4().hex[:12]}:example.test"
    _, _, controller = _make_keypair()
    await env.db.execute(
        "INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key) "
        "VALUES ($1, 'example.test', $2, $3)", team, team.split(':')[0], controller,
    )
    for alias in ('mallory', 'eve'):
        sk, _, did = _make_keypair()
        agent_id = uuid4()
        await env.db.execute(
            "INSERT INTO {{tables.agents}} (agent_id, team_id, did_key, alias, identity_scope, inbound_mode) "
            "VALUES ($1, $2, $3, $4, 'local', 'open')", agent_id, team, did, alias,
        )
        env.actors[alias] = SimpleNamespace(sk=sk, did=did, id=agent_id)


async def _snapshot(env):
    result = {}
    for table in ('conversations', 'conversation_participants', 'chat_sessions', 'chat_participants', 'messages', 'chat_messages'):
        rows = await env.db.fetch_all(f"SELECT row_to_json(t)::text AS row FROM {{{{tables.{table}}}}} t")
        result[table] = sorted(row['row'] for row in rows)
    return result


async def _chat(env, sender, recipients, **fields):
    return await _request(env, sender, 'POST', '/v1/chat/sessions', {
        'to_dids': [env.actors[alias].did for alias in recipients], 'message': 'private chat', **fields,
    })


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['mail', 'chat'])
@pytest.mark.parametrize('foreign', [False, True], ids=['same-team', 'other-team'])
async def test_create_cannot_inject_membership_into_known_thread(privacy_app, kind, foreign):
    env = privacy_app
    await _foreign_actors(env)
    if kind == 'mail':
        seed = await _request(env, 'alice', 'POST', '/v1/messages', {
            'to_did': env.actors['bob'].did, 'subject': 'secret', 'body': 'private mail',
        })
    else:
        seed = await _chat(env, 'alice', ['bob'])
    assert seed.status_code == 200, seed.text
    thread = seed.json()['conversation_id']
    attacker, recipients = ('mallory', ['eve']) if foreign else ('carol', ['bob'])
    path = f'/v1/messages/conversations/{thread}'
    assert (await _request(env, attacker, 'GET', path)).status_code == 404
    before = await _snapshot(env)
    effects = list(env.dispatched)

    # The original PoC: create a session with a victim thread UUID, then read it.
    response = await _chat(env, attacker, recipients, session_id=thread)
    after = await _snapshot(env)
    read = await _request(env, attacker, 'GET', path)
    assert read.status_code == 404, read.text
    assert after == before, 'refused create changed thread or participant state'
    assert env.dispatched == effects
    assert response.status_code == 409, response.text
    participant_path = path if kind == 'mail' else f'/v1/chat/sessions/{thread}/messages'
    assert (await _request(env, 'bob', 'GET', participant_path)).status_code == 200


@pytest.mark.asyncio
async def test_participant_reuse_does_not_add_or_update_create_participants(privacy_app):
    env = privacy_app
    seed = await _chat(env, 'alice', ['bob'])
    assert seed.status_code == 200, seed.text
    thread = seed.json()['session_id']
    before = await _snapshot(env)
    # A real participant may reuse the id; a new target is not a membership grant.
    response = await _chat(env, 'alice', ['bob', 'carol'], session_id=thread)
    assert response.status_code == 200, response.text
    after = await _snapshot(env)
    for table in ('conversation_participants', 'chat_participants'):
        assert after[table] == before[table]
    assert (await _request(env, 'carol', 'GET', f'/v1/messages/conversations/{thread}')).status_code == 404
    again = await _chat(env, 'bob', ['alice'], session_id=thread)
    assert again.status_code == 200, again.text
    assert again.json()['session_id'] == thread


@pytest.mark.asyncio
async def test_removed_participant_cannot_reuse_session(privacy_app):
    env = privacy_app
    seed = await _chat(env, 'alice', ['bob'])
    thread = seed.json()['session_id']
    await env.db.execute(
        'UPDATE {{tables.chat_participants}} SET left_at = NOW() WHERE session_id = $1 AND did = $2',
        UUID(thread), env.actors['alice'].did,
    )
    before = await _snapshot(env)
    response = await _chat(env, 'alice', ['bob'], session_id=thread)
    assert response.status_code == 409, response.text
    assert await _snapshot(env) == before


@pytest.mark.asyncio
async def test_fresh_signed_session_uuid_remains_supported(privacy_app):
    env = privacy_app
    thread, message = str(uuid4()), str(uuid4())
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    signed = canonical_json_bytes({
        'type': 'chat', 'from': env.actors['alice'].did, 'from_did': env.actors['alice'].did,
        'to': env.actors['bob'].did, 'to_did': env.actors['bob'].did,
        'body': 'private chat', 'conversation_id': thread, 'message_id': message,
        'timestamp': timestamp, 'wait_seconds': 0,
    }).decode()
    response = await _chat(env, 'alice', ['bob'], session_id=thread, message_id=message,
        timestamp=timestamp, from_did=env.actors['alice'].did, wait_seconds=0,
        signed_payload=signed, signature=sign_message(env.actors['alice'].sk, signed.encode()))
    assert response.status_code == 200, response.text
    assert response.json()['session_id'] == thread


@pytest.mark.asyncio
async def test_concurrent_fresh_uuid_collision_never_joins_loser(privacy_app):
    env = privacy_app
    await _foreign_actors(env)
    thread = str(uuid4())
    requests = []
    # Let both requests finish their reads before either can insert a session.
    async with env.db.transaction() as tx:
        await tx.execute('LOCK TABLE {{tables.chat_sessions}} IN SHARE MODE')
        requests = [asyncio.create_task(_chat(env, sender, [recipient], session_id=thread))
                    for sender, recipient in [('alice', 'bob'), ('mallory', 'eve')]]
        try:
            async with asyncio.timeout(5):
                while True:
                    waiting = await env.db.fetch_value(
                        "SELECT count(*) FROM pg_locks WHERE relation = 'aweb.chat_sessions'::regclass "
                        "AND mode = 'RowExclusiveLock' AND NOT granted"
                    )
                    if waiting >= 2:
                        break
                    if any(task.done() for task in requests):
                        raise AssertionError('request ended before the concurrent insert barrier')
                    await asyncio.sleep(0.01)
        except BaseException:
            for task in requests:
                task.cancel()
            await asyncio.gather(*requests, return_exceptions=True)
            raise
    responses = await asyncio.gather(*requests)
    assert sorted(response.status_code for response in responses) == [200, 409], [r.text for r in responses]
    winner = 0 if responses[0].status_code == 200 else 1
    groups = [('alice', 'bob'), ('mallory', 'eve')]
    participants = await env.db.fetch_all(
        'SELECT did FROM {{tables.conversation_participants}} WHERE conversation_id = $1', UUID(thread),
    )
    assert {row['did'] for row in participants} == {env.actors[a].did for a in groups[winner]}
    for actor in groups[1 - winner]:
        assert (await _request(env, actor, 'GET', f'/v1/messages/conversations/{thread}')).status_code == 404


@pytest.mark.asyncio
async def test_mail_participant_cannot_convert_their_thread_to_chat(privacy_app):
    env = privacy_app
    mail = await _request(env, 'alice', 'POST', '/v1/messages', {
        'to_did': env.actors['bob'].did, 'subject': 'secret', 'body': 'private mail',
    })
    assert mail.status_code == 200, mail.text
    before = await _snapshot(env)
    response = await _chat(env, 'alice', ['bob'], session_id=mail.json()['conversation_id'])
    assert response.status_code == 409, response.text
    assert await _snapshot(env) == before


@pytest.mark.asyncio
async def test_legacy_reuse_projects_only_stored_participants(privacy_app):
    env = privacy_app
    thread = uuid4()
    await env.db.execute(
        'INSERT INTO {{tables.chat_sessions}} (session_id, team_id, created_by) VALUES ($1, $2, $3)',
        thread, TEAM, 'alice',
    )
    for alias in ('alice', 'bob'):
        actor = env.actors[alias]
        await env.db.execute(
            'INSERT INTO {{tables.chat_participants}} (session_id, did, agent_id, alias) VALUES ($1, $2, $3, $4)',
            thread, actor.did, actor.id, alias,
        )
    response = await _chat(env, 'alice', ['carol'], session_id=str(thread))
    assert response.status_code == 200, response.text
    participants = await env.db.fetch_all(
        'SELECT did FROM {{tables.conversation_participants}} WHERE conversation_id = $1', thread,
    )
    assert {row['did'] for row in participants} == {env.actors[a].did for a in ('alice', 'bob')}
    assert (await _request(env, 'carol', 'GET', f'/v1/messages/conversations/{thread}')).status_code == 404


@pytest.mark.asyncio
async def test_remote_identity_cannot_borrow_target_membership_on_create(privacy_app):
    env = privacy_app
    victim = await _chat(env, 'alice', ['bob'])
    assert victim.status_code == 200, victim.text
    thread = victim.json()['session_id']
    # A remote self-custodial caller has no local agent/team row. Its target
    # is a victim-session member; target-first ordering would grant access.
    sk, _, did = _make_keypair()
    env.actors['remote'] = SimpleNamespace(sk=sk, did=did, id=None)
    fresh = await _chat(env, 'remote', ['bob'])
    assert fresh.status_code == 200, fresh.text
    before = await _snapshot(env)
    response = await _chat(env, 'remote', ['bob'], session_id=thread)
    assert response.status_code == 409, response.text
    assert await _snapshot(env) == before
    denied = await _request(env, 'remote', 'GET', f'/v1/chat/sessions/{thread}/messages')
    assert denied.status_code == 404, denied.text


@pytest.mark.asyncio
async def test_federated_sender_cannot_join_known_session_by_uuid(privacy_app):
    from test_chat_http import _federated_chat_payload

    env = privacy_app
    victim = await _chat(env, 'alice', ['bob'])
    assert victim.status_code == 200, victim.text
    thread = victim.json()['session_id']
    sk, _, did = _make_keypair()
    payload = _federated_chat_payload(
        sender_sk=sk, sender_did_key=did, sender_did_aw=did,
        sender_address='remote.example/outsider',
        target_address='example.test/bob', target_did_key=env.actors['bob'].did,
        conversation_id=thread, signed_to_did=env.actors['bob'].did,
    )
    # The wrapper and signed envelope name the actual local recipient.
    payload['envelope']['target_did_aw'] = env.actors['bob'].did
    before = await _snapshot(env)
    response = await env.client.post('/v1/federation/messages', json=payload)
    assert response.status_code == 409, response.text
    assert response.json()['reason'] == 'federation_conversation_invalid'
    assert await _snapshot(env) == before
