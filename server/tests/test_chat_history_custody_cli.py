"""Real encrypted chat history through a grant, Unix custody and aweb/AWID/PG.

The HTTP front only records requests and adds latency; all responses, authority
checks, stored-message reads and cryptography come from the actual services.
"""
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
import time
from types import SimpleNamespace
from urllib.parse import parse_qs
from uuid import uuid4

import pytest

from awid.e2ee_keys import build_encryption_key_assertion
from aweb.e2ee_messages import encrypt_e2ee_chat, generate_x25519_keypair
from test_addressless_sender_cli import _registry_http
from test_cli_human_reply import _cli
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401
from test_e2ee_local_sender_read_trust import _local_sender_mail


@asynccontextmanager
async def encrypted_history(env, root, count):
    observed = SimpleNamespace(stored=[], history=[], unwrap_delay=0, history_delay=0)

    async def front(scope, receive, send):
        if scope['type'] == 'http' and scope['method'] == 'GET' and scope['path'].endswith('/messages'):
            query = parse_qs(scope.get('query_string', b'').decode())
            if 'message_id' in query:
                observed.stored.append(query['message_id'][0])
                await asyncio.sleep(observed.unwrap_delay)
            else:
                observed.history.append(query)
                await asyncio.sleep(observed.history_delay)
        await env.app(scope, receive, send)

    async with _registry_http(front) as (url, _):
        env.client.base_url = url
        async with _local_sender_mail(env, root, False, True, False) as (
                _, _, binary, cwd, command_env, _):
            assertion = json.loads((root / '.aw' / 'assertion.json').read_text())
            recipient = dict(did=env.actors['bob'].did, team_id=TEAM, encryption_key=assertion)
            sessions = {}
            bodies = {}
            for name, size in [('alice', count), ('carol', 1)]:
                actor = env.actors[name]
                _, public = generate_x25519_keypair()
                sender = dict(did=actor.did, team_id=TEAM, signing_key=actor.sk,
                              encryption_key=build_encryption_key_assertion(
                                  signing_key=actor.sk, identity_did=actor.did, identity_stable_id='',
                                  encryption_public_key=public, custody='self', now=datetime.now(timezone.utc)))
                cid = str(uuid4())
                sessions[name] = cid
                for index in range(size):
                    mid = str(uuid4())
                    bodies[mid] = f'{name} private history {index}'
                    envelope = encrypt_e2ee_chat(sender=sender, recipients=[recipient], body=bodies[mid],
                                                 message_id=mid, conversation_id=cid)
                    wire = dict(content_mode='encrypted_v2', message_version=2, encrypted_envelope=envelope,
                                message_id=mid, timestamp=envelope['created_at'], from_did=actor.did)
                    if index == 0:
                        path = '/v1/chat/sessions'
                        wire.update(session_id=cid, to_dids=[recipient['did']], message='')
                    else:
                        path = f'/v1/chat/sessions/{cid}/messages'
                        wire['body'] = ''
                    sent = await _request(env, name, 'POST', path, wire)
                    assert sent.status_code == 200, sent.text
            observed.stored.clear()
            observed.history.clear()
            yield binary, cwd, command_env, sessions, bodies, observed


@pytest.mark.usefixtures('source_cli_binary')
@pytest.mark.asyncio
async def test_recipient_history_limits_before_custody_and_skips_unrelated_previews(privacy_app, tmp_path):
    async with encrypted_history(privacy_app, tmp_path, 6) as (binary, cwd, env, sessions, bodies, observed):
        result = await _cli(binary, cwd, env, 'chat', 'history', 'alice', '--limit', '2', '--unread-only', '--json')
        messages = result['messages']
        assert result['session_id'] == sessions['alice']
        assert len(messages) == 2
        assert observed.history == [{'limit': ['2'], 'unread_only': ['true']}]
        assert observed.stored == [message['message_id'] for message in messages]
        assert all(message['body'] == bodies[message['message_id']] for message in messages)


@pytest.mark.usefixtures('source_cli_binary')
@pytest.mark.asyncio
@pytest.mark.parametrize('by_session', [False, True])
async def test_encrypted_history_has_per_request_not_whole_command_timeout(privacy_app, tmp_path, by_session):
    async with encrypted_history(privacy_app, tmp_path, 6) as (binary, cwd, env, sessions, bodies, observed):
        observed.unwrap_delay = 0.65  # Six real stored reads exceed the 2s API budget together.
        command_env = dict(env, AWEB_HTTP_TIMEOUT='2s')
        target = ['--session-id', sessions['alice']] if by_session else ['alice']
        result = await _cli(binary, cwd, command_env, 'chat', 'history', *target, '--limit', '6', '--json')
        messages = result['messages']
        assert len(messages) == 6
        assert observed.stored == [message['message_id'] for message in messages]
        assert all(message['body'] == bodies[message['message_id']] for message in messages)


@pytest.mark.usefixtures('source_cli_binary')
@pytest.mark.asyncio
async def test_history_keeps_the_individual_http_timeout(privacy_app, tmp_path):
    async with encrypted_history(privacy_app, tmp_path, 1) as (binary, cwd, env, sessions, _, observed):
        observed.history_delay = 4
        started = time.monotonic()
        process = await asyncio.create_subprocess_exec(
            str(binary), 'chat', 'history', '--session-id', sessions['alice'], '--limit', '1', '--json',
            cwd=cwd, env=dict(env, AWEB_HTTP_TIMEOUT='1s'),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(process.communicate(), 10)
        assert process.returncode != 0
        assert stderr
        assert time.monotonic() - started < 3
        assert observed.history == [{'limit': ['1']}]
        # Under --json the failure's stdout is its error envelope alone,
        # carrying the same message as stderr.
        envelope = json.loads(stdout)
        assert set(envelope) == {'error'}, stdout
        assert envelope['error']['message'] and envelope['error']['message'] in stderr.decode(), (stdout, stderr)
        assert not observed.stored
