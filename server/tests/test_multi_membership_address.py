"""One global recipient, two team memberships: preserve the addressed route."""
import json
import os
from types import SimpleNamespace
from uuid import UUID, uuid4
from datetime import datetime, timezone

from aweb.human_channels.http import _target
from aweb.human_channels.contract import ContractError
from aweb.identity_auth_deps import MessagingAuth
from aweb.messaging.conversations import create_conversation

import pytest
import pytest_asyncio
from awid.signing import canonical_json_bytes, sign_message
from identity_binding_support import register_global_identity
from test_addressless_sender_cli import _registry_http
from test_cli_human_reply import _cli, _pem
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_messages_http import _make_certificate, _signed_identity_headers


@pytest_asyncio.fixture
async def addressed_human(privacy_app, tmp_path):
    env = privacy_app
    stable = {}
    for name in ("alice", "bob"):
        actor = env.actors[name]
        address = f"example.test/{name}"
        stable[name] = await register_global_identity(env, actor, address)
        key = await env.app.state.awid_registry_client.resolve_key_fresh(stable[name])
        assert key.current_did_key == actor.did
        await env.db.execute(
            "UPDATE {{tables.agents}} SET did_aw=$1,address=$2,identity_scope='global',did_aw_verified_key=did_key WHERE agent_id=$3",
            stable[name], address, actor.id,
        )
    await env.db.execute("UPDATE {{tables.agents}} SET agent_type='human' WHERE agent_id=$1", env.actors['alice'].id)
    partner_team, partner_actor = f"partner-{uuid4().hex[:12]}:partner.test", uuid4()
    await env.db.execute(
        "INSERT INTO {{tables.teams}} (team_id,namespace,team_name,team_did_key) VALUES ($1,'partner.test','partner',$2)", partner_team, env.team_did,
    )
    namespace = await env.registry_db.fetch_one(
        "INSERT INTO {{tables.dns_namespaces}} (domain,controller_did,verification_status) VALUES ('partner.test',$1,'verified') RETURNING namespace_id", env.team_did,
    )
    await env.registry_db.execute(
        "INSERT INTO {{tables.public_addresses}} (namespace_id,name,did_aw) VALUES ($1,'alice',$2)", namespace['namespace_id'], stable['alice'],
    )
    # A later membership of the SAME verified global human, as in the real walk.
    await env.db.execute(
        """INSERT INTO {{tables.agents}} (agent_id,team_id,alias,did_key,did_aw,did_aw_verified_key,address,identity_scope,agent_type,inbound_mode,created_at)
        VALUES ($1,$2,'alice',$3,$4,$3,'partner.test/alice','global','human','open',NOW()+INTERVAL '1 second')""",
        partner_actor, partner_team, env.actors['alice'].did, stable['alice'],
    )
    actor = env.actors['bob']
    home = tmp_path / '.aw'
    home.mkdir(mode=0o700)
    (home / 'team-certs').mkdir(mode=0o700)
    cert = _make_certificate(env.team_sk, env.team_did, actor.did, team_id=TEAM, alias='bob', identity_scope='global', member_did_aw=stable['bob'], member_address='example.test/bob')
    cert.pop('signature')
    cert['signature'] = sign_message(env.team_sk, canonical_json_bytes(cert))
    cert_path = 'team-certs/' + TEAM.replace('__', '____').replace(':', '__') + '.pem'
    (home / cert_path).write_text(json.dumps(cert))
    membership = {'team_id': TEAM, 'alias': 'bob', 'cert_path': cert_path}
    (home / 'teams.yaml').write_text(json.dumps({'active_team': TEAM, 'memberships': [membership]}))
    (home / 'workspace.yaml').write_text(json.dumps({'aweb_url': str(env.client.base_url), 'memberships': [{**membership, 'workspace_id': str(actor.workspace)}]}))
    (home / 'identity.yaml').write_text(json.dumps({'did': actor.did, 'stable_id': stable['bob'], 'address': 'example.test/bob', 'custody': 'self', 'identity_scope': 'global'}))
    _pem(home / 'signing.key', 'ED25519 PRIVATE KEY', actor.sk)
    child = {key: value for key, value in os.environ.items() if not key.startswith(('AW', 'XDG_'))}
    child.update(HOME=str(tmp_path), PWD=str(tmp_path), XDG_CONFIG_HOME=str(tmp_path / '.config'), AW_NO_UPDATE_CHECK='1', AWEB_URL=str(env.client.base_url))
    env.stable = stable
    async with _registry_http(env.registry_app) as (registry_url, _):
        child['AWID_REGISTRY_URL'] = registry_url
        yield SimpleNamespace(env=env, cwd=tmp_path, child=child)


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['mail', 'chat'])
@pytest.mark.parametrize('address', ['example.test/alice', 'partner.test/alice'])
@pytest.mark.parametrize('same_namespace', [False, True])
async def test_cli_new_and_continued_message_keep_identity_and_address(addressed_human, source_cli_binary, kind, address, same_namespace):
    fixture = addressed_human
    env = fixture.env
    if same_namespace:
        team = f"neighbor-{uuid4().hex[:12]}:example.test"
        await env.db.execute("INSERT INTO {{tables.teams}} (team_id,namespace,team_name,team_did_key) VALUES ($1,'example.test','neighbor',$2)", team, env.team_did)
        await env.db.execute("""INSERT INTO {{tables.agents}} (team_id,alias,did_key,did_aw,did_aw_verified_key,address,identity_scope,agent_type,inbound_mode)
            VALUES ($1,'alice',$2,$3,$2,'example.test/alice','global','human','open')""", team, env.actors['alice'].did, env.stable['alice'])
    if kind == 'mail':
        args = ['mail', 'send', '--to-address', address, '--subject', 'Explicit route', '--body', 'first']
    else:
        args = ['chat', 'send-and-wait', address, 'first', '--start-conversation', '--wait', '1']
    result = await _cli(source_cli_binary, fixture.cwd, fixture.child, *args, '--plaintext', '--json')
    cid = result['conversation_id'] if kind == 'mail' else result['session_id']
    table, id_column = ('conversation_participants', 'conversation_id') if kind == 'mail' else ('chat_participants', 'session_id')
    participant = await env.db.fetch_one(
        'SELECT agent_id,address FROM {{tables.' + table + '}} WHERE ' + id_column + '=$1 AND did=$2', UUID(cid), env.stable['alice'],
    )
    assert participant['agent_id'] is None
    assert participant['address'] == address
    # A stale/wrong actor projection cannot redirect the subsequent send.
    await env.db.execute('UPDATE {{tables.' + table + '}} SET agent_id=$1 WHERE ' + id_column + '=$2 AND did=$3', env.actors['carol'].id, UUID(cid), env.stable['alice'])
    if kind == 'mail':
        args = ['mail', 'send', '--conversation-id', cid, '--body', 'continued']
    else:
        args = ['chat', 'send', '--session-id', cid, '--body', 'continued']
    continued = await _cli(source_cli_binary, fixture.cwd, fixture.child, *args, '--plaintext', '--json')
    if kind == 'mail':
        assert continued['conversation_id'] == cid
    else:
        assert continued['delivered'] is True
    message_table = 'messages' if kind == 'mail' else 'chat_messages'
    messages = await env.db.fetch_all('SELECT signed_payload FROM {{tables.' + message_table + '}} WHERE ' + id_column + '=$1 ORDER BY created_at', UUID(cid))
    assert len(messages) == 2
    assert json.loads(messages[0]['signed_payload'])['to'] == address


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['mail', 'chat'])
async def test_native_continuation_uses_did_and_ignores_stored_actor(addressed_human, kind):
    env = addressed_human.env
    alice, bob = env.actors['alice'], env.actors['bob']
    cid = uuid4()
    if kind == 'mail':
        await create_conversation(env.infra, conversation_type='mail', conversation_id=str(cid),
            team_id=TEAM, created_by_did=env.stable['bob'],
            initiator={'did': env.stable['bob'], 'agent_id': bob.id, 'alias': 'bob', 'transport_hint': 'local'},
            recipients=[{'did': env.stable['alice'], 'agent_id': alice.id, 'alias': 'alice', 'address': 'example.test/alice', 'transport_hint': 'local'}])
    else:
        await env.db.execute("INSERT INTO {{tables.chat_sessions}} (session_id,team_id,created_by) VALUES ($1,$2,$3)", cid, TEAM, env.stable['bob'])
        for name in ('alice', 'bob'):
            await env.db.execute("INSERT INTO {{tables.chat_participants}} (session_id,did,agent_id,alias,address) VALUES ($1,$2,$3,$4,$5)", cid, env.stable[name], env.actors[name].id, name, f'example.test/{name}')
    table, column = ('conversation_participants', 'conversation_id') if kind == 'mail' else ('chat_participants', 'session_id')
    await env.db.execute('UPDATE {{tables.' + table + '}} SET agent_id=$1 WHERE ' + column + '=$2 AND did=$3', env.actors['carol'].id, cid, env.stable['alice'])
    auth = MessagingAuth(did_key=bob.did, did_aw=env.stable['bob'], address='example.test/bob', team_id=TEAM, agent_id=str(bob.id), alias='bob')
    payload = SimpleNamespace(conversation_id=str(cid))
    selected = await _target(None, payload, auth, env.infra, kind, str(cid) if kind == 'chat' else None)
    assert selected['did_aw'] == env.stable['alice']
    assert selected['agent_id'] is None
    assert selected['address'] == 'example.test/alice'
    # Native ingress has no new address selector authority; it continues a stored route.
    with pytest.raises(ContractError) as refused:
        await _target(None, SimpleNamespace(to_address='example.test/alice'), auth, env.infra, kind, None)
    assert refused.value.code == 'unsupported'


@pytest.mark.asyncio
@pytest.mark.parametrize('field', ['to_did', 'to_stable_id'])
async def test_address_binding_mismatch_still_refuses_without_writes(addressed_human, field):
    env = addressed_human.env
    bob = env.actors['bob']
    mid, cid = str(uuid4()), str(uuid4())
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    signed = {'type': 'mail', 'from_did': bob.did, 'from_stable_id': env.stable['bob'], 'to': 'example.test/alice',
        'to_did': env.actors['alice'].did, 'to_stable_id': env.stable['alice'], 'message_id': mid, 'conversation_id': cid,
        'subject': 'Must refuse', 'body': 'no effects', 'timestamp': timestamp}
    signed[field] = env.actors['carol'].did if field == 'to_did' else env.stable['bob']
    encoded = canonical_json_bytes(signed).decode()
    body = {'to_address': 'example.test/alice', 'subject': signed['subject'], 'body': signed['body'], 'from_did': bob.did,
        'message_id': mid, 'conversation_id': cid, 'timestamp': timestamp, 'signed_payload': encoded, 'signature': sign_message(bob.sk, encoded.encode())}
    raw = json.dumps(body).encode()
    response = await env.client.post('/v1/messages', content=raw, headers={'Content-Type': 'application/json', **_signed_identity_headers(bob.sk, bob.did, env.stable['bob'], raw)})
    assert response.status_code == 422, response.text
    assert response.json()['detail'] == 'signed_payload recipient must match the mail recipient'
    assert await env.db.fetch_value('SELECT count(*) FROM {{tables.messages}}') == 0
    assert await env.db.fetch_value('SELECT count(*) FROM {{tables.conversations}}') == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['mail', 'chat'])
async def test_membership_projection_never_grants_thread_read_access(addressed_human, kind):
    from test_dashboard_privacy import _request
    env = addressed_human.env
    conv = await create_conversation(env.infra, conversation_type=kind, team_id=TEAM, created_by_did=env.stable['bob'],
        initiator={'did': env.stable['bob'], 'alias': 'bob', 'transport_hint': 'local'},
        recipients=[{'did': env.stable['alice'], 'alias': 'alice', 'agent_id': env.actors['carol'].id, 'transport_hint': 'local'}])
    cid = UUID(conv['conversation_id'])
    if kind == 'mail':
        await env.db.execute("INSERT INTO {{tables.messages}} (conversation_id,from_did,to_did,from_alias,to_alias,subject,body) VALUES ($1,$2,$3,'bob','alice','Private','Private')", cid, env.stable['bob'], env.stable['alice'])
        path, read_path, key = '/v1/conversations?conversation_type=mail', '/v1/messages/conversations/' + str(cid), 'conversations'
    else:
        await env.db.execute("INSERT INTO {{tables.chat_sessions}} (session_id,team_id,created_by) VALUES ($1,$2,$3)", cid, TEAM, env.stable['bob'])
        for name, actor in (('alice', env.actors['carol']), ('bob', env.actors['bob'])):
            await env.db.execute("INSERT INTO {{tables.chat_participants}} (session_id,did,agent_id,alias) VALUES ($1,$2,$3,$4)", cid, env.stable[name], actor.id, name)
        await env.db.execute("INSERT INTO {{tables.chat_messages}} (session_id,from_did,from_alias,body) VALUES ($1,$2,'bob','Private')", cid, env.stable['bob'])
        path, read_path, key = '/v1/chat/pending', '/v1/chat/sessions/' + str(cid) + '/messages', 'pending'
    page = await _request(env, 'carol', 'GET', path)
    assert page.status_code == 200, page.text
    assert page.json()[key] == []
    denied = await _request(env, 'carol', 'GET', read_path)
    assert denied.status_code == 404
