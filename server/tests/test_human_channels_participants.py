"""P3 identity/storage readiness; public guest traffic remains disabled until P5."""
import json
from pathlib import Path
from uuid import uuid4

import pytest
from pgdbm.errors import QueryError
import asyncpg

from aweb.human_channels.contract import ContractError, decode_record
from aweb.human_channels.participants import derive_guest_reference, scoped_participant_key, project_session_author

ROOT = Path(__file__).resolve().parents[2]
VECTORS = json.loads((ROOT / 'docs/vectors/human-channels-participants-v1.json').read_text())


def record(schema, value):
    return decode_record(schema, json.dumps(value).encode())


def participant(value):
    return record('NativeParticipant' if value['kind'] == 'native' else 'BridgedParticipant', value)


@pytest.mark.parametrize('case', VECTORS['derivations'], ids=lambda c: c['name'])
def test_shared_pairwise_derivation(case):
    inputs = {k: v for k, v in case.items() if k not in ('name', 'expected', 'key_hex')}
    assert derive_guest_reference(bytes.fromhex(case['key_hex']), **inputs).value == case['expected']


@pytest.mark.parametrize('case', VECTORS['projections'], ids=lambda c: c['name'])
def test_shared_author_context_and_assurance(case):
    def project():
        return project_session_author(
            expected_session=case['expected_session'], expected_participant=participant(case['expected_participant']),
            group=record('GroupContext', case['group']), signer_principal=case['signer_principal'],
            signer_verified=case['signer_verified'], confidentiality=case['confidentiality'],
            native_trust_status=case['native_trust_status'])
    if 'error' in case:
        with pytest.raises(ContractError) as refusal:
            project()
        assert refusal.value.code == case['error']
    else:
        assert project().value == case['expected']


def test_derivation_uses_exact_private_scope_and_never_a_bot_or_display_name():
    values = VECTORS['derivations']
    by_name = {v['name']: v['expected'] for v in values}
    assert by_name['same_session_second_bot'] == by_name['same_session']
    original = by_name['same_session']
    for name in ('other_session', 'other_account', 'other_scope', 'bot_subject', 'new_generation', 'lost_key'):
        assert by_name[name] != original
    assert scoped_participant_key(values[0]['session_id'], participant(original)) != scoped_participant_key(
        values[0]['session_id'], participant({'kind':'native','did':original['bridge']}))
    with pytest.raises(ContractError):
        derive_guest_reference(b'short', **{k:v for k,v in values[0].items() if k not in ('name','expected','key_hex')})


@pytest.mark.asyncio
async def test_native_defaults_and_guest_activation_gate(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    sid = uuid4()
    await db.execute("INSERT INTO {{tables.chat_sessions}} (session_id, created_by) VALUES ($1, 'did:aw:alice')", sid)
    await db.execute("INSERT INTO {{tables.chat_participants}} (session_id, did, alias) VALUES ($1, 'did:aw:alice', 'alice')", sid)
    row = await db.fetch_one("SELECT * FROM {{tables.chat_participants}} WHERE session_id=$1", sid)
    assert row['participant_kind'] == 'native' and row['bridge_did'] is None and row['guest_subject'] is None
    await db.execute("INSERT INTO {{tables.conversations}} (conversation_id,conversation_type,created_by_did) VALUES ($1,'chat','did:aw:alice')", sid)
    await db.execute("INSERT INTO {{tables.conversation_participants}} (conversation_id,did,alias,transport_hint) VALUES ($1,'did:aw:alice','alice','chat')", sid)
    with pytest.raises(QueryError) as error:
        await db.execute("INSERT INTO {{tables.conversation_participants}} (conversation_id,participant_kind,bridge_did,guest_subject,alias,transport_hint) VALUES ($1,'bridged','did:aw:bridge','guest-1','same name','chat')", sid)
    assert isinstance(error.value.__cause__, asyncpg.CheckViolationError)
    assert error.value.__cause__.constraint_name == 'conversation_participants_p5_gate'
    # Old ON CONFLICT and native receipt FKs survive the new typed primary key.
    await db.execute("INSERT INTO {{tables.chat_participants}} (session_id, did, alias) VALUES ($1, 'did:aw:alice', 'alice') ON CONFLICT (session_id,did) DO NOTHING", sid)
    message = await db.fetch_one("INSERT INTO {{tables.chat_messages}} (session_id, from_did, from_alias, body) VALUES ($1, 'did:aw:alice', 'alice', 'native') RETURNING message_id", sid)
    await db.execute("INSERT INTO {{tables.chat_message_reads}} (session_id,did,message_id) VALUES ($1,'did:aw:alice',$2)", sid, message['message_id'])
    with pytest.raises(QueryError) as error:
        await db.execute("INSERT INTO {{tables.chat_participants}} (session_id,participant_kind,bridge_did,guest_subject,alias) VALUES ($1,'bridged','did:aw:bridge','guest-1','same name')", sid)
    assert isinstance(error.value.__cause__, asyncpg.CheckViolationError)
    assert error.value.__cause__.constraint_name == 'chat_participants_p5_gate'
    # A guest cannot masquerade as a native DID to evade the gate.
    with pytest.raises(QueryError):
        await db.execute("INSERT INTO {{tables.chat_participants}} (session_id,did,bridge_did,guest_subject,alias) VALUES ($1,'did:aw:bridge','did:aw:bridge','guest-1','same name')", sid)
    await db.execute("DELETE FROM {{tables.chat_participants}} WHERE session_id=$1 AND did='did:aw:alice'", sid)
    assert await db.fetch_value("SELECT COUNT(*) FROM {{tables.chat_message_reads}} WHERE session_id=$1", sid) == 0


@pytest.mark.asyncio
async def test_future_typed_storage_is_exact_and_retains_opt_out(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    # Isolated schema exercise, not public activation. P5 alone may remove these
    # gates in a reviewed migration after consent/label/client readiness.
    await db.execute('ALTER TABLE {{tables.chat_participants}} DROP CONSTRAINT chat_participants_p5_gate')
    await db.execute('ALTER TABLE {{tables.conversation_participants}} DROP CONSTRAINT conversation_participants_p5_gate')
    sid = uuid4()
    await db.execute("INSERT INTO {{tables.chat_sessions}} (session_id,created_by) VALUES ($1,'did:aw:alice')", sid)
    await db.execute("INSERT INTO {{tables.conversations}} (conversation_id,conversation_type,created_by_did) VALUES ($1,'chat','did:aw:alice')", sid)
    for subject_id in ('guest-1','guest-2'):
        await db.execute("INSERT INTO {{tables.chat_participants}} (session_id,participant_kind,bridge_did,guest_subject,alias) VALUES ($1,'bridged','did:aw:bridge',$2,'same name')", sid, subject_id)
        await db.execute("INSERT INTO {{tables.conversation_participants}} (conversation_id,participant_kind,bridge_did,guest_subject,alias,transport_hint) VALUES ($1,'bridged','did:aw:bridge',$2,'same name','chat')", sid, subject_id)
    rows = await db.fetch_all('SELECT * FROM {{tables.chat_participants}} WHERE session_id=$1 ORDER BY guest_subject', sid)
    assert len(rows) == 2 and all(r['did'] is None and r['agent_id'] is None for r in rows)
    assert rows[0]['participant_id'] != rows[1]['participant_id']
    assert await db.fetch_value('SELECT COUNT(*) FROM {{tables.agents}}') == 0
    with pytest.raises(QueryError):
        await db.execute("INSERT INTO {{tables.chat_participants}} (session_id,participant_kind,bridge_did,guest_subject,alias) VALUES ($1,'bridged','did:aw:bridge','guest-1','another name')", sid)
    with pytest.raises(QueryError):
        await db.execute("INSERT INTO {{tables.chat_participants}} (session_id,did,participant_kind,bridge_did,guest_subject,alias) VALUES ($1,'did:aw:alice','bridged','did:aw:bridge','guest-3','same name')", sid)
    for bridge, subject_id in ((None, 'guest-3'), ('did:aw:bridge', None), ('did:key:zBridge', 'guest-3'), ('did:aw:bridge', 'did:aw:pretend-native'), ('did:aw:bridge', 'DID:aw:pretend-native'), ('did:aw:bridge', 'DiD:aw:pretend-native')):
        with pytest.raises(QueryError) as error:
            await db.execute("INSERT INTO {{tables.chat_participants}} (session_id,participant_kind,bridge_did,guest_subject,alias) VALUES ($1,'bridged',$2,$3,'same name')", sid, bridge, subject_id)
        assert isinstance(error.value.__cause__, asyncpg.CheckViolationError)
    await db.execute("UPDATE {{tables.chat_participants}} SET guest_opted_out_at=NOW() WHERE session_id=$1 AND guest_subject='guest-1'", sid)
    # A future native link adds another distinct participant; it cannot rewrite
    # the historical guest ref or erase the guest's refusal tombstone.
    await db.execute("INSERT INTO {{tables.chat_participants}} (session_id,did,alias) VALUES ($1,'did:aw:linked-human','same name')", sid)
    old = await db.fetch_one("SELECT * FROM {{tables.chat_participants}} WHERE session_id=$1 AND guest_subject='guest-1'", sid)
    assert old['guest_opted_out_at'] is not None and old['did'] is None
    for wrong_sid, bridge, subject_id in ((uuid4(),'did:aw:bridge','guest-1'), (sid,'did:aw:other','guest-1'), (sid,'did:aw:bridge','missing')):
        assert not await db.fetch_value('SELECT EXISTS(SELECT 1 FROM {{tables.chat_participants}} WHERE session_id=$1 AND bridge_did=$2 AND guest_subject=$3)', wrong_sid, bridge, subject_id)
    assert not await db.fetch_value("SELECT EXISTS(SELECT 1 FROM {{tables.chat_participants}} WHERE session_id=$1 AND did='did:aw:bridge')", sid)


from test_dashboard_privacy import TEAM, privacy_app, _request  # noqa: F401


@pytest.mark.asyncio
async def test_live_native_creation_and_managed_refusal_have_no_side_effects(privacy_app):
    env = privacy_app
    response = await _request(env, 'alice', 'POST', '/v1/chat/sessions', {'to_dids':[env.actors['bob'].did],'message':'native P3 neighbor'})
    assert response.status_code == 200, response.text
    body = response.json()
    assert {p['participant_ref']['did'] for p in body['participants']} == {env.actors['alice'].did,env.actors['bob'].did}
    assert all(p['participant_ref']['kind'] == 'native' for p in body['participants'])
    counts = await env.db.fetch_one('SELECT (SELECT COUNT(*) FROM {{tables.chat_messages}}) AS messages,(SELECT COUNT(*) FROM {{tables.chat_participants}}) AS participants,(SELECT COUNT(*) FROM {{tables.agents}}) AS agents')
    mutations = len(env.dispatched)
    guest = VECTORS['derivations'][0]['expected']
    response = await _request(env, 'alice', 'POST', '/v1/chat/sessions', {'participants':[guest],'message':'must refuse'})
    assert response.status_code == 422, response.text
    assert counts == await env.db.fetch_one('SELECT (SELECT COUNT(*) FROM {{tables.chat_messages}}) AS messages,(SELECT COUNT(*) FROM {{tables.chat_participants}}) AS participants,(SELECT COUNT(*) FROM {{tables.agents}}) AS agents')
    assert len(env.dispatched) == mutations


@pytest.mark.asyncio
async def test_typed_guest_metadata_never_resolves_the_bridge_as_the_human(aweb_cloud_db):
    from aweb.identity_metadata import lookup_participant_identity_metadata, routable_chat_address
    db = aweb_cloud_db.aweb_db
    await db.execute("INSERT INTO {{tables.teams}} (team_id,namespace,team_name,team_did_key) VALUES ('team:example.test','example.test','team','did:key:zTeam')")
    await db.execute("INSERT INTO {{tables.agents}} (team_id,did_key,did_aw,alias,identity_scope,inbound_mode) VALUES ('team:example.test','did:key:zBridge','did:aw:bridge','Bridge','global','open')")
    guest = participant(VECTORS['derivations'][0]['expected'])
    meta = await lookup_participant_identity_metadata(db, guest)
    assert meta['participant_kind'] == 'bridged'
    assert 'agent_id' not in meta and 'stable_id' not in meta and 'alias' not in meta
    assert routable_chat_address(meta, 'team:example.test', 'Same name') == ''
    native = await lookup_participant_identity_metadata(db, participant({'kind':'native','did':'did:aw:bridge'}))
    assert native['stable_id'] == 'did:aw:bridge' and native['alias'] == 'Bridge'


@pytest.mark.asyncio
async def test_populated_pre_p3_upgrade_preserves_native_rows_and_receipt_fk(shared_test_pool, tmp_path):
    import shutil
    from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
    root = ROOT / 'server/src/aweb/migrations/aweb'
    before = tmp_path / 'before_p3'
    before.mkdir()
    for path in root.glob('*.sql'):
        if path.name < '033_typed_chat_participants.sql':
            shutil.copyfile(path, before / path.name)
    await AsyncDatabaseManager(pool=shared_test_pool, schema=None).execute('CREATE SCHEMA aweb')
    db = AsyncDatabaseManager(pool=shared_test_pool, schema='aweb')
    def migrations(path):
        return AsyncMigrationManager(db, migrations_path=str(path), module_name='aweb-aweb', migrations_table='schema_migrations')
    await migrations(before).apply_pending_migrations()
    sid = uuid4()
    await db.execute("INSERT INTO {{tables.chat_sessions}} (session_id,created_by) VALUES ($1,'legacy-native-did')", sid)
    await db.execute("INSERT INTO {{tables.conversations}} (conversation_id,conversation_type,created_by_did) VALUES ($1,'chat','legacy-native-did')", sid)
    await db.execute("INSERT INTO {{tables.chat_participants}} (session_id,did,alias) VALUES ($1,'legacy-native-did','Legacy')", sid)
    await db.execute("INSERT INTO {{tables.conversation_participants}} (conversation_id,did,alias,transport_hint) VALUES ($1,'legacy-native-did','Legacy','chat')", sid)
    message = await db.fetch_one("INSERT INTO {{tables.chat_messages}} (session_id,from_did,from_alias,body) VALUES ($1,'legacy-native-did','Legacy','old message') RETURNING message_id", sid)
    await db.execute("INSERT INTO {{tables.chat_message_reads}} (session_id,did,message_id) VALUES ($1,'legacy-native-did',$2)", sid, message['message_id'])
    old = await db.fetch_one('SELECT * FROM {{tables.chat_participants}} WHERE session_id=$1', sid)
    old_conversation = await db.fetch_one('SELECT * FROM {{tables.conversation_participants}} WHERE conversation_id=$1', sid)
    await migrations(root).apply_pending_migrations()
    new = await db.fetch_one('SELECT * FROM {{tables.chat_participants}} WHERE session_id=$1', sid)
    new_conversation = await db.fetch_one('SELECT * FROM {{tables.conversation_participants}} WHERE conversation_id=$1', sid)
    assert dict(old) == {k:new[k] for k in old}
    assert dict(old_conversation) == {k:new_conversation[k] for k in old_conversation}
    assert new['participant_kind'] == new_conversation['participant_kind'] == 'native'
    assert await db.fetch_value('SELECT COUNT(*) FROM {{tables.chat_message_reads}} WHERE session_id=$1', sid) == 1
    await db.execute("DELETE FROM {{tables.chat_participants}} WHERE session_id=$1 AND did='legacy-native-did'", sid)
    assert await db.fetch_value('SELECT COUNT(*) FROM {{tables.chat_message_reads}} WHERE session_id=$1', sid) == 0


@pytest.mark.asyncio
async def test_native_embedding_cannot_discard_a_guest_tag(aweb_cloud_db):
    from aweb.messaging.chat import ensure_session
    from aweb.messaging.conversations import create_conversation
    from aweb.service_errors import ValidationError
    class DB:
        def get_manager(self, name):
            return aweb_cloud_db.aweb_db
    db = DB()
    alice = {'did':'did:aw:alice','alias':'Alice','transport_hint':'chat'}
    disguised = {'did':'did:aw:bridge','alias':'Same name','transport_hint':'chat','participant_ref':VECTORS['derivations'][0]['expected']}
    with pytest.raises(ValidationError):
        await ensure_session(db, team_id=None, participant_rows=[alice,disguised], created_by=alice['did'])
    with pytest.raises(ValidationError):
        await create_conversation(db, conversation_type='chat', created_by_did=alice['did'], initiator=alice, recipients=[disguised])
    assert await aweb_cloud_db.aweb_db.fetch_value('SELECT COUNT(*) FROM {{tables.chat_sessions}}') == 0
    assert await aweb_cloud_db.aweb_db.fetch_value('SELECT COUNT(*) FROM {{tables.conversations}}') == 0
