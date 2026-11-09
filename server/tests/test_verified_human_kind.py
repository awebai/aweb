"""Own certificate kind, not the connect payload, controls human treatment.

Real request auth, public registry, chain verifier, PostgreSQL and messaging.
Only DNS is fixture authority. Both cases deliberately send the same human claim.
"""
import json
from uuid import UUID, uuid4

import pytest

from awid.dns_verify import DomainAuthority
from awid_service.deps import get_domain_verifier
from aweb.api import _build_awid_registry_client
from test_dashboard_privacy import privacy_app, TEAM  # noqa: F401
from test_cli_never_grants import registry_listener
from test_id_chain_request_auth import ALICE, ROOT, VECTORS, _signed_fixture_certificate, _fixture_signer
from test_messages_http import _encode_certificate, _make_certificate, _signed_team_headers


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['agent', 'owned-agent', 'human'])
@pytest.mark.parametrize('hint', ['human', 'codex'])
async def test_connect_own_verified_kind_controls_chat_mail_and_roster(privacy_app, monkeypatch, kind, hint):
    env = privacy_app
    domain = f'awtest-kind-{uuid4().hex}.test'
    subject = VECTORS['keys']['bob_agent'] if kind == 'owned-agent' else ALICE
    async with registry_listener(env) as (writer, origin):
        env.registry_app.state.awid_public_origins = (origin,)

        async def exact_dns(selected):
            assert selected == domain
            return DomainAuthority(ROOT['did_key'], origin, '_awid.' + domain)

        env.registry_app.dependency_overrides[get_domain_verifier] = lambda: exact_dns
        monkeypatch.setenv('AWID_REGISTRY_URL', origin)
        monkeypatch.setenv('AWEB_DATABASE_URL', 'postgresql://unused/test')
        cached = _build_awid_registry_client(env.app, redis=env.redis)
        object.__setattr__(cached, '_domain_verifier', exact_dns)
        env.app.state.awid_registry_client = cached
        try:
            await writer.register_did(subject['did_key'], bytes.fromhex(subject['seed_hex']))
            await writer.register_namespace(domain, ROOT['did_key'], bytes.fromhex(ROOT['seed_hex']))
            certificates = []
            if kind == 'owned-agent':
                parent = VECTORS['keys']['bob']
                await writer.register_did(parent['did_key'], bytes.fromhex(parent['seed_hex']))
                human = _signed_fixture_certificate('alice', domain=domain, identity=parent['did_aw'],
                    parent={'kind': 'namespace', 'id': domain}, issuer='root')
                certificates.append(human)
                await writer.register_id_certificate({'v': 1, 'type': 'aweb.id-chain', 'certificates': certificates},
                    signer=_fixture_signer('bob'), expected_head=None, invitation_id=None)
                signed = _signed_fixture_certificate('bob-agent', domain=domain, identity=subject['did_aw'],
                    parent={'kind': 'identity', 'id': parent['did_aw']}, issuer='bob')
            else:
                signed = _signed_fixture_certificate('alice' if kind == 'human' else 'root-agent',
                    domain=domain, identity=subject['did_aw'], parent={'kind': 'namespace', 'id': domain}, issuer='root')
            bundle = {'v': 1, 'type': 'aweb.id-chain', 'certificates': [*certificates, signed]}
            await writer.register_id_certificate(bundle, signer=_fixture_signer('bob_agent' if kind == 'owned-agent' else 'alice'),
                                                  expected_head=None, invitation_id=None)
            cert = _encode_certificate(_make_certificate(env.team_sk, env.team_did, subject['did_key'],
                team_id=TEAM, alias='subject', member_did_aw=subject['did_aw'], certificate_id='kind-subject'))
            body = json.dumps({'agent_type': hint}).encode()
            response = await env.client.post('/v1/connect', content=body, headers={
                **_signed_team_headers(bytes.fromhex(subject['seed_hex']), subject['did_key'], TEAM, cert, body),
                'Content-Type': 'application/json'})
            assert response.status_code == 200, response.text
            row = await env.db.fetch_one('SELECT * FROM {{tables.agents}} WHERE agent_id=$1',
                                        UUID(response.json()['agent_id']))
            # This assertion reproduces the released defect before any new API is used.
            expected_type = 'human' if kind == 'human' else ('agent' if hint == 'human' else hint)
            assert row['agent_type'] == expected_type
            assert response.json()['agent_type'] == expected_type
            assert row['human_verified_key'] == (subject['did_key'] if kind == 'human' else None)
            sender = env.actors['bob']
            headers = _signed_team_headers(sender.sk, sender.did, TEAM, sender.certificate)
            roster = await env.client.get('/v1/agents', headers=headers)
            assert roster.status_code == 200, roster.text
            assert ('subject' in {r['alias'] for r in roster.json()['agents']}) == (kind != 'human')
            for path, payload, expected in [
                ('/v1/chat/sessions', {'to_aliases': ['subject'], 'message': 'hello'}, 422 if kind == 'human' else 200),
                ('/v1/messages', {'to_alias': 'subject', 'subject': 'hello', 'body': 'mail works'}, 200),
            ]:
                body = json.dumps(payload).encode()
                response = await env.client.post(path, content=body, headers={
                    **_signed_team_headers(sender.sk, sender.did, TEAM, sender.certificate, body),
                    'Content-Type': 'application/json'})
                assert response.status_code == expected, response.text
            # The deployment command uses the same public verifier. Default is
            # read-only; only a verified human subject may be stamped on apply.
            from aweb.human_kind_revalidation import revalidate_human_kind
            await env.db.execute("UPDATE {{tables.agents}} SET agent_type='human',human_verified_key=NULL WHERE agent_id=$1", row['agent_id'])
            preview = await revalidate_human_kind(env.db, cached)
            outcome = 'human' if kind == 'human' else 'agent'
            assert preview['outcomes']['active'][outcome] == 1
            assert preview['before'] == preview['after']
            assert preview['stamped'] == 0
            applied = await revalidate_human_kind(env.db, cached, apply=True)
            assert applied['stamped'] == (1 if kind == 'human' else 0)
            assert applied['after']['active']['verified'] == (1 if kind == 'human' else 0)
            if kind == 'human':
                from dataclasses import replace
                from aweb import human_kind_revalidation as revalidation
                observe = revalidation.observe_identity_kind
                # Start with real public human evidence, then vary its row or
                # observation binding at the point just before compare-and-set.
                for change in ('did_key', 'did_aw', 'cross-subject', 'retirement'):
                    await env.db.execute("UPDATE {{tables.agents}} SET did_key=$2,did_aw=$3,human_verified_key=NULL,deleted_at=NULL WHERE agent_id=$1",
                                         row['agent_id'], subject['did_key'], subject['did_aw'])
                    async def changed_observation(client, binding):
                        verified = await observe(client, binding)
                        assert verified.is_human
                        if change == 'cross-subject':
                            return replace(verified, did_key=ROOT['did_key'])
                        if change == 'retirement':
                            await env.db.execute('UPDATE {{tables.agents}} SET deleted_at=NOW() WHERE agent_id=$1', row['agent_id'])
                        elif change == 'did_key':
                            await env.db.execute('UPDATE {{tables.agents}} SET did_key=$2 WHERE agent_id=$1', row['agent_id'], ROOT['did_key'])
                        else:
                            await env.db.execute('UPDATE {{tables.agents}} SET did_aw=$2 WHERE agent_id=$1', row['agent_id'], ROOT['did_aw'])
                        return verified
                    with monkeypatch.context() as patch:
                        patch.setattr(revalidation, 'observe_identity_kind', changed_observation)
                        raced = await revalidate_human_kind(env.db, cached, apply=True)
                    assert raced['stamped'] == 0, change
                    assert raced['unresolved_active'] == 1, change
                    assert raced['changed'] == (0 if change == 'cross-subject' else 1), change
                    assert await env.db.fetch_val('SELECT human_verified_key FROM {{tables.agents}} WHERE agent_id=$1', row['agent_id']) is None
                # Retired human rows are observed and counted, never stamped.
                await env.db.execute('UPDATE {{tables.agents}} SET did_key=$2,did_aw=$3 WHERE agent_id=$1', row['agent_id'], subject['did_key'], subject['did_aw'])
                retired = await revalidate_human_kind(env.db, cached, apply=True)
                assert retired['outcomes']['retired']['human'] == 1
                assert retired['stamped'] == retired['unresolved_active'] == 0
        finally:
            env.app.state.awid_registry_client = writer
            await cached.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize('marker', ['missing', 'wrong-key', 'verified'])
async def test_legacy_label_needs_exact_key_marker_on_every_current_surface(privacy_app, monkeypatch, marker):
    from aweb.mcp.auth import AuthContext
    from aweb.mcp.tools import _common
    from aweb.mcp.tools.agents import list_agents
    from aweb.messaging.messages import get_agent_by_alias, get_agent_by_id
    from aweb.messaging.mail_routing import _require_live_mail_participant, ParticipantRetiredError
    from test_dashboard import _make_jwt

    env = privacy_app
    bob, sender = env.actors['bob'], env.actors['alice']
    key = {'missing': None, 'wrong-key': sender.did, 'verified': bob.did}[marker]
    await env.db.execute("UPDATE {{tables.agents}} SET agent_type='human',human_verified_key=$2 WHERE agent_id=$1", bob.id, key)
    human = marker == 'verified'
    headers = _signed_team_headers(sender.sk, sender.did, TEAM, sender.certificate)
    response = await env.client.get('/v1/agents', headers=headers)
    assert response.status_code == 200, response.text
    rows = {row['alias']: row for row in response.json()['agents']}
    # Display exclusion is deliberately raw-label based and grants no capability.
    assert 'bob' not in rows
    dashboard = await env.client.get(f'/v1/teams/{TEAM}/agents', headers={'X-Dashboard-Token': _make_jwt([TEAM])})
    assert dashboard.status_code == 200, dashboard.text
    assert 'bob' not in {r['alias'] for r in dashboard.json()['agents']}
    detail = await env.client.get(f'/v1/teams/{TEAM}/agents/bob', headers={'X-Dashboard-Token': _make_jwt([TEAM])})
    assert detail.status_code == 404, detail.text
    monkeypatch.setattr(_common, 'get_auth', lambda: AuthContext(certificate_id='privacy-alice',
        team_id=TEAM, agent_id=str(sender.id), workspace_id=str(sender.workspace), alias='alice', did_key=sender.did))
    mcp = json.loads(await list_agents(env.infra, env.redis))
    assert 'bob' not in {r['alias'] for r in mcp['agents']}
    assert (await get_agent_by_alias(env.infra, team_id=TEAM, alias='bob') is None) == human
    looked_up = await get_agent_by_id(env.infra, agent_id=str(bob.id))
    assert looked_up['agent_type'] == ('human' if human else 'unknown')
    for path, payload, expected in [
        ('/v1/chat/sessions', {'to_aliases': ['bob'], 'message': 'hello'}, 422 if human else 200),
        ('/v1/messages', {'to_alias': 'bob', 'subject': 'hello', 'body': 'mail'}, 200),
    ]:
        body = json.dumps(payload).encode()
        response = await env.client.post(path, content=body, headers={
            **_signed_team_headers(sender.sk, sender.did, TEAM, sender.certificate, body),
            'Content-Type': 'application/json'})
        assert response.status_code == expected, response.text
    await env.db.execute('UPDATE {{tables.agents}} SET deleted_at=NOW() WHERE agent_id=$1', bob.id)
    if human:
        with pytest.raises(ParticipantRetiredError):
            await _require_live_mail_participant(env.infra, {'did': bob.did}, {}, human_only=True)
    else:
        await _require_live_mail_participant(env.infra, {'did': bob.did}, {}, human_only=True)


@pytest.mark.asyncio
async def test_connect_rejects_kind_observation_for_another_subject(aweb_cloud_db):
    from aweb.human_kind import observe_identity_kind
    from aweb.identity_binding import IdentityBinding
    from aweb.routes.connect import connect_agent
    from test_connect import _make_keypair

    _, _, key = _make_keypair()
    _, _, other = _make_keypair()
    observed = await observe_identity_kind(None, IdentityBinding(did_key=other))
    kwargs = dict(db=aweb_cloud_db.aweb_db, cert_info={'team_id': 't:example.com', 'alias': 'subject', 'did_key': key},
                  team_did_key=key, hostname='', workspace_path='', repo_origin='', role='', human_name='', agent_type='human')
    for evidence in [observed, {'did_key': key, 'kind': 'human', 'identity_valid': True}]:
        with pytest.raises(ValueError, match='identity_kind_mismatch'):
            await connect_agent(**kwargs, identity_kind=evidence)
    assert await aweb_cloud_db.aweb_db.fetch_val('SELECT count(*) FROM {{tables.agents}}') == 0

    # Chainless local reconnect cannot preserve an old human label or marker.
    connected = await connect_agent(**kwargs)
    await aweb_cloud_db.aweb_db.execute(
        "UPDATE {{tables.agents}} SET agent_type='human',human_verified_key=did_key WHERE agent_id=$1",
        UUID(connected['agent_id']),
    )
    reconnected = await connect_agent(**kwargs)
    row = await aweb_cloud_db.aweb_db.fetch_one('SELECT * FROM {{tables.agents}} WHERE agent_id=$1', UUID(connected['agent_id']))
    assert reconnected['agent_type'] == row['agent_type'] == 'agent'
    assert row['human_verified_key'] is None


@pytest.mark.asyncio
async def test_self_derived_binding_does_not_establish_human_kind(privacy_app, monkeypatch):
    env = privacy_app
    async with registry_listener(env) as (writer, origin):
        monkeypatch.setenv('AWID_REGISTRY_URL', origin)
        monkeypatch.setenv('AWEB_DATABASE_URL', 'postgresql://unused/test')
        cached = _build_awid_registry_client(env.app, redis=env.redis)
        env.app.state.awid_registry_client = cached
        try:
            # ALICE is absent from AWID: only public-key derivation binds this ID.
            cert = _encode_certificate(_make_certificate(env.team_sk, env.team_did, ALICE['did_key'],
                team_id=TEAM, alias='unenrolled', member_did_aw=ALICE['did_aw'], certificate_id='kind-unenrolled'))
            body = json.dumps({'agent_type': 'human'}).encode()
            response = await env.client.post('/v1/connect', content=body, headers={
                **_signed_team_headers(bytes.fromhex(ALICE['seed_hex']), ALICE['did_key'], TEAM, cert, body),
                'Content-Type': 'application/json'})
            assert response.status_code == 200, response.text
            row = await env.db.fetch_one('SELECT * FROM {{tables.agents}} WHERE agent_id=$1',
                                        UUID(response.json()['agent_id']))
            assert row['did_aw_verified_key'] == row['did_key'] == ALICE['did_key']
            assert row['agent_type'] == response.json()['agent_type'] == 'agent'
            assert row['human_verified_key'] is None
            from aweb.human_kind_revalidation import revalidate_human_kind
            await env.db.execute("UPDATE {{tables.agents}} SET agent_type='human' WHERE agent_id=$1", row['agent_id'])
            report = await revalidate_human_kind(env.db, cached, apply=True)
            assert report['outcomes']['active']['unregistered'] == 1
            assert report['stamped'] == 0
            assert report['unresolved_active'] == 1
        finally:
            env.app.state.awid_registry_client = writer
            await cached.aclose()


@pytest.mark.asyncio
async def test_revalidation_cli_defaults_to_read_only_and_reports_unresolved(test_db_factory):
    import asyncio
    import os
    import sys
    from aweb.db import DatabaseInfra
    from awid.db_config import build_database_config
    from pgdbm import AsyncDatabaseManager

    base = await test_db_factory.create_db(suffix='human_revalidation_cli')
    await base.execute('CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public')
    pool = await AsyncDatabaseManager.create_shared_pool(build_database_config(connection_string=base.config.get_dsn()))
    infra = DatabaseInfra()
    await infra.initialize(shared_pool=pool)
    db = infra.get_manager()
    try:
        await db.execute("INSERT INTO {{tables.teams}} (team_id,namespace,team_name,team_did_key) VALUES ('cli:test','test','test',$1)", ALICE['did_key'])
        await db.execute("INSERT INTO {{tables.agents}} (team_id,alias,did_key,agent_type) VALUES ('cli:test','old-human',$1,'human')", ALICE['did_key'])
        for args in ([], ['--apply']):
            child_env = {**os.environ, 'AWEB_DATABASE_URL': base.config.get_dsn()}
            # A server-enforced read-only session proves the default path does
            # not attempt DDL or DML (nor apply for a nonhuman observation).
            dsn = child_env['AWEB_DATABASE_URL']
            child_env['AWEB_DATABASE_URL'] = dsn + ('&' if '?' in dsn else '?') + 'default_transaction_read_only=on'
            process = await asyncio.create_subprocess_exec(sys.executable, '-c',
                'from aweb.cli import app; app()', 'revalidate-human-kind', *args,
                env=child_env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(process.communicate(), 20)
            assert process.returncode == 1, stderr.decode()
            report = json.loads(stdout)
            assert report['apply'] == bool(args)
            assert report['outcomes']['active']['unregistered'] == 1
            assert report['before'] == report['after']
            assert report['stamped'] == 0
            assert report['unresolved_active'] == 1
        assert await db.fetch_val('SELECT human_verified_key FROM {{tables.agents}}') is None
    finally:
        await infra.close()
        await pool.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('case_name,expected', [
    ('team-omission-of-enrolled-revoked-id', 'revoked'),
    ('wrong-authenticated-key', 'invalid'),
    ('human-leaf-is-itself', 'unavailable'),
])
async def test_revalidation_failed_public_evidence_reports_without_clearing(privacy_app, case_name, expected):
    from copy import deepcopy
    from types import SimpleNamespace
    from awid.id_certificates import IDChainEvidence
    from awid.registry import IDTreeEnrollment, KeyResolution
    from aweb.human_kind_revalidation import revalidate_human_kind

    case = next(c for c in VECTORS['verification_cases'] if c['name'] == case_name)
    subject = {**case['subject'], **case.get('subject_patch', {})}
    status = deepcopy(VECTORS['status_fixtures'][case['status']])
    epoch = next(e for e in status['namespace']['epochs'] if e['retired_at'] is None)
    authority = dict(domain=status['domain'], dns_name='_awid.' + status['domain'], inherited=False, controller_key=epoch['did_key'])
    async def resolve(did):
        return KeyResolution(did, subject['did_key'], id_tree=IDTreeEnrollment(True, status['domain']))
    async def evidence(bundle, bound, *, domain):
        assert bound == {key: subject[key] for key in ('id', 'did_key')}
        return IDChainEvidence(status, authority, None if expected == 'unavailable' else 0)
    client = SimpleNamespace(resolve_key_fresh=resolve, id_chain_evidence=evidence)
    row_id = privacy_app.actors['bob'].id
    await privacy_app.db.execute("UPDATE {{tables.agents}} SET agent_type='human',did_key=$2,did_aw=$3,human_verified_key=$2 WHERE agent_id=$1",
                                 row_id, subject['did_key'], subject['id'])
    before = await privacy_app.db.fetch_val('SELECT xmin::text FROM {{tables.agents}} WHERE agent_id=$1', row_id)
    report = await revalidate_human_kind(privacy_app.db, client, apply=True)
    assert report['outcomes']['active'][expected] == 1
    assert report['stamped'] == 0
    assert report['unresolved_active'] == 1
    assert await privacy_app.db.fetch_val('SELECT xmin::text FROM {{tables.agents}} WHERE agent_id=$1', row_id) == before
