"""Operator audit through real HTTP, AWID, PostgreSQL and Redis."""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

from awid.signing import canonical_json_bytes, sign_message
from aweb.presence import clear_workspace_presence, get_agent_presence, update_agent_presence
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_identity_grants import _grant_headers
from test_messages_http import _make_keypair, _signed_team_headers


async def _request(env, method, path, body=None, *, version=1):
    actor = env.actors['alice']
    content = json.dumps(body).encode() if body is not None else b''
    headers = _signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate, content)
    if version == 2:
        payload = canonical_json_bytes({
            'v': 2, 'aud': str(env.client.base_url).rstrip('/'), 'method': method,
            'path': path, 'team_id': TEAM, 'timestamp': headers['X-AWEB-Timestamp'],
            'body_sha256': hashlib.sha256(content).hexdigest(),
        })
        headers['X-AWEB-Signed-Payload'] = base64.urlsafe_b64encode(payload).rstrip(b'=').decode()
        headers['Authorization'] = f'DIDKey {actor.did} {sign_message(actor.sk, payload)}'
    headers['Content-Type'] = 'application/json'
    return await env.client.request(method, path, content=content, headers=headers)


async def _audit_rows(env):
    return await env.db.fetch_all(
        "SELECT * FROM {{tables.audit_log}} WHERE event_type IN "
        "('roles.create','roles.activate','roles.reset','roles.deactivate','repos.delete') ORDER BY created_at, id"
    )


async def _repo(env):
    repo_id = uuid4()
    await env.db.execute(
        "INSERT INTO {{tables.repos}} (id,team_id,origin_url,canonical_origin) VALUES ($1,$2,$3,$3)",
        repo_id, TEAM, f'example.test/{repo_id}',
    )
    workspace = env.actors['alice'].workspace
    await env.db.execute('UPDATE {{tables.workspaces}} SET repo_id=$1 WHERE workspace_id=$2', repo_id, workspace)
    await env.db.execute(
        "INSERT INTO {{tables.task_claims}} (team_id,workspace_id,alias,task_ref) VALUES ($1,$2,'alice','audit-task')",
        TEAM, workspace,
    )
    await update_agent_presence(env.redis, str(workspace), 'alice', team_id=TEAM, repo_id=str(repo_id))
    return repo_id


@pytest.mark.asyncio
@pytest.mark.parametrize('version', [1, 2])
async def test_sensitive_success_writes_one_attributed_row_per_operation(privacy_app, version):
    env = privacy_app
    env.app.state.public_origin = str(env.client.base_url).rstrip('/')
    sentinel = 'content-never-in-audit'
    created = await _request(env, 'POST', '/v1/roles', {'bundle': {'roles': {'dev': {'playbook_md': sentinel}}}}, version=version)
    assert created.status_code == 200, created.text
    roles_id = created.json()['team_roles_id']
    repo_id = await _repo(env)
    workspace = str(env.actors['alice'].workspace)
    try:
        for path in (f'/v1/roles/{roles_id}/activate', '/v1/roles/reset', '/v1/roles/deactivate'):
            response = await _request(env, 'POST', path, version=version)
            assert response.status_code == 200, response.text
        deleted = await _request(env, 'DELETE', f'/v1/repos/{repo_id}', version=version)
        assert deleted.status_code == 200, deleted.text
        assert deleted.json()['claims_deleted'] == deleted.json()['workspaces_deleted'] == 1
        assert await get_agent_presence(env.redis, workspace) is None
        rows = await _audit_rows(env)
        assert [r['event_type'] for r in rows] == ['roles.create', 'roles.activate', 'roles.reset', 'roles.deactivate', 'repos.delete']
        assert [r['resource'] for r in rows] == [f'roles:{TEAM}', f'roles:{roles_id}', f'roles:{TEAM}', f'roles:{TEAM}', f'repo:{repo_id}']
        assert len({r['request_id'] for r in rows}) == 5
        for row in rows:
            assert row['team_id'] == TEAM
            assert row['actor_did_key'] == env.actors['alice'].did
            assert row['actor_user_id'] is None and row['actor_grant_id'] is None
            assert row['principal_type'] == 'c' and row['auth_mode'] == f'team_auth_v{version}'
            assert row['outcome'] == 'success' and row['created_at'] <= datetime.now(timezone.utc)
            assert row['details'] is None and sentinel not in str(dict(row))
    finally:
        await clear_workspace_presence(env.redis, [workspace])


OPERATIONS = [
    ('POST', '/v1/roles', {'bundle': {}}, 'roles.create'),
    ('POST', '/v1/roles/{id}/activate', None, 'roles.activate'),
    ('POST', '/v1/roles/reset', None, 'roles.reset'),
    ('POST', '/v1/roles/deactivate', None, 'roles.deactivate'),
    ('DELETE', '/v1/repos/{id}', None, 'repos.delete'),
]


@pytest.mark.asyncio
@pytest.mark.parametrize('method,path,body,action', OPERATIONS)
async def test_verified_but_unconnected_refusal_has_one_denied_row(privacy_app, method, path, body, action):
    env = privacy_app
    await env.db.execute('UPDATE {{tables.agents}} SET deleted_at=NOW() WHERE agent_id=$1', env.actors['alice'].id)
    response = await _request(env, method, path.format(id=uuid4()), body)
    assert response.status_code == 403, response.text
    rows = await _audit_rows(env)
    assert len(rows) == 1
    assert (rows[0]['event_type'], rows[0]['outcome'], rows[0]['principal_type']) == (action, 'denied', 'c')
    assert rows[0]['actor_did_key'] == env.actors['alice'].did
    assert await env.db.fetch_value('SELECT count(*) FROM {{tables.team_roles}}') == 0


@pytest.mark.asyncio
async def test_conflict_hidden_validation_and_unverified_refusals(privacy_app):
    env = privacy_app
    created = await _request(env, 'POST', '/v1/roles', {'bundle': {}})
    assert created.status_code == 200, created.text
    active = created.json()['team_roles_id']
    assert (await _request(env, 'POST', f'/v1/roles/{active}/activate')).status_code == 200
    conflict = await _request(env, 'POST', '/v1/roles', {'base_team_roles_id': str(uuid4()), 'bundle': {}})
    assert conflict.status_code == 409, conflict.text
    hidden = await _request(env, 'DELETE', f'/v1/repos/{uuid4()}')
    assert hidden.status_code == 404
    invalid = await _request(env, 'POST', '/v1/roles', {'bundle': 'invalid'})
    assert invalid.status_code == 422
    rows = await _audit_rows(env)
    assert [r['outcome'] for r in rows] == ['success', 'success', 'denied', 'denied', 'denied']
    # Neither a forged certificate/signature nor claimed actor headers establish attribution.
    for headers in ({}, {'Authorization': 'DIDKey did:key:forged invalid', 'X-AWEB-User-ID': str(uuid4())}):
        response = await env.client.post('/v1/roles/reset', headers=headers)
        assert response.status_code == 401
    assert len(await _audit_rows(env)) == len(rows)
    assert await env.db.fetch_value('SELECT count(*) FROM {{tables.team_roles}}') == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('method,path,body,action', OPERATIONS)
async def test_audit_failure_rolls_back_mutation_and_preserves_presence(privacy_app, method, path, body, action):
    env = privacy_app
    created = await _request(env, 'POST', '/v1/roles', {'bundle': {}})
    roles_id = created.json()['team_roles_id']
    repo_id = await _repo(env)
    workspace = str(env.actors['alice'].workspace)
    before = await env.db.fetch_all('SELECT * FROM {{tables.team_roles}} ORDER BY id')
    await env.db.execute(
        "ALTER TABLE {{tables.audit_log}} ADD CONSTRAINT audit_test_failure "
        "CHECK (event_type NOT LIKE 'roles.%' AND event_type <> 'repos.delete') NOT VALID"
    )
    try:
        target = repo_id if action == 'repos.delete' else roles_id
        response = await _request(env, method, path.format(id=target), body)
        assert response.status_code == 500, response.text
        assert await env.db.fetch_all('SELECT * FROM {{tables.team_roles}} ORDER BY id') == before
        assert await env.db.fetch_value('SELECT deleted_at FROM {{tables.repos}} WHERE id=$1', repo_id) is None
        assert await env.db.fetch_value('SELECT deleted_at FROM {{tables.workspaces}} WHERE workspace_id=$1', env.actors['alice'].workspace) is None
        assert await env.db.fetch_value('SELECT count(*) FROM {{tables.task_claims}} WHERE workspace_id=$1', env.actors['alice'].workspace) == 1
        assert await get_agent_presence(env.redis, workspace) is not None
        assert len(await _audit_rows(env)) == 1
    finally:
        await env.db.execute('ALTER TABLE {{tables.audit_log}} DROP CONSTRAINT audit_test_failure')
        await clear_workspace_presence(env.redis, [workspace])


@pytest.mark.asyncio
async def test_valid_grant_denial_attributes_subject_and_grant_not_session_key(privacy_app):
    env = privacy_app
    env.app.state.public_origin = str(env.client.base_url).rstrip('/')
    sk, _, did = _make_keypair()
    minted = await _request(env, 'POST', '/v1/identity-grants', {'grant_did_key': did, 'scopes': ['coord.read']})
    assert minted.status_code == 200, minted.text
    grant_id = minted.json()['grant_id']
    for method, path, body, action in OPERATIONS:
        path = path.format(id=uuid4())
        content = json.dumps(body).encode() if body is not None else b''
        headers = _grant_headers(signing_key=sk, did_key=did, grant_id=grant_id, method=method, path=path, body=content, aud=env.app.state.public_origin)
        response = await env.client.request(method, path, content=content, headers=headers)
        assert response.status_code == 403, response.text
    rows = await _audit_rows(env)
    assert len(rows) == 5
    for row in rows:
        assert row['outcome'] == 'denied' and row['principal_type'] == 'c'
        assert row['auth_mode'] == 'identity_grant' and str(row['actor_grant_id']) == grant_id
        assert row['actor_did_key'] == env.actors['alice'].did != did
    await env.db.execute('UPDATE {{tables.identity_session_grants}} SET revoked_at=NOW() WHERE grant_id=$1', UUID(grant_id))
    response = await env.client.request(method, path, content=content, headers=headers)
    assert response.status_code in (401, 403)
    assert len(await _audit_rows(env)) == 5


@pytest.mark.asyncio
async def test_embedding_helper_is_insert_only_and_obeys_callers_transaction(privacy_app):
    from aweb.audit import AuditActor, record_coordination_audit

    env = privacy_app
    for principal, mode in [('u', 'session'), ('k', 'api_key'), ('m', 'internal'), ('p', 'internal')]:
        actor = AuditActor(team_id=TEAM, principal_type=principal, auth_mode=mode, user_id=str(uuid4()))
        async with env.db.transaction() as tx:
            await record_coordination_audit(tx, actor=actor, action='roles.reset', target=f'roles:{TEAM}', outcome='denied', request_id=str(uuid4()))
    assert [(r['principal_type'], r['auth_mode'], r['outcome']) for r in await _audit_rows(env)] == [('u', 'session', 'denied'), ('k', 'api_key', 'denied'), ('m', 'internal', 'denied'), ('p', 'internal', 'denied')]
    with pytest.raises(RuntimeError):
        async with env.db.transaction() as tx:
            await record_coordination_audit(tx, actor=actor, action='repos.delete', target=f'repo:{uuid4()}', outcome='success', request_id=str(uuid4()))
            raise RuntimeError('abort outer transaction')
    assert len(await _audit_rows(env)) == 4
    for kwargs in ({'principal_type': 'other'}, {'auth_mode': 'header'}, {'user_id': None}):
        with pytest.raises(ValueError):
            AuditActor(**{'team_id': TEAM, 'principal_type': 'u', 'auth_mode': 'session', 'user_id': str(uuid4()), **kwargs})
