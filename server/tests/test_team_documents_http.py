"""Team instructions and roles through real HTTP: audit of instruction changes
and the size limit on both documents."""
from __future__ import annotations

from uuid import uuid4

import pytest

from aweb.coordination.team_documents import MAX_TEAM_DOCUMENT_BYTES
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_operator_audit_http import _request


async def _instruction_audit_rows(env):
    return await env.db.fetch_all(
        "SELECT * FROM {{tables.audit_log}} WHERE event_type LIKE 'instructions.%' ORDER BY created_at, id"
    )


INSTRUCTION_OPERATIONS = [
    ('POST', '/v1/instructions', {'document': {'body_md': 'refused'}}, 'instructions.create'),
    ('POST', '/v1/instructions/{id}/activate', None, 'instructions.activate'),
    ('POST', '/v1/instructions/reset', None, 'instructions.reset'),
]


@pytest.mark.asyncio
async def test_each_instruction_change_writes_one_attributed_row(privacy_app):
    env = privacy_app
    sentinel = 'content-never-in-audit'
    created = await _request(env, 'POST', '/v1/instructions', {'document': {'body_md': sentinel}})
    assert created.status_code == 200, created.text
    instructions_id = created.json()['team_instructions_id']
    activated = await _request(env, 'POST', f'/v1/instructions/{instructions_id}/activate')
    assert activated.status_code == 200, activated.text
    reset = await _request(env, 'POST', '/v1/instructions/reset')
    assert reset.status_code == 200, reset.text

    rows = await _instruction_audit_rows(env)
    assert [r['event_type'] for r in rows] == ['instructions.create', 'instructions.activate', 'instructions.reset']
    assert [r['resource'] for r in rows] == [
        f'instructions:{TEAM}', f'instructions:{instructions_id}', f'instructions:{TEAM}',
    ]
    assert len({r['request_id'] for r in rows}) == 3
    for row in rows:
        assert row['team_id'] == TEAM
        assert row['actor_did_key'] == env.actors['alice'].did
        assert row['principal_type'] == 'c' and row['outcome'] == 'success'
        assert row['details'] is None and sentinel not in str(dict(row))


@pytest.mark.asyncio
@pytest.mark.parametrize('method,path,body,action', INSTRUCTION_OPERATIONS)
async def test_a_refused_instruction_change_writes_one_denied_row(privacy_app, method, path, body, action):
    env = privacy_app
    await env.db.execute('UPDATE {{tables.agents}} SET deleted_at=NOW() WHERE agent_id=$1', env.actors['alice'].id)
    response = await _request(env, method, path.format(id=uuid4()), body)
    assert response.status_code == 403, response.text
    rows = await _instruction_audit_rows(env)
    assert [(r['event_type'], r['outcome']) for r in rows] == [(action, 'denied')]
    assert rows[0]['actor_did_key'] == env.actors['alice'].did
    assert await env.db.fetch_value('SELECT count(*) FROM {{tables.team_instructions}}') == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('method,path,body,action', INSTRUCTION_OPERATIONS)
async def test_an_instruction_change_that_cannot_be_audited_is_not_made(privacy_app, method, path, body, action):
    env = privacy_app
    created = await _request(env, 'POST', '/v1/instructions', {'document': {'body_md': 'kept'}})
    instructions_id = created.json()['team_instructions_id']
    assert (await _request(env, 'POST', f'/v1/instructions/{instructions_id}/activate')).status_code == 200
    spare = await _request(env, 'POST', '/v1/instructions', {'document': {'body_md': 'spare'}})
    before = await env.db.fetch_all('SELECT * FROM {{tables.team_instructions}} ORDER BY id')
    audited = len(await _instruction_audit_rows(env))
    await env.db.execute(
        "ALTER TABLE {{tables.audit_log}} ADD CONSTRAINT audit_test_failure "
        "CHECK (event_type NOT LIKE 'instructions.%') NOT VALID"
    )
    try:
        response = await _request(env, method, path.format(id=spare.json()['team_instructions_id']), body)
        assert response.status_code == 500, response.text
        assert await env.db.fetch_all('SELECT * FROM {{tables.team_instructions}} ORDER BY id') == before
        assert len(await _instruction_audit_rows(env)) == audited
    finally:
        await env.db.execute('ALTER TABLE {{tables.audit_log}} DROP CONSTRAINT audit_test_failure')


@pytest.mark.asyncio
async def test_a_team_document_over_the_limit_is_refused_and_one_at_the_limit_is_stored(privacy_app):
    env = privacy_app
    # {"body_md": "...", "format": "markdown"} serialized, less the body itself.
    overhead = len(b'{"body_md": "", "format": "markdown"}')
    at_limit = 'a' * (MAX_TEAM_DOCUMENT_BYTES - overhead)

    stored = await _request(env, 'POST', '/v1/instructions', {'document': {'body_md': at_limit}})
    assert stored.status_code == 200, stored.text
    refused = await _request(env, 'POST', '/v1/instructions', {'document': {'body_md': at_limit + 'a'}})
    assert refused.status_code == 413, refused.text
    assert str(MAX_TEAM_DOCUMENT_BYTES) in refused.text
    assert await env.db.fetch_value('SELECT count(*) FROM {{tables.team_instructions}}') == 1

    oversized_roles = {'bundle': {'roles': {'dev': {'title': 'dev', 'playbook_md': 'a' * MAX_TEAM_DOCUMENT_BYTES}}}}
    refused = await _request(env, 'POST', '/v1/roles', oversized_roles)
    assert refused.status_code == 413, refused.text
    assert await env.db.fetch_value('SELECT count(*) FROM {{tables.team_roles}}') == 0
