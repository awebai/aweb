"""Read-time sender membership through the real OSS/AWID/PG/Redis apps."""
import json
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import pytest
from awid.did import stable_id_from_did_key
from test_dashboard_privacy import TEAM, _request, _seed_mail, privacy_app  # noqa: F401


@pytest.mark.asyncio
async def test_sender_membership_mail_and_chat_is_current_and_participant_scoped(privacy_app):
    env = privacy_app
    sender = env.actors['alice']
    stable_id = stable_id_from_did_key(sender.did)
    await env.db.execute(
        "UPDATE {{tables.agents}} SET agent_type='human', identity_scope='global', "
        "did_aw=$1, certificate_id='privacy-alice' WHERE agent_id=$2", stable_id, sender.id,
    )
    mail_id = await _seed_mail(env)
    chat = await _request(env, 'alice', 'POST', '/v1/chat/sessions', {
        'to_dids': [env.actors['bob'].did], 'message': 'membership control',
    })
    assert chat.status_code == 200, chat.text
    paths = [f'/v1/messages/{mail_id}', f"/v1/chat/sessions/{chat.json()['session_id']}/messages"]
    for state in ('active', 'inactive'):
        if state == 'inactive':
            await env.db.execute("UPDATE {{tables.agents}} SET status='retired' WHERE agent_id=$1", sender.id)
        for path in paths:
            response = await _request(env, 'bob', 'GET', path)
            assert response.status_code == 200, response.text
            data = response.json()
            message = data['messages'][0] if 'messages' in data else data
            assert message['sender_membership'] == {
                'team_id': TEAM, 'member_did_aw': stable_id, 'state': state,
            }
    query = urlencode({"after": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
                       "deadline": (datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat()})
    streamed = await _request(env, "bob", "GET", f"/v1/chat/sessions/{chat.json()['session_id']}/stream?{query}")
    assert streamed.status_code == 200, streamed.text
    events = [json.loads(line[6:]) for line in streamed.text.splitlines() if line.startswith("data: ")]
    message = next(event for event in events if event.get("type") == "message")
    assert message["sender_membership"]["state"] == "inactive"
    assert message["sender_membership"]["member_did_aw"] == stable_id
    for path in paths:
        response = await _request(env, 'carol', 'GET', path)
        assert response.status_code in (403, 404)


@pytest.mark.asyncio
async def test_sender_membership_revocation_and_missing_provenance(privacy_app):
    env = privacy_app
    sender = env.actors['alice']
    stable_id = stable_id_from_did_key(sender.did)
    await env.db.execute(
        "UPDATE {{tables.agents}} SET did_aw=$1, certificate_id='privacy-alice' WHERE agent_id=$2", stable_id, sender.id,
    )
    mail_id = await _seed_mail(env)
    await env.registry_db.execute(
        "INSERT INTO {{tables.team_certificates}} "
        "(team_uuid, certificate_id, member_did_key, member_did_aw, alias, revoked_at) "
        "SELECT team_uuid, 'privacy-alice', $1, $2, 'alice', NOW() FROM {{tables.teams}}",
        sender.did, stable_id,
    )
    response = await _request(env, 'bob', 'GET', f'/v1/messages/{mail_id}')
    assert response.status_code == 200, response.text
    assert response.json()['sender_membership']['state'] == 'inactive'
    await env.db.execute("UPDATE {{tables.agents}} SET certificate_id=NULL WHERE agent_id=$1", sender.id)
    response = await _request(env, 'bob', 'GET', f'/v1/messages/{mail_id}')
    assert response.status_code == 200, response.text
    assert response.json()['sender_membership']['state'] == 'unknown'
