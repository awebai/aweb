"""AWID and team-auth request purposes cannot be interchanged."""
import base64
import hashlib
import json
from datetime import datetime, timezone

import pytest

from awid.signing import canonical_json_bytes, sign_message
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401


@pytest.mark.asyncio
@pytest.mark.parametrize('purpose,expected', [(None, 200), ('aweb.awid-controller-request', 401)])
async def test_team_auth_rejects_awid_purpose_even_with_otherwise_valid_claims(privacy_app, purpose, expected):
    env = privacy_app
    env.app.state.public_origin = str(env.client.base_url).rstrip('/')
    actor = env.actors['alice']
    content = json.dumps({'to_did': env.actors['bob'].did, 'subject': 'purpose', 'body': 'bound'}).encode()
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = {'v': 2, 'aud': env.app.state.public_origin, 'method': 'POST', 'path': '/v1/messages', 'team_id': TEAM,
               'domain': 'local', 'operation': 'create_team', 'body_sha256': hashlib.sha256(content).hexdigest(), 'timestamp': timestamp}
    if purpose:
        payload['type'] = purpose
    canonical = canonical_json_bytes(payload)
    response = await env.client.post('/v1/messages', content=content, headers={
        'Authorization': f'DIDKey {actor.did} {sign_message(actor.sk, canonical)}',
        'X-AWEB-Timestamp': timestamp, 'X-AWID-Team-Certificate': actor.certificate,
        'X-AWEB-Signed-Payload': base64.urlsafe_b64encode(canonical).rstrip(b'=').decode(),
        'Content-Type': 'application/json',
    })
    assert response.status_code == expected, response.text
