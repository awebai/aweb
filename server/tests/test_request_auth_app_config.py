"""Request audiences belong to this app, independently of process DB settings."""
import base64
from datetime import datetime, timezone
import hashlib

import httpx
import pytest

from aweb.api import create_app
from awid.did import stable_id_from_did_key
from awid.signing import canonical_json_bytes, sign_message
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401


@pytest.mark.asyncio
@pytest.mark.parametrize('family', ['certificate', 'identity-local', 'identity-global'])
async def test_v2_uses_explicit_app_origin_without_database_environment(privacy_app, monkeypatch, family):
    env = privacy_app
    origin = 'http://configured.test'
    for name in ('DATABASE_URL', 'AWEB_DATABASE_URL'):
        monkeypatch.delenv(name, raising=False)
    app = create_app(public_origin=origin)
    app.state.db = env.infra
    app.state.redis = env.redis
    app.state.awid_registry_client = env.app.state.awid_registry_client
    # A request cannot select a different global configuration after construction.
    monkeypatch.setenv('AWEB_PUBLIC_ORIGIN', 'http://other-process-config.test')
    actor = env.actors['alice']
    stable = ''
    if family == 'identity-global':
        await env.app.state.awid_registry_client.register_did(actor.did, actor.sk)
        stable = stable_id_from_did_key(actor.did)
    timestamp = datetime.now(timezone.utc).isoformat()
    claim = {'team_id': TEAM} if family == 'certificate' else {'did_aw': stable}
    headers = {'X-AWEB-Timestamp': timestamp}
    if family == 'certificate':
        headers['X-AWID-Team-Certificate'] = actor.certificate
    elif stable:
        headers['X-AWEB-DID-AW'] = stable
    def signed(audience):
        canonical = canonical_json_bytes(dict(v=2, aud=audience, method='GET',
            path='/v1/messages/inbox', timestamp=timestamp,
            body_sha256=hashlib.sha256(b'').hexdigest(), **claim))
        return {**headers, 'Authorization': f'DIDKey {actor.did} {sign_message(actor.sk, canonical)}',
                'X-AWEB-Signed-Payload': base64.urlsafe_b64encode(canonical).rstrip(b'=').decode()}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                                 base_url=origin) as client:
        good = await client.get('/v1/messages/inbox', headers=signed(origin))
        assert good.status_code == 200, good.text
        bad = await client.get('/v1/messages/inbox', headers=signed('http://other-process-config.test'))
        assert bad.status_code == 401, bad.text
        # Host headers cannot replace the configured audience either.
        bad_host = await client.get('/v1/messages/inbox', headers={
            **signed('http://untrusted-host.test'), 'Host': 'untrusted-host.test'})
        assert bad_host.status_code == 401, bad_host.text
