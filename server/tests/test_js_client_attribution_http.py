"""Built JS clients identify real inbox, ack and SSE requests to aweb."""
import asyncio
import json
from pathlib import Path
import subprocess

import pytest

from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401
from test_messages_http import _signed_identity_headers

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def built_js_clients():
    for package in ("channel-core", "channel", "pi-extension"):
        subprocess.run(["npm", "run", "build"], cwd=ROOT / package, check=True,
                       capture_output=True, text=True)
    return {package: (ROOT / package / "dist/index.js").as_uri()
            for package in ("channel-core", "channel", "pi-extension")}


@pytest.mark.asyncio
@pytest.mark.parametrize("product", ["aweb-channel", "aweb-pi", "aweb-wake", "aweb-channel-core"])
async def test_js_client_versions_reach_real_inbox_ack_and_sse(privacy_app, built_js_clients, product):
    env = privacy_app
    sent = await _request(env, "alice", "POST", "/v1/messages", {
        "to_did": env.actors["bob"].did, "subject": "client attribution", "body": "receipt",
    })
    assert sent.status_code == 200, sent.text
    observed = []
    original = env.app.middleware_stack

    async def observe(scope, receive, send):
        if scope["type"] == "http":
            headers = dict(scope["headers"])
            observed.append((scope["method"], scope["path"], headers.get(b"user-agent"),
                             headers.get(b"x-aweb-client-version")))
        await original(scope, receive, send)

    # Observe actual incoming headers; all auth, responses and storage stay real.
    env.app.middleware_stack = observe
    actor = env.actors["bob"]
    package = {"aweb-channel": "channel", "aweb-pi": "pi-extension"}.get(product, "channel-core")
    version = "2.3.4" if product == "aweb-wake" else json.loads((ROOT / package / "package.json").read_text())["version"]
    metadata = {"name": product, "version": version}
    script = """
      import { readFileSync } from 'node:fs';
      const input = JSON.parse(readFileSync(0, 'utf8'));
      const {APIClient, ackMessage} = await import(input.core);
      const auth = {...input.auth, signingKey: Buffer.from(input.key, 'hex')};
      const module = await import(input.module);
      const client = input.factory ? module[input.factory]({baseURL: input.url, ...auth})
        : new APIClient(input.url, auth, input.product === 'aweb-wake' ? input.metadata : undefined);
      await client.get('/v1/messages/inbox?unread_only=true&limit=5');
      await ackMessage(client, input.message);
      const deadline = encodeURIComponent(new Date(Date.now() - 1000).toISOString());
      const stream = await client.openSSE('/v1/events/stream?deadline=' + deadline);
      await stream.text();
    """
    process = await asyncio.create_subprocess_exec(
        "node", "--input-type=module", "-e", script,
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(json.dumps({
            "module": built_js_clients[package], "core": built_js_clients["channel-core"],
            "factory": {"aweb-channel": "createClaudeChannelClient", "aweb-pi": "createPiChannelClient"}.get(product),
            "product": product, "url": str(env.client.base_url).rstrip('/'),
            "auth": {"did": actor.did, "stableID": "", "teamID": TEAM,
                     "teamCertificateHeader": actor.certificate},
            "key": actor.sk.hex(), "metadata": metadata, "message": sent.json()["message_id"],
        }).encode()), 30)
        assert process.returncode == 0, stderr.decode()
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()
        env.app.middleware_stack = original
    token = f"{product}/{version}".encode()
    assert [(method, path) for method, path, _, _ in observed] == [
        ("GET", "/v1/messages/inbox"),
        ("POST", f"/v1/messages/{sent.json()['message_id']}/ack"),
        ("GET", "/v1/events/stream"),
    ]
    assert all(ua == token and version == token for _, _, ua, version in observed), observed


@pytest.mark.asyncio
@pytest.mark.parametrize("reported,label", [
    ("aweb-channel/1.8.0", "aweb-channel/1.8.0"),
    ("aw/1.36.45", "1.36.45"),
    ("unknown-product/1.2.3", "other"),
    ("aweb-channel/not-a-version", "other"),
    ("aweb-channel/" + "1" * 100 + ".2.3", "other"),
])
async def test_client_label_is_bounded_and_never_changes_auth(privacy_app, reported, label):
    from aweb.auth_metrics import LEGACY_REQUEST_AUTH_ACCEPTED
    env = privacy_app
    actor = env.actors["alice"]
    counter = LEGACY_REQUEST_AUTH_ACCEPTED.labels("identity", "GET", "/v1/messages/inbox", label)
    before = counter._value.get()
    headers = _signed_identity_headers(actor.sk, actor.did, "", b"")
    headers.update({"User-Agent": "node", "X-AWEB-Client-Version": reported})
    response = await env.client.get("/v1/messages/inbox", headers=headers)
    assert response.status_code == 200, response.text
    assert counter._value.get() == before + 1
