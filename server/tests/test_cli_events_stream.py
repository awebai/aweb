"""Production aw stays subscribed across the real server's bounded streams."""
from __future__ import annotations

import asyncio
import base64
import json
import os
from pathlib import Path
import signal

import pytest

import aweb.routes.events
from awid.signing import canonical_json_bytes, sign_message
from test_agent_status_host_http import _team_request
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_messages_http import _make_certificate


@pytest.mark.usefixtures("source_cli_binary")
@pytest.mark.asyncio
@pytest.mark.parametrize("with_mail", [False, True], ids=["idle", "actionable-mail"])
async def test_cli_subscription_survives_the_real_server_stream_cap(privacy_app, tmp_path, monkeypatch, with_mail):
    env = privacy_app
    # Exercise the real deadline clamp, SSE generator and clean HTTP EOF,
    # without waiting the production five minutes for each reconnect.
    monkeypatch.setattr(aweb.routes.events, "MAX_STREAM_DURATION", 1)
    message_id = None
    if with_mail:
        sent = await _team_request(env, "alice", "POST", "/v1/messages", {
            "to_did": env.actors["bob"].did, "subject": "Stay subscribed", "body": "One actionable mail",
        })
        assert sent.status_code == 200, sent.text
        message_id = sent.json()["message_id"]

    binary = Path(os.environ["AW_TEST_CLI_BINARY"])

    actor = env.actors["bob"]
    home = tmp_path / "selected" / ".aw"
    (home / "team-certs").mkdir(parents=True)
    certificate = _make_certificate(env.team_sk, env.team_did, actor.did, team_id=TEAM, alias="bob", identity_scope="local")
    # The released Go wire shape omits these optional local-identity fields.
    for key in ("member_did_aw", "member_address", "signature"):
        certificate.pop(key)
    certificate["signature"] = sign_message(env.team_sk, canonical_json_bytes(certificate))
    cert_path = "team-certs/team.pem"
    (home / cert_path).write_text(json.dumps(certificate))
    membership = {"team_id": TEAM, "alias": "bob", "cert_path": cert_path}
    (home / "teams.yaml").write_text(json.dumps({"active_team": TEAM, "memberships": [membership]}))
    (home / "workspace.yaml").write_text(json.dumps({"aweb_url": str(env.client.base_url), "memberships": [membership]}))
    (home / "signing.key").write_text(
        "-----BEGIN ED25519 PRIVATE KEY-----\n" + base64.b64encode(actor.sk).decode() + "\n-----END ED25519 PRIVATE KEY-----\n",
    )
    (home / "signing.key").chmod(0o600)
    child_env = {k: v for k, v in os.environ.items() if not k.startswith(("AWEB_", "AWID_", "AW_AGENT_STATUS_"))}
    child_env.update(HOME=str(tmp_path), AW_NO_UPDATE_CHECK="1")
    # Deliberately omit --timeout: the default promises an indefinite subscription.
    process = await asyncio.create_subprocess_exec(
        str(binary), "events", "stream", "--json",
        cwd=home.parent, env=child_env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    received = []
    try:
        while sum(event.get("type") == "connected" for event in received) < 3:
            line = await asyncio.wait_for(process.stdout.readline(), 10)
            if not line:
                await process.wait()
                stderr = (await process.stderr.read()).decode()
                pytest.fail(f"events stream ended at a server stream cap: exit={process.returncode}, events={received}, stderr={stderr!r}")
            received.append(json.loads(line))
        assert process.returncode is None
        if with_mail:
            assert sum(event.get("message_id") == message_id for event in received) == 1
        process.send_signal(signal.SIGINT)
        await asyncio.wait_for(process.wait(), 5)
        assert process.returncode == 0
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()
