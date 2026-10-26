"""Genuine plaintext chat from the actual aw producer through REST history.

Override AW_TEST_CLI_BINARY with a released artifact to reproduce a field user's
read. PostgreSQL, Redis, AWID, both server routes and the CLI subprocess are real.
"""
import asyncio
import base64
import json
import os

import pytest

from awid.signing import canonical_json_bytes, sign_message, verify_signature, VerifyResult
from test_addressless_sender_cli import _registry_http
from test_cli_human_reply import _pem
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401


def _client_home(env, root, alias, registry_url):
    actor = env.actors[alias]
    home = root / alias / ".aw"
    home.mkdir(parents=True)
    cert_path = "team-certs/" + TEAM.replace("__", "____").replace(":", "__") + ".pem"
    (home / "team-certs").mkdir()
    cert = json.loads(base64.b64decode(actor.certificate))
    cert.pop("signature")
    # Go's local certificate DTO omits absent optional identity fields.
    for field in ("member_did_aw", "member_address"):
        if not cert.get(field):
            cert.pop(field, None)
    cert["signature"] = sign_message(env.team_sk, canonical_json_bytes(cert))
    (home / cert_path).write_text(json.dumps(cert))
    membership = dict(team_id=TEAM, alias=alias, cert_path=cert_path)
    (home / "teams.yaml").write_text(json.dumps(dict(active_team=TEAM, memberships=[membership])))
    (home / "workspace.yaml").write_text(json.dumps(dict(
        aweb_url=str(env.client.base_url),
        memberships=[dict(membership, workspace_id=str(actor.workspace))],
    )))
    _pem(home / "signing.key", "ED25519 PRIVATE KEY", actor.sk)
    child = {k: v for k, v in os.environ.items() if not k.startswith(("AWEB_", "AWID_"))}
    child.update(AWEB_IDENTITY_HOME=str(home), AWEB_URL=str(env.client.base_url),
                 AWID_REGISTRY_URL=registry_url, HOME=str(root / alias),
                 XDG_CONFIG_HOME=str(root / alias / "config"))
    return home.parent, child


async def _aw(binary, context, *args):
    cwd, child = context
    process = await asyncio.create_subprocess_exec(str(binary), *args, cwd=cwd, env=child,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await asyncio.wait_for(process.communicate(), 30)
    assert process.returncode == 0, stderr.decode()
    return json.loads(stdout)


@pytest.mark.asyncio
@pytest.mark.parametrize("recipient_key", [False, True], ids=["alias-neighbor", "signed-recipient-key"])
async def test_real_aw_chat_retains_signed_recipient_display(privacy_app, tmp_path, aw_cli_binary, recipient_key):
    env = privacy_app
    async with _registry_http(env.registry_app) as (registry_url, _):
        alice = _client_home(env, tmp_path, "alice", registry_url)
        bob = _client_home(env, tmp_path, "bob", registry_url)
        body = tmp_path / "body.txt"
        body.write_text("Genuine aw plaintext chat")
        target = env.actors["bob"].did if recipient_key else "bob"
        sent = await _aw(aw_cli_binary, alice, "chat", "send-and-wait", target,
                         "--wait", "0", "--start-conversation", "--plaintext",
                         "--body-file", str(body), "--json")
        session = sent["session_id"]
        response = await _request(env, "bob", "GET", f"/v1/chat/sessions/{session}/messages")
        assert response.status_code == 200, response.text
        original = response.json()["messages"][0]
        signed = json.loads(original["signed_payload"])
        assert "via" not in signed
        assert signed["to_did"] == (env.actors["bob"].did if recipient_key else "")
        assert verify_signature(signed["from_did"], original["signed_payload"].encode(), original["signature"]) == VerifyResult.VERIFIED
        shown = await _aw(aw_cli_binary, bob, "chat", "history", "--session-id", session, "--json")
        assert shown["messages"][0]["verification_status"] == "verified", {
            "signed_to_did": signed["to_did"], "projected_to_did": original.get("to_did"),
            "status": shown["messages"][0]["verification_status"],
        }
