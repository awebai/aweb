"""Genuine plaintext chat from the actual aw producer through REST history.

Override AW_TEST_CLI_BINARY with a released artifact to reproduce a field user's
read. PostgreSQL, Redis, AWID, both server routes and the CLI subprocess are real.
"""
import asyncio
import base64
import json
import os
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest

from awid.signing import canonical_json_bytes, sign_message, verify_signature, VerifyResult
from test_addressless_sender_cli import _registry_http
from test_cli_human_reply import _pem
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401
from test_messages_http import _signed_team_headers


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
        denied = await _request(env, "carol", "GET", f"/v1/chat/sessions/{session}/messages")
        assert denied.status_code == 404
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


@pytest.mark.asyncio
@pytest.mark.parametrize("view", ["sse-replay", "sse-live", "mcp-history", "mcp-wait", "contact"])
async def test_signed_recipient_display_read_paths(privacy_app, tmp_path, aw_cli_binary, view):
    from aweb.mcp.auth import AuthContext, _auth_context
    from aweb.mcp.tools import chat, contacts

    env = privacy_app
    async with _registry_http(env.registry_app) as (registry_url, _):
        alice = _client_home(env, tmp_path, "alice", registry_url)
        body = tmp_path / "body.txt"
        body.write_text("Signed recipient display across reads")
        sent = await _aw(aw_cli_binary, alice, "chat", "send-and-wait", env.actors["bob"].did,
                         "--wait", "0", "--start-conversation", "--plaintext",
                         "--body-file", str(body), "--json")
        session = sent["session_id"]
        response = await _request(env, "bob", "GET", f"/v1/chat/sessions/{session}/messages")
        original = response.json()["messages"][0]
        actor = env.actors["bob"]
        auth = AuthContext(team_id=TEAM, agent_id=str(actor.id), workspace_id=str(actor.workspace),
                           alias="bob", did_key=actor.did, identity_scope="local")
        before = datetime.now(timezone.utc) - timedelta(seconds=5)
        # Exercise MCP projections using the established real participant's
        # context. HTTP auth and nonparticipant refusal are covered above.
        token = _auth_context.set(auth)
        try:
            if view.startswith("sse"):
                headers = _signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate)
                params = {"deadline": (datetime.now(timezone.utc) + timedelta(seconds=10)).isoformat()}
                if view == "sse-replay":
                    params["after"] = before.isoformat()
                async with env.client.stream("GET", f"/v1/chat/sessions/{session}/stream",
                                             params=params, headers=headers) as stream:
                    assert stream.status_code == 200
                    # Opening the real stream establishes its live cursor before this send.
                    if view == "sse-live":
                        signed = json.loads(original["signed_payload"])
                        signed.update(message_id=str(uuid4()), timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
                        raw = canonical_json_bytes(signed).decode()
                        signature = sign_message(env.actors["alice"].sk, raw.encode())
                        posted = await _request(env, "alice", "POST", f"/v1/chat/sessions/{session}/messages", dict(
                            body=signed["body"], message_id=signed["message_id"], timestamp=signed["timestamp"],
                            from_did=signed["from_did"], signature=signature, signed_payload=raw))
                        assert posted.status_code == 200, posted.text
                        original = dict(signed_payload=raw, signature=signature)
                    async with asyncio.timeout(8):
                        async for line in stream.aiter_lines():
                            if line.startswith("data: "):
                                message = json.loads(line[6:])
                                if message.get("type") == "message":
                                    break
                        else:
                            pytest.fail("No chat message in stream")
            elif view == "mcp-history":
                message = json.loads(await chat.chat_history(env.infra, session_id=session))["messages"][0]
            elif view == "mcp-wait":
                replies, timed_out = await chat._wait_for_replies(env.db, env.redis, auth=auth,
                    hosted_decryptor=None, session_id=UUID(session), participant_did=actor.did,
                    after=before, wait_seconds=1)
                assert not timed_out
                message = replies[0]
            else:
                messages = await contacts._read_chat_messages_from_target(env.infra,
                    target={"did_key": env.actors["alice"].did}, limit=20)
                message = messages[0]
            assert message.get("to_did") == env.actors["bob"].did, message
            # Every projection preserves the original signature and payload verbatim.
            assert message["signed_payload"] == original["signed_payload"]
            assert message["signature"] == original["signature"]
        finally:
            _auth_context.reset(token)


@pytest.mark.parametrize("case", ["verified", "legacy", "absent", "empty", "bad-signature", "wrong-conversation", "unsigned", "encrypted", "non-string"])
def test_recipient_display_requires_verified_original_payload(case):
    from awid.did import generate_keypair, did_from_public_key
    from aweb.messaging.verification import verified_signed_recipient_fields

    private, public = generate_keypair()
    payload = dict(from_did=did_from_public_key(public), to_did="did:key:recipient",
                   to_stable_id="did:aw:recipient", conversation_id="original", body="body")
    if case == "legacy":
        payload.pop("conversation_id")
    if case == "non-string":
        payload.update(to_did={"spoof": "recipient"}, to_stable_id=None)
    if case == "absent":
        payload.pop("to_did")
        payload.pop("to_stable_id")
    if case == "empty":
        payload.update(to_did="", to_stable_id="")
    raw = canonical_json_bytes(payload).decode()
    row = dict(signed_payload=raw, signature=sign_message(private, raw.encode()), conversation_id="original",
               # A stored stable sender is not a replacement for the signing key in the original.
               from_did="did:aw:stored-sender")
    if case == "bad-signature":
        row["signed_payload"] = raw.replace("body", "tampered")
    if case == "wrong-conversation":
        row["conversation_id"] = "another"
    if case == "unsigned":
        row["signature"] = None
    if case == "encrypted":
        row["content_mode"] = "encrypted_v2"
    expected = {key: payload[key] for key in ("to_did", "to_stable_id")} if case in ("verified", "legacy", "empty") else {}
    assert verified_signed_recipient_fields(row) == expected
    assert row["signed_payload"] == (raw.replace("body", "tampered") if case == "bad-signature" else raw)
