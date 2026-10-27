"""Real Postgres/Redis/AWID/server, with current or explicitly released readers."""
import asyncio
import base64
from datetime import datetime, timedelta, timezone
import json
import os
import hashlib
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from awid.signing import canonical_payload, sign_message, verify_signature, VerifyResult
from awid.signing import canonical_json_bytes
from awid.e2ee_keys import build_encryption_key_assertion
from aweb.e2ee_messages import generate_x25519_keypair
from aweb.e2ee_messages import encrypt_e2ee_message
from aweb.mcp.auth import AuthContext, _auth_context, get_auth
from aweb.mcp.tools import chat as mcp_chat, mail as mcp_mail, contacts
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401
from test_addressless_sender_cli import _registry_http
from test_cli_human_reply import _pem
from test_chat_signed_recipient_display import _aw
from test_messages_http import _signed_team_headers


async def _cli(binary, cwd, env, *args):
    # Window notices belong to stderr, while stdout is the CLI JSON contract.
    return await _aw(binary, (cwd, env), *args)


def cli_context(env, root, alias):
    actor = env.actors[alias]
    home = root / alias / ".aw"
    home.mkdir(parents=True)
    cert_path = "team-certs/" + TEAM.replace("__", "____").replace(":", "__") + ".pem"
    (home / "team-certs").mkdir()
    cert = json.loads(base64.b64decode(actor.certificate))
    cert.pop("signature")
    for field in ("member_did_aw", "member_address"):
        if not cert.get(field):
            cert.pop(field, None)
    cert["signature"] = sign_message(env.team_sk, canonical_json_bytes(cert))
    (home / cert_path).write_text(json.dumps(cert))
    membership = dict(team_id=TEAM, alias=alias, cert_path=cert_path)
    (home / "teams.yaml").write_text(json.dumps(dict(active_team=TEAM, memberships=[membership])))
    (home / "workspace.yaml").write_text(json.dumps(dict(
        aweb_url=str(env.client.base_url), memberships=[dict(membership, workspace_id=str(actor.workspace))],
    )))
    _pem(home / "signing.key", "ED25519 PRIVATE KEY", actor.sk)
    private, public = generate_x25519_keypair()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    assertion = build_encryption_key_assertion(signing_key=actor.sk, identity_did=actor.did,
        identity_stable_id="", encryption_public_key=public, custody="self", now=now)
    _pem(home / "encryption.key", "X25519 PRIVATE KEY", private)
    (home / "assertion.json").write_text(json.dumps(assertion))
    (home / "encryption.yaml").write_text(json.dumps(dict(active_key_id=assertion["encryption_key_id"], keys=[dict(
        key_id=assertion["encryption_key_id"], public_key=assertion["encryption_public_key"],
        private_key_path="encryption.key", assertion_path="assertion.json", published_at=now.isoformat(),
        **{k:assertion[k] for k in ("created_at","not_before","expires_at")},
    )])))
    child = {k: v for k, v in os.environ.items() if not k.startswith(("AWEB_", "AWID_"))}
    child.update(AWEB_IDENTITY_HOME=str(home), AWEB_URL=str(env.client.base_url),
                 HOME=str(root / alias), XDG_CONFIG_HOME=str(root / alias / "config"))
    return home, child


async def send_plain(env, kind, via, *, conversation_id=None):
    actor, recipient = env.actors["alice"], env.actors["bob"]
    mid, cid = str(uuid4()), conversation_id or str(uuid4())
    stamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    fields = dict(type=kind, from_did=actor.did, to_did=recipient.did,
                  subject="subject" if kind == "mail" else "", body="via body",
                  timestamp=stamp, message_id=mid, conversation_id=cid,
                  **{"from": "alice", "to": "bob"})
    if via is not None:
        fields["via"] = via
    raw = canonical_payload(fields).decode()
    signed = dict(from_did=actor.did, signature=sign_message(actor.sk, raw.encode()),
                  signed_payload=raw, message_id=mid, timestamp=stamp)
    if kind == "mail":
        body = dict(signed, to_did=recipient.did, subject="subject", body="via body", conversation_id=cid)
        response = await _request(env, "alice", "POST", "/v1/messages", body)
    else:
        if conversation_id:
            response = await _request(env, "alice", "POST", f"/v1/chat/sessions/{cid}/messages", dict(signed, body="via body"))
        else:
            body = dict(signed, to_dids=[recipient.did], message="via body", session_id=cid)
            response = await _request(env, "alice", "POST", "/v1/chat/sessions", body)
    assert response.status_code == 200, response.text
    return mid, cid, raw


def assert_source(msg, raw):
    assert msg["signed_payload"] == raw
    payload = json.loads(raw)
    assert verify_signature(payload["from_did"], raw.encode(), msg["signature"]) == VerifyResult.VERIFIED


@pytest.mark.asyncio
@pytest.mark.parametrize("via", [None, "telegram", "msteams"])
async def test_plaintext_retention_paths_and_real_cli(privacy_app, tmp_path, aw_cli_binary, via):
    env = privacy_app
    mail_id, mail_cid, mail_raw = await send_plain(env, "mail", via)
    next_id, _, next_raw = await send_plain(env, "mail", via, conversation_id=mail_cid)
    chat_id, chat_cid, chat_raw = await send_plain(env, "chat", via)
    # Both recipient and sender read the exact retained string, including replay.
    for alias in ["bob", "alice", "bob"]:
        for path in [f"/v1/messages/{mail_id}", f"/v1/messages/conversations/{mail_cid}"]:
            response = await _request(env, alias, "GET", path)
            assert response.status_code == 200, response.text
            msg = response.json()
            if "messages" in msg:
                assert_source(next(row for row in msg["messages"] if row["message_id"] == mail_id), mail_raw)
            else:
                assert_source(msg, mail_raw)
        response = await _request(env, alias, "GET", f"/v1/chat/sessions/{chat_cid}/messages?message_id={chat_id}")
        assert response.status_code == 200, response.text
        assert_source(response.json()["messages"][0], chat_raw)
    inbox = await _request(env, "bob", "GET", f"/v1/messages/inbox?message_id={mail_id}")
    assert_source(inbox.json()["messages"][0], mail_raw)
    page = await _request(env, "bob", "GET", f"/v1/messages/conversations/{mail_cid}?limit=1")
    assert_source(page.json()["messages"][0], mail_raw)
    cursor = page.json()["next_cursor"]
    assert cursor
    page = await _request(env, "bob", "GET", f"/v1/messages/conversations/{mail_cid}?limit=1&cursor={cursor}")
    assert_source(page.json()["messages"][0], next_raw)
    # Discovery previews point at the full read above; they never establish via.
    pending = await _request(env, "bob", "GET", "/v1/chat/pending")
    assert any(p["session_id"] == chat_cid for p in pending.json()["pending"])
    sessions = await _request(env, "bob", "GET", "/v1/chat/sessions")
    assert chat_cid in sessions.text
    deadline = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    bob = env.actors["bob"]
    events = await env.client.get("/v1/events/stream", params={"deadline": deadline},
        headers=_signed_team_headers(bob.sk, bob.did, TEAM, bob.certificate))
    assert events.status_code == 200, events.text
    assert mail_id in events.text and chat_cid in events.text
    # Project the same authenticated reader context through MCP on real rows.
    actor = env.actors["bob"]
    token = _auth_context.set(AuthContext(team_id=TEAM, agent_id=str(actor.id), alias="bob", did_key=actor.did))
    try:
        history = json.loads(await mcp_chat.chat_history(env.infra, session_id=chat_cid))
        assert_source(history["messages"][0], chat_raw)
        target = dict(did_key=env.actors["alice"].did, alias="alice")
        mail_rows = json.loads(await mcp_mail.check_inbox(env.infra, unread_only=False))["messages"]
        assert_source(next(row for row in mail_rows if row["message_id"] == mail_id), mail_raw)
        contact_mail = await contacts._read_mail_messages_from_target(env.infra, target=target, limit=10)
        assert_source(next(row for row in contact_mail if row["message_id"] == mail_id), mail_raw)
        mcp_pending = json.loads(await mcp_chat.chat_pending(env.infra, env.redis))
        assert chat_cid in json.dumps(mcp_pending)
        contact_rows = await contacts._read_chat_messages_from_target(env.infra, target=target, limit=10)
        assert_source(next(row for row in contact_rows if row["message_id"] == chat_id), chat_raw)
        replies, _ = await mcp_chat._wait_for_replies(
            env.db, env.redis, session_id=UUID(chat_cid),
            participant_did=actor.did, after=datetime.now(timezone.utc) - timedelta(minutes=1),
            wait_seconds=1, auth=get_auth(),
            hosted_decryptor=None,
        )
        assert_source(replies[0], chat_raw)
    finally:
        _auth_context.reset(token)

    # The actual released/current binary verifies REST bytes before presentation.
    async with _registry_http(env.registry_app) as (registry_url, _):
        for alias in ["bob", "alice"]:
            home, child = cli_context(env, tmp_path, alias)
            child["AWID_REGISTRY_URL"] = registry_url
            mail = await _cli(aw_cli_binary, home.parent, child, "mail", "show", "--message-id", mail_id, "--json")
            assert mail["messages"][0]["verification_status"] == "verified"
            assert_source(mail["messages"][0], mail_raw)
            history = await _cli(aw_cli_binary, home.parent, child, "mail", "show", "--conversation-id", mail_cid, "--limit", "1", "--json")
            assert history["messages"][0]["verification_status"] == "verified"
            assert_source(history["messages"][0], mail_raw)
            if alias == "bob":
                inbox_cli = await _cli(aw_cli_binary, home.parent, child, "mail", "inbox", "--show-all", "--json")
                assert_source(next(row for row in inbox_cli["messages"] if row["message_id"] == mail_id), mail_raw)
            chat = await _cli(aw_cli_binary, home.parent, child, "chat", "history", "--session-id", chat_cid, "--json")
            assert chat["messages"][0]["verification_status"] == "verified"


@pytest.mark.asyncio
@pytest.mark.parametrize("via", [None, "telegram", "msteams"])
async def test_released_channel_real_server_retention_matrix(privacy_app, tmp_path, via):
    artifact = os.environ.get("AW_TEST_CHANNEL_BUNDLE")
    if not artifact:
        pytest.skip("set AW_TEST_CHANNEL_BUNDLE to the published channel1.8.0 dist/index.js")
    original = Path(artifact).read_bytes()
    assert hashlib.sha256(original).hexdigest() == "bf9c42ccc91c82eb172a9304bdc493288097c794efa6da56d7afc4d765dd4c96"
    module = tmp_path / "released.mjs"
    module.write_bytes(original + b"\nexport {APIClient,fetchInbox,fetchHistory,verifyInboxMessage,verifyChatMessage,parseSSEResponse};\n")
    env = privacy_app
    messages = {}
    for kind in ("mail", "chat"):
        mid, cid, raw = await send_plain(env, kind, via)
        messages[kind] = dict(mid=mid, cid=cid, raw=raw)
    mid, cid, raw = await send_plain(env, "mail", via, conversation_id=messages["mail"]["cid"])
    messages["mail_next"] = dict(mid=mid, cid=cid, raw=raw)
    bob = env.actors["bob"]
    arguments = dict(url=str(env.client.base_url), messages=messages, auth=dict(
        did=bob.did, stableID="", teamID=TEAM, teamCertificateHeader=bob.certificate,
        signingKey=bob.sk.hex()))
    process = await asyncio.create_subprocess_exec("node", str(Path(__file__).with_name("released_signed_via_probe.mjs")),
        str(module), stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await asyncio.wait_for(process.communicate(json.dumps(arguments).encode()), 30)
    assert process.returncode == 0, stderr.decode()
    assert json.loads(stdout)["event_then_fetch"] == ["chat", "mail"]


@pytest.mark.asyncio
@pytest.mark.parametrize("via", ["telegram", "msteams"])
async def test_real_cli_live_chat_via(privacy_app, tmp_path, aw_cli_binary, via):
    from aweb.messaging.waiting import get_waiting_agents
    env = privacy_app
    first, cid, _ = await send_plain(env, "chat", None)
    marked = await _request(env, "bob", "POST", f"/v1/chat/sessions/{cid}/read", {"up_to_message_id": first})
    assert marked.status_code == 200, marked.text
    home, child = cli_context(env, tmp_path, "bob")
    async with _registry_http(env.registry_app) as (registry_url, _):
        child["AWID_REGISTRY_URL"] = registry_url
        listening = asyncio.create_task(_cli(aw_cli_binary, home.parent, child, "chat", "listen", "alice", "--wait", "5", "--json"))
        try:
            async with asyncio.timeout(5):
                while not await get_waiting_agents(env.redis, cid, [env.actors["bob"].did]):
                    await asyncio.sleep(0.02)
            mid, _, _ = await send_plain(env, "chat", via, conversation_id=cid)
            shown = await listening
            message = next(event for event in shown["events"] if event.get("message_id") == mid)
            assert message["verification_status"] == "verified", message
            assert message["body"] == "via body"
        finally:
            # Drain the owned subprocess before the fixture tears down its app.
            if not listening.done():
                await listening


async def read_v2_messages(env, tmp_path, aw_cli_binary, kind, via):
    identities, contexts = {}, {}
    for alias in ("alice", "bob"):
        home, child = cli_context(env, tmp_path, alias)
        contexts[alias] = home, child
        actor = env.actors[alias]
        assertion = json.loads((home / "assertion.json").read_text())
        identities[alias] = dict(did=actor.did, team_id=TEAM, signing_key=actor.sk, encryption_key=assertion)
    mid, cid = str(uuid4()), str(uuid4())
    envelope = encrypt_e2ee_message(kind=kind, sender=identities["alice"], recipients=[identities["bob"]],
        body="protected via body", subject="protected subject", message_id=mid,
        conversation_id=cid, created_at=datetime.now(timezone.utc), **({"via": via} if via is not None else {}))
    assert "via" not in envelope
    if via is not None:
        assert via not in json.dumps(envelope)
    request = dict(message_id=mid, timestamp=envelope["created_at"], from_did=env.actors["alice"].did,
                   content_mode="encrypted_v2", message_version=2, encrypted_envelope=envelope)
    if kind == "mail":
        request.update(to_did=env.actors["bob"].did, conversation_id=cid)
        response = await _request(env, "alice", "POST", "/v1/messages", request)
    else:
        request.update(to_dids=[env.actors["bob"].did], session_id=cid, message="")
        response = await _request(env, "alice", "POST", "/v1/chat/sessions", request)
    assert response.status_code == 200, response.text
    projected = []
    async with _registry_http(env.registry_app) as (registry_url, _):
        for alias in ("bob", "alice"):
            home, child = contexts[alias]
            child["AWID_REGISTRY_URL"] = registry_url
            args = ("mail", "show", "--message-id", mid, "--json") if kind == "mail" else (
                "chat", "history", "--session-id", cid, "--json")
            shown = await _cli(aw_cli_binary, home.parent, child, *args)
            message = shown["messages"][0]
            assert message["verification_status"] == "verified", message
            assert message["body"] == "protected via body"
            # Released Go omits optional empty strings in its DTO JSON. Its
            # signature and ciphertext commitments remain byte-identical.
            assert message["encrypted_envelope"]["ciphertext"] == envelope["ciphertext"]
            assert message["encrypted_envelope"]["signature"] == envelope["signature"]
            projected.append(message)
    return projected


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("via", ["telegram", "msteams"])
async def test_real_cli_decrypts_via_under_unchanged_v2(privacy_app, tmp_path, aw_cli_binary, kind, via):
    await read_v2_messages(privacy_app, tmp_path, aw_cli_binary, kind, via)
