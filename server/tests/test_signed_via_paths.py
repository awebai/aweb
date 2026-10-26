"""Real Postgres/Redis/AWID/server, with current or explicitly released readers."""
import asyncio
import base64
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from awid.signing import canonical_payload, sign_message, verify_signature, VerifyResult
from awid.signing import canonical_json_bytes
from awid.e2ee_keys import build_encryption_key_assertion
from aweb.e2ee_messages import generate_x25519_keypair
from aweb.mcp.auth import AuthContext, _auth_context, get_auth
from aweb.mcp.tools import chat as mcp_chat, mail as mcp_mail, contacts
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401
from test_addressless_sender_cli import _registry_http
from test_cli_human_reply import _cli, _pem
from test_messages_http import _signed_team_headers


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


async def send_plain(env, kind, via):
    actor, recipient = env.actors["alice"], env.actors["bob"]
    mid, cid = str(uuid4()), str(uuid4())
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
    chat_id, chat_cid, chat_raw = await send_plain(env, "chat", via)
    # Both recipient and sender read the exact retained string, including replay.
    for alias in ["bob", "alice", "bob"]:
        for path in [f"/v1/messages/{mail_id}", f"/v1/messages/conversations/{mail_cid}"]:
            response = await _request(env, alias, "GET", path)
            assert response.status_code == 200, response.text
            msg = response.json()
            assert_source(msg["messages"][0] if "messages" in msg else msg, mail_raw)
        response = await _request(env, alias, "GET", f"/v1/chat/sessions/{chat_cid}/messages?message_id={chat_id}")
        assert response.status_code == 200, response.text
        assert_source(response.json()["messages"][0], chat_raw)
    inbox = await _request(env, "bob", "GET", f"/v1/messages/inbox?message_id={mail_id}")
    assert_source(inbox.json()["messages"][0], mail_raw)
    # Discovery previews point at the full read above; they never establish via.
    pending = await _request(env, "bob", "GET", "/v1/chat/pending")
    assert any(p["session_id"] == chat_cid for p in pending.json()["pending"])
    deadline = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    bob = env.actors["bob"]
    events = await env.client.get("/v1/events/stream", params={"deadline": deadline},
        headers=_signed_team_headers(bob.sk, bob.did, TEAM, bob.certificate))
    assert events.status_code == 200, events.text
    assert mail_id in events.text and chat_cid in events.text
    # The actual released/current binary verifies REST bytes before presentation.
    async with _registry_http(env.registry_app) as (registry_url, _):
        for alias in ["bob", "alice"]:
            home, child = cli_context(env, tmp_path, alias)
            child["AWID_REGISTRY_URL"] = registry_url
            mail = await _cli(aw_cli_binary, home.parent, child, "mail", "show", "--message-id", mail_id, "--json")
            assert mail["messages"][0]["verification_status"] == "verified"
            assert_source(mail["messages"][0], mail_raw)
            chat = await _cli(aw_cli_binary, home.parent, child, "chat", "history", "--session-id", chat_cid, "--json")
            assert chat["messages"][0]["verification_status"] == "verified"
    # Project the same authenticated reader context through MCP on real rows.
    actor = env.actors["bob"]
    token = _auth_context.set(AuthContext(team_id=TEAM, agent_id=str(actor.id), alias="bob", did_key=actor.did))
    try:
        history = json.loads(await mcp_chat.chat_history(env.infra, session_id=chat_cid))
        assert_source(history["messages"][0], chat_raw)
        target = dict(did_key=env.actors["alice"].did, alias="alice")
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
