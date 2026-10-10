"""Addressless global sender verification using real apps and the public CLI."""
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import socket
from uuid import UUID, uuid4

import pytest
import uvicorn
from awid.did import stable_id_from_did_key
from awid.e2ee_keys import build_encryption_key_assertion
from awid.signing import canonical_json_bytes, sign_message
from aweb.e2ee_messages import encrypt_e2ee_mail, encrypt_e2ee_chat, generate_x25519_keypair
from test_cli_human_reply import _cli, _pem, _reply_context
from test_messages_http import _make_keypair, _make_certificate, _signed_team_headers
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401


@asynccontextmanager
async def _registry_http(app):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    server = uvicorn.Server(uvicorn.Config(app, lifespan="off", log_level="error"))
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        for _ in range(100):
            if server.started:
                break
            await asyncio.sleep(0.02)
        assert server.started
        yield f"http://127.0.0.1:{sock.getsockname()[1]}", server
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 5)
        sock.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("global_resident,grant", [(False, False), (False, True), (True, False), (True, True)])
async def test_addressless_global_sender_verified(privacy_app, tmp_path, global_resident, grant):
    env = privacy_app
    env.app.state.public_origin = str(env.client.base_url).rstrip("/")
    now = datetime.now(timezone.utc)
    identities = {}
    for name, custody in (("alice", "hosted_custodial"), ("bob", "self"), ("carol", "self")):
        actor = env.actors[name]
        private, public = generate_x25519_keypair()
        address = "example.test/bob" if global_resident and name == "bob" else ""
        stable_id = stable_id_from_did_key(actor.did) if address or name == "alice" else ""
        if stable_id:
            await env.db.execute("UPDATE {{tables.agents}} SET identity_scope = 'global', did_aw = $1, address = $2 WHERE agent_id = $3",
                                 stable_id, address, actor.id)
        assertion = build_encryption_key_assertion(
            signing_key=actor.sk, identity_did=actor.did, identity_stable_id=stable_id,
            encryption_public_key=public, custody=custody, now=now,
        )
        identities[name] = dict(address=address, did=actor.did, stable_id=stable_id, team_id=TEAM,
                                signing_key=actor.sk, private_key=private, encryption_key=assertion)
    await env.db.execute("UPDATE {{tables.agents}} SET agent_type = 'human' WHERE agent_id = $1", env.actors["alice"].id)
    human, agent = identities["alice"], identities["bob"]
    peer = identities["carol"]
    peer_body = json.dumps(peer["encryption_key"]).encode()
    peer_actor = env.actors["carol"]
    peer_headers = _signed_team_headers(peer_actor.sk, peer_actor.did, TEAM, peer_actor.certificate, peer_body)
    peer_headers["Content-Type"] = "application/json"
    published = await env.client.put("/v1/agents/me/encryption-key", content=peer_body, headers=peer_headers)
    assert published.status_code == 200, published.text
    await env.app.state.awid_registry_client.register_did(human["did"], human["signing_key"])
    await env.db.execute("UPDATE {{tables.agents}} SET certificate_id='privacy-alice' WHERE agent_id=$1", env.actors["alice"].id)
    message_id, conversation_id = str(uuid4()), str(uuid4())
    source = encrypt_e2ee_mail(sender=human, recipients=[agent], subject="Human question",
                              body="Human private text", message_id=message_id,
                              conversation_id=conversation_id, created_at=now)
    sent = await _request(env, "alice", "POST", "/v1/messages", {
        "to_did": agent["did"], "message_id": message_id, "conversation_id": conversation_id,
        "content_mode": "encrypted_v2", "message_version": 2, "encrypted_envelope": source,
    })
    assert sent.status_code == 200, sent.text
    assert source["sender_encryption_key"]["custody"] == "hosted_custodial"

    chat_id, chat_message_id = str(uuid4()), str(uuid4())
    chat_source = encrypt_e2ee_chat(sender=human, recipients=[agent], body="Human chat",
                                   message_id=chat_message_id, conversation_id=chat_id, created_at=now)
    chat_sent = await _request(env, "alice", "POST", "/v1/chat/sessions", {
        "to_dids": [agent["did"]], "session_id": chat_id, "message": "",
        "message_id": chat_message_id, "timestamp": chat_source["created_at"],
        "content_mode": "encrypted_v2", "message_version": 2, "encrypted_envelope": chat_source,
    })
    assert chat_sent.status_code == 200, chat_sent.text

    identity_home = tmp_path / ".aw"
    identity_home.mkdir(mode=0o700)
    # API-key local init intentionally omits identity.yaml. Neither root nor
    # grant custody may require it or manufacture global identity state.
    if global_resident:
        (identity_home / "identity.yaml").write_text(json.dumps({
            "did": agent["did"], "stable_id": agent["stable_id"], "address": agent["address"],
            "custody": "self", "identity_scope": "global", "created_at": now.isoformat(),
        }))
    else:
        assert not (identity_home / "identity.yaml").exists()
    team_sk, _, team_did = _make_keypair()
    await env.db.execute("UPDATE {{tables.teams}} SET team_did_key = $1 WHERE team_id = $2", team_did, TEAM)
    await env.registry_db.execute("UPDATE {{tables.teams}} SET team_did_key = $1 WHERE name = $2", team_did, TEAM.split(":", 1)[0])
    cert = _make_certificate(team_sk, team_did, agent["did"], team_id=TEAM, alias="bob", identity_scope="global" if global_resident else "local",
                             member_did_aw=agent["stable_id"], member_address=agent["address"])
    # Match the CLI wire format: absent optional local fields, not empty strings.
    cert.pop("signature")
    if not global_resident:
        for field in ("member_did_aw", "member_address"):
            cert.pop(field)
    cert["signature"] = sign_message(team_sk, canonical_json_bytes(cert))
    cert_path = "team-certs/" + TEAM.replace("__", "____").replace(":", "__") + ".pem"
    (identity_home / "team-certs").mkdir(mode=0o700)
    (identity_home / cert_path).write_text(json.dumps(cert))
    (identity_home / cert_path).chmod(0o600)
    membership = {"team_id": TEAM, "alias": "bob", "cert_path": cert_path}
    (identity_home / "teams.yaml").write_text(json.dumps({"active_team": TEAM, "memberships": [membership]}))
    (identity_home / "workspace.yaml").write_text(json.dumps({
        "aweb_url": str(env.client.base_url), "memberships": [{**membership, "workspace_id": str(env.actors["bob"].workspace)}],
    }))
    _pem(identity_home / "signing.key", "ED25519 PRIVATE KEY", agent["signing_key"])
    _pem(identity_home / "encryption.key", "X25519 PRIVATE KEY", agent["private_key"])
    assertion = agent["encryption_key"]
    (identity_home / "assertion.json").write_text(json.dumps(assertion))
    (identity_home / "encryption.yaml").write_text(json.dumps({
        "active_key_id": assertion["encryption_key_id"], "keys": [{
            "key_id": assertion["encryption_key_id"], "public_key": assertion["encryption_public_key"],
            "private_key_path": "encryption.key",
            "assertion_path": "assertion.json",
            **{key: assertion[key] for key in ("created_at", "not_before", "expires_at")},
            "published_at": now.isoformat(),
        }],
    }))
    root = Path(__file__).resolve().parents[2]
    binary = Path(os.environ.get("AW_TEST_CLI_BINARY", str(tmp_path / "aw")))
    if "AW_TEST_CLI_BINARY" not in os.environ:
        build = await asyncio.create_subprocess_exec("go", "build", "-o", str(binary), "./cmd/aw",
                                                    cwd=root / "cli/go", stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.STDOUT)
        output, _ = await build.communicate()
        assert build.returncode == 0, output.decode()
    child_env = {k: v for k, v in os.environ.items() if not k.startswith(("AWEB_", "AWID_"))}
    child_env.update(AWEB_IDENTITY_HOME=str(identity_home), AWEB_URL=str(env.client.base_url),
                     HOME=str(tmp_path), XDG_CONFIG_HOME=str(tmp_path / "config"),
                     AWID_REGISTRY_URL=str(env.client.base_url))
    async with _registry_http(env.registry_app) as (registry_url, registry_server):
        child_env["AWID_REGISTRY_URL"] = registry_url
        async with _reply_context(binary, tmp_path, child_env, grant, agent["address"]) as (command_dir, command_env):
            async def read_both(expected):
                for args in (("mail", "show", "--message-id", message_id),
                             ("chat", "history", "--session-id", chat_id)):
                    result = await _cli(binary, command_dir, command_env, *args, "--json")
                    shown = result["messages"][0]
                    assert shown["verification_status"] == expected, {
                        k: shown.get(k) for k in ("verification_status", "from_address", "sender_membership")
                    }
                    assert shown["from_stable_id"] == human["stable_id"]
                    assert not shown.get("from_address")
            await read_both("verified")
            # Read-time metadata must not promote a forged encrypted signature.
            stored = await env.db.fetch_value("SELECT encrypted_envelope FROM {{tables.messages}} WHERE message_id=$1", UUID(message_id))
            envelope = json.loads(stored) if isinstance(stored, str) else dict(stored)
            damaged = dict(envelope, signature=sign_message(env.actors["carol"].sk, b"wrong message"))
            await env.db.execute("UPDATE {{tables.messages}} SET encrypted_envelope=$1::jsonb WHERE message_id=$2", json.dumps(damaged), UUID(message_id))
            refused = await asyncio.create_subprocess_exec(str(binary), "mail", "show", "--message-id", message_id, "--json",
                cwd=command_dir, env=command_env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            _, error = await asyncio.wait_for(refused.communicate(), 30)
            assert refused.returncode != 0, error.decode()
            await env.db.execute("UPDATE {{tables.messages}} SET encrypted_envelope=$1::jsonb WHERE message_id=$2", json.dumps(envelope), UUID(message_id))
            await env.db.execute("UPDATE {{tables.agents}} SET certificate_id=NULL WHERE agent_id=$1", env.actors["alice"].id)
            await read_both("verification_stale")
            await env.db.execute("UPDATE {{tables.agents}} SET certificate_id='privacy-alice' WHERE agent_id=$1", env.actors["alice"].id)
            # A second CLI process restores the registry-scoped checkpoint.
            await read_both("verified")
            await env.db.execute("UPDATE {{tables.agents}} SET status='retired' WHERE agent_id=$1", env.actors["alice"].id)
            await read_both("identity_mismatch")
            await env.db.execute("UPDATE {{tables.agents}} SET status='active' WHERE agent_id=$1", env.actors["alice"].id)
            # Real signed registry rotation: old messages remain signed correctly,
            # but the current key must no longer match the old signer.
            rotated_sk, _, rotated_did = _make_keypair()
            await env.app.state.awid_registry_client.rotate_key(human["stable_id"], rotated_did, human["signing_key"], rotated_sk)
            await read_both("identity_mismatch")
            registry_server.should_exit = True
            for _ in range(100):
                if not registry_server.started or not registry_server.servers[0].is_serving():
                    break
                await asyncio.sleep(0.02)
            await read_both("verification_stale")
