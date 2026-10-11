"""Encrypted mail from a local sender reads back verified through the real aw CLI.

A local sender signs no address into the E2EE envelope. Real HTTP/DB/registry,
real CLI subprocesses; no routing, identity, delivery or cryptography is mocked.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path

import pytest

from awid.did import stable_id_from_did_key
from awid.e2ee_keys import build_encryption_key_assertion
from awid.signing import canonical_json_bytes, sign_message
from aweb.e2ee_messages import generate_x25519_keypair
from test_cli_human_reply import _cli, _pem
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_messages_http import _make_keypair, _make_certificate, _signed_team_headers


async def _cli_binary(tmp_path):
    binary = Path(os.environ.get("AW_TEST_CLI_BINARY", str(tmp_path / "aw")))
    if "AW_TEST_CLI_BINARY" not in os.environ:
        build = await asyncio.create_subprocess_exec(
            "go", "build", "-o", str(binary), "./cmd/aw",
            cwd=Path(__file__).resolve().parents[2] / "cli/go",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        output, _ = await build.communicate()
        assert build.returncode == 0, output.decode()
    return binary


async def _home(env, tmp_path, name, team_sk, team_did, now, global_scope):
    actor = env.actors[name]
    address = f"example.test/{name}" if global_scope else ""
    stable_id = stable_id_from_did_key(actor.did) if global_scope else ""
    scope = "global" if global_scope else "local"
    if global_scope:
        await env.db.execute(
            "UPDATE {{tables.agents}} SET identity_scope='global', did_aw=$1, address=$2 WHERE agent_id=$3",
            stable_id, address, actor.id)
        await env.app.state.awid_registry_client.register_did(actor.did, actor.sk)
    private, public = generate_x25519_keypair()
    assertion = build_encryption_key_assertion(
        signing_key=actor.sk, identity_did=actor.did, identity_stable_id=stable_id,
        encryption_public_key=public, custody="self", now=now)
    cert = _make_certificate(team_sk, team_did, actor.did, team_id=TEAM, alias=name, identity_scope=scope,
                             member_did_aw=stable_id, member_address=address)
    cert.pop("signature")
    if not global_scope:
        cert.pop("member_did_aw")
        cert.pop("member_address")
    cert["signature"] = sign_message(team_sk, canonical_json_bytes(cert))
    body = json.dumps(assertion).encode()
    headers = _signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate, body)
    headers["Content-Type"] = "application/json"
    published = await env.client.put("/v1/agents/me/encryption-key", content=body, headers=headers)
    assert published.status_code == 200, published.text

    root = (tmp_path / name).resolve()
    home = root / ".aw"
    home.mkdir(parents=True, mode=0o700)
    if global_scope:
        (home / "identity.yaml").write_text(json.dumps({
            "did": actor.did, "stable_id": stable_id, "address": address,
            "custody": "self", "identity_scope": scope, "created_at": now.isoformat()}))
    cert_path = "team-certs/" + TEAM.replace("__", "____").replace(":", "__") + ".pem"
    (home / "team-certs").mkdir(mode=0o700)
    (home / cert_path).write_text(json.dumps(cert))
    (home / cert_path).chmod(0o600)
    membership = {"team_id": TEAM, "alias": name, "cert_path": cert_path}
    (home / "teams.yaml").write_text(json.dumps({"active_team": TEAM, "memberships": [membership]}))
    (home / "workspace.yaml").write_text(json.dumps({
        "aweb_url": str(env.client.base_url),
        "memberships": [{**membership, "workspace_id": str(actor.workspace)}]}))
    _pem(home / "signing.key", "ED25519 PRIVATE KEY", actor.sk)
    _pem(home / "encryption.key", "X25519 PRIVATE KEY", private)
    (home / "assertion.json").write_text(json.dumps(assertion))
    (home / "encryption.yaml").write_text(json.dumps({
        "active_key_id": assertion["encryption_key_id"], "keys": [{
            "key_id": assertion["encryption_key_id"], "public_key": assertion["encryption_public_key"],
            "private_key_path": "encryption.key", "assertion_path": "assertion.json",
            **{key: assertion[key] for key in ("created_at", "not_before", "expires_at")},
            "published_at": now.isoformat()}]}))
    child = {k: v for k, v in os.environ.items() if not k.startswith(("AW", "XDG_"))}
    child.update(AWEB_IDENTITY_HOME=str(home), AWEB_URL=str(env.client.base_url), HOME=str(root),
                 XDG_CONFIG_HOME=str(root / "config"), AW_NO_UPDATE_CHECK="1",
                 AWID_REGISTRY_URL=str(env.client.base_url))
    return root, child


@pytest.mark.asyncio
@pytest.mark.parametrize("reader_global", [False, True])
async def test_local_sender_e2ee_mail_reads_verified(privacy_app, tmp_path, reader_global):
    env = privacy_app
    env.app.state.public_origin = str(env.client.base_url).rstrip("/")
    now = datetime.now(timezone.utc)
    team_sk, _, team_did = _make_keypair()
    await env.db.execute("UPDATE {{tables.teams}} SET team_did_key=$1 WHERE team_id=$2", team_did, TEAM)
    await env.registry_db.execute("UPDATE {{tables.teams}} SET team_did_key=$1 WHERE name=$2",
                                  team_did, TEAM.split(":", 1)[0])
    sender = await _home(env, tmp_path, "alice", team_sk, team_did, now, global_scope=False)
    reader = await _home(env, tmp_path, "bob", team_sk, team_did, now, global_scope=reader_global)
    binary = await _cli_binary(tmp_path)

    body_file = tmp_path / "body.txt"
    body_file.write_text("local sender private text")
    sent = await _cli(binary, *sender, "mail", "send", "--e2ee", "--to", "bob",
                      "--subject", "Local encrypted", "--body-file", str(body_file), "--json")
    shown = await _cli(binary, *reader, "mail", "show", "--message-id", sent["message_id"], "--json")
    message = next(m for m in shown["messages"] if m["message_id"] == sent["message_id"])
    assert message["content_mode"] == "encrypted_v2"
    assert message["body"] == "local sender private text"
    assert message["encrypted_envelope"]["from"].get("address", "") == ""
    assert message["verification_status"] == "verified", json.dumps(message, indent=1)
