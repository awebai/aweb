"""Encrypted mail from a local sender is verified against the live team roster,
both by `aw mail show` and by the channel-core bundle aw embeds for its wake broker.

A local sender signs no address and no stable ID into the E2EE envelope.
Real HTTP/DB/registry and real CLI subprocesses; the only stand-in records
what the wake broker types into the terminal.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest

from awid.did import stable_id_from_did_key
from awid.e2ee_keys import build_encryption_key_assertion
from awid.signing import canonical_json_bytes, sign_message
from aweb.e2ee_messages import encrypt_e2ee_mail, generate_x25519_keypair
from test_addressless_sender_cli import _registry_http
from test_cli_human_reply import _cli, _pem, _reply_context
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401
from test_messages_http import _make_keypair, _make_certificate


@asynccontextmanager
async def _local_sender_mail(env, tmp_path, global_resident, grant, sender_retired):
    """Deliver one local-sender E2EE mail to bob; yield bob's real CLI context."""
    env.app.state.public_origin = str(env.client.base_url).rstrip("/")
    now = datetime.now(timezone.utc)
    identities = {}
    for name in ("alice", "bob"):
        actor = env.actors[name]
        private, public = generate_x25519_keypair()
        address = "example.test/bob" if global_resident and name == "bob" else ""
        stable_id = stable_id_from_did_key(actor.did) if address else ""
        if stable_id:
            await env.db.execute("UPDATE {{tables.agents}} SET identity_scope = 'global', did_aw = $1, address = $2 WHERE agent_id = $3",
                                 stable_id, address, actor.id)
            await env.app.state.awid_registry_client.register_did(actor.did, actor.sk)
        assertion = build_encryption_key_assertion(
            signing_key=actor.sk, identity_did=actor.did, identity_stable_id=stable_id,
            encryption_public_key=public, custody="self", now=now,
        )
        identities[name] = dict(address=address, did=actor.did, stable_id=stable_id, team_id=TEAM,
                                signing_key=actor.sk, private_key=private, encryption_key=assertion)
    sender, agent = identities["alice"], identities["bob"]
    message_id, conversation_id = str(uuid4()), str(uuid4())
    source = encrypt_e2ee_mail(sender=sender, recipients=[agent], subject="Local encrypted",
                              body="local sender private text", message_id=message_id,
                              conversation_id=conversation_id, created_at=now)
    assert not source["from"].get("address") and not source["from"].get("stable_id")
    sent = await _request(env, "alice", "POST", "/v1/messages", {
        "to_did": agent["did"], "message_id": message_id, "conversation_id": conversation_id,
        "content_mode": "encrypted_v2", "message_version": 2, "encrypted_envelope": source,
    })
    assert sent.status_code == 200, sent.text
    if sender_retired:
        # Team lifecycle removal of a local member after it sent.
        await env.db.execute("UPDATE {{tables.workspaces}} SET deleted_at = NOW() WHERE workspace_id = $1",
                             env.actors["alice"].workspace)
        await env.db.execute("UPDATE {{tables.agents}} SET deleted_at = NOW(), status = 'deleted' WHERE agent_id = $1",
                             env.actors["alice"].id)

    identity_home = tmp_path / ".aw"
    identity_home.mkdir(mode=0o700)
    if global_resident:
        (identity_home / "identity.yaml").write_text(json.dumps({
            "did": agent["did"], "stable_id": agent["stable_id"], "address": agent["address"],
            "custody": "self", "identity_scope": "global", "created_at": now.isoformat(),
        }))
    team_sk, _, team_did = _make_keypair()
    await env.db.execute("UPDATE {{tables.teams}} SET team_did_key = $1 WHERE team_id = $2", team_did, TEAM)
    await env.registry_db.execute("UPDATE {{tables.teams}} SET team_did_key = $1 WHERE name = $2", team_did, TEAM.split(":", 1)[0])
    cert = _make_certificate(team_sk, team_did, agent["did"], team_id=TEAM, alias="bob", identity_scope="global" if global_resident else "local",
                             member_did_aw=agent["stable_id"], member_address=agent["address"])
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
            "private_key_path": "encryption.key", "assertion_path": "assertion.json",
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
                     HOME=str(tmp_path), XDG_CONFIG_HOME=str(tmp_path / "config"))
    async with _registry_http(env.registry_app) as (registry_url, _):
        child_env["AWID_REGISTRY_URL"] = registry_url
        async with _reply_context(binary, tmp_path, child_env, grant, agent["address"]) as (command_dir, command_env):
            yield message_id, conversation_id, binary, command_dir, command_env


@pytest.mark.asyncio
@pytest.mark.parametrize("sender_retired", [False, True])
@pytest.mark.parametrize("global_resident,grant", [(False, False), (False, True), (True, False), (True, True)])
async def test_local_sender_e2ee_mail_read_trust(privacy_app, tmp_path, global_resident, grant, sender_retired):
    async with _local_sender_mail(privacy_app, tmp_path, global_resident, grant, sender_retired) as (
            message_id, _, binary, command_dir, command_env):
        result = await _cli(binary, command_dir, command_env, "mail", "show", "--message-id", message_id, "--json")
        shown = result["messages"][0]
        assert shown["body"] == "local sender private text"
        # The live roster re-check is load-bearing: a removed member no
        # longer binds its key (docs/trust-model.md threat-model rulings).
        expected = "identity_mismatch" if sender_retired else "verified"
        assert shown["verification_status"] == expected, {
            k: shown.get(k) for k in ("verification_status", "from_alias", "from_address", "from_did",
                                      "from_stable_id", "to_did", "to_stable_id", "sender_membership")
        }


@pytest.mark.asyncio
@pytest.mark.parametrize("global_resident,grant", [(False, False), (False, True), (True, False), (True, True)])
async def test_wake_bundle_presents_local_sender_e2ee_mail_verified(privacy_app, tmp_path, global_resident, grant):
    """Drive the bundle aw embeds for its wake broker, decrypting through real aw."""
    async with _local_sender_mail(privacy_app, tmp_path, global_resident, grant, False) as (
            message_id, conversation_id, binary, command_dir, command_env):
        terminal = tmp_path / "terminal"
        terminal.mkdir()
        delivered = tmp_path / "terminal-input.txt"
        # Stands in for the terminal multiplexer only: it records what the
        # broker types. Delivery, decryption and trust are all real.
        oats = tmp_path / "oats"
        oats.write_text(
            "#!/bin/sh\n"
            "if [ \"$1 $2\" = \"session inspect\" ]; then echo '{\"ok\":true,\"result\":{\"present\":true,\"state\":\"idle\"}}'; exit 0; fi\n"
            f"if [ \"$1 $2\" = \"session input\" ]; then cat >> '{delivered}'; echo '{{\"ok\":true,\"result\":{{\"submitted\":true}}}}'; exit 0; fi\n"
            "exit 1\n")
        oats.chmod(0o755)
        identity_home = command_env["AWEB_IDENTITY_HOME"]
        lines = [
            {"type": "init", "home": str(terminal), "oatsBin": str(oats), "awCommand": str(binary),
             "bindings": [{"binding_id": "bob", "identity_home": identity_home, "team_id": TEAM,
                           "delivery_store_path": str(tmp_path / "delivery.json")}]},
            {"type": "event", "binding_id": "bob",
             "event": {"type": "mail_message", "message_id": message_id, "conversation_id": conversation_id}},
        ]
        bundle = Path(__file__).resolve().parents[2] / "cli/go/wake/channel_core_runner_bundle.mjs"
        runner = await asyncio.create_subprocess_exec(
            "node", str(bundle), cwd=command_dir, env=command_env, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        try:
            runner.stdin.write("".join(json.dumps(line) + "\n" for line in lines).encode())
            await runner.stdin.drain()
            statuses = []
            try:
                async with asyncio.timeout(30):
                    while not (delivered.exists() and "Use the aw CLI" in delivered.read_text()):
                        line = await runner.stdout.readline()
                        assert line, f"runner exited: {statuses}"
                        statuses.append(line.decode().strip())
            except TimeoutError:
                pytest.fail(f"wake runner presented nothing; statuses: {statuses}")
        finally:
            runner.stdin.write(b'{"type":"shutdown"}\n')
            await runner.stdin.drain()
            await asyncio.wait_for(runner.wait(), 10)
        text = delivered.read_text()
        assert "local sender private text" in text, text
        assert "- trust_status: verified\n" in text, text
