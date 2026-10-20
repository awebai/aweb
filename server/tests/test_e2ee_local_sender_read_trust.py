"""Encrypted mail from a local sender is verified against the live team roster,
by `aw mail show` and by every channel-core runtime: the Claude channel plugin,
the Pi extension and the bundle aw embeds for its wake broker.

A local sender signs no address and no stable ID into the E2EE envelope.
Real HTTP/DB/registry and real CLI subprocesses. The stand-ins are the hosts
only: what records the wake broker's terminal input, and the Pi session the
extension runs in. Registry faults are real conditions: an unreachable
registry, and a registry front that answers an address lookup with a 503.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import socket
import subprocess
from types import SimpleNamespace
from uuid import uuid4

import pytest

from awid.did import stable_id_from_did_key
from awid.e2ee_keys import build_encryption_key_assertion
from awid.signing import canonical_json_bytes, sign_message
from aweb.e2ee_messages import encrypt_e2ee_mail, generate_x25519_keypair
from test_addressless_sender_cli import _registry_http
from test_cli_human_reply import _cli, _pem, _reply_context
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401
from test_messages_http import _make_keypair, _make_certificate, _signed_team_headers, _encode_certificate


@asynccontextmanager
async def _local_sender_mail(env, tmp_path, global_resident, grant, sender_retired, *, human=False, cross_team=False, plaintext=False):
    """Deliver one local-sender E2EE mail to bob; yield bob's real CLI context
    and the registry it resolves through."""
    env.app.state.public_origin = str(env.client.base_url).rstrip("/")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    sender_team = TEAM
    if cross_team:
        sender_team = f"outbound-{uuid4().hex[:12]}:sender.test"
        sender_team_sk, _, sender_team_did = _make_keypair()
        await env.db.execute(
            "INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key) VALUES ($1, 'sender.test', $2, $3)",
            sender_team, sender_team.split(":", 1)[0], sender_team_did)
        await env.registry_db.execute(
            "INSERT INTO {{tables.teams}} (domain, name, team_did_key, visibility) VALUES ('sender.test', $1, $2, 'public')",
            sender_team.split(":", 1)[0], sender_team_did)
        await env.db.execute("UPDATE {{tables.agents}} SET team_id=$1, certificate_id='privacy-alice' WHERE agent_id=$2",
                             sender_team, env.actors["alice"].id)
        await env.db.execute("UPDATE {{tables.workspaces}} SET team_id=$1 WHERE workspace_id=$2",
                             sender_team, env.actors["alice"].workspace)
    identities = {}
    for name in ("alice", "bob"):
        actor = env.actors[name]
        private, public = generate_x25519_keypair()
        address = "example.test/bob" if global_resident and name == "bob" else ""
        stable_id = stable_id_from_did_key(actor.did) if address or (human and name == "alice") else ""
        if stable_id:
            await env.db.execute("UPDATE {{tables.agents}} SET identity_scope = 'global', did_aw = $1, address = $2 WHERE agent_id = $3",
                                 stable_id, address, actor.id)
            await env.app.state.awid_registry_client.register_did(actor.did, actor.sk)
        assertion = build_encryption_key_assertion(
            signing_key=actor.sk, identity_did=actor.did, identity_stable_id=stable_id,
            encryption_public_key=public, custody="hosted_custodial" if human and name == "alice" else "self", now=now,
        )
        identities[name] = dict(address=address, did=actor.did, stable_id=stable_id, team_id=sender_team if name == "alice" else TEAM,
                                signing_key=actor.sk, private_key=private, encryption_key=assertion)
    sender, agent = identities["alice"], identities["bob"]
    if human:
        await env.db.execute("UPDATE {{tables.agents}} SET agent_type='human', certificate_id='privacy-alice' WHERE agent_id=$1",
                             env.actors["alice"].id)
    message_id, conversation_id = str(uuid4()), str(uuid4())
    source = encrypt_e2ee_mail(sender=sender, recipients=[agent], subject="Local encrypted",
                              body="local sender private text", message_id=message_id,
                              conversation_id=conversation_id, created_at=now)
    assert not source["from"].get("address")
    assert bool(source["from"].get("stable_id")) == human
    if plaintext:
        payload = canonical_json_bytes(dict(
            type="mail", from_did=sender["did"], to_did=agent["did"], to_stable_id=agent["stable_id"],
            subject="Local encrypted", body="local sender private text", message_id=message_id,
            conversation_id=conversation_id, timestamp=now.isoformat(),
            **{"from": sender_team.split(":", 1)[1] + "/alice", "to": agent["address"]},
        ))
        body = dict(to_did=agent["did"], to_address=agent["address"], subject="Local encrypted",
                    body="local sender private text", message_id=message_id, conversation_id=conversation_id,
                    timestamp=now.isoformat(), from_did=sender["did"], to_stable_id=agent["stable_id"],
                    signature=sign_message(sender["signing_key"], payload), signed_payload=payload.decode())
    else:
        body = dict(to_did=agent["did"], message_id=message_id, conversation_id=conversation_id,
                    content_mode="encrypted_v2", message_version=2, encrypted_envelope=source)
    sent = await _request(env, "alice", "POST", "/v1/messages", body)
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
    registry = SimpleNamespace(url="", responses=[], address_lookup_status=None)

    async def recorded_registry(scope, receive, send):
        async def record(event):
            if event["type"] == "http.response.start":
                user_agent = dict(scope.get("headers") or []).get(b"user-agent", b"").decode()
                registry.responses.append((scope["method"], scope["path"], event["status"], user_agent))
            await send(event)
        if registry.address_lookup_status and scope["type"] == "http" and "/addresses/" in scope["path"]:
            await record({"type": "http.response.start", "status": registry.address_lookup_status, "headers": []})
            await send({"type": "http.response.body", "body": b"registry unavailable"})
            return
        await env.registry_app(scope, receive, record)

    async with _registry_http(recorded_registry) as (registry_url, _):
        registry.url = registry_url
        child_env["AWID_REGISTRY_URL"] = registry_url
        async with _reply_context(binary, tmp_path, child_env, grant, agent["address"], ttl="never" if cross_team else "5m") as (command_dir, command_env):
            yield message_id, conversation_id, binary, command_dir, command_env, registry


@pytest.mark.asyncio
@pytest.mark.parametrize("sender_retired", [False, True])
@pytest.mark.parametrize("global_resident,grant", [(False, False), (False, True), (True, False), (True, True)])
async def test_local_sender_e2ee_mail_read_trust(privacy_app, tmp_path, global_resident, grant, sender_retired):
    async with _local_sender_mail(privacy_app, tmp_path, global_resident, grant, sender_retired) as (
            message_id, _, binary, command_dir, command_env, _):
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


REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def runtime_packages():
    """Build the channel plugin and the Pi extension as they are packaged."""
    for package in ("channel", "pi-extension"):
        build = subprocess.run(["npm", "run", "build"], cwd=REPO / package, capture_output=True, text=True)
        assert build.returncode == 0, build.stdout + build.stderr


async def _read_until(process, presented, description):
    """Read JSON lines from a runtime until `presented` accepts one."""
    lines = []
    try:
        async with asyncio.timeout(30):
            while True:
                line = await process.stdout.readline()
                assert line, f"{description} exited: {lines}"
                lines.append(line.decode().strip())
                try:
                    found = presented(json.loads(line))
                except ValueError:
                    continue
                if found:
                    return found
    except TimeoutError:
        pytest.fail(f"{description} presented nothing; output: {lines}")


async def _present_by_wake(tmp_path, binary, command_dir, command_env, message_id, conversation_id):
    terminal = tmp_path / "terminal"
    terminal.mkdir()
    delivered = tmp_path / "terminal-input.txt"
    # Stands in for the terminal multiplexer only: it records what the broker types.
    oats = tmp_path / "oats"
    oats.write_text(
        "#!/bin/sh\n"
        "if [ \"$1 $2\" = \"session inspect\" ]; then echo '{\"ok\":true,\"result\":{\"present\":true,\"state\":\"idle\"}}'; exit 0; fi\n"
        f"if [ \"$1 $2\" = \"session input\" ]; then cat >> '{delivered}'; echo '{{\"ok\":true,\"result\":{{\"submitted\":true}}}}'; exit 0; fi\n"
        "exit 1\n")
    oats.chmod(0o755)
    lines = [
        {"type": "init", "home": str(terminal), "oatsBin": str(oats), "awCommand": str(binary),
         "bindings": [{"binding_id": "bob", "identity_home": command_env["AWEB_IDENTITY_HOME"], "team_id": TEAM,
                       "delivery_store_path": str(tmp_path / "delivery.json")}]},
        {"type": "event", "binding_id": "bob",
         "event": {"type": "mail_message", "message_id": message_id, "conversation_id": conversation_id}},
    ]
    runner = await asyncio.create_subprocess_exec(
        "node", str(REPO / "cli/go/wake/channel_core_runner_bundle.mjs"), cwd=command_dir, env=command_env,
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    try:
        runner.stdin.write("".join(json.dumps(line) + "\n" for line in lines).encode())
        await runner.stdin.drain()
        await _read_until(
            runner, lambda _: delivered.exists() and "Use the aw CLI" in delivered.read_text(), "wake runner")
    finally:
        runner.stdin.write(b'{"type":"shutdown"}\n')
        await runner.stdin.drain()
        await asyncio.wait_for(runner.wait(), 10)
    text = delivered.read_text()
    status = re.search(r"^- trust_status: (\S+)$", text, re.MULTILINE)
    return (status.group(1) if status else None), text


async def _present_by_channel(tmp_path, binary, command_dir, command_env, message_id, conversation_id):
    stderr = (tmp_path / "channel.stderr").open("wb")
    plugin = await asyncio.create_subprocess_exec(
        "node", str(REPO / "channel/dist/index.js"), cwd=command_dir, env=command_env,
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=stderr)
    try:
        # The MCP handshake Claude Code performs before it accepts notifications.
        for message in (
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "pytest", "version": "0"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
        ):
            plugin.stdin.write((json.dumps(message) + "\n").encode())
        await plugin.stdin.drain()
        params = await _read_until(plugin, lambda message: message.get("method") == "notifications/claude/channel"
                                   and message["params"]["meta"].get("message_id") == message_id
                                   and message["params"], "channel plugin")
    finally:
        plugin.stdin.close()
        plugin.terminate()
        await asyncio.wait_for(plugin.wait(), 10)
        stderr.close()
    return params["meta"].get("trust_status"), params["content"]


async def _present_by_pi(tmp_path, binary, command_dir, command_env, message_id, conversation_id):
    session = await asyncio.create_subprocess_exec(
        "node", str(Path(__file__).with_name("pi_extension_host.mjs")), str(REPO / "pi-extension/dist/index.js"),
        command_dir, cwd=command_dir, env=command_env,
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    def presented(message):
        assert not (message.get("customType") == "aweb-channel-status" and "not ready" in message["content"]), (
            message["content"])
        return (message.get("customType") == "aweb-channel"
                and message["details"].get("message_id") == message_id and message)

    try:
        message = await _read_until(session, presented, "pi extension")
    finally:
        session.stdin.close()
        await asyncio.wait_for(session.wait(), 10)
    return message["details"].get("trust_status"), message["content"]


PRESENTERS = {"wake": _present_by_wake, "channel": _present_by_channel, "pi": _present_by_pi}


def _unreachable_url():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return f"http://127.0.0.1:{port}"


@pytest.mark.asyncio
@pytest.mark.parametrize("sender_retired,registry_condition,expected", [
    (False, "available", "verified"),
    # A retired local sender is absent from the roster; the registry knows no
    # address for it, which is a definitive absence.
    (True, "available", "identity_mismatch"),
    # Without a registry answer the sender is unconfirmed, never mismatched.
    (True, "unavailable", "verification_stale"),
    (True, "unreachable", "verification_stale"),
])
@pytest.mark.parametrize("global_resident,grant", [(False, False), (False, True), (True, False), (True, True)])
@pytest.mark.parametrize("runtime", sorted(PRESENTERS))
async def test_channel_core_runtimes_present_local_sender_e2ee_mail_trust(
        privacy_app, runtime_packages, tmp_path, runtime, global_resident, grant, sender_retired,
        registry_condition, expected):
    async with _local_sender_mail(privacy_app, tmp_path, global_resident, grant, sender_retired) as (
            message_id, conversation_id, binary, command_dir, command_env, registry):
        runtime_env = dict(command_env, PATH=f"{binary.parent}{os.pathsep}{command_env.get('PATH', '')}")
        if registry_condition == "unavailable":
            registry.address_lookup_status = 503
        if registry_condition == "unreachable":
            runtime_env["AWID_REGISTRY_URL"] = _unreachable_url()
        status, text = await PRESENTERS[runtime](
            tmp_path, binary, command_dir, runtime_env, message_id, conversation_id)
        assert "local sender private text" in text, text
        assert status == expected, text
        # The runtimes resolve through Node's fetch; aw's own lookups are Go's.
        runtime_lookups = [(method, path, code) for method, path, code, agent in registry.responses
                           if agent == "node"]
        alice = ("GET", "/v1/namespaces/example.test/addresses/alice")
        if sender_retired and registry_condition == "available":
            assert (*alice, 404) in runtime_lookups, registry.responses
        if registry_condition == "unavailable":
            assert (*alice, 503) in runtime_lookups, registry.responses


@pytest.mark.asyncio
@pytest.mark.parametrize("runtime", ["channel", "wake"])
@pytest.mark.parametrize("grant", [False, True])
@pytest.mark.parametrize("sender_retired,expected", [(False, "verified"), (True, "identity_mismatch")])
async def test_channel_core_addressless_human_mail(
        privacy_app, runtime_packages, tmp_path, runtime, grant, sender_retired, expected):
    async with _local_sender_mail(privacy_app, tmp_path, True, grant, sender_retired, human=True) as (
            message_id, conversation_id, binary, command_dir, command_env, registry):
        # Humans are deliberately absent from the discovery roster. Trust uses
        # the participant-authorized stored sender membership and public DID.
        roster_actor = privacy_app.actors["bob"]
        roster_cert = json.loads(next((tmp_path / ".aw/team-certs").glob("*.pem")).read_text())
        roster = await privacy_app.client.get("/v1/agents", headers=_signed_team_headers(
            roster_actor.sk, roster_actor.did, TEAM, _encode_certificate(roster_cert), b""))
        assert roster.status_code == 200, roster.text
        assert "alice" not in [row["alias"] for row in roster.json()["agents"]]
        inbox = await _request(privacy_app, "bob", "GET", f"/v1/messages/inbox?message_id={message_id}")
        assert inbox.status_code == 200, inbox.text
        projection = inbox.json()["messages"][0]["sender_membership"]
        assert projection["state"] == ("inactive" if sender_retired else "active"), projection
        runtime_env = dict(command_env, PATH=f"{binary.parent}{os.pathsep}{command_env.get('PATH', '')}")
        status, text = await PRESENTERS[runtime](
            tmp_path, binary, command_dir, runtime_env, message_id, conversation_id)
        assert "local sender private text" in text
        assert status == expected, (text, projection, registry.responses)
        node_reads = [path for _, path, _, agent in registry.responses if agent == "node"]
        assert not any("/addresses/" in path for path in node_reads), node_reads
        if not sender_retired:
            assert any(path.endswith("/key") for path in node_reads), node_reads


@pytest.mark.asyncio
@pytest.mark.parametrize("plaintext", [False, True], ids=["encrypted_v2", "plaintext"])
@pytest.mark.parametrize("runtime", ["channel", "wake"])
@pytest.mark.parametrize("state,expected", [("active", "verified"), ("inactive", "identity_mismatch"), ("unknown", "verification_stale")])
async def test_cross_team_local_sender_to_global_grant(
        privacy_app, runtime_packages, tmp_path, plaintext, runtime, state, expected):
    async with _local_sender_mail(privacy_app, tmp_path, True, True, state == "inactive",
                                 cross_team=True, plaintext=plaintext) as (
            message_id, conversation_id, binary, command_dir, command_env, registry):
        if state == "unknown":
            await privacy_app.db.execute("UPDATE {{tables.agents}} SET certificate_id=NULL WHERE agent_id=$1", privacy_app.actors["alice"].id)
        shown = await _cli(binary, command_dir, command_env, "mail", "show", "--message-id", message_id, "--json")
        row = shown["messages"][0]
        runtime_env = dict(command_env, PATH=f"{binary.parent}{os.pathsep}{command_env.get('PATH', '')}")
        status, text = await PRESENTERS[runtime](tmp_path, binary, command_dir, runtime_env, message_id, conversation_id)
        assert "local sender private text" in text
        assert (row["verification_status"], status) == (expected, expected), (row["verification_status"], status, row.get("sender_membership"), registry.responses)
        assert not any("/addresses/" in path for _, path, _, _ in registry.responses), registry.responses
