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

from messaging_actor_support import admit_privacy_actor, messaging_actor_headers
from aweb.application_state import application_registry_client
from awid.identity_observation import IdentityKind
import base64

import asyncio
from contextlib import AsyncExitStack, asynccontextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import socket
import subprocess
from types import SimpleNamespace
from uuid import UUID, uuid4

import httpx
import pytest
from tests.js_runtime_tree import runtime_repo
from aweb_naapp_testing.network import DnsServer

from awid.e2ee_keys import build_encryption_key_assertion
from awid.signing import canonical_json_bytes, sign_message
from aweb.e2ee_messages import encrypt_e2ee_mail, generate_x25519_keypair
from test_addressless_sender_cli import _registry_http
from test_cli_human_reply import _cli, _pem, _reply_context
import test_dashboard_privacy
from test_dashboard_privacy import TEAM, _request
from test_messages_http import _signed_team_headers, _encode_certificate


def _signed_plaintext_mail_request(
    *, sender, agent, sender_team, message_id, conversation_id, now
):
    """Build the signed plaintext request sent through the real mail route."""
    payload = canonical_json_bytes(
        dict(
            type="mail",
            from_did=sender["did"],
            to_did=agent["did"],
            to_stable_id=agent["stable_id"],
            subject="Local encrypted",
            body="local sender private text",
            message_id=message_id,
            conversation_id=conversation_id,
            timestamp=now.isoformat(),
            **{
                "from": sender_team.split(":", 1)[1] + "/alice",
                "to": agent["address"],
            },
        )
    )
    request = dict(
        to_did=agent["did"],
        subject="Local encrypted",
        body="local sender private text",
        message_id=message_id,
        conversation_id=conversation_id,
        timestamp=now.isoformat(),
        from_did=sender["did"],
        signature=sign_message(sender["signing_key"], payload),
        signed_payload=payload.decode(),
    )
    # Optional selectors use absence, not empty strings: SendMessageRequest
    # requires at least one character when either selector is supplied.
    for field, value in (
        ("to_address", agent["address"]),
        ("to_stable_id", agent["stable_id"]),
    ):
        if value:
            request[field] = value
    return request


privacy_app = test_dashboard_privacy.privacy_app


@asynccontextmanager
async def _local_sender_mail(
    env,
    tmp_path,
    global_resident,
    grant,
    sender_retired,
    *,
    human=False,
    cross_team=False,
    plaintext=False,
):
    """Deliver local-sender mail to bob and yield its real CLI/registry context.

    The default is encrypted v2; plaintext selects the signed plaintext route.
    """
    env.app.state.public_origin = str(env.client.base_url).rstrip("/")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    sender_team = TEAM
    if cross_team:
        sender_team = f"outbound-{uuid4().hex[:12]}:sender.test"
    sender_actor = await admit_privacy_actor(
        env,
        "alice",
        team_id=sender_team,
        local=not human,
        kind=IdentityKind.HUMAN if human else IdentityKind.UNKNOWN,
        new_identity=cross_team,
    )
    await admit_privacy_actor(
        env,
        "bob",
        address="example.test/bob" if global_resident else "",
        local=not global_resident,
    )
    identities = {}
    for name in ("alice", "bob"):
        actor = env.actors[name]
        private, public = generate_x25519_keypair()
        address = "example.test/bob" if global_resident and name == "bob" else ""
        stable_id = actor.stable_id
        assertion = build_encryption_key_assertion(
            signing_key=actor.sk,
            identity_did=actor.did,
            identity_stable_id=stable_id,
            encryption_public_key=public,
            custody="hosted_custodial" if human and name == "alice" else "self",
            now=now,
        )
        raw_assertion = json.dumps(assertion).encode()
        published = await env.client.put(
            "/v1/agents/me/encryption-key",
            content=raw_assertion,
            headers=messaging_actor_headers(actor.registered, body=raw_assertion),
        )
        assert published.status_code == 200, published.text
        if stable_id:
            await application_registry_client(env.app.state).publish_encryption_key(
                stable_id, assertion
            )
        identities[name] = dict(
            address=address,
            did=actor.did,
            stable_id=stable_id,
            team_id=sender_team if name == "alice" else TEAM,
            signing_key=actor.sk,
            private_key=private,
            encryption_key=assertion,
        )
    sender, agent = identities["alice"], identities["bob"]
    message_id, conversation_id = str(uuid4()), str(uuid4())
    source = encrypt_e2ee_mail(
        sender=sender,
        recipients=[agent],
        subject="Local encrypted",
        body="local sender private text",
        message_id=message_id,
        conversation_id=conversation_id,
        created_at=now,
    )
    assert not source["from"].get("address")
    assert bool(source["from"].get("stable_id")) == human
    if plaintext:
        body = _signed_plaintext_mail_request(
            sender=sender,
            agent=agent,
            sender_team=sender_team,
            message_id=message_id,
            conversation_id=conversation_id,
            now=now,
        )
    else:
        body = dict(
            to_did=agent["did"],
            message_id=message_id,
            conversation_id=conversation_id,
            content_mode="encrypted_v2",
            message_version=2,
            encrypted_envelope=source,
        )
    sent = await _request(env, "alice", "POST", "/v1/messages", body)
    assert sent.status_code == 200, sent.text
    if sender_retired:
        if human:
            certificate = json.loads(base64.b64decode(sender_actor.certificate))
            team_name, domain = sender_team.split(":", 1)
            await application_registry_client(env.app.state).revoke_team_certificate(
                domain,
                team_name,
                team_controller_signing_key=env.team_sk,
                certificate_id=certificate["certificate_id"],
            )
        else:
            retired = await env.client.delete(
                f"/v1/workspaces/{sender_actor.workspace}",
                headers=_signed_team_headers(
                    sender_actor.sk,
                    sender_actor.did,
                    sender_team,
                    sender_actor.certificate,
                ),
            )
            assert retired.status_code == 200, retired.text
            assert retired.json()["identity_deleted"] is True, retired.text

    identity_home = tmp_path / ".aw"
    identity_home.mkdir(mode=0o700)
    if global_resident:
        (identity_home / "identity.yaml").write_text(
            json.dumps(
                {
                    "did": agent["did"],
                    "stable_id": agent["stable_id"],
                    "address": agent["address"],
                    "custody": "self",
                    "identity_scope": "global",
                    "created_at": now.isoformat(),
                }
            )
        )
    cert = json.loads(base64.b64decode(env.actors["bob"].certificate))
    cert_path = "team-certs/" + TEAM.replace("__", "____").replace(":", "__") + ".pem"
    (identity_home / "team-certs").mkdir(mode=0o700)
    (identity_home / cert_path).write_text(json.dumps(cert))
    (identity_home / cert_path).chmod(0o600)
    membership = {"team_id": TEAM, "alias": "bob", "cert_path": cert_path}
    (identity_home / "teams.yaml").write_text(
        json.dumps({"active_team": TEAM, "memberships": [membership]})
    )
    (identity_home / "workspace.yaml").write_text(
        json.dumps(
            {
                "aweb_url": str(env.client.base_url),
                "memberships": [
                    {**membership, "workspace_id": str(env.actors["bob"].workspace)}
                ],
            }
        )
    )
    _pem(identity_home / "signing.key", "ED25519 PRIVATE KEY", agent["signing_key"])
    _pem(identity_home / "encryption.key", "X25519 PRIVATE KEY", agent["private_key"])
    assertion = agent["encryption_key"]
    (identity_home / "assertion.json").write_text(json.dumps(assertion))
    (identity_home / "encryption.yaml").write_text(
        json.dumps(
            {
                "active_key_id": assertion["encryption_key_id"],
                "keys": [
                    {
                        "key_id": assertion["encryption_key_id"],
                        "public_key": assertion["encryption_public_key"],
                        "private_key_path": "encryption.key",
                        "assertion_path": "assertion.json",
                        **{
                            key: assertion[key]
                            for key in ("created_at", "not_before", "expires_at")
                        },
                        "published_at": now.isoformat(),
                    }
                ],
            }
        )
    )
    binary = Path(os.environ["AW_TEST_CLI_BINARY"])
    child_env = {
        k: v for k, v in os.environ.items() if not k.startswith(("AWEB_", "AWID_"))
    }
    child_env.update(
        AWEB_IDENTITY_HOME=str(identity_home),
        AWEB_URL=str(env.client.base_url),
        HOME=str(tmp_path),
        XDG_CONFIG_HOME=str(tmp_path / "config"),
    )
    registry = SimpleNamespace(url="", responses=[], address_lookup_status=None)

    async def recorded_registry(scope, receive, send):
        async def record(event):
            if event["type"] == "http.response.start":
                user_agent = (
                    dict(scope.get("headers") or []).get(b"user-agent", b"").decode()
                )
                registry.responses.append(
                    (scope["method"], scope["path"], event["status"], user_agent)
                )
            await send(event)

        if (
            registry.address_lookup_status
            and scope["type"] == "http"
            and "/addresses/" in scope["path"]
        ):
            await record(
                {
                    "type": "http.response.start",
                    "status": registry.address_lookup_status,
                    "headers": [],
                }
            )
            await send({"type": "http.response.body", "body": b"registry unavailable"})
            return
        await env.registry_app(scope, receive, record)

    async with AsyncExitStack() as network:
        registry_url, _ = await network.enter_async_context(
            _registry_http(recorded_registry)
        )
        registry.url = registry_url
        child_env["AWID_REGISTRY_URL"] = registry_url
        if human:
            # Enrollment locates authoritative status even when the message omits
            # id_chain (docs/id-certificates.md:963-976). Serve that actual
            # namespace through the existing disposable DNS/registry owners.
            key = await application_registry_client(env.app.state).resolve_key(
                sender["stable_id"]
            )
            assert key.id_tree is not None and key.id_tree.domain is not None
            domain = key.id_tree.domain
            authority = await env.registry.namespace_authority(domain)
            dns_server = DnsServer()
            await dns_server.start()
            network.callback(dns_server.close)
            registry_host = f"registry-{uuid4().hex}.test"
            public_registry = registry_url.replace("127.0.0.1", registry_host)
            dns_server.records[(f"_awid.{domain}", "TXT")] = [
                f'"awid=v1;controller={authority.controller_did};registry={public_registry}"'
            ]
            dns_server.records[(registry_host, "A")] = ["127.0.0.1"]
            registry.dns = dns_server
            registry.enrollment_domain = domain
            env.registry_app.state.awid_public_origins = (
                *env.registry_app.state.awid_public_origins,
                public_registry,
            )
            # Node's lookup uses the OS resolver, unlike resolveTxt. Forward
            # both APIs to the SAME live DNS server; do not synthesize answers.
            dns_preload = tmp_path / "disposable-dns.cjs"
            dns_preload.write_text(
                "const dns = require('node:dns');\n"
                f"dns.setServers(['127.0.0.1:{dns_server.port}']);\n"
                "dns.lookup = (host, options, callback) => {\n"
                "  if (typeof options === 'function') { callback=options; options={}; }\n"
                "  if (typeof options === 'number') options={family:options};\n"
                "  const family=options?.family === 6 ? 6 : 4;\n"
                "  const resolve=family === 6 ? dns.resolve6 : dns.resolve4;\n"
                "  resolve(host, (error, addresses) => {\n"
                "    if (error) return callback(error);\n"
                "    if (options?.all) callback(null, addresses.map(address=>({address,family})));\n"
                "    else callback(null, addresses[0], family);\n"
                "  });\n"
                "};\n"
                "require('node:module').syncBuiltinESMExports();\n"
            )
            child_env["NODE_OPTIONS"] = (
                child_env.get("NODE_OPTIONS", "") + f" --require={dns_preload}"
            ).strip()
            child_env["APP_ENV"] = "development"
        async with _reply_context(
            binary,
            tmp_path,
            child_env,
            grant,
            agent["address"],
            ttl="never" if cross_team else "5m",
        ) as (command_dir, command_env):
            yield (
                message_id,
                conversation_id,
                binary,
                command_dir,
                command_env,
                registry,
            )


@pytest.mark.usefixtures("source_cli_binary")
@pytest.mark.asyncio
@pytest.mark.parametrize("sender_retired", [False, True])
@pytest.mark.parametrize(
    "global_resident,grant",
    [(False, False), (False, True), (True, False), (True, True)],
)
async def test_local_sender_e2ee_mail_read_trust(
    privacy_app, tmp_path, global_resident, grant, sender_retired
):
    async with _local_sender_mail(
        privacy_app, tmp_path, global_resident, grant, sender_retired
    ) as (message_id, _, binary, command_dir, command_env, _):
        result = await _cli(
            binary,
            command_dir,
            command_env,
            "mail",
            "show",
            "--message-id",
            message_id,
            "--json",
        )
        shown = result["messages"][0]
        assert shown["body"] == "local sender private text"
        # The live roster re-check is load-bearing: a removed member no
        # longer binds its key (docs/trust-model.md threat-model rulings).
        expected = "identity_mismatch" if sender_retired else "verified"
        assert shown["verification_status"] == expected, {
            k: shown.get(k)
            for k in (
                "verification_status",
                "from_alias",
                "from_address",
                "from_did",
                "from_stable_id",
                "to_did",
                "to_stable_id",
                "sender_membership",
            )
        }


SOURCE_REPO = Path(__file__).resolve().parents[2]
REPO = runtime_repo(SOURCE_REPO)


@pytest.fixture(scope="module")
def runtime_packages(server_js_runtime):
    """Build once per worker, or retain the original serial fixture path."""
    if REPO != SOURCE_REPO:
        assert server_js_runtime == REPO
        return
    for package in ("channel", "pi-extension"):
        build = subprocess.run(
            ["npm", "run", "build"], cwd=REPO / package, capture_output=True, text=True
        )
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


async def _present_by_wake(
    tmp_path, binary, command_dir, command_env, message_id, conversation_id
):
    terminal = tmp_path / "terminal"
    terminal.mkdir()
    delivered = tmp_path / "terminal-input.txt"
    # Stands in for the terminal multiplexer only: it records what the broker types.
    oats = tmp_path / "oats"
    oats.write_text(
        "#!/bin/sh\n"
        'if [ "$1 $2" = "session inspect" ]; then echo \'{"ok":true,"result":{"present":true,"state":"idle"}}\'; exit 0; fi\n'
        f'if [ "$1 $2" = "session input" ]; then cat >> \'{delivered}\'; echo \'{{"ok":true,"result":{{"submitted":true}}}}\'; exit 0; fi\n'
        "exit 1\n"
    )
    oats.chmod(0o755)
    lines = [
        {
            "type": "init",
            "home": str(terminal),
            "oatsBin": str(oats),
            "awCommand": str(binary),
            "bindings": [
                {
                    "binding_id": "bob",
                    "identity_home": command_env["AWEB_IDENTITY_HOME"],
                    "team_id": TEAM,
                    "delivery_store_path": str(tmp_path / "delivery.json"),
                }
            ],
        },
        {
            "type": "event",
            "binding_id": "bob",
            "event": {
                "type": "mail_message",
                "message_id": message_id,
                "conversation_id": conversation_id,
            },
        },
    ]
    runner = await asyncio.create_subprocess_exec(
        "node",
        str(REPO / "cli/go/internal/wake/channel_core_runner_bundle.mjs"),
        cwd=command_dir,
        env=command_env,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        runner.stdin.write("".join(json.dumps(line) + "\n" for line in lines).encode())
        await runner.stdin.drain()

        def presented(message):
            if not delivered.exists():
                return False
            text = delivered.read_text()
            if text.startswith(("[aweb] 1 message held", "Withheld mail")):
                # Wait for the bounded retry window, so shutdown cannot hide an
                # incorrect acknowledgment or delivered-ID write after input.
                return message.get("trace_stage") == "lane_job_failed"
            return "Answer in the conversation: aw mail reply <message_id>." in text

        await _read_until(runner, presented, "wake runner")
    finally:
        runner.stdin.write(b'{"type":"shutdown"}\n')
        await runner.stdin.drain()
        await asyncio.wait_for(runner.wait(), 10)
    text = delivered.read_text()
    status = re.search(r"^- trust_status: (\S+)$", text, re.MULTILINE)
    if text.startswith("Withheld mail"):
        status = re.search(r": (failed|identity_mismatch)\. Body and subject", text)
    return (status.group(1) if status else None), text


def channel_command():
    """The Claude Code channel plugin from this worker's runtime tree."""
    return ["node", str(REPO / "channel/dist/index.js")]


def pi_command(command_dir):
    """The pi extension, hosted from this worker's runtime tree."""
    return [
        "node",
        str(Path(__file__).with_name("pi_extension_host.mjs")),
        str(REPO / "pi-extension/dist/index.js"),
        str(command_dir),
    ]


async def _present_by_channel(
    tmp_path, binary, command_dir, command_env, message_id, conversation_id
):
    stderr = (tmp_path / "channel.stderr").open("wb")
    plugin = await asyncio.create_subprocess_exec(
        *channel_command(),
        cwd=command_dir,
        env=command_env,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=stderr,
    )
    try:
        # The MCP handshake Claude Code performs before it accepts notifications.
        for message in (
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "pytest", "version": "0"},
                },
            },
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
        ):
            plugin.stdin.write((json.dumps(message) + "\n").encode())
        await plugin.stdin.drain()
        params = await _read_until(
            plugin,
            lambda message: (
                message.get("method") == "notifications/claude/channel"
                and message["params"]["meta"].get("message_id") == message_id
                and message["params"]
            ),
            "channel plugin",
        )
    finally:
        plugin.stdin.close()
        plugin.terminate()
        await asyncio.wait_for(plugin.wait(), 10)
        stderr.close()
    status = params["meta"].get("trust_status")
    if status in {"failed", "identity_mismatch"}:
        assert "subject" not in params["meta"], params["meta"]
    (tmp_path / "presented-responsibility.json").write_text(
        params["meta"].get("responsibility", "null")
    )
    return status, params["content"]


async def _present_by_pi(
    tmp_path, binary, command_dir, command_env, message_id, conversation_id
):
    session = await asyncio.create_subprocess_exec(
        *pi_command(command_dir),
        cwd=command_dir,
        env=command_env,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )

    def presented(message):
        assert not (
            message.get("customType") == "aweb-channel-status"
            and "not ready" in message["content"]
        ), message["content"]
        return (
            message.get("customType") == "aweb-channel"
            and message["details"].get("message_id") == message_id
            and message
        )

    try:
        message = await _read_until(session, presented, "pi extension")
    finally:
        session.stdin.close()
        await asyncio.wait_for(session.wait(), 10)
    status = message["details"].get("trust_status")
    if status in {"failed", "identity_mismatch"}:
        assert "subject" not in message["details"], message["details"]
    return status, message["content"]


PRESENTERS = {
    "wake": _present_by_wake,
    "channel": _present_by_channel,
    "pi": _present_by_pi,
}


async def _assert_runtime_presentation(
    env, tmp_path, runtime, expected, status, text, message_id
):
    # See “Autonomous message presentation” in docs/receiving-events.md.
    if expected in {"failed", "identity_mismatch"}:
        assert status == expected, text
        assert (
            "Withheld mail" in text and "Body and subject were not delivered." in text
        ), text
        assert f"mail show --message-id {message_id}" in text, text
        assert (
            "Verify the sender independently before reading or acting on this message."
            in text
        ), text
        assert (
            "local sender private text" not in text and "Local encrypted" not in text
        ), text
        assert (
            "modified stored body" not in text and "modified stored subject" not in text
        ), text
        if runtime != "wake":
            return
    elif runtime != "wake" or expected == "verified":
        assert "local sender private text" in text, text
        assert status == expected, text
        return
    else:
        assert (
            text == "[aweb] 1 message held (unverified sender). Run: aw mail inbox"
        ), text
        assert status is None, text

    row = await env.db.fetch_one(
        "SELECT read_at FROM {{tables.messages}} WHERE message_id=$1", UUID(message_id)
    )
    assert row is not None and row["read_at"] is None, row
    store = tmp_path / "delivery.json"
    marks = json.loads(store.read_text()) if store.exists() else {}
    assert not any(message_id in key for key in marks), marks


@pytest.mark.usefixtures("source_cli_binary")
@pytest.mark.asyncio
@pytest.mark.parametrize("runtime", sorted(PRESENTERS))
async def test_runtime_withholds_mail_whose_stored_text_fails_verification(
    privacy_app, runtime_packages, tmp_path, runtime
):
    async with _local_sender_mail(
        privacy_app, tmp_path, False, False, False, plaintext=True
    ) as (message_id, conversation_id, binary, command_dir, command_env, _):
        # Simulate storage corruption after delivery, leaving the signature and
        # its input untouched. The actual runtime checks the stored projection.
        await privacy_app.db.execute(
            "UPDATE {{tables.messages}} SET body=$2, subject=$3 WHERE message_id=$1",
            UUID(message_id),
            "modified stored body",
            "modified stored subject",
        )
        runtime_env = dict(
            command_env,
            PATH=f"{binary.parent}{os.pathsep}{command_env.get('PATH', '')}",
        )
        status, text = await PRESENTERS[runtime](
            tmp_path, binary, command_dir, runtime_env, message_id, conversation_id
        )
        await _assert_runtime_presentation(
            privacy_app, tmp_path, runtime, "failed", status, text, message_id
        )


def _unreachable_url():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return f"http://127.0.0.1:{port}"


@pytest.mark.usefixtures("source_cli_binary")
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "sender_retired,registry_condition,expected",
    [
        (False, "available", "verified"),
        # A retired local sender is absent from the roster; the registry knows no
        # address for it, which is a definitive absence.
        (True, "available", "identity_mismatch"),
        # Without a registry answer the sender is unconfirmed, never mismatched.
        (True, "unavailable", "verification_stale"),
        (True, "unreachable", "verification_stale"),
    ],
)
@pytest.mark.parametrize(
    "global_resident,grant",
    [(False, False), (False, True), (True, False), (True, True)],
)
@pytest.mark.parametrize("runtime", sorted(PRESENTERS))
async def test_channel_core_runtimes_present_local_sender_e2ee_mail_trust(
    privacy_app,
    runtime_packages,
    tmp_path,
    runtime,
    global_resident,
    grant,
    sender_retired,
    registry_condition,
    expected,
):
    async with _local_sender_mail(
        privacy_app, tmp_path, global_resident, grant, sender_retired
    ) as (message_id, conversation_id, binary, command_dir, command_env, registry):
        runtime_env = dict(
            command_env,
            PATH=f"{binary.parent}{os.pathsep}{command_env.get('PATH', '')}",
        )
        if registry_condition == "unavailable":
            registry.address_lookup_status = 503
        if registry_condition == "unreachable":
            runtime_env["AWID_REGISTRY_URL"] = _unreachable_url()
        status, text = await PRESENTERS[runtime](
            tmp_path, binary, command_dir, runtime_env, message_id, conversation_id
        )
        await _assert_runtime_presentation(
            privacy_app, tmp_path, runtime, expected, status, text, message_id
        )
        # The runtimes resolve through Node's fetch; aw's own lookups are Go's.
        runtime_lookups = [
            (method, path, code)
            for method, path, code, agent in registry.responses
            if agent == "node"
        ]
        alice = ("GET", "/v1/namespaces/example.test/addresses/alice")
        if sender_retired and registry_condition == "available":
            assert (*alice, 404) in runtime_lookups, registry.responses
        if registry_condition == "unavailable":
            assert (*alice, 503) in runtime_lookups, registry.responses


@pytest.mark.usefixtures("source_cli_binary")
@pytest.mark.asyncio
@pytest.mark.parametrize("runtime", ["channel", "wake"])
@pytest.mark.parametrize("grant", [False, True])
@pytest.mark.parametrize(
    "sender_retired,expected", [(False, "verified"), (True, "identity_mismatch")]
)
async def test_channel_core_addressless_human_mail(
    privacy_app, runtime_packages, tmp_path, runtime, grant, sender_retired, expected
):
    async with _local_sender_mail(
        privacy_app, tmp_path, True, grant, sender_retired, human=True
    ) as (message_id, conversation_id, binary, command_dir, command_env, registry):
        # Humans are deliberately absent from the discovery roster. Trust uses
        # the participant-authorized stored sender membership and public DID.
        roster_actor = privacy_app.actors["bob"]
        roster_cert = json.loads(
            next((tmp_path / ".aw/team-certs").glob("*.pem")).read_text()
        )
        roster = await privacy_app.client.get(
            "/v1/agents",
            headers=_signed_team_headers(
                roster_actor.sk,
                roster_actor.did,
                TEAM,
                _encode_certificate(roster_cert),
                b"",
            ),
        )
        assert roster.status_code == 200, roster.text
        assert "alice" not in [row["alias"] for row in roster.json()["agents"]]
        inbox = await _request(
            privacy_app, "bob", "GET", f"/v1/messages/inbox?message_id={message_id}"
        )
        assert inbox.status_code == 200, inbox.text
        projection = inbox.json()["messages"][0]["sender_membership"]
        assert projection["state"] == ("inactive" if sender_retired else "active"), (
            projection
        )
        runtime_env = dict(
            command_env,
            PATH=f"{binary.parent}{os.pathsep}{command_env.get('PATH', '')}",
        )
        status, text = await PRESENTERS[runtime](
            tmp_path, binary, command_dir, runtime_env, message_id, conversation_id
        )
        await _assert_runtime_presentation(
            privacy_app, tmp_path, runtime, expected, status, text, message_id
        )
        node_reads = [
            path for _, path, _, agent in registry.responses if agent == "node"
        ]
        assert not any("/addresses/" in path for path in node_reads), node_reads
        if not sender_retired:
            assert any(path.endswith("/key") for path in node_reads), node_reads
            assert (
                registry.dns.queries[(f"_awid.{registry.enrollment_domain}", "TXT")] > 0
            )
            assert (
                "POST",
                "/v1/id-certificates/status",
                200,
                "node",
            ) in registry.responses
            (tmp_path / "human-authority-observations.json").write_text(
                json.dumps(
                    {
                        "domain": registry.enrollment_domain,
                        "dns_queries": [
                            [*key, count] for key, count in registry.dns.queries.items()
                        ],
                        "registry_requests": registry.responses,
                    }
                )
            )


@pytest.mark.usefixtures("source_cli_binary")
@pytest.mark.asyncio
@pytest.mark.parametrize("plaintext", [False, True], ids=["encrypted_v2", "plaintext"])
@pytest.mark.parametrize("runtime", ["channel", "wake"])
@pytest.mark.parametrize(
    "state,expected",
    [
        ("active", "verified"),
        ("inactive", "identity_mismatch"),
        ("unknown", "verification_stale"),
    ],
)
async def test_cross_team_local_sender_to_global_grant(
    privacy_app,
    runtime_packages,
    tmp_path,
    monkeypatch,
    plaintext,
    runtime,
    state,
    expected,
):
    async with _local_sender_mail(
        privacy_app,
        tmp_path,
        True,
        True,
        state == "inactive",
        cross_team=True,
        plaintext=plaintext,
    ) as (message_id, conversation_id, binary, command_dir, command_env, registry):
        failed_reads = []
        if state == "unknown":
            name, domain = privacy_app.actors["alice"].team_id.split(":", 1)
            revocations = f"/v1/namespaces/{domain}/teams/{name}/revocations"

            def fail_sender_standing(request, response):
                if request.method == "GET" and request.url.path == revocations:
                    failed_reads.append(request.url.path)
                    return httpx.Response(
                        503, json={"detail": "sender authority temporarily unavailable"}
                    )
                return response

            monkeypatch.setattr(
                privacy_app.registry.transport, "fault", fail_sender_standing
            )
        shown = await _cli(
            binary,
            command_dir,
            command_env,
            "mail",
            "show",
            "--message-id",
            message_id,
            "--json",
        )
        row = shown["messages"][0]
        runtime_env = dict(
            command_env,
            PATH=f"{binary.parent}{os.pathsep}{command_env.get('PATH', '')}",
        )
        status, text = await PRESENTERS[runtime](
            tmp_path, binary, command_dir, runtime_env, message_id, conversation_id
        )
        assert row["verification_status"] == expected, (row, registry.responses)
        assert bool(failed_reads) is (state == "unknown")
        await _assert_runtime_presentation(
            privacy_app, tmp_path, runtime, expected, status, text, message_id
        )
        assert not any("/addresses/" in path for _, path, _, _ in registry.responses), (
            registry.responses
        )
