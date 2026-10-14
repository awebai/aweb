"""Actual runtime processes survive an HTTP listener restart without model notices.

The two listeners share the real aweb DB/Redis app: the sender can persist mail
through the ingress listener while the recipient listener is stopped. No fake
SSE, mailbox, trust decision or acknowledgement. Only agent hosts are recorders.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import socket
import tempfile
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from uuid import uuid4

import pytest
import uvicorn

from awid.signing import canonical_json_bytes, sign_message
from test_dashboard_privacy import TEAM, _request, privacy_app  # noqa: F401
from test_e2ee_local_sender_read_trust import _local_sender_mail, runtime_packages, REPO  # noqa: F401


class RecipientListener:
    def __init__(self, app):
        self.app, self.port, self.server, self.task = app, 0, None, None

    async def start(self):
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", self.port))
        self.port = sock.getsockname()[1]
        self.server = uvicorn.Server(uvicorn.Config(
            self.app, lifespan="off", log_level="critical", timeout_graceful_shutdown=0))
        self.task = asyncio.create_task(self.server.serve(sockets=[sock]))
        await _until(lambda: self.server.started, "recipient listener start")

    async def stop(self):
        if self.task is None:
            return
        self.server.should_exit = True
        for connection in list(self.server.server_state.connections):
            connection.transport.abort()
        await asyncio.wait_for(self.task, 5)
        self.task = None

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"


async def _until(predicate, description):
    async with asyncio.timeout(20):
        while not predicate():
            await asyncio.sleep(0.025)
    assert predicate(), description


async def _mail_while_down(env, cid):
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    sender, recipient = env.actors["alice"], env.actors["bob"]
    mid = str(uuid4())
    payload = canonical_json_bytes({
        "type": "mail", "from": "example.test/alice", "from_did": sender.did,
        "to": "example.test/bob", "to_did": recipient.did,
        "message_id": mid, "conversation_id": cid, "timestamp": now,
        "subject": "During outage", "body": "durable mail accepted during outage",
    })
    sent = await _request(env, "alice", "POST", "/v1/messages", {
        "to_did": recipient.did, "message_id": mid, "conversation_id": cid,
        "subject": "During outage", "body": "durable mail accepted during outage",
        "timestamp": now, "from_did": sender.did,
        "signed_payload": payload.decode(), "signature": sign_message(sender.sk, payload),
    })
    assert sent.status_code == 200, sent.text
    return mid


@asynccontextmanager
async def _runtime(name, root, binary, env):
    messages = []
    log_path = root / f"{name}.log"
    log = log_path.open("wb")
    run_env = dict(env, PATH=f"{binary.parent}{os.pathsep}{env.get('PATH', '')}", AWEB_DELIVERY="channel")
    terminal = root / "terminal-input"
    terminal_state = None
    if name == "wake":
        # Production Go broker opens SSE, snapshots, starts the embedded child,
        # which calls this stand-in for the terminal multiplexer only.
        run_env["AWEB_DELIVERY"] = "session"
        terminal_state = tempfile.TemporaryDirectory(prefix="abze-wake-")
        oats = root / "oats"
        oats.write_text(
            "#!/bin/sh\n"
            "if [ \"$1 $2\" = \"session inspect\" ]; then echo '{\"ok\":true,\"result\":{\"present\":true,\"state\":\"idle\"}}'; exit 0; fi\n"
            f"if [ \"$1 $2\" = \"session input\" ]; then cat >> '{terminal}'; echo '{{\"ok\":true,\"result\":{{\"submitted\":true}}}}'; exit 0; fi\n"
            "exit 1\n")
        oats.chmod(0o755)
        registering = await asyncio.create_subprocess_exec(str(binary), "wake", "register", "--home", str(root),
                   "--identity-home", env["AWEB_IDENTITY_HOME"], "--delivery", "session",
                   "--state-dir", terminal_state.name, cwd=root, env=run_env,
                   stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        registered, _ = await asyncio.wait_for(registering.communicate(), 10)
        assert registering.returncode == 0, registered.decode()
        command = [str(binary), "wake", "run", "--state-dir", terminal_state.name, "--oats-bin", str(oats)]
    elif name == "channel":
        command = ["node", str(REPO / "channel/dist/index.js")]
    else:
        host = "pi_extension_host.mjs" if name == "pi" else "channel_core_session_host.mjs"
        package = "pi-extension" if name == "pi" else "channel-core"
        command = ["node", str(Path(__file__).with_name(host)), str(REPO / f"{package}/dist/index.js"), str(root)]
    process = await asyncio.create_subprocess_exec(*command, cwd=root, env=run_env,
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=log)

    async def read_messages():
        while line := await process.stdout.readline():
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if name == "channel":
                if item.get("method") == "notifications/claude/channel":
                    messages.append(item["params"])
            elif name == "pi":
                messages.append(item)
            elif name == "core":
                messages.append(item)
    reading = asyncio.create_task(read_messages())
    if name == "channel":
        for item in (
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "pytest", "version": "0"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
        ):
            process.stdin.write((json.dumps(item) + "\n").encode())
        await process.stdin.drain()

    def inputs():
        if name == "wake":
            return terminal.read_text() if terminal.exists() else ""
        return json.dumps(messages)
    try:
        yield inputs, messages, log_path, process
    finally:
        if process.returncode is None:
            if name in ("core", "pi"):
                process.stdin.close()
            else:
                process.terminate()
            try:
                await asyncio.wait_for(process.wait(), 10)
            except TimeoutError:
                process.kill()
                await process.wait()
        await reading
        log.close()
        if terminal_state:
            terminal_state.cleanup()


@pytest.mark.asyncio
@pytest.mark.parametrize("runtime", ["core", "channel", "pi", "wake"])
async def test_listener_restart_is_operator_only_and_catches_pending_mail(
        privacy_app, runtime_packages, tmp_path, runtime):
    async with _local_sender_mail(privacy_app, tmp_path, False, False, False) as (
            first_id, conversation_id, binary, root, env, _):
        listener = RecipientListener(privacy_app.app)
        await listener.start()
        env = dict(env, AWEB_URL=listener.url)
        workspace_path = Path(env["AWEB_IDENTITY_HOME"]) / "workspace.yaml"
        workspace = json.loads(workspace_path.read_text())
        workspace["aweb_url"] = listener.url
        workspace_path.write_text(json.dumps(workspace))
        try:
            async with _runtime(runtime, root, binary, env) as (inputs, messages, log_path, process):
                await _until(lambda: first_id in inputs(), f"{runtime} first mail")
                if runtime == "pi":
                    await _until(lambda: any(row.get("customType") == "aweb-welcome" for row in messages), "Pi startup welcome")
                before = inputs()
                before_messages = len(messages)
                await listener.stop()
                await asyncio.sleep(0.15)  # allow the already-open socket's EOF to be consumed
                assert inputs() == before, f"{runtime} injected a notice on disconnect: {inputs()}"
                second_id = await _mail_while_down(privacy_app, conversation_id)
                assert second_id not in inputs()
                await listener.start()
                await _until(lambda: second_id in inputs(), f"{runtime} catch-up mail")
                await asyncio.sleep(0.15)  # detect a notice queued behind the delivered mail
                observed = inputs()
                if runtime == "wake":
                    assert observed.count(first_id) == 1 and observed.count(second_id) == 1, observed
                else:
                    ids = [row.get("meta", row.get("details", {})).get("message_id") for row in messages]
                    assert ids.count(first_id) == 1 and ids.count(second_id) == 1, messages
                assert "durable mail accepted during outage" in observed
                assert "channel_status" not in observed and "stream_state" not in observed, observed
                assert "aweb channel stopped:" not in observed, observed
                cycle = observed[max(0, len(before) - 1):] if runtime == "wake" else json.dumps(messages[before_messages:])
                assert "aw mail inbox" not in cycle and "aw chat pending" not in cycle, cycle
                logs = log_path.read_text()
                assert ("stream disconnected" in logs or "stream outage" in logs), logs
                assert "stream reconnected" in logs, logs
                if runtime != "wake":
                    delivered = [row for row in messages if row.get("meta", row.get("details", {})).get("message_id")]
                    assert len(delivered) == 2, messages
                async with asyncio.timeout(10):
                    while True:
                        inbox = await _request(privacy_app, "bob", "GET", "/v1/messages/inbox?unread_only=true")
                        assert inbox.status_code == 200, inbox.text
                        if not inbox.json()["messages"]:
                            break
                        await asyncio.sleep(0.025)
                assert process.returncode is None
        finally:
            await listener.stop()
