"""Run released clients inside the standing user-paths team's private network."""

import argparse
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import threading
import time

from user_paths import CLICommandError, Lane, sent_identity


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


class Plugin:
    """The passive MCP host observes the published process's actual notifications."""

    def __init__(self, lane, entry, actor):
        self.lane = lane
        self.entry = entry
        self.actor = actor
        self.messages = queue.Queue()

    def __enter__(self):
        env = dict(
            self.lane.environment, AWEB_DELIVERY="channel", AW_BIN=self.lane.binary
        )
        env["PATH"] = str(Path(self.lane.binary).parent) + os.pathsep + env["PATH"]
        self.log = (self.lane.root / "released-channel.log").open("a")
        self.process = subprocess.Popen(
            ["node", str(self.entry)],
            cwd=self.lane.actors[self.actor]["home"],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.log,
            text=True,
        )
        self.reader = threading.Thread(target=self.read_messages)
        self.reader.start()
        return self

    def __exit__(self, *_):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.reader.join()
        self.process.stdout.close()
        self.log.close()

    def read_messages(self):
        try:
            for line in self.process.stdout:
                self.messages.put(json.loads(line))
        except ValueError as error:
            self.messages.put(error)
        finally:
            self.messages.put(None)

    def write(self, method, **fields):
        self.process.stdin.write(
            json.dumps({"jsonrpc": "2.0", "method": method, **fields}) + "\n"
        )
        self.process.stdin.flush()

    def until(self, predicate, label):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                message = self.messages.get(timeout=max(0, deadline - time.monotonic()))
            except queue.Empty:
                break
            require(
                isinstance(message, dict),
                "Published channel closed or emitted invalid MCP.",
            )
            if predicate(message):
                return message
        raise RuntimeError(f"Published channel did not produce {label}.")

    def connect(self):
        self.write(
            "initialize",
            id=1,
            params={
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "released-user-paths", "version": "1"},
            },
        )
        result = self.until(lambda message: message.get("id") == 1, "MCP initialize")[
            "result"
        ]
        require(
            "claude/channel" in result.get("capabilities", {}).get("experimental", {}),
            "Published plugin did not advertise the channel capability.",
        )
        self.write("notifications/initialized")
        return {
            key: result[key]
            for key in ("serverInfo", "capabilities", "instructions")
            if key in result
        }

    def notification(self, message_id, thread, kind, body, sender):
        def matches(message):
            return (
                message.get("method") == "notifications/claude/channel"
                and message.get("params", {}).get("meta", {}).get("message_id")
                == message_id
            )

        payload = self.until(matches, f"{kind} notification")["params"]
        with (self.lane.root / "released-channel-notifications.jsonl").open("a") as log:
            log.write(json.dumps(payload) + "\n")
        meta = payload["meta"]
        require(
            body in payload["content"]
            and meta.get("conversation_id") == thread
            and meta.get("from") == sender
            and meta.get("type") == kind
            and meta.get("verified") in ("true", True),
            "Published channel notification changed content, provenance or conversation.",
        )
        return seen_notification(payload)


def seen_notification(payload):
    meta = payload["meta"]
    # Message/conversation binding is asserted before normalization. Actor
    # keys and clock readings are freshly created in each isolated runtime.
    volatile = {
        "message_id",
        "conversation_id",
        "session_id",
        "timestamp",
        "sent_at",
        "from_did",
        "from_stable_id",
    }
    observed = {key: value for key, value in meta.items() if key not in volatile}
    return {"content": payload["content"], "meta": observed}


class Receipts:
    def __init__(self, path):
        self.path = path
        self.rows = {}

    def observe(self, case, operation):
        try:
            self.rows[case] = {"status": "PASSED", "visible": operation()}
        except CLICommandError as exc:
            failure = exc.failure
            response = failure["response"] or {}
            error = response.get("error") or {}
            command = failure["args"][:1]
            diagnostic = None
            if not case.endswith("/join") or command == ["init"]:
                diagnostic = error.get("message")
            self.rows[case] = {
                "status": "FAILED",
                "visible": {
                    "exit": failure["exit"],
                    "code": error.get("code"),
                    "command": command,
                    "diagnostic": diagnostic,
                    "retirement_status": response.get("status"),
                    "retirement_stores": [
                        {key: row.get(key) for key in ("store", "result", "detail")}
                        for row in response.get("stores", [])
                    ],
                },
            }
        except (
            RuntimeError,
            ValueError,
            OSError,
            KeyError,
            AssertionError,
            subprocess.TimeoutExpired,
        ) as exc:
            # Provisioning may fail with a one-time token in child diagnostics.
            self.rows[case] = {
                "status": "FAILED",
                "visible": {
                    "error": type(exc).__name__,
                    "diagnostic": str(exc) if type(exc) is RuntimeError else None,
                },
            }
        self.path.write_text(json.dumps(self.rows, indent=2) + "\n")
        print(case, self.rows[case]["status"], flush=True)


def send(lane, receiver, kind, body):
    if kind == "mail":
        result = lane.command(
            "g1",
            "mail",
            "send",
            "--to",
            receiver,
            "--subject",
            "RC validation",
            "--body",
            body,
            "--plaintext",
        )
    else:
        result = lane.command(
            "g1", "chat", "send-and-wait", receiver, body, "--plaintext", "--wait", "0"
        )
    return sent_identity(result, kind)


def aw_delivery(lane, kind):
    body = f"Released aw {kind} on the RC validation team."
    message, thread = send(lane, "t1", kind, body)
    views = lane.read_message("t1", "g1", kind, body, thread, message, False)
    observed = {}
    for view, row in views.items():
        observed[view] = {
            key: row[key]
            for key in (
                "from_address",
                "last_from_address",
                "verification_status",
                "content_mode",
                "body",
                "last_message",
                "subject",
            )
            if key in row
        }
    return observed


def plugin_delivery(lane, plugin, kind):
    body = f"Released channel {kind} on the RC validation team."
    message, thread = send(lane, "t2", kind, body)
    return plugin.notification(
        message, thread, kind, body, lane.actors["g1"]["address"]
    )


def plugin_reconnect_wake(lane, channel):
    """Show an idle host wake on reconnect from unread state queued offline."""

    def unread_count():
        return lane.command("t2", "mail", "inbox", "--count-only")["unread_count"]

    require(unread_count() == 0, "The channel wake case needs an empty unread inbox.")
    body = "Released channel wakes from queued mail after reconnect."
    message, thread = send(lane, "t2", "mail", body)
    require(unread_count() == 1, "The offline plugin's message was not queued unread.")
    with Plugin(lane, channel, "t2") as plugin:
        plugin.connect()
        presented = plugin.notification(
            message, thread, "mail", body, lane.actors["g1"]["address"]
        )
        deadline = time.monotonic() + 15
        while unread_count() != 0:
            require(
                time.monotonic() < deadline,
                "The reconnected channel did not settle its delivered wake.",
            )
            time.sleep(0.1)
    return {
        "trigger": "unread-on-reconnect",
        "presentation": presented,
        "acknowledged": True,
    }


def retire(lane, actor):
    enrolled = lane.command("g1", "team", "admin", "agent-status", actor)
    out = lane.command(actor, "workspace", "delete", enrolled["workspace_id"])
    require(
        out.get("identity_deleted") is True,
        "Workspace did not delete its own local identity.",
    )
    reason = out.get("alias_released_reason")
    if out.get("alias_released") is False and reason == "team_not_hosted":
        # The released actor removes its own workspace under its certificate.
        # A customer-controlled team's controller performs separate revocation.
        lane.command(
            "g1",
            "id",
            "team",
            "remove-member",
            "--namespace",
            lane.actors[actor]["domain"],
            "--team",
            "members",
            "--cert-id",
            enrolled["certificate_id"],
        )
    else:
        require(
            out.get("alias_released") is True,
            "Unexpected released retirement response.",
        )
    observed = lane.command("g1", "team", "admin", "agent-status", actor)
    require(
        observed.get("state") == "clear" and observed.get("name_reusable") is True,
        "Public retirement did not clear the member's stores.",
    )
    return {
        "retirement": {
            key: out.get(key)
            for key in (
                "identity_deleted",
                "alias_released",
                "alias_released_reason",
            )
        },
        "agent_status": {
            key: observed.get(key)
            for key in (
                "state",
                "certificate",
                "workspace",
                "claims_held",
                "claims_complete",
                "name_reusable",
            )
        },
    }


def joined(lane, actor):
    observed = lane.command("g1", "team", "admin", "agent-status", actor)
    require(
        observed.get("state") == "holding"
        and observed.get("certificate") == "active"
        and observed.get("workspace") == "present",
        "Released aw did not join and connect the actor.",
    )
    return {
        key: observed.get(key)
        for key in ("team_id", "alias", "state", "certificate", "workspace")
    }


def run_kernel(lane, receipts, source, oats, *, manual=False):
    client = "aw" if manual else "oats"
    output = lane.root / (client + "-wake-lifecycle.json")
    result = subprocess.run(
        [
            "node",
            "/work/user_paths_oats.mjs",
            "--released-lifecycle",
            "--released-artifacts",
            str(oats),
            *(["--aw-actor", str(lane.actors["t1"]["home"])] if manual else []),
            "--aw",
            lane.binary,
            "--root",
            "/identities/" + client + "-wake",
            "--seat",
            str(lane.actors["g1"]["home"]),
            "--fixture-home",
            str(lane.home),
            "--sender",
            str(lane.actors["g1" if manual else "t1"]["home"]),
            "--team",
            "members:" + lane.actors["g1"]["domain"],
            "--source-commit",
            source,
            "--output",
            str(output),
        ],
        check=False,
        timeout=150,
    )
    evidence = json.loads(output.read_text()) if output.is_file() else {}
    for case, row in evidence.get("lifecycle", {}).items():
        receipts.rows[case] = row
    receipts.path.write_text(json.dumps(receipts.rows, indent=2) + "\n")
    if result.returncode:
        receipts.rows[client + "/runner"] = {
            "status": "FAILED",
            "visible": {"exit": result.returncode},
        }
        receipts.path.write_text(json.dumps(receipts.rows, indent=2) + "\n")
        print(
            f"Released {client} wake lifecycle failed; see {output.name}.",
            flush=True,
        )


def main(channel, oats, aw_source):
    lane = Lane("released", os.environ["AW_BIN"])
    receipts = Receipts(lane.root / "compatibility.json")

    def provision():
        lane.provision(start_receivers=False)
        return joined(lane, "t1")

    try:
        receipts.observe("aw/join", provision)
        if receipts.rows["aw/join"]["status"] != "PASSED":
            return
        for kind in ("mail", "chat"):
            receipts.observe("aw/" + kind, lambda: aw_delivery(lane, kind))
    finally:
        lane.close()

    # The plugin owns delivery for its actor after the standing core readers
    # have stopped. It uses the same released CLI for join and retirement.
    try:
        with Plugin(lane, channel, "t2") as plugin:
            receipts.observe(
                "channel/join",
                lambda: {"workspace": joined(lane, "t2"), "mcp": plugin.connect()},
            )
            if receipts.rows["channel/join"]["status"] == "PASSED":
                for kind in ("mail", "chat"):
                    receipts.observe(
                        "channel/" + kind, lambda: plugin_delivery(lane, plugin, kind)
                    )
        if receipts.rows["channel/join"]["status"] == "PASSED":
            receipts.observe(
                "channel/wake", lambda: plugin_reconnect_wake(lane, channel)
            )
    except (OSError, RuntimeError) as exc:
        receipts.rows["channel/runner"] = {
            "status": "FAILED",
            "visible": {"error": type(exc).__name__},
        }
        receipts.path.write_text(json.dumps(receipts.rows, indent=2) + "\n")
    try:
        run_kernel(lane, receipts, aw_source, oats, manual=True)
        run_kernel(lane, receipts, aw_source, oats)
    finally:
        receipts.observe("aw/retire", lambda: retire(lane, "t1"))
        receipts.observe("channel/retire", lambda: retire(lane, "t2"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--channel", required=True, type=Path)
    parser.add_argument("--aw-source", required=True)
    parser.add_argument("--oats", required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.aw_source):
        parser.error("--aw-source must be a full release SHA")
    main(args.channel, args.oats, args.aw_source)
