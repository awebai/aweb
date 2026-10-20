"""Subprocess harness for test_live_delivery.py; actual Hermes plugin commands.

The fixture command uses the public plugin command extension point and real
Hermes clarify registry/waiter. It proves transport/control behavior without
inference, not a model-generated tool call. Gates only control scheduling at
real I/O boundaries; all message/event/history/reply/read traffic uses real aw.
"""
import asyncio
import json
import logging
import os
from pathlib import Path
import signal
import sys
import tempfile
import time

CASE = sys.argv[1]
SOURCE = Path(os.environ["HERMES_AGENT_SOURCE"]).resolve()
RECEIVER = Path(os.environ["HERMES_LIVE_RECEIVER_HOME"]).resolve()
SENDER = Path(os.environ["HERMES_LIVE_SENDER_HOME"]).resolve()
POSTGRES = os.environ["HERMES_LIVE_POSTGRES_CONTAINER"]
UNAUTHORIZED = os.environ.get("HERMES_LIVE_UNAUTHORIZED_HOME")
PLUGIN = Path(os.environ.get("HERMES_LIVE_PLUGIN_SOURCE", Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0, str(SOURCE))

TEMP = tempfile.TemporaryDirectory(prefix="hermes-delivery-")
HOME = Path(TEMP.name)
ENV = {k: v for k, v in os.environ.items()
       if not k.startswith(("AWEB_", "AWID_", "HERMES_"))
       and not k.endswith(("API_KEY", "TOKEN"))}
os.environ.clear()
os.environ.update(ENV, HERMES_HOME=str(HOME), HERMES_SKIP_UPDATE_CHECK="1",
                  AWEB_PLATFORM_ENABLED="true", AWEB_PLATFORM_WORKDIR=str(RECEIVER),
                  AWEB_ALLOWED_USERS="hermes-acft1.test/alice", AWEB_ALLOW_ALL_USERS="false")
from ruamel.yaml import YAML
assert YAML(typ="safe").load((RECEIVER / ".aw/workspace.yaml").read_text())["aweb_url"].startswith("http://127.0.0.1:")
(HOME / "plugins/platforms").mkdir(parents=True)
(HOME / "plugins/platforms/aweb").symlink_to(PLUGIN)
fixture = HOME / "plugins/fixture"
fixture.mkdir()
(fixture / "plugin.yaml").write_text("name: fixture\nversion: 0.1.0\ndescription: Local acceptance commands\n")
(fixture / "__init__.py").write_text('''
import asyncio
from pathlib import Path
import os
from tools import clarify_gateway
from tools import approval
from tools.approval_context import set_current_session_key, reset_current_session_key
from gateway.session_context import get_session_env

async def clarify(args, *, session_key=None, source=None):
    # v0.22.2 exposes session context; newer Hermes also supplies command kwargs.
    session_key = session_key or get_session_env("HERMES_SESSION_KEY")
    chat_id = source.chat_id if source else get_session_env("HERMES_SESSION_CHAT_ID")
    assert session_key and chat_id, "Actual gateway command context is required"
    with Path(os.environ["HERMES_HOME"], "pending_keys").open("a") as f:
        f.write(session_key + "\\n")
    entry = clarify_gateway.register("fixture-" + session_key, session_key, "Pick one", ["one", "two"])
    Path(os.environ["HERMES_HOME"], "blocked").write_text(chat_id)
    response = await asyncio.to_thread(clarify_gateway.wait_for_response, entry.clarify_id, 15)
    return "fixture-resolved:" + str(response)

async def hold(args, *, source=None):
    chat_id = source.chat_id if source else get_session_env("HERMES_SESSION_CHAT_ID")
    assert chat_id, "Actual gateway command context is required"
    root = Path(os.environ["HERMES_HOME"])
    (root / "blocked").write_text(chat_id)
    while not (root / "release").exists():
        await asyncio.sleep(.02)
    return "fixture-held-reply:" + chat_id

def register(ctx):
    def approve(args, *, session_key=None, source=None):
        session_key = session_key or get_session_env("HERMES_SESSION_KEY")
        chat_id = source.chat_id if source else get_session_env("HERMES_SESSION_CHAT_ID")
        assert session_key and chat_id, "Actual gateway command context is required"
        token = set_current_session_key(session_key)
        with Path(os.environ["HERMES_HOME"], "pending_keys").open("a") as f:
            f.write(session_key + "\\n")
        approval.register_gateway_notify(session_key, lambda data: Path(os.environ["HERMES_HOME"], "blocked").write_text(chat_id))
        try:
            result = approval.request_tool_approval("fixture_noop", "Acceptance only; no tool runs")
            return "fixture-approval:" + str(result.get("approved", False))
        finally:
            approval.unregister_gateway_notify(session_key)
            reset_current_session_key(token)
    ctx.register_command("fixtureapproval", approve)
    ctx.register_command("fixtureclarify", clarify)
    ctx.register_command("fixturehold", hold)
    ctx.register_command("fixtureecho", lambda args: "fixture-echo:" + args)
''')
(HOME / "config.yaml").write_text("_config_version: 12\nplugins:\n  enabled: [platforms/aweb, fixture]\ngateway:\n  unauthorized_dm_behavior: ignore\n  platforms:\n    aweb:\n      enabled: true\n")
logging.basicConfig(level=logging.INFO)
from hermes_cli.plugins import discover_plugins
discover_plugins()
from gateway.run import GatewayRunner
from gateway.config import Platform
from gateway.platform_registry import platform_registry


async def command(argv, *, cwd=None):
    proc = await asyncio.create_subprocess_exec(*argv, cwd=cwd, env=ENV,
             stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out, err = await asyncio.wait_for(proc.communicate(), 12)
    if proc.returncode:
        raise RuntimeError(f"{argv[:3]}: {err.decode()}")
    return out.decode()


async def aw(home, *args):
    return json.loads(await command(["aw", *args, "--json"], cwd=home))


async def sql(query):
    return await command(["docker", "exec", POSTGRES, "psql", "-U", "aweb", "-d", "aweb", "-At", "-c", query])


async def until(predicate, description, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if hasattr(value, "__await__"):
            value = await value
        if value:
            return value
        await asyncio.sleep(.04)
    raise AssertionError(description)


async def send(text, session=None):
    path = HOME / "body"
    path.write_text(text)
    if session:
        return await aw(SENDER, "chat", "send", "--session-id", session, "--plaintext", "--leave", "--body-file", str(path))
    return await aw(SENDER, "chat", "send-and-leave", "hermes", "--plaintext", "--start-conversation", "--body-file", str(path))


async def mail(text, conversation=None, sender=SENDER):
    path = HOME / "body"
    path.write_text(text)
    args = ["mail", "send", "--plaintext", "--body-file", str(path)]
    if conversation:
        args += ["--conversation-id", conversation]
    else:
        args += ["--to", "hermes", "--new-conversation"]
    return await aw(sender, *args)


async def history(session):
    return (await aw(SENDER, "chat", "history", "--session-id", session))["messages"]


async def main():
    upstream = (await command(["git", "rev-parse", "HEAD"], cwd=SOURCE)).strip()
    await command(["git", "diff", "--exit-code"], cwd=SOURCE)
    print(json.dumps({"upstream_hermes": upstream, "plugin": str(PLUGIN)}), flush=True)
    runner = GatewayRunner()
    # Obtain the actual installed plugin class. Probes wrap the real I/O, never
    # fabricate its return values or bypass the gateway handler.
    adapter = platform_registry.create_adapter("aweb", runner.config.platforms[Platform("aweb")])
    cls = type(adapter)
    original_io = cls._run_aw_json
    original_event = cls._handle_aw_event
    original_complete = cls.on_processing_complete
    empty = asyncio.Event()
    release = asyncio.Event()
    hint = asyncio.Event()
    connected = asyncio.Event()
    fault = asyncio.Event()
    handled = asyncio.Event()
    target = None
    replies = []
    dropped = False
    connections = 0

    def runtime_state():
        status = HOME / "gateway_state.json"
        if not status.exists():
            return None
        return json.loads(status.read_text()).get("platforms", {}).get("aweb", {}).get("state")

    async def io(self, *args):
        nonlocal dropped
        result = await original_io(self, *args)
        if args[:2] == ("mail", "reply"):
            replies.append({"input": args[2], "body": Path(args[args.index("--body-file") + 1]).read_text()})
        if CASE == "mail_retry" and args[:2] == ("mail", "show") and args[-1] == target and not dropped:
            dropped = True
            fault.set()
            # A successful real fetch whose response is lost before admission.
            # Retrying must refetch; no synthetic message data is supplied.
            raise ConnectionError("acceptance probe: lost completed fetch response")
        if CASE == "hint" and args[:2] == ("chat", "history") and target in args and not result.get("messages") and not empty.is_set():
            empty.set()
            await release.wait()
        return result

    async def event(self, value):
        nonlocal connections
        if value.get("type") == "connected":
            connections += 1
        if CASE == "health" and not connected.is_set():
            connected.set()
            await release.wait()  # hold the first actual parsed server frame
        if CASE == "hint" and empty.is_set() and value.get("session_id") == target:
            hint.set()
        return await original_event(self, value)

    async def complete(self, value, outcome):
        await original_complete(self, value, outcome)
        if CASE == "unauthorized" and str(value.message_id) == target:
            handled.set()

    cls._run_aw_json = io
    cls._handle_aw_event = event
    cls.on_processing_complete = complete
    try:
        assert await runner.start(), "real gateway failed startup"
        adapter = runner.adapters[Platform("aweb")]
        if CASE == "health":
            await until(connected.is_set, "no real server frame")
            assert adapter.send_path_degraded, "reports healthy before first live frame is accepted"
            await until(lambda: runtime_state() == "retrying", "unproven receive path not exposed in Hermes status")
            release.set()
            await until(lambda: not adapter.send_path_degraded, "stream never became healthy")
            await until(lambda: runtime_state() == "connected", "live receive path not exposed in Hermes status")
            old = adapter._proc
            old.terminate()
            await old.wait()
            await until(lambda: adapter.send_path_degraded, "dead stream still reports healthy", 1)
            await until(lambda: runtime_state() == "retrying", "stream failure not exposed in Hermes status", 1)
            await until(lambda: adapter._proc and adapter._proc.pid != old.pid and not adapter.send_path_degraded,
                        "stream did not recover on real traffic")
            await until(lambda: runtime_state() == "connected", "recovery not exposed in Hermes status")
            print(json.dumps({"case": CASE, "old_pid": old.pid, "new_pid": adapter._proc.pid,
                              "states": ["retrying", "connected", "retrying", "connected"]}))
        elif CASE == "clarify":
            first = await send("/fixtureclarify")
            session = first["session_id"]
            await until(lambda: (HOME / "blocked").exists() and (HOME / "blocked").read_text() == "chat:" + session,
                        "real clarify wait never started")
            second = await send("2", session)
            third = await send("/fixtureecho third", session)
            fourth = await send("/fixtureecho fourth", session)
            async def finished():
                rows = await history(session)
                bodies = [r["body"] for r in rows if r.get("from_agent") == "hermes"]
                return rows if bodies == ["fixture-resolved:two", "fixture-echo:third", "fixture-echo:fourth"] else None
            rows = await until(finished, "later input failed to unblock real clarify or ordinary turns merged/reordered", 7)
            ids = [r["message_id"] for r in (first, second, third, fourth)]
            receipts = json.loads(await sql(f"SELECT json_agg(x) FROM (SELECT message_id,read_at FROM aweb.chat_message_reads WHERE message_id IN ({','.join(repr(x) for x in ids)})) x"))
            assert {r["message_id"] for r in receipts} == set(ids), "an accepted input was not marked read"
            print(json.dumps({"case": CASE, "session": session, "rows": rows, "receipts": receipts}))
        elif CASE == "approval":
            records = []
            for control, approved in (("/approve", True), ("/deny", False)):
                first = await send("/fixtureapproval")
                session = first["session_id"]
                await until(lambda: (HOME / "blocked").exists() and (HOME / "blocked").read_text() == "chat:" + session,
                            "real approval gate never started")
                second = await send(control, session)
                async def finished():
                    rows = await history(session)
                    return rows if any(r["body"] == "fixture-approval:" + str(approved) for r in rows) else None
                rows = await until(finished, "control input failed to resolve the real approval gate", 6)
                records.append({"control": control, "session": session, "input": second, "rows": rows})
            print(json.dumps({"case": CASE, "records": records}))
        elif CASE == "stop":
            first = await send("/fixtureclarify")
            session = first["session_id"]
            await until(lambda: (HOME / "blocked").exists() and (HOME / "blocked").read_text() == "chat:" + session,
                        "real clarify wait never started")
            stop = await send("/stop", session)
            third = await send("/fixtureecho after-stop", session)
            async def finished():
                rows = await history(session)
                return rows if any(r["body"] == "fixture-echo:after-stop" for r in rows) else None
            rows = await until(finished, "stop did not release the session for a later ordinary turn", 6)
            # A later shutdown cancellation must not inherit the earlier stop's
            # receipt and consume an unrelated unfinished input.
            (HOME / "blocked").unlink(missing_ok=True)
            unfinished = await send("/fixturehold", session)
            await until(lambda: (HOME / "blocked").exists() and (HOME / "blocked").read_text() == "chat:" + session,
                        "follow-up hold never started")
            await runner.stop()
            read = await sql(f"SELECT count(*) FROM aweb.chat_message_reads WHERE message_id='{unfinished['message_id']}'")
            assert read.strip() == "0", "shutdown consumed an unfinished input using a stale stop receipt"
            print(json.dumps({"case": CASE, "session": session, "stop": stop, "next": third, "rows": rows}))
        elif CASE == "hint":
            first = await send("/fixtureecho first")
            target = first["session_id"]
            await until(empty.is_set, "no empty real history snapshot to hold")
            stream_pid, stream_connections = adapter._proc.pid, connections
            second = await send("/fixtureecho second", target)
            await until(hint.is_set, "fresh real server summary did not arrive while response held")
            release.set()
            async def finished():
                rows = await history(target)
                return rows if any(r["body"] == "fixture-echo:second" for r in rows) else None
            rows = await until(finished, "fresh hint lost at empty-history boundary", 3)
            assert adapter._proc.pid == stream_pid and connections == stream_connections, "race test recovered through reconnect"
            print(json.dumps({"case": CASE, "session": target, "input": second, "rows": rows,
                              "stream_pid": stream_pid, "connected_frames": connections}))
        elif CASE == "unauthorized":
            first = await mail("/fixtureecho unauthorized", sender=Path(UNAUTHORIZED))
            target = first["message_id"]
            await until(handled.is_set, "unauthorized input never reached the real Hermes refusal boundary")
            read = await sql(f"SELECT read_at IS NULL FROM aweb.messages WHERE message_id='{target}'")
            replies_count = await sql(f"SELECT count(*) FROM aweb.messages WHERE conversation_id='{first['conversation_id']}' AND from_alias='hermes'")
            assert read.strip() == "t", "unauthorized input was marked read"
            assert replies_count.strip() == "0", "unauthorized input received a reply"
            print(json.dumps({"case": CASE, "input": target, "unread": True, "reply_count": 0}))
        elif CASE == "mail_retry":
            first = await mail("/fixtureecho retry")
            target = first["message_id"]
            await until(fault.is_set, "fetch fault was not exercised")
            async def finished():
                data = await aw(RECEIVER, "mail", "show", "--message-id", target)
                return data if data["messages"][0].get("read_at") else None
            receipt = await until(finished, "lost fetch was never retried/acknowledged", 5)
            print(json.dumps({"case": CASE, "receipt": receipt, "replies": replies}))
        elif CASE == "mail_routes":
            first = await mail("/fixturehold")
            chat_id = "mail:" + first["conversation_id"]
            await until(lambda: (HOME / "blocked").exists() and (HOME / "blocked").read_text() == chat_id,
                        "mail hold command never ran")
            second = await mail("/approve", first["conversation_id"])
            await until(lambda: any(r["input"] == second["message_id"] for r in replies), "control command blocked behind mail turn")
            (HOME / "release").touch()
            await until(lambda: any(r["body"] == "fixture-held-reply:" + chat_id for r in replies), "first mail reply missing")
            held = next(r for r in replies if r["body"] == "fixture-held-reply:" + chat_id)
            assert held["input"] == first["message_id"], "first turn replied to latest conversation input"
            print(json.dumps({"case": CASE, "first": first, "second": second,
                              "reply_inputs": [r["input"] for r in replies]}))
    finally:
        release.set()
        (HOME / "release").touch()
        pending_keys = HOME / "pending_keys"
        if pending_keys.exists():
            from tools import approval, clarify_gateway
            for key in pending_keys.read_text().splitlines():
                approval.clear_session(key)
                clarify_gateway.clear_session(key)
        await runner.stop()
        cls._run_aw_json = original_io
        cls._handle_aw_event = original_event
        cls.on_processing_complete = original_complete


try:
    asyncio.run(main())
finally:
    TEMP.cleanup()
