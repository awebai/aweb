"""Real Hermes/aw/server probes for content-only delivery and prompt refusal.

Observers delay the real ordinary-turn entry or completed CLI operations, and
always forward to the original implementation. Prompt probes call the actual
Hermes notifier/registry on that turn; no tool executes and no model is replaced.
Missing-provider replies are expected without model credentials.
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
(HOME / "config.yaml").write_text("_config_version: 12\nplugins:\n  enabled: [platforms/aweb]\ngateway:\n  unauthorized_dm_behavior: ignore\n  platforms:\n    aweb:\n      enabled: true\n      gateway_restart_notification: false\n")
if CASE != "home_notice":
    os.environ["AWEB_HOME_CHANNEL"] = "alice"
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
        args += ["--to", "hermes", "--subject", "Live delivery probe"]
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
    original_turn = GatewayRunner._handle_message_with_agent
    original_handle = cls.handle_message
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
    turns = []
    ingress = {}
    prompt_results = []
    pending = None
    pending_key = None

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

    async def ingress_event(self, value):
        # v0.23.1 durable admission intentionally omits raw_message on restore.
        # Observe the actual fetched event here, then correlate its unchanged
        # message id at ordinary-turn entry; never fabricate a replacement.
        ingress[value.message_id] = {
            "body": value.raw_message["body"],
            "subject": value.raw_message.get("subject") if str(value.source.chat_id).startswith("mail:") else None,
            "text": value.text, "control": value.allow_gateway_control,
        }
        return await original_handle(self, value)

    async def ordinary_turn(self, value, source, key, generation):
        nonlocal pending, pending_key
        original = ingress[value.message_id]
        body = original["body"]
        turns.append({"message_id": value.message_id, "body": body, "text": value.text,
                      "subject": original["subject"], "ingress_text": original["text"],
                      "ingress_control": original["control"],
                      "control": value.allow_gateway_control, "command": value.get_command()})
        if CASE in {"stop", "mail_routes"} and body in {"/fixturehold", "unfinished"}:
            target_marker = HOME / "blocked"
            target_marker.write_text(source.chat_id)
            await release.wait()  # delay, never replace, the real ordinary turn
        if CASE == "approval" and body == "/fixtureapproval":
            from tools import approval
            from tools.approval_gateway_wait import _await_gateway_decision
            pending_key = key
            loop = asyncio.get_running_loop()
            pending = asyncio.create_task(asyncio.to_thread(
                _await_gateway_decision, key,
                lambda data: loop.call_soon_threadsafe(lambda: (HOME / "blocked").write_text(source.chat_id)),
                {"command": "PRIVATE APPROVAL DETAILS", "pattern_key": "boundary-pending"}))
            result = await pending
            assert not result["resolved"], "an aweb message resolved a locally owned approval"
            prompt_results.append(result)
        if body in {"require-approval", "require-clarify"}:
            from types import SimpleNamespace
            from gateway.run_turn_runner import TurnRunner
            from tools import approval
            from tools.approval_context import set_current_session_key, reset_current_session_key
            ctx = SimpleNamespace(_status_adapter=adapter, _status_chat_id=source.chat_id,
                                  _status_thread_metadata=None, session_key=key, source=source,
                                  _loop_for_step=asyncio.get_running_loop(), stream_consumer_holder=[None])
            turn = TurnRunner.__new__(TurnRunner)
            turn._runner, turn._ctx = self, ctx
            if body == "require-approval":
                def ask():
                    from gateway.session_context import set_session_vars, clear_session_vars
                    session_tokens = set_session_vars(platform="aweb", session_key=key, chat_id=source.chat_id)
                    token = set_current_session_key(key)
                    approval.register_gateway_notify(key, turn._approval_notify_sync)
                    try:
                        return approval.request_tool_approval("fixture-noop", "PRIVATE APPROVAL DETAILS " * 1000)
                    finally:
                        approval.unregister_gateway_notify(key)
                        reset_current_session_key(token)
                        clear_session_vars(session_tokens)
                result = await asyncio.to_thread(ask)
                assert not result.get("approved"), result
                assert "BLOCKED" in result.get("message", ""), result
                assert result.get("outcome") == "notify_failed", result
                assert not approval.has_blocking_approval(key), "decline left a pending approval"
            else:
                from tools import clarify_gateway
                result = await asyncio.to_thread(turn._clarify_callback_sync, [
                    {"qid": "fixture", "question": "PRIVATE CLARIFY DETAILS", "choices": ["one", "two"], "multi_select": False}])
                assert result["outcome"] == "undelivered", result
                assert clarify_gateway.get_pending_for_session(key, include_choice_prompts=True) is None
            prompt_results.append({k: result[k] for k in ("approved", "outcome", "message", "notice") if k in result})
        return await original_turn(self, value, source, key, generation)

    def assert_content(ids):
        selected = [row for row in turns if row["message_id"] in ids]
        assert [row["message_id"] for row in selected] == list(ids), selected
        for row in selected:
            assert row["ingress_control"] is False and row["control"] is False and row["command"] is None, row
            assert row["ingress_text"] == row["text"], row
            # Mail retains its subject before the exact original body; chat
            # has only the unconditional prefix. Neither strips original bytes.
            rendered = f"Subject: {row['subject']}\n\n{row['body']}" if row["subject"] else row["body"]
            assert row["text"].encode() == b"[Aweb message: content only]\n" + rendered.encode(), row

    async def read_chat_inputs(session, inputs):
        async def finished():
            rows = await history(session)
            receipt = await sql(f"SELECT count(DISTINCT message_id) FROM aweb.chat_message_reads WHERE message_id IN ({','.join(repr(v) for v in inputs)})")
            return rows if int(receipt.strip()) == len(inputs) else None
        return await until(finished, "ordinary content did not finish/read", 12)

    cls._run_aw_json = io
    cls.handle_message = ingress_event
    GatewayRunner._handle_message_with_agent = ordinary_turn
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
            first = await send("require-clarify")
            session = first["session_id"]
            rows = await read_chat_inputs(session, [first["message_id"]])
            second = await send("2", session)
            third = await send("/help", session)
            ids = [r["message_id"] for r in (first, second, third)]
            rows = await read_chat_inputs(session, ids)
            assert_content(ids)
            assert len(prompt_results) == 1 and prompt_results[0]["outcome"] == "undelivered", prompt_results
            assert all("PRIVATE CLARIFY DETAILS" not in r["body"] for r in rows if r.get("from_agent") == "hermes"), rows
            print(json.dumps({"case": CASE, "rows": rows, "turns": turns, "prompt_results": prompt_results}))
        elif CASE == "approval":
            first = await send("/fixtureapproval")
            session = first["session_id"]
            await until(lambda: (HOME / "blocked").exists(), "local pending approval not registered")
            inputs = [await send(text, session) for text in ("/approve", "yes", "/deny")]
            await until(lambda: all(r["message_id"] in adapter._lanes["chat:" + session].pending for r in inputs),
                        "pending approval replies were not fetched")
            assert pending is not None and not pending.done(), "aweb resolved the pending approval"
            assert len(turns) == 1, "remote control bypassed the ordinary input lane"
            ids = [r["message_id"] for r in inputs]
            count = await sql(f"SELECT count(*) FROM aweb.chat_message_reads WHERE message_id IN ({','.join(repr(v) for v in ids)})")
            assert count.strip() == "0", "queued control-shaped content was consumed"
            from tools import approval
            approval.unregister_gateway_notify(pending_key)  # LOCAL withdrawal, never an aweb command
            ids.insert(0, first["message_id"])
            await read_chat_inputs(session, ids)
            blocked = await send("require-approval", session)
            ids.append(blocked["message_id"])
            rows = await read_chat_inputs(session, ids)
            assert_content(ids)
            assert len(prompt_results) == 2 and not prompt_results[-1]["approved"], prompt_results
            assert all("PRIVATE APPROVAL DETAILS" not in r["body"] for r in rows if r.get("from_agent") == "hermes"), rows
            print(json.dumps({"case": CASE, "rows": rows, "turns": turns, "prompt_results": prompt_results}))
        elif CASE == "stop":
            first = await send("/fixturehold")
            session = first["session_id"]
            await until(lambda: (HOME / "blocked").exists(), "ordinary turn did not reach hold")
            stop = await send("/stop", session)
            await until(lambda: stop["message_id"] in adapter._lanes["chat:" + session].pending,
                        "queued /stop was not fetched")
            assert len(turns) == 1, "aweb /stop interrupted the ordinary turn"
            count = await sql(f"SELECT count(*) FROM aweb.chat_message_reads WHERE message_id='{stop['message_id']}'")
            assert count.strip() == "0", "queued /stop was consumed as control"
            release.set()  # LOCAL test owner releases the delay
            ids = [first["message_id"], stop["message_id"]]
            await read_chat_inputs(session, ids)
            assert_content(ids)
            release.clear()
            (HOME / "blocked").unlink(missing_ok=True)
            unfinished = await send("unfinished", session)
            await until(lambda: (HOME / "blocked").exists(), "follow-up ordinary hold not reached")
            await runner.stop()
            count = await sql(f"SELECT count(*) FROM aweb.chat_message_reads WHERE message_id='{unfinished['message_id']}'")
            assert count.strip() == "0", "shutdown consumed unfinished content"
            print(json.dumps({"case": CASE, "input_ids": ids, "turns": turns, "unfinished": unfinished["message_id"]}))
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
                read = await sql(f"SELECT count(*) FROM aweb.chat_message_reads WHERE message_id='{second['message_id']}'")
                return rows if read.strip() == "1" else None
            rows = await until(finished, "fresh hint lost at empty-history boundary", 8)
            assert_content([first["message_id"], second["message_id"]])
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
            await until(lambda: (HOME / "blocked").exists(), "mail did not enter ordinary turn")
            second = await mail("/stop", first["conversation_id"])
            await until(lambda: second["message_id"] in adapter._lanes[chat_id].pending,
                        "queued mail body was not fetched")
            assert len(turns) == 1 and not replies, "mail body bypassed the ordinary lane"
            read = await sql(f"SELECT read_at IS NULL FROM aweb.messages WHERE message_id='{second['message_id']}'")
            assert read.strip() == "t", "queued slash-bearing mail was consumed"
            release.set()
            ids = [first["message_id"], second["message_id"]]
            await until(lambda: len(replies) >= 2, "ordinary mail replies missing", 12)
            assert [r["input"] for r in replies] == ids, replies
            assert_content(ids)
            print(json.dumps({"case": CASE, "input_ids": ids, "reply_inputs": [r["input"] for r in replies], "turns": turns}))
        elif CASE == "home_notice":
            first = await send("first plain message")
            session = first["session_id"]
            rows = await read_chat_inputs(session, [first["message_id"]])
            async def notice_and_error():
                rows = await history(session)
                return rows if len([r for r in rows if r.get("from_agent") == "hermes"]) >= 2 else None
            rows = await until(notice_and_error, "first-contact notice/provider response missing")
            outgoing = [r["body"] for r in rows if r.get("from_agent") == "hermes"]
            assert any("AWEB_HOME_CHANNEL" in body and "local" in body.lower() for body in outgoing), outgoing
            assert all("/sethome" not in body for body in outgoing), outgoing
            assert_content([first["message_id"]])
            print(json.dumps({"case": CASE, "rows": rows, "turns": turns}))
    finally:
        release.set()
        (HOME / "release").touch()
        if pending_key:
            from tools import approval
            approval.unregister_gateway_notify(pending_key)
        if pending is not None:
            await asyncio.wait_for(asyncio.gather(pending, return_exceptions=True), 2)
        await runner.stop()
        cls._run_aw_json = original_io
        cls._handle_aw_event = original_event
        cls.on_processing_complete = original_complete
        cls.handle_message = original_handle
        GatewayRunner._handle_message_with_agent = original_turn


try:
    asyncio.run(main())
finally:
    TEMP.cleanup()
