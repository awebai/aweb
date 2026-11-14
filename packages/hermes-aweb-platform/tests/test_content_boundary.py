"""Content/control boundary against the real, pinned Hermes implementation.

Only aw transport is in memory here. Message construction, base-adapter turn
scheduling, control predicates, approval notifier and pending registries are real.
The opt-in gateway probe separately exercises real aw/server transport.
"""
import asyncio
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = os.environ.get("HERMES_AGENT_SOURCE")
if not SOURCE:
    raise unittest.SkipTest("Set HERMES_AGENT_SOURCE to a real Hermes checkout")
sys.path.insert(0, str(Path(SOURCE).resolve()))

from agent.i18n import t
from gateway.config import PlatformConfig
from gateway.platform_registry import PlatformEntry, platform_registry
from gateway.run import GatewayRunner
from gateway.run_turn_runner import TurnRunner
from tools import approval, clarify_gateway
from tools.approval_gateway_wait import _await_gateway_decision
from tools.approval_context import set_current_session_key, reset_current_session_key

spec = importlib.util.spec_from_file_location(
    "aweb_content_adapter", Path(__file__).resolve().parents[1] / "adapter.py")
adapter_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter_module)
platform_registry.register(PlatformEntry(name="aweb", label="Aweb", adapter_factory=lambda cfg: None,
                                       check_fn=lambda: True))


class MemoryTransport(adapter_module.AwebAdapter):
    def __init__(self):
        super().__init__(PlatformConfig(extra={"workdir": ".", "aw_bin": "aw"}))
        self._running = True
        self.inbound = {}
        self.outbound = []
        self.turns = asyncio.Queue()
        self.set_message_handler(self.model_turn)

    async def model_turn(self, event):
        # The real base adapter invokes this ordinary-turn boundary. No model is
        # substituted: this unit test stops before model inference.
        await self.turns.put(event)
        return None

    async def _run_aw_json(self, *args):
        if args[:2] == ("mail", "show"):
            return {"messages": [self.inbound[args[3]]]}
        if args[:2] == ("chat", "history"):
            return {"messages": list(self.inbound.values())}
        if args[:2] in (("mail", "reply"), ("chat", "send"), ("chat", "send-and-leave")):
            if "--body-file" in args:
                body = Path(args[args.index("--body-file") + 1]).read_text()
            else:
                body = args[-1]
            self.outbound.append(body)
            return {"message_id": "outbound"}
        if args[:2] in (("mail", "ack"), ("chat", "read")):
            self.inbound.pop(args[-1], None)
        return {}


class ContentBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.home = tempfile.TemporaryDirectory(prefix="aweb-content-unit-")
        self.env = patch.dict(os.environ, {"HERMES_HOME": self.home.name})
        self.env.start()
        self.adapter = MemoryTransport()
        self.addAsyncCleanup(self.adapter.disconnect)
        self.addCleanup(self.env.stop)
        self.addCleanup(self.home.cleanup)

    async def inbound(self, kind, body, subject=""):
        message_id = f"{kind}-{len(self.adapter._seen)}"
        raw = {"message_id": message_id, "conversation_id": "conversation", "from_agent": "alice",
               "from_address": "team.example/alice", "subject": subject, "body": body,
               "created_at": "2026-11-13T23:00:00Z", "timestamp": "2026-11-13T23:00:00Z"}
        self.adapter.inbound[message_id] = raw
        if kind == "chat":
            await self.adapter._dispatch_chat_event({"session_id": "conversation"})
        else:
            await self.adapter._dispatch_mail_event({"message_id": message_id})
        event = await asyncio.wait_for(self.adapter.turns.get(), 2)
        tasks = list(self.adapter._session_tasks.values())
        if tasks:
            await asyncio.gather(*tasks)
        self.assertEqual(event.raw_message["body"].encode(), body.encode())
        return event

    async def test_chat_slashes_and_whitespace_are_model_content_without_losing_body(self):
        for body in ("/approve", "  \n/stop\n", "@file:/tmp/example /help", "ordinary\r\ntext\n"):
            with self.subTest(body=body):
                event = await self.inbound("chat", body)
                self.assertFalse(event.is_command(), "aweb chat must not dispatch a Hermes command")
                self.assertFalse(event.allow_gateway_control)
                self.assertEqual(event.text.encode(), b"[Aweb message: content only]\n" + body.encode())
        self.assertFalse(self.adapter.outbound)

    async def test_mail_stop_is_content_with_and_without_a_subject(self):
        for subject in ("", "Title"):
            with self.subTest(subject=subject):
                body = "/stop\r\nleave these bytes intact\n"
                event = await self.inbound("mail", body, subject)
                self.assertFalse(event.is_command(), "mail without a subject must also be safe")
                self.assertFalse(event.allow_gateway_control)
                rendered = f"Subject: {subject}\n\n{body}" if subject else body
                self.assertEqual(event.text.encode(), b"[Aweb message: content only]\n" + rendered.encode())

    async def test_aweb_messages_cannot_answer_a_pending_approval_or_clarify(self):
        key = "aweb-content-boundary"
        ready = asyncio.Event()
        loop = asyncio.get_running_loop()
        pending = asyncio.create_task(asyncio.to_thread(
            _await_gateway_decision, key, lambda data: loop.call_soon_threadsafe(ready.set),
            {"command": "private command", "pattern_key": "content-test"}))
        self.addCleanup(approval.unregister_gateway_notify, key)
        try:
            await asyncio.wait_for(ready.wait(), 2)
            question = clarify_gateway.register("content-question", key, "Pick one", ["one", "two"])
            runner = GatewayRunner.__new__(GatewayRunner)
            for body in ("/approve", "/approve all always", "yes", "approve", "always", "session", "👍", "2"):
                event = await self.inbound("chat", body)
                self.assertIsNone(event.get_command())
                self.assertFalse(await runner._route_plaintext_approval_while_busy(event, key))
                self.assertIsNone(await runner._hm_pending_reply_intercepts(event, event.source, key))
                self.assertFalse(pending.done(), "an aweb message resolved the approval")
                self.assertIsNotNone(clarify_gateway.get_pending_for_session(key, include_choice_prompts=True))
            # Neighbor: the pending approval is genuinely live and can still be
            # resolved by its local owner; the preceding messages did not do so.
            self.assertEqual(approval.resolve_gateway_approval(key, "once"), 1)
            result = await asyncio.wait_for(pending, 2)
            self.assertTrue(result["resolved"])
            self.assertEqual(result["choice"], "once")
        finally:
            approval.unregister_gateway_notify(key)
            clarify_gateway.clear_session(key)
            await asyncio.wait_for(pending, 2)

    def turn_runner(self):
        token = adapter_module._input_route.set(
            adapter_module.InputRoute("chat", "conversation", "input", "chat:conversation"))
        self.addCleanup(adapter_module._input_route.reset, token)
        ctx = SimpleNamespace(_status_adapter=self.adapter, _status_chat_id="chat:conversation",
                              _status_thread_metadata=None, session_key="aweb-decline-test",
                              _loop_for_step=asyncio.get_running_loop(), stream_consumer_holder=[None])
        turn = TurnRunner.__new__(TurnRunner)
        turn._ctx = ctx
        turn._runner = SimpleNamespace()
        return turn

    async def test_real_approval_notifier_declines_without_prompt_preview_or_pending_wait(self):
        turn = self.turn_runner()
        def request():
            token = set_current_session_key(turn._ctx.session_key)
            approval.register_gateway_notify(turn._ctx.session_key, turn._approval_notify_sync)
            try:
                return approval.request_tool_approval("private-tool", "SECRET COMMAND " * 1000)
            finally:
                approval.unregister_gateway_notify(turn._ctx.session_key)
                reset_current_session_key(token)
        self.env_changes = patch.dict(os.environ, {"HERMES_EXEC_ASK": "1"})
        self.env_changes.start()
        self.addCleanup(self.env_changes.stop)
        task = asyncio.create_task(asyncio.to_thread(request))
        try:
            # Before the fix this really sends a text prompt. Do not wait for
            # the long production approval timeout to establish the regression.
            for _ in range(100):
                if task.done() or self.adapter.outbound:
                    break
                await asyncio.sleep(.01)
            self.assertEqual(self.adapter.outbound, [], "approval details leaked to the aweb sender")
            result = await asyncio.wait_for(asyncio.shield(task), 1)
            self.assertFalse(result.get("approved"), result)
            self.assertIn("BLOCKED", result.get("message", ""))
            self.assertEqual(result.get("outcome"), "notify_failed", result)
            self.assertFalse(approval.has_blocking_approval(turn._ctx.session_key))
        finally:
            approval.unregister_gateway_notify(turn._ctx.session_key)
            await asyncio.wait_for(task, 2)

    async def test_interactive_clarify_declines_and_clears_its_pending_registration(self):
        turn = self.turn_runner()
        task = asyncio.create_task(asyncio.to_thread(
            turn._clarify_callback_sync,
            [{"qid": "question", "question": "PRIVATE QUESTION", "choices": ["one", "two"], "multi_select": False}]))
        try:
            for _ in range(100):
                if task.done() or self.adapter.outbound:
                    break
                await asyncio.sleep(.01)
            self.assertEqual(self.adapter.outbound, [], "interactive clarify leaked to the aweb sender")
            result = await asyncio.wait_for(asyncio.shield(task), 1)
            self.assertEqual(result["outcome"], "undelivered")
            self.assertIsNone(clarify_gateway.get_pending_for_session(turn._ctx.session_key, include_choice_prompts=True))
        finally:
            clarify_gateway.clear_session(turn._ctx.session_key)
            await asyncio.wait_for(task, 2)

    async def test_fallback_prompt_refused_but_ordinary_content_still_delivered(self):
        result = await self.adapter.send("chat:conversation", "PRIVATE COMMAND /approve",
                                         reply_to="input", metadata={"is_approval_prompt": True})
        self.assertFalse(result.success)
        self.assertEqual(self.adapter.outbound, [])
        result = await self.adapter.send("chat:conversation", "ordinary answer", reply_to="input")
        self.assertTrue(result.success, result.error)
        self.assertEqual(self.adapter.outbound, ["ordinary answer"])

    async def test_exact_home_notice_replaced_without_rewriting_other_text(self):
        notice = t("gateway.notify.no_home_channel", platform="Aweb", sethome_cmd="/sethome")
        await self.adapter.send("chat:conversation", notice, reply_to="input")
        self.assertNotIn("/sethome", self.adapter.outbound[-1])
        self.assertIn("AWEB_HOME_CHANNEL", self.adapter.outbound[-1])
        self.assertIn("local", self.adapter.outbound[-1].lower())
        ordinary = "The document mentions /sethome as an old command."
        await self.adapter.send("chat:conversation", ordinary, reply_to="input")
        self.assertEqual(self.adapter.outbound[-1], ordinary)


if __name__ == "__main__":
    unittest.main()
