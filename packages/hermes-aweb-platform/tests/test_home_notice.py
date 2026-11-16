"""Real Hermes first-contact preparation and retry semantics; aw I/O is in memory."""
import os
import unittest
from types import MethodType, SimpleNamespace
from unittest.mock import AsyncMock, patch

from test_content_boundary import GatewayRunner, MemoryTransport, adapter_module, t


class HomeNoticeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import tempfile

        self.home = tempfile.TemporaryDirectory(prefix="aweb-home-unit-")
        self.addCleanup(self.home.cleanup)
        env = patch.dict(os.environ, {"HERMES_HOME": self.home.name, "AWEB_HOME_CHANNEL": ""})
        env.start()
        self.addCleanup(env.stop)
        logged = patch.object(adapter_module, "_home_notice_logged", False, create=True)
        logged.start()
        self.addCleanup(logged.stop)
        # Runtime-status file publication is outside this send/notice unit seam.
        status = patch("gateway.status.publish_runtime_status")
        status.start()
        self.addCleanup(status.stop)
        self.adapter = MemoryTransport()
        self.addAsyncCleanup(self.adapter.disconnect)
        self.runner = SimpleNamespace()
        self.runner.config = SimpleNamespace(
            get_home_channel=lambda platform: None,
            get_notice_delivery=lambda platform: "public",
        )
        self.runner.async_session_store = SimpleNamespace(has_any_sessions=AsyncMock(return_value=True))
        self.runner._delivery_adapter_for = lambda source: self.adapter
        self.runner._thread_metadata_for_source = lambda source: None
        self.runner._deliver_platform_notice = MethodType(GatewayRunner._deliver_platform_notice,
                                                          self.runner)

    async def first_turn(self, chat_id):
        source = SimpleNamespace(platform=adapter_module.Platform("aweb"), chat_type="dm", chat_id=chat_id,
                                 user_id="alice", profile=None, is_bot=False)
        route = adapter_module.InputRoute("chat", chat_id.split(":", 1)[1], "input", chat_id)
        token = adapter_module._input_route.set(route)
        try:
            await GatewayRunner._hmwa_first_contact_notes(self.runner, source, [], [])
            result = await self.adapter.send(chat_id, "ordinary model reply", reply_to="input")
            self.assertTrue(result.success, result.error)
        finally:
            adapter_module._input_route.reset(token)

    async def test_first_contact_only_sends_reply_and_logs_once_for_two_conversations(self):
        with self.assertLogs(adapter_module.logger, level="INFO") as logs:
            await self.first_turn("chat:first")
            self.assertEqual(self.adapter.outbound, ["ordinary model reply"])
            await self.first_turn("chat:second")
        self.assertEqual(self.adapter.outbound, ["ordinary model reply"] * 2)
        self.assertEqual(len(logs.records), 1)
        self.assertEqual(logs.records[0].levelname, "INFO")
        for hint in ("optional", "hermes config set AWEB_HOME_CHANNEL", "restart"):
            self.assertIn(hint, logs.records[0].getMessage())

    async def test_successful_suppression_is_not_retried(self):
        notice = t("gateway.notify.no_home_channel", platform="Aweb", sethome_cmd="/sethome")
        with patch.object(self.adapter, "send", wraps=self.adapter.send) as send:
            result = await self.adapter._send_with_retry("chat:first", notice, reply_to="input",
                                                         base_delay=0)
        self.assertTrue(result.success, result.error)
        self.assertEqual(send.await_count, 1)
        self.assertEqual(self.adapter.outbound, [])

    async def test_quoted_notice_is_delivered_unchanged(self):
        notice = t("gateway.notify.no_home_channel", platform="Aweb", sethome_cmd="/sethome")
        quoted = "The model quotes this text:\n" + notice + "\nEnd quote."
        result = await self.adapter.send("chat:first", quoted, reply_to="input")
        self.assertTrue(result.success, result.error)
        self.assertEqual(self.adapter.outbound, [quoted])

    async def test_configured_home_sends_reply_without_a_local_hint(self):
        with patch.dict(os.environ, {"AWEB_HOME_CHANNEL": "alice"}), self.assertNoLogs(
                adapter_module.logger, level="INFO"):
            await self.first_turn("chat:first")
        self.assertEqual(self.adapter.outbound, ["ordinary model reply"])

    async def test_local_hint_is_process_wide_across_adapter_instances(self):
        other = MemoryTransport()
        self.addAsyncCleanup(other.disconnect)
        notice = t("gateway.notify.no_home_channel", platform="Aweb", sethome_cmd="/sethome")
        with self.assertLogs(adapter_module.logger, level="INFO") as logs:
            await self.adapter.send("chat:first", notice)
            await other.send("chat:second", notice)
        self.assertEqual(len(logs.records), 1)
        self.assertEqual(self.adapter.outbound + other.outbound, [])


if __name__ == "__main__":
    unittest.main()
