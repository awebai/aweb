import asyncio
import importlib.util
import sys
import types
import unittest
from pathlib import Path

HERE = Path(__file__).resolve()
HERMES = HERE.parents[4] / "other" / "hermes-agent"
sys.path.insert(0, str(HERMES))

if "yaml" not in sys.modules:
    yaml_stub = types.ModuleType("yaml")
    yaml_stub.safe_load = lambda *args, **kwargs: None
    yaml_stub.safe_dump = lambda *args, **kwargs: ""
    sys.modules["yaml"] = yaml_stub

from gateway.config import PlatformConfig  # noqa: E402
from gateway.platform_registry import PlatformEntry, platform_registry  # noqa: E402

ADAPTER_PATH = HERE.parents[1] / "adapter.py"
spec = importlib.util.spec_from_file_location("aweb_platform_adapter", ADAPTER_PATH)
adapter_mod = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(adapter_mod)

# Platform("aweb") is accepted only after the plugin registry knows the name.
platform_registry.register(PlatformEntry(
    name="aweb",
    label="Aweb",
    adapter_factory=lambda cfg: None,
    check_fn=lambda: True,
))


class FakeAwebAdapter(adapter_mod.AwebAdapter):
    def __init__(self):
        super().__init__(PlatformConfig(extra={"aw_bin": "aw", "workdir": str(HERE.parents[1])}))
        self.commands = []
        self.delivered = []
        self.payloads = {}

    async def _run_aw_json(self, *args):
        self.commands.append(args)
        key = args[:3]
        if key == ("mail", "show", "--message-id"):
            return {"messages": [{
                "message_id": args[3],
                "conversation_id": "conv-1",
                "from_address": "team.example/alice",
                "subject": "Review",
                "body": "please review",
                "created_at": "2026-05-27T00:00:00Z",
            }]}
        if key == ("chat", "history", "--session-id"):
            return {"messages": [{
                "message_id": "chat-1",
                "conversation_id": "sess-1",
                "from_agent": "alice",
                "from_address": "team.example/alice",
                "body": "ping",
                "timestamp": "2026-05-27T00:00:00Z",
            }]}
        if args[:2] == ("mail", "reply"):
            return {"message_id": "reply-1"}
        if args[:2] == ("mail", "ack"):
            return {"message_id": args[2], "acknowledged_at": "now"}
        if args[:2] == ("chat", "send"):
            return {"message_id": "reply-chat-1", "delivered": True}
        if args[:2] == ("chat", "send-and-leave"):
            return {"session_id": "sess-1", "events": [{"message_id": "legacy-reply-chat-1"}]}
        if args[:2] == ("chat", "read"):
            return {"success": True, "messages_marked": 1}
        return {}

    async def handle_message(self, event):
        self.delivered.append(event)


class AwebAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_mail_event_fetches_body_and_records_reply_route(self):
        adapter = FakeAwebAdapter()
        await adapter._dispatch_mail_event({
            "type": "actionable_mail",
            "message_id": "mail-1",
            "conversation_id": "conv-1",
            "from_address": "team.example/alice",
        })

        self.assertEqual(len(adapter.delivered), 1)
        event = adapter.delivered[0]
        self.assertEqual(event.source.chat_id, "mail:conv-1")
        self.assertEqual(event.source.user_id, "team.example/alice")
        self.assertIn("Subject: Review", event.text)
        self.assertIn("please review", event.text)
        self.assertEqual(adapter._routes["mail:conv-1"]["message_id"], "mail-1")

    async def test_mail_reply_acks_only_after_send(self):
        adapter = FakeAwebAdapter()
        adapter._routes["mail:conv-1"] = {"kind": "mail", "message_id": "mail-1", "conversation_id": "conv-1", "sender": "team.example/alice"}

        result = await adapter.send("mail:conv-1", "done")

        self.assertTrue(result.success, result.error)
        self.assertEqual(adapter.commands[0][:2], ("mail", "reply"))
        self.assertEqual(adapter.commands[1], ("mail", "ack", "mail-1"))

    async def test_chat_reply_marks_read_after_send(self):
        adapter = FakeAwebAdapter()
        adapter._routes["chat:sess-1"] = {"kind": "chat", "session_id": "sess-1", "message_id": "chat-1", "sender": "team.example/alice"}

        result = await adapter.send("chat:sess-1", "pong")

        self.assertTrue(result.success, result.error)
        self.assertEqual(adapter.commands[0], ("chat", "send", "--session-id", "sess-1", "--plaintext", "--body", "pong", "--leave"))
        self.assertEqual(adapter.commands[1], ("chat", "read", "--session-id", "sess-1", "--message-id", "chat-1"))


if __name__ == "__main__":
    unittest.main()
