"""Strict membership intake with real Hermes; only aw I/O is in memory."""
import asyncio
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SOURCE = os.environ.get("HERMES_AGENT_SOURCE")
if not SOURCE:
    raise unittest.SkipTest("Set HERMES_AGENT_SOURCE to a real Hermes checkout")
sys.path.insert(0, str(Path(SOURCE).resolve()))
from gateway.config import PlatformConfig
from gateway.platform_registry import PlatformEntry, platform_registry

spec = importlib.util.spec_from_file_location("team_adapter", Path(__file__).resolve().parents[1] / "adapter.py")
adapter_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter_module)
platform_registry.register(PlatformEntry(name="aweb", label="Aweb", adapter_factory=lambda cfg: None, check_fn=lambda: True))
TEAM = "demo:example.test"


class MemoryTransport(adapter_module.AwebAdapter):
    def __init__(self):
        super().__init__(PlatformConfig(extra={"workdir": ".", "aw_bin": sys.executable}))
        self._own_team_id = TEAM
        self.inbound = {}
        self.commands = []
        self.turns = asyncio.Queue()
        self.set_message_handler(self.model_turn)
        self._running = True

    async def model_turn(self, event):
        await self.turns.put(event)

    async def _run_aw_json(self, *args):
        self.commands.append(args)
        if args[:2] == ("workspace", "status"):
            return {"selected_team": TEAM}
        if args[:2] == ("mail", "show"):
            return {"messages": [self.inbound[args[3]]]}
        if args[:2] == ("chat", "history"):
            return {"session_id": "conversation", "messages": list(self.inbound.values())}
        return {}

    async def _run_event_stream(self):
        await asyncio.Event().wait()


class TeamPolicyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        home = tempfile.TemporaryDirectory(prefix="aweb-team-unit-")
        self.addCleanup(home.cleanup)
        env = patch.dict(os.environ, {"HERMES_HOME": home.name, "AWEB_ALLOW_TEAM": "true",
                                     "AWEB_ALLOW_ALL_USERS": "false", "AWEB_ALLOWED_USERS": ""})
        env.start()
        self.addCleanup(env.stop)
        self.adapter = MemoryTransport()
        self.adapter._write_runtime_status_safe = lambda *a, **k: None
        self.addAsyncCleanup(self.adapter.disconnect)

    async def deliver(self, kind, membership, message_id="input"):
        raw = {"message_id": message_id, "conversation_id": "conversation", "from_agent": "alice",
               "from_address": "example.test/alice", "body": "PRIVATE /approve", "subject": "Title"}
        if membership is not None:
            raw["sender_membership"] = membership
        self.adapter.inbound[message_id] = raw
        if kind == "mail":
            await self.adapter._dispatch_mail_event({"message_id": message_id,
                "sender_membership": {"state": "active", "team_id": TEAM}})
        else:
            await self.adapter._dispatch_chat_event({"session_id": "conversation",
                "sender_membership": {"state": "active", "team_id": TEAM}})
        # Give the actual asynchronous intake and ordinary lane an opportunity.
        await asyncio.sleep(.08)

    async def test_exact_active_team_and_dashboard_human_projection_are_admitted(self):
        for kind in ("mail", "chat"):
            for member in ("did:aw:agent", "did:aw:human"):
                with self.subTest(kind=kind, member=member):
                    mid = f"{kind}-{member}"
                    await self.deliver(kind, {"state": "active", "team_id": TEAM, "member_did_aw": member}, mid)
                    event = await asyncio.wait_for(self.adapter.turns.get(), .5)
                    self.assertTrue(event.source.role_authorized, "strict mode must grant verified teammate access")
                    self.assertFalse(event.allow_gateway_control)
                    self.assertIsNone(event.get_command())
                    self.assertTrue(event.text.endswith("PRIVATE /approve"))

    async def test_other_team_contact_nonmember_and_missing_metadata_stay_unread(self):
        evidence = [None, {}, {"state": "unknown", "team_id": TEAM}, {"state": "inactive", "team_id": TEAM},
                    {"state": "active", "team_id": "other:example.test"},
                    {"state": "active", "team_id": "outside:elsewhere.test"},
                    {"state": "active", "team_id": ""}, {"state": "active", "team_id": None}, [], "active"]
        for kind in ("mail", "chat"):
            for index, member in enumerate(evidence):
                with self.subTest(kind=kind, member=member):
                    self.adapter.commands.clear()
                    with self.assertLogs(adapter_module.logger, level="WARNING") as logs:
                        await self.deliver(kind, member, f"{kind}-{index}")
                    self.assertTrue(self.adapter.turns.empty(), "refused sender reached ordinary turn")
                    self.assertFalse(any(c[:2] in (("mail", "ack"), ("chat", "read")) for c in self.adapter.commands))
                    self.assertNotIn("PRIVATE", "\n".join(logs.output))
                    self.assertIn("team", "\n".join(logs.output).lower())

    async def test_legacy_mode_does_not_apply_membership_gate(self):
        with patch.dict(os.environ, {"AWEB_ALLOW_TEAM": "false"}):
            adapter = MemoryTransport()
        await self.adapter.disconnect()
        self.adapter = adapter
        self.addAsyncCleanup(adapter.disconnect)
        await self.deliver("mail", None)
        event = await asyncio.wait_for(adapter.turns.get(), .5)
        self.assertFalse(event.source.role_authorized)

    async def test_conflicting_broad_settings_fail_before_stream_start(self):
        for settings in ({"AWEB_ALLOW_ALL_USERS": "true"}, {"AWEB_ALLOWED_USERS": "example.test/alice"}):
            with self.subTest(settings=settings), patch.dict(os.environ, settings):
                adapter = MemoryTransport()
                adapter._write_runtime_status_safe = lambda *a, **k: None
                try:
                    self.assertFalse(await adapter.connect())
                    self.assertEqual(adapter.fatal_error_code, "team_policy_conflict")
                    self.assertIsNone(adapter._stream_task)
                finally:
                    await adapter.disconnect()

    async def test_false_allow_all_is_valid_and_selected_team_is_loaded(self):
        self.adapter._own_team_id = None
        with patch.object(adapter_module, "CONNECT_TIMEOUT", .01, create=True):
            self.assertTrue(await self.adapter.connect())
        self.assertEqual(self.adapter._own_team_id, TEAM)
        self.assertIn(("workspace", "status"), self.adapter.commands)

    async def test_durable_role_grant_is_rechecked_against_fetched_membership(self):
        for kind in ("mail", "chat"):
            with self.subTest(kind=kind):
                mid = kind + "-durable"
                await self.deliver(kind, {"state": "active", "team_id": TEAM}, mid)
                event = await asyncio.wait_for(self.adapter.turns.get(), .5)
                check = getattr(self.adapter, "reauthorize_native_roles", None)
                self.assertIsNotNone(check, "Hermes durable ingress needs fresh adapter role authorization")
                if check is not None:
                    self.assertTrue(await check(event.source))
                    self.adapter.inbound[mid]["sender_membership"]["state"] = "inactive"
                    self.assertFalse(await check(event.source), "revoked membership retained a durable grant")

    async def test_missing_selected_team_fails_closed_without_stream(self):
        for response in ({}, {"selected_team": ""}, {"selected_team": None}):
            with self.subTest(response=response):
                adapter = MemoryTransport()
                adapter._write_runtime_status_safe = lambda *a, **k: None
                original = adapter._run_aw_json
                async def missing(*args, response=response, original=original):
                    return response if args[:2] == ("workspace", "status") else await original(*args)
                adapter._run_aw_json = missing
                try:
                    self.assertFalse(await adapter.connect())
                    self.assertEqual(adapter.fatal_error_code, "team_unavailable")
                    self.assertIsNone(adapter._stream_task)
                finally:
                    await adapter.disconnect()
