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

    async def test_real_runner_global_and_pairing_grants_refuse_strict_connect(self):
        from gateway.config import Platform
        from gateway.run import GatewayRunner
        try:
            from gateway.session_ingress_context import reauthorize_roles
        except ModuleNotFoundError:
            reauthorize_roles = None  # v0.22.2 predates the durable role seam.
        await self.deliver("mail", {"state": "active", "team_id": TEAM}, "saved")
        retained = await asyncio.wait_for(self.adapter.turns.get(), .5)
        self.adapter.inbound["saved"]["sender_membership"]["state"] = "inactive"
        runner = GatewayRunner()
        self.addCleanup(runner.close_all_session_db_handles)
        if hasattr(runner.session_store, "close_all_db_handles"):
            self.addCleanup(runner.session_store.close_all_db_handles)
        runner.adapters[Platform("aweb")] = self.adapter
        self.adapter.gateway_runner = runner
        source = retained.source
        self.assertTrue(source.role_authorized)
        direct = runner._is_user_authorized_for_source
        for grant in ("all", "allowlist", "pairing"):
            with self.subTest(grant=grant), patch.dict(os.environ, {
                "GATEWAY_ALLOW_ALL_USERS": "true" if grant == "all" else "false",
                "GATEWAY_ALLOWED_USERS": "example.test/alice" if grant == "allowlist" else "",
            }):
                store = runner.pairing_store
                if grant == "pairing":
                    code = store.generate_code("aweb", source.user_id)
                    self.assertIsNotNone(store.approve_code("aweb", code))
                try:
                    self.assertTrue(direct(source, allow_adapter_delegation=False), "real grant positive failed")
                    if reauthorize_roles is not None:
                        # The provenance port is local ownership, not an auth grant.
                        # Actual runner auth and actual upstream replay function run.
                        before = len(self.adapter.commands)
                        with patch("gateway.session_ingress_context.restore_provenance", lambda *a: None):
                            self.assertTrue(await reauthorize_roles(runner, source, {"transport_home": os.environ["HERMES_HOME"]}))
                        self.assertEqual(len(self.adapter.commands), before, "real upstream seam did not reproduce the bypass")
                    with patch.object(adapter_module, "CONNECT_TIMEOUT", .01, create=True):
                        self.assertFalse(await self.adapter.connect(), "strict transport started with a replay-bypassing grant")
                    self.assertEqual(self.adapter.fatal_error_code, "team_policy_conflict")
                    self.assertIsNone(self.adapter._stream_task)
                finally:
                    await self.adapter.disconnect()
                    if grant == "pairing":
                        store.revoke("aweb", source.user_id)
        self.assertIs(runner._is_user_authorized_for_source.__func__, direct.__func__)
        # No global/pairing overlap: the existing strict positive remains valid.
        with patch.dict(os.environ, {"GATEWAY_ALLOW_ALL_USERS": "false", "GATEWAY_ALLOWED_USERS": ""}), \
                patch.object(adapter_module, "CONNECT_TIMEOUT", .01, create=True):
            self.assertTrue(await self.adapter.connect())
            if reauthorize_roles is not None:
                from hermes_state_runtime import RuntimeStoreError
                with patch("gateway.session_ingress_context.restore_provenance", lambda *a: None):
                    with self.assertRaises(RuntimeStoreError):
                        await reauthorize_roles(runner, source, {"transport_home": os.environ["HERMES_HOME"]})
                    self.adapter.inbound["saved"]["sender_membership"]["state"] = "active"
                    self.assertTrue(await reauthorize_roles(runner, source, {"transport_home": os.environ["HERMES_HOME"]}))
        await self.adapter.disconnect()
        self.adapter._allow_team = False
        with patch.dict(os.environ, {"GATEWAY_ALLOW_ALL_USERS": "true"}), \
                patch.object(adapter_module, "CONNECT_TIMEOUT", .01, create=True):
            self.assertTrue(await self.adapter.connect(), "legacy global grants must keep working")

    async def test_served_profile_global_and_pairing_grants_are_also_conflicts(self):
        from types import SimpleNamespace

        from agent.secret_scope import reset_multiplex_context, set_multiplex_context
        from gateway.pairing import PairingStore
        secondary = Path(os.environ["HERMES_HOME"]) / "secondary"
        secondary.mkdir()
        runner = SimpleNamespace(config=SimpleNamespace(_runtime_profile_homes=[("secondary", secondary)]),
                                 pairing_store=None, pairing_stores={})
        self.adapter.gateway_runner = runner
        (secondary / ".env").write_text("AWEB_ALLOW_TEAM=true\nGATEWAY_ALLOW_ALL_USERS=true\n")
        with patch.dict(os.environ, {"GATEWAY_ALLOW_ALL_USERS": "false", "GATEWAY_ALLOWED_USERS": ""}):
            token = set_multiplex_context(True)
            try:
                from gateway.run import _profile_runtime_scope
                with patch.dict(os.environ, {"AWEB_ALLOW_TEAM": "false"}), _profile_runtime_scope(secondary):
                    scoped_adapter = MemoryTransport()
                    scoped_adapter._write_runtime_status_safe = lambda *a, **k: None
                    self.addAsyncCleanup(scoped_adapter.disconnect)
                    self.assertTrue(scoped_adapter._allow_team, "TEAM mode used ambient instead of served profile policy")
                self.assertFalse(await self.adapter.connect(), "served profile grant was ignored")
            finally:
                reset_multiplex_context(token)
        (secondary / ".env").write_text("")
        with patch.dict(os.environ, {"HERMES_HOME": str(secondary)}):
            store = PairingStore()
            code = store.generate_code("aweb", "example.test/alice")
            self.assertIsNotNone(store.approve_code("aweb", code))
        try:
            self.assertFalse(await self.adapter.connect(), "not-yet-loaded served profile pairing was ignored")
            runner.pairing_stores["secondary"] = store
            self.assertFalse(await self.adapter.connect(), "served profile pairing was ignored")
        finally:
            store.revoke("aweb", "example.test/alice")
        with patch.object(adapter_module, "CONNECT_TIMEOUT", .01, create=True):
            self.assertTrue(await self.adapter.connect(), "cleared profile policy should remain supported")
