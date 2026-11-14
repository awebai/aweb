"""Real Hermes lifecycle, controlled child stream; no server or identity fixture."""
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
from gateway.config import Platform, PlatformConfig
from gateway.platform_registry import PlatformEntry, platform_registry
from gateway.run_adapters import GatewayAdapterLifecycleMixin

spec = importlib.util.spec_from_file_location("startup_adapter", Path(__file__).resolve().parents[1] / "adapter.py")
adapter_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter_module)
platform_registry.register(PlatformEntry(name="aweb", label="Aweb", adapter_factory=lambda cfg: None, check_fn=lambda: True))


async def until(predicate):
    async with asyncio.timeout(3):
        while not predicate():
            await asyncio.sleep(.01)


class StartupHealthTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hermes-startup-unit-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.frames = self.root / "frames"
        self.frames.touch()
        self.child = self.root / "aw-unit-stream"
        self.child.write_text(f"#!{sys.executable}\n" + '''import pathlib, sys, time
root = pathlib.Path.cwd()
(root / "ready").touch()
with (root / "frames").open() as source:
    while True:
        line = source.readline()
        if line:
            sys.stdout.write(line)
            sys.stdout.flush()
        else:
            time.sleep(.005)
''')
        self.child.chmod(0o700)
        self.env = patch.dict(os.environ, {"HERMES_HOME": str(self.root / "profile"), "AWEB_ALLOW_TEAM": "false"})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.adapter = adapter_module.AwebAdapter(PlatformConfig(extra={"workdir": str(self.root), "aw_bin": str(self.child)}))
        self.adapter._write_runtime_status_safe = lambda *a, **k: None
        self.addAsyncCleanup(self.adapter.disconnect)
        self.lifecycle = GatewayAdapterLifecycleMixin()

    def frame(self, text):
        with self.frames.open("a") as output:
            output.write(text + "\n")

    async def connect_snapshot(self, reconnect=False):
        connected = await self.lifecycle._connect_adapter_with_timeout(
            self.adapter, Platform("aweb"), is_reconnect=reconnect, initial=not reconnect)
        return connected, self.adapter.send_path_degraded

    async def test_connected_and_heartbeat_prove_health_before_return(self):
        for reconnect, frame in ((False, "connected"), (True, "heartbeat")):
            with self.subTest(reconnect=reconnect):
                operation = asyncio.create_task(self.connect_snapshot(reconnect))
                try:
                    await until(lambda: self.adapter._proc is not None)
                    self.frame('{"type":"' + frame + '"}')
                    connected, degraded = await asyncio.wait_for(operation, 3)
                    self.assertTrue(connected)
                    self.assertFalse(degraded, "connect must await parsed health proof")
                finally:
                    operation.cancel()
                    await asyncio.gather(operation, return_exceptions=True)
                    await self.adapter.disconnect()
                    self.frames.write_text("")

    async def test_silent_stream_times_out_once_and_recovers_in_background(self):
        started = asyncio.get_running_loop().time()
        connected, degraded = await self.connect_snapshot()
        elapsed = asyncio.get_running_loop().time() - started
        self.assertTrue(connected)
        self.assertTrue(degraded)
        self.assertGreaterEqual(elapsed, 4.9)
        self.assertLess(elapsed, 6.5)
        self.assertFalse(self.adapter._stream_task.done())
        self.frame('{"type":"heartbeat"}')
        await until(lambda: not self.adapter.send_path_degraded)

    async def test_nonproof_frames_and_reconnect_diagnostic_do_not_admit_stale_health(self):
        # Internal constant patch accelerates the same deadline; no operator knob.
        with patch.object(adapter_module, "CONNECT_TIMEOUT", .15, create=True):
            operation = asyncio.create_task(self.connect_snapshot())
            await until(lambda: self.adapter._proc is not None)
            for line in ('not json', '{"type":"unknown"}', '{"type":"actionable_chat"}', '{"type":"error"}'):
                self.frame(line)
            connected, degraded = await operation
            self.assertTrue(connected)
            self.assertTrue(degraded)
            self.assertFalse(self.adapter._stream_task.done())
        self.frame('{"type":"connected"}')
        await until(lambda: not self.adapter.send_path_degraded)
        diagnostic = asyncio.StreamReader()
        diagnostic.feed_data(b"aw events stream: reconnecting after EOF\n")
        diagnostic.feed_eof()
        await self.adapter._log_stderr(diagnostic)
        self.assertTrue(self.adapter.send_path_degraded)

    async def test_cancelling_connect_joins_its_child_and_tasks(self):
        # Hermes lifecycle detaches cancelled connect tasks; test adapter cleanup
        # by awaiting its own cancellation boundary.
        operation = asyncio.create_task(self.adapter.connect())
        await until(lambda: self.adapter._proc is not None)
        child = self.adapter._proc
        operation.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await operation
        self.assertFalse(self.adapter._running)
        self.assertIsNotNone(child.returncode)
        self.assertIsNone(self.adapter._stream_task)
        self.assertIsNone(self.adapter._stderr_task)

    async def test_disconnect_interrupts_startup_wait(self):
        operation = asyncio.create_task(self.connect_snapshot())
        await until(lambda: self.adapter._proc is not None)
        await self.adapter.disconnect()
        connected, _ = await asyncio.wait_for(operation, .5)
        self.assertFalse(connected)
