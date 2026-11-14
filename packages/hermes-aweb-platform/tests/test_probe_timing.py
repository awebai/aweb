"""Execute the actual forwarding observer without importing a live-probe process."""
import ast
import asyncio
import time
import unittest
from pathlib import Path
from types import SimpleNamespace


class ProbeTimingTests(unittest.IsolatedAsyncioTestCase):
    def observer(self, clock=time):
        path = Path(__file__).with_name("live_delivery_probe.py")
        functions = [node for node in ast.parse(path.read_text()).body
                     if isinstance(node, ast.AsyncFunctionDef) and node.name == "observe_connect"]
        self.assertEqual(len(functions), 1, "probe must measure the real connect separately from runner.start")
        namespace = {"time": clock}
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), "exec"), namespace)  # noqa: S102 - Only the named observer AST from this repository.
        return namespace["observe_connect"]

    async def test_forwarded_method_preserves_owner_arguments_and_result(self):
        observe = self.observer()
        adapter = SimpleNamespace(send_path_degraded=True)
        calls, samples = [], []
        async def original(owner, *, is_reconnect=False):
            calls.append((owner, is_reconnect))
            return False
        self.assertFalse(await observe(original, adapter, samples, is_reconnect=True))
        self.assertEqual(calls, [(adapter, True)])
        self.assertFalse(samples[0]["returned"])
        self.assertTrue(samples[0]["completed"])
        self.assertTrue(samples[0]["degraded_after"])

    async def test_runner_overhead_is_outside_the_connect_metric(self):
        clock = SimpleNamespace(now=0.0)
        clock.monotonic = lambda: clock.now
        observe = self.observer(clock)
        adapter = SimpleNamespace(send_path_degraded=True)
        samples = []
        runner_started = clock.monotonic()
        clock.now += 1.2
        async def original(owner, *, is_reconnect=False):
            clock.now += 5.0
            return True
        self.assertTrue(await observe(original, adapter, samples))
        clock.now += .59
        self.assertAlmostEqual(clock.monotonic() - runner_started, 6.79)
        self.assertAlmostEqual(samples[0]["adapter_connect_seconds"], 5.0)

    async def test_cancellation_is_forwarded_and_the_incomplete_sample_survives(self):
        observe = self.observer()
        samples, entered = [], asyncio.Event()
        async def original(owner, *, is_reconnect=False):
            entered.set()
            await asyncio.Event().wait()
        operation = asyncio.create_task(observe(original, SimpleNamespace(send_path_degraded=True), samples))
        await entered.wait()
        operation.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await operation
        self.assertEqual(len(samples), 1)
        self.assertFalse(samples[0]["completed"])
        self.assertNotIn("returned", samples[0])
