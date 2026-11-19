"""Execute the actual forwarding observer without importing a live-probe process."""
import ast
import asyncio
import os
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


class ProbeCommandTests(unittest.IsolatedAsyncioTestCase):
    def command(self):
        path = Path(__file__).with_name("live_delivery_probe.py")
        functions = [node for node in ast.parse(path.read_text()).body
                     if isinstance(node, ast.AsyncFunctionDef) and node.name == "command"]
        self.assertEqual(len(functions), 1)
        namespace = {"asyncio": asyncio, "ENV": dict(os.environ)}
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), "exec"), namespace)  # noqa: S102 - Only the named command helper AST from this repository.
        return namespace["command"]

    async def check_child_cleanup(self, *, interruption):
        command = self.command()
        original = asyncio.create_subprocess_exec
        ready = asyncio.Event()
        children = []
        operation = None

        async def observe_spawn(*args, **kwargs):
            child = await original(*args, **kwargs)
            children.append(child)
            self.assertEqual(await child.stdout.readline(), b"READY\n")
            ready.set()
            return child

        try:
            with patch.object(asyncio, "create_subprocess_exec", observe_spawn):
                operation = asyncio.create_task(command([
                    sys.executable, "-c", "import time; print('READY', flush=True); time.sleep(60)",
                ], timeout=1))
                await asyncio.wait_for(ready.wait(), 5)
                if interruption is asyncio.CancelledError:
                    operation.cancel()
                with self.assertRaises(interruption):
                    await operation
            self.assertIsNotNone(children[0].returncode, "interrupted command left its child running")
        finally:
            if operation is not None and not operation.done():
                operation.cancel()
                try:
                    await operation
                except asyncio.CancelledError:
                    pass
            for child in children:
                if child.returncode is None:
                    child.kill()
                    await child.communicate()

    async def test_cancellation_joins_the_actual_child(self):
        await self.check_child_cleanup(interruption=asyncio.CancelledError)

    async def test_timeout_joins_the_actual_child(self):
        await self.check_child_cleanup(interruption=TimeoutError)

    async def test_actual_child_output_and_failure_are_preserved(self):
        command = self.command()
        self.assertEqual(await command([sys.executable, "-c", "print('probe output')"]), "probe output\n")
        self.assertEqual(await command([sys.executable, "-c", "import sys; print(sys.stdin.read(), end='')"],
                                      stdin_data=b"private stdin\n"), "private stdin\n")
        with self.assertRaisesRegex(RuntimeError, "probe failure"):
            await command([sys.executable, "-c", "import sys; sys.stderr.write('probe failure'); sys.exit(7)"])


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
