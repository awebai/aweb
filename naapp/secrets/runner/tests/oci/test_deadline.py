"""A watchdog under the pinned runner interpreter survives worker SIGKILL."""

import asyncio
import hashlib
import json
import os
import sys
import time
import unittest
from dataclasses import replace
from pathlib import Path

import test_recovery

from aweb_secrets_runner.errors import Refused
from aweb_secrets_runner.oci_prepare import BinaryPin
from aweb_secrets_runner.oci_recovery import recover
from aweb_secrets_runner.oci_workspace import mark_container


@unittest.skipUnless(os.environ.get("AWEB_SECRETS_OCI_PROOF") == "1", "explicit Linux OCI proof")
class DeadlineTests(unittest.IsolatedAsyncioTestCase):
    command = test_recovery.RecoveryTests.command
    inputs = test_recovery.RecoveryTests.inputs
    config = test_recovery.RecoveryTests.config
    credential = test_recovery.RecoveryTests.credential
    run_job = test_recovery.RecoveryTests.run_job
    observe_container = test_recovery.RecoveryTests.observe_container
    assert_reaped = test_recovery.RecoveryTests.assert_reaped
    crashed_worker = test_recovery.RecoveryTests.crashed_worker

    def setUp(self):
        test_recovery.RecoveryTests.setUp(self)
        path = Path(sys.executable)
        self.runtime = replace(
            self.runtime, supervisor=BinaryPin(path, hashlib.sha256(path.read_bytes()).hexdigest())
        )

    async def test_original_job_deadline_stops_processes_after_worker_sigkill_without_recovery(
        self,
    ):
        start = time.monotonic()
        work, pids = await self.crashed_worker(timeout=1)
        try:
            # No recovery command or live Python worker enforces this deadline.
            await self.assert_reaped(pids)
            self.assertLess(time.monotonic() - start, 4)
            self.assertTrue(work.exists())
            self.assertTrue(json.loads((work / "run.json").read_bytes())["stopped"])
            self.assertEqual(list((work / "state").iterdir()), [])
        finally:
            await recover(self.runtime)
        self.assertEqual(list(self.workspace.iterdir()), [])

    async def test_missing_supervisor_refuses_instead_of_releasing_an_unbounded_job(self):
        self.runtime = replace(self.runtime, supervisor=None)
        config, body = self.config("exit 0")
        with self.assertRaisesRegex(Refused, "runner_runtime_unavailable"):
            await self.run_job(config, body, credential=self.credential(wrong_dispatch=True))
        self.assertEqual(list(self.workspace.iterdir()), [])

    async def test_supervisor_pin_is_checked_before_real_hpke_opening(self):
        self.runtime = replace(
            self.runtime, supervisor=BinaryPin(self.runtime.supervisor.path, "0" * 64)
        )
        config, body = self.config("exit 0")
        with self.assertRaisesRegex(Refused, "file_pin_mismatch"):
            await self.run_job(config, body, credential=self.credential(wrong_dispatch=True))
        self.assertEqual(list(self.workspace.iterdir()), [])

    async def test_helper_rechecks_expiry_after_its_own_startup_before_runtime_launch(self):
        async with self.runtime.prepare(self.inputs()) as bundle:
            mark_container(
                bundle.directory.parent,
                engine=bundle.engine,
                sha256=self.runtime.engine.sha256,
                container="job-" + "a" * 32,
            )
            child = await asyncio.create_subprocess_exec(
                sys.executable,
                "-I",
                "-m",
                "aweb_secrets_runner.oci_watchdog",
                "--work",
                str(bundle.directory.parent),
                "--timeout",
                "5",
                "--expires-at",
                str(time.time() - 1),
                env={},
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            async with asyncio.timeout(3):
                self.assertEqual(await child.wait(), 124)
            self.assertFalse((bundle.directory.parent / "init.pid").exists())
            self.assertEqual(list(bundle.state.iterdir()), [])
            self.assertTrue(
                json.loads((bundle.directory.parent / "run.json").read_bytes())["stopped"]
            )
        self.assertEqual(list(self.workspace.iterdir()), [])

    async def test_a_real_job_exit_124_is_not_an_assignment_expiry_refusal(self):
        config, body = self.config("exit 124")
        report = await self.run_job(config, body)
        self.assertEqual(report["exit_code"], 124)
        self.assertEqual(list(self.workspace.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
