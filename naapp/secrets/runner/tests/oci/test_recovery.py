"""Real SIGKILL/recovery of private runtime state, with no assignment re-execution."""

import asyncio
import hashlib
import json
import os
import signal
import sys
import time
import unittest
from dataclasses import replace
from pathlib import Path

import test_lifecycle
import test_prepare

from aweb_secrets_runner.errors import Refused
from aweb_secrets_runner.journal import Journal
from aweb_secrets_runner.oci_prepare import BinaryPin
from aweb_secrets_runner.oci_recovery import recover


@unittest.skipUnless(os.environ.get("AWEB_SECRETS_OCI_PROOF") == "1", "explicit Linux OCI proof")
class RecoveryTests(unittest.IsolatedAsyncioTestCase):
    command = test_lifecycle.LifecycleTests.command
    inputs = test_lifecycle.LifecycleTests.inputs
    config = test_lifecycle.LifecycleTests.config
    credential = test_lifecycle.LifecycleTests.credential
    run_job = test_lifecycle.LifecycleTests.run_job
    observe_container = test_lifecycle.LifecycleTests.observe_container
    assert_reaped = test_lifecycle.LifecycleTests.assert_reaped

    def setUp(self):
        test_prepare.PreparationTests.setUp(self)

    async def crashed_worker(
        self, *, preparation_only=False, blocked_unpack=False, blocked_launch=False, timeout=30
    ):
        config, body = self.config("/bin/busybox sleep 30 & wait", timeout=timeout)
        supervisor = self.runtime.supervisor
        self.assertIsNotNone(supervisor)
        ready = self.root / (
            "tool-ready"
            if blocked_unpack
            else "launcher-ready"
            if blocked_launch
            else "public-ready"
        )
        script = self.root / "worker.py"
        script.write_text(
            "import asyncio, hashlib, json, time\nfrom pathlib import Path\n"
            "from cryptography.hazmat.primitives import hpke\n"
            "from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey\n"
            "from aweb_secrets_values import encode_value\n"
            "from aweb_secrets_runner.jobs import CredentialInput, RunnerConfig, job_digest\n"
            "from aweb_secrets_runner.protocol import encode64\n"
            "from aweb_secrets_runner.oci_prepare import BinaryPin, RuncPreparation\n"
            "from aweb_secrets_runner.oci_execution import execute_oci\n"
            f"runtime=RuncPreparation(BinaryPin(Path({str(self.runtime.engine.path)!r}),"
            f"{self.runtime.engine.sha256!r}),BinaryPin(Path({str(self.runtime.unpacker.path)!r}),"
            f"{self.runtime.unpacker.sha256!r}),Path({str(self.layout)!r}),Path({str(self.workspace)!r}),"
            f"supervisor=BinaryPin(Path({str(supervisor.path)!r}),{supervisor.sha256!r}))\n"
            f"config=RunnerConfig.load(Path({str(self.root / 'runner.json')!r}))\n"
            f"body=json.loads({json.dumps(body)!r})\n"
            "async def main():\n"
            " if " + repr(preparation_only) + ":\n"
            "  selected=config.inputs(job_id='fixture',digest=job_digest(body),"
            "runner_id=body['runner_ids'][0],params={},credential_refs=('db',))\n"
            "  async with runtime.prepare(selected):\n"
            f"   Path({str(ready)!r}).write_text('prepared')\n"
            "   await asyncio.Event().wait()\n"
            " else:\n"
            "  key=X25519PrivateKey.generate()\n"
            "  suite=hpke.Suite(hpke.KEM.X25519,hpke.KDF.HKDF_SHA256,hpke.AEAD.CHACHA20_POLY1305)\n"
            "  dispatch='dsp_'+'a'*22\n"
            "  sealed=encode64(suite.encrypt(encode_value('basic',{'username':'',"
            "'password':'synthetic-recovery-value'}),key.public_key(),dispatch.encode()))\n"
            "  await execute_oci(runtime,config,job_id='fixture',digest=job_digest(body),"
            "runner_id=body['runner_ids'][0],params={},credentials=[CredentialInput('db',sealed,key,dispatch)],"
            "expires_at=time.time()+300)\n"
            "asyncio.run(main())\n"
        )
        script.chmod(0o600)
        child = await asyncio.create_subprocess_exec(
            sys.executable,
            str(script),
            env={"PYTHONPATH": os.environ["PYTHONPATH"]},
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        pids = []
        try:
            if preparation_only or blocked_launch:
                async with asyncio.timeout(5):
                    while not ready.exists():
                        if child.returncode is not None:
                            self.fail("preparation child exited early")
                        await asyncio.sleep(0.01)
            else:
                await self.observe_container(asyncio.Event(), pids)
                pids.extend(
                    int(pid)
                    for pid in Path(f"/proc/{child.pid}/task/{child.pid}/children")
                    .read_text()
                    .split()
                )
            child.kill()  # No finally block in the killed worker can clean state.
            self.assertEqual(await child.wait(), -signal.SIGKILL)
            (work,) = self.workspace.glob("job-*")
            return work, pids
        finally:
            if child.returncode is None:
                child.kill()
                await child.wait()

    async def test_sigkill_during_preparation_cleans_only_public_private_state(self):
        work, _ = await self.crashed_worker(preparation_only=True)
        self.assertTrue((work / "bundle/config.json").exists())
        await recover(self.runtime)
        self.assertEqual(list(self.workspace.iterdir()), [])

    async def test_sigkill_during_execution_recovers_processes_without_rearming_the_journal(self):
        journal = Journal(self.root / "journal.sqlite3")
        dispatch = "dsp_" + "a" * 22
        journal.accept(dispatch, expires_at=time.time() + 300)
        work, pids = await self.crashed_worker()
        self.assertTrue(any((work / "state").iterdir()))
        try:
            await recover(self.runtime)
            await self.assert_reaped(pids)
            self.assertEqual(list(self.workspace.iterdir()), [])
            self.assertEqual(journal.pending_results(), ())
            with self.assertRaisesRegex(Refused, "assignment_replayed"):
                Journal(journal.path).accept(dispatch, expires_at=time.time() + 300)
        finally:
            await recover(self.runtime)

    async def test_recovery_cannot_stop_an_active_preparation_in_the_same_workspace(self):
        async with self.runtime.prepare(self.inputs()):
            with self.assertRaisesRegex(Refused, "runner_busy"):
                await recover(self.runtime)
        self.assertEqual(list(self.workspace.iterdir()), [])

    async def test_interrupted_unpacking_is_retained_until_the_operator_reconciles_the_tool(self):
        tool = self.root / "blocked-unpacker"
        ready = self.root / "tool-ready"
        tool.write_text(
            "#!/usr/bin/python3\nimport os, signal\n"
            f"open({str(ready)!r},'w').write(str(os.getpid()))\n"
            "signal.pause()\n"
        )
        tool.chmod(0o700)
        self.runtime = replace(
            self.runtime, unpacker=BinaryPin(tool, hashlib.sha256(tool.read_bytes()).hexdigest())
        )
        work, _ = await self.crashed_worker(preparation_only=True, blocked_unpack=True)
        pid = int(ready.read_text())
        try:
            self.assertTrue(Path(f"/proc/{pid}").exists())
            with self.assertRaisesRegex(Refused, "oci_recovery_required"):
                await recover(self.runtime)
            self.assertTrue(work.exists())
            self.assertTrue(Path(f"/proc/{pid}").exists())
        finally:
            # This fixture created and observed this exact external group. The
            # product does not guess a PID from incomplete preparation state.
            os.killpg(os.getpgid(pid), signal.SIGKILL)
            await self.assert_reaped([pid])

    async def test_nonempty_unmarked_job_tree_is_never_deleted_by_its_name_alone(self):
        work = self.workspace / ("job-" + "a" * 32)
        work.mkdir(mode=0o700)
        (work / "keep").write_bytes(b"public-marker")
        with self.assertRaisesRegex(Refused, "oci_recovery_required"):
            await recover(self.runtime)
        self.assertEqual((work / "keep").read_bytes(), b"public-marker")

    async def test_a_live_launcher_before_state_creation_is_retained_after_worker_sigkill(self):
        launcher = self.root / "delayed-runc"
        ready, gate = self.root / "launcher-ready", self.root / "allow-launch"
        executable = str(self.runtime.engine.path)
        launcher.write_text(
            "#!/usr/bin/python3\nimport os, sys, time\n"
            "if 'run' in sys.argv[1:]:\n"
            f" open({str(ready)!r},'w').write(str(os.getpid()))\n"
            f" while not os.path.exists({str(gate)!r}): time.sleep(0.01)\n"
            f"os.execv({executable!r},[{executable!r},*sys.argv[1:]])\n"
        )
        launcher.chmod(0o700)
        self.runtime = replace(
            self.runtime,
            engine=BinaryPin(launcher, hashlib.sha256(launcher.read_bytes()).hexdigest()),
        )
        work, _ = await self.crashed_worker(blocked_launch=True)
        pid = int(ready.read_text())
        try:
            self.assertTrue(Path(f"/proc/{pid}").exists())
            self.assertEqual(list((work / "state").iterdir()), [])
            self.assertIsNotNone(json.loads((work / "run.json").read_bytes())["container"])
            for absent in (False, True):
                with self.subTest(state_absent=absent):
                    if absent:
                        (work / "state").rmdir()
                    with self.assertRaisesRegex(Refused, "oci_recovery_required"):
                        await recover(self.runtime)
                    self.assertTrue((work / "bundle/config.json").exists())
                    self.assertTrue(Path(f"/proc/{pid}").exists())
        finally:
            # Only this fixture knows the paused, newly created process group.
            os.killpg(os.getpgid(pid), signal.SIGKILL)
            await self.assert_reaped([pid])

    async def test_changed_engine_binding_retains_uncertain_state(self):
        work, pids = await self.crashed_worker()
        marker = work / "run.json"
        original = marker.read_bytes()
        document = json.loads(original)
        document["engine"]["sha256"] = "0" * 64
        marker.write_text(json.dumps(document))
        try:
            with self.assertRaisesRegex(Refused, "oci_recovery_required"):
                await recover(self.runtime)
            self.assertTrue((work / "bundle/config.json").exists())
            self.assertTrue(any((work / "state").iterdir()))
        finally:
            if marker.exists():
                marker.write_bytes(original)
            await recover(self.runtime)
            await self.assert_reaped(pids)

    async def test_unknown_workspace_entry_is_never_deleted(self):
        marker = self.workspace / "operator-file"
        marker.write_bytes(b"must-survive")
        with self.assertRaisesRegex(Refused, "oci_recovery_required"):
            await recover(self.runtime)
        self.assertEqual(marker.read_bytes(), b"must-survive")

    async def test_a_symlink_job_directory_never_traverses_an_external_tree(self):
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        (outside / "keep").write_bytes(b"public-marker")
        (self.workspace / ("job-" + "a" * 32)).symlink_to(outside)
        with self.assertRaises(Refused):
            await recover(self.runtime)
        self.assertEqual((outside / "keep").read_bytes(), b"public-marker")


if __name__ == "__main__":
    unittest.main()
