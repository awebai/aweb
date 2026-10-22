"""Real credential-bearing OCI processes; worker activation remains separate."""

import asyncio
import json
import os
import pwd
import signal
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import test_prepare
import test_runtime
from aweb_secrets_values import encode_value
from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from aweb_secrets_runner.errors import Refused
from aweb_secrets_runner.jobs import CredentialInput, RunnerConfig, job_digest
from aweb_secrets_runner.oci_execution import execute_oci
from aweb_secrets_runner.protocol import canonical, encode64


@unittest.skipUnless(os.environ.get("AWEB_SECRETS_OCI_PROOF") == "1", "explicit Linux OCI proof")
class LifecycleTests(unittest.IsolatedAsyncioTestCase):
    command = test_runtime.RuntimeCapabilityTests.command
    inputs = test_prepare.PreparationTests.inputs

    def setUp(self):
        test_prepare.PreparationTests.setUp(self)

    def config(self, script, *, timeout=5, home="/pinned-home"):
        body = self.inputs(environment={"HOME": home, "PASSWORD": None}).definition
        body["argv"] = ["/bin/busybox", "sh", "-c", script]
        body["timeout_s"] = timeout
        body["output"]["max_bytes"] = 1024
        path = self.root / "runner.json"
        path.write_bytes(
            canonical(
                {
                    "v": 1,
                    "agent_uids": [pwd.getpwnam("nobody").pw_uid],
                    "jobs": {"fixture": {"digest": job_digest(body), "definition": body}},
                }
            )
        )
        return RunnerConfig.load(path), body

    def credential(self, *, wrong_dispatch=False):
        key = X25519PrivateKey.generate()
        suite = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.CHACHA20_POLY1305)
        dispatch = "dsp_" + "a" * 22
        sealed = encode64(
            suite.encrypt(
                encode_value("basic", {"username": "", "password": "fixture-oci-password"}),
                key.public_key(),
                dispatch.encode(),
            )
        )
        return CredentialInput(
            "db", sealed, key, dispatch + "wrong" if wrong_dispatch else dispatch
        )

    async def run_job(self, config, body, *, credential=None, expires_at=None, started=None):
        return await execute_oci(
            self.runtime,
            config,
            job_id="fixture",
            digest=job_digest(body),
            runner_id=body["runner_ids"][0],
            params={},
            credentials=[self.credential() if credential is None else credential],
            expires_at=time.time() + 300 if expires_at is None else expires_at,
            started=started,
        )

    async def test_real_hpke_value_reaches_only_pinned_env_and_is_redacted(self):
        config, body = self.config('printf "%s\\n" "$PASSWORD"; printf "HOME=%s\\n" "$HOME"')
        report = await self.run_job(config, body)
        self.assertEqual(report["exit_code"], 0)
        self.assertNotIn("fixture-oci-password", json.dumps(report))
        self.assertIn("HOME=/pinned-home", report["stdout"])
        self.assertGreater(report["redaction_count"], 0)
        self.assertEqual(list(self.workspace.iterdir()), [])

    async def test_runtime_state_and_credential_bundle_stay_private_and_privileges_are_fixed(self):
        config, body = self.config("/bin/busybox sleep 0.1")
        observed = asyncio.Event()

        async def started(pid):
            (bundle,) = self.workspace.glob("job-*/bundle")
            spec = json.loads((bundle / "config.json").read_bytes())
            self.assertIn("PASSWORD=fixture-oci-password", spec["process"]["env"])
            self.assertTrue(spec["process"]["noNewPrivileges"])
            self.assertTrue(all(not value for value in spec["process"]["capabilities"].values()))
            self.assertEqual((bundle / "config.json").stat().st_mode & 0o777, 0o600)
            self.assertEqual(bundle.stat().st_mode & 0o777, 0o700)
            self.assertEqual((bundle.parent / "state").stat().st_mode & 0o777, 0o700)
            self.assertNotIn("fixture-oci-password", Path(f"/proc/{pid}/cmdline").read_text())
            self.assertNotIn("fixture-oci-password", Path(f"/proc/{pid}/environ").read_text())
            observed.set()

        report = await self.run_job(config, body, started=started)
        self.assertEqual(report["exit_code"], 0)
        self.assertTrue(observed.is_set())
        self.assertEqual(list(self.workspace.iterdir()), [])

    async def test_home_and_pin_checks_precede_real_hpke_failure(self):
        config, body = self.config("exit 0", home="")
        with self.assertRaisesRegex(Refused, "oci_environment_unsupported"):
            await self.run_job(config, body, credential=self.credential(wrong_dispatch=True))
        self.assertEqual(list(self.workspace.iterdir()), [])

    async def test_wrong_dispatch_authentication_failure_cleans_public_preparation(self):
        config, body = self.config("exit 0")
        with self.assertRaisesRegex(Refused, "credential_invalid"):
            await self.run_job(config, body, credential=self.credential(wrong_dispatch=True))
        self.assertEqual(list(self.workspace.iterdir()), [])

    async def test_credential_config_write_error_is_a_value_free_execution_refusal(self):
        config, body = self.config("exit 0")
        original = os.open

        def fail_write(path, flags, *args, **kwargs):
            if str(path).endswith("/bundle/config.json") and flags & os.O_WRONLY:
                raise OSError("synthetic-private-diagnostic")
            return original(path, flags, *args, **kwargs)

        with patch.object(os, "open", fail_write):
            with self.assertRaisesRegex(Refused, "^oci_execution_failed$"):
                await self.run_job(config, body)
        self.assertEqual(list(self.workspace.iterdir()), [])

    async def test_config_change_during_real_unpacking_refuses_before_hpke(self):
        config, body = self.config("exit 0")
        original = asyncio.create_subprocess_exec
        changed = False

        async def change_after_unpack(*args, **kwargs):
            nonlocal changed
            process = await original(*args, **kwargs)
            if str(args[0]) == str(self.runtime.unpacker.path):
                await process.wait()
                path = self.root / "runner.json"
                document = json.loads(path.read_bytes())
                document["jobs"]["fixture"]["definition"]["timeout_s"] += 1
                path.write_bytes(canonical(document))
                changed = True
            return process

        # Observe the real umoci subprocess at the stdlib return boundary;
        # neither the runtime preparation nor the config checker is replaced.
        with patch.object(asyncio, "create_subprocess_exec", change_after_unpack):
            with self.assertRaisesRegex(Refused, "config_changed"):
                await self.run_job(config, body, credential=self.credential(wrong_dispatch=True))
        self.assertTrue(changed)
        self.assertEqual(list(self.workspace.iterdir()), [])

    async def test_actual_oci_output_uses_the_shared_bound_and_utf8_refusal(self):
        config, body = self.config("/bin/busybox head -c 3000 /dev/zero | /bin/busybox tr '\\0' x")
        report = await self.run_job(config, body)
        self.assertEqual(report["exit_code"], 0)
        self.assertTrue(report["truncated"])
        self.assertLessEqual(len(report["stdout"].encode()) + len(report["stderr"].encode()), 1024)
        config, body = self.config("/bin/busybox printf '\\377'")
        report = await self.run_job(config, body)
        self.assertEqual(report["exit_code"], 0)
        self.assertTrue(report["result_withheld"])
        self.assertEqual(report["stdout"], "")
        self.assertEqual(report["stderr"], "")
        self.assertEqual(list(self.workspace.iterdir()), [])

    async def test_expired_after_preparation_refuses_without_spawning(self):
        config, body = self.config("exit 0")
        with self.assertRaisesRegex(Refused, "assignment_expired"):
            await self.run_job(config, body, expires_at=time.time() - 1)
        self.assertEqual(list(self.workspace.iterdir()), [])

    async def test_expiry_after_opening_is_rechecked_before_runtime_spawn(self):
        config, body = self.config("exit 0")
        reads = []

        def clock():
            reads.append(None)
            return 499 if len(reads) == 1 else 501

        # Gate the stdlib clock, retaining real preparation, HPKE and runtime.
        with patch.object(time, "time", clock):
            with self.assertRaisesRegex(Refused, "assignment_expired"):
                await self.run_job(config, body, expires_at=500)
        self.assertGreaterEqual(len(reads), 2)
        self.assertEqual(list(self.workspace.iterdir()), [])

    async def observe_container(self, ready, pids):
        async with asyncio.timeout(3):
            while True:
                for path in self.workspace.glob("job-*/state/*/state.json"):
                    try:
                        pid = json.loads(path.read_bytes())["init_process_pid"]
                        children = Path(f"/proc/{pid}/task/{pid}/children").read_text().split()
                    except (FileNotFoundError, json.JSONDecodeError):
                        continue
                    if children:
                        pids.extend([pid, *(int(child) for child in children)])
                        ready.set()
                        return
                await asyncio.sleep(0.01)

    async def assert_reaped(self, pids):
        self.assertTrue(pids)
        async with asyncio.timeout(3):
            while any(Path(f"/proc/{pid}").exists() for pid in pids):
                await asyncio.sleep(0.01)

    async def test_timeout_stops_all_container_processes_and_cleans_both_state_roots(self):
        config, body = self.config("/bin/busybox sleep 30 & wait", timeout=1)
        ready, pids = asyncio.Event(), []

        async def started(pid):
            await self.observe_container(ready, pids)

        async with asyncio.timeout(3):
            report = await self.run_job(config, body, started=started)
        self.assertEqual(report["exit_code"], -signal.SIGKILL)
        self.assertTrue(ready.is_set())
        await self.assert_reaped(pids)
        self.assertEqual(list(self.workspace.iterdir()), [])

    async def test_cancel_stops_and_reaps_container_before_private_cleanup(self):
        config, body = self.config("/bin/busybox sleep 30 & wait")
        ready = asyncio.Event()
        pids = []

        async def started(pid):
            await self.observe_container(ready, pids)

        task = asyncio.create_task(self.run_job(config, body, started=started))
        try:
            async with asyncio.timeout(3):
                await ready.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            await self.assert_reaped(pids)
            self.assertEqual(list(self.workspace.iterdir()), [])
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def test_start_failure_is_distinct_from_preparation_and_cleans(self):
        config, body = self.config("exit 0")
        body["argv"] = ["/not-present"]
        path = self.root / "runner.json"
        document = json.loads(path.read_bytes())
        document["jobs"]["fixture"] = {"definition": body, "digest": job_digest(body)}
        path.write_bytes(canonical(document))
        with self.assertRaisesRegex(Refused, "job_start_failed"):
            await self.run_job(RunnerConfig.load(path), body)
        self.assertEqual(list(self.workspace.iterdir()), [])

    async def test_a_real_job_exit_one_remains_a_result(self):
        config, body = self.config("exit 1")
        report = await self.run_job(config, body)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(list(self.workspace.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
