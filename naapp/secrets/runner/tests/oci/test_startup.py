"""Real run-command startup recovers before its first outbound connection."""

import asyncio
import os
import shutil
import signal
import sys
import time
import unittest
from contextlib import asynccontextmanager

import test_operator
import test_recovery
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from aweb_secrets_runner.errors import Refused
from aweb_secrets_runner.journal import Journal
from aweb_secrets_runner.oci_recovery import recover
from aweb_secrets_runner.oci_workspace import workspace_lock, write_marker
from aweb_secrets_runner.protocol import canonical, public_did
from aweb_secrets_runner.state import Identity, IdentityStore


@unittest.skipUnless(os.environ.get("AWEB_SECRETS_OCI_PROOF") == "1", "explicit Linux OCI proof")
class StartupTests(unittest.IsolatedAsyncioTestCase):
    command = test_operator.OperatorTests.command
    inputs = test_operator.OperatorTests.inputs
    config = test_operator.OperatorTests.config
    credential = test_operator.OperatorTests.credential
    configured = test_operator.OperatorTests.configured
    crashed_worker = test_recovery.RecoveryTests.crashed_worker
    observe_container = test_recovery.RecoveryTests.observe_container
    assert_reaped = test_recovery.RecoveryTests.assert_reaped

    def setUp(self):
        test_operator.OperatorTests.setUp(self)

    def saved(self, origin):
        _, body = self.configured()
        state = self.root / "identity"
        identity = Identity(
            origin=origin,
            runner_id=body["runner_ids"][0],
            service_kid=public_did(Ed25519PrivateKey.generate().public_key()),
            signing_key=Ed25519PrivateKey.generate(),
            encryption_key=X25519PrivateKey.generate(),
        )
        store = IdentityStore(state)
        with store.registration_lock():
            store.save(identity)
        journal = Journal(state / "journal.sqlite3")
        dispatch = "dsp_" + "a" * 22
        journal.accept(dispatch, expires_at=time.time() + 300)
        report = canonical(
            {
                "exit_code": 0,
                "stdout": "",
                "stderr": "",
                "truncated": False,
                "result_withheld": False,
                "redaction_count": 0,
            }
        )
        journal.save_result(dispatch, report)
        return state, journal, report

    def leftover(self, *, prepared=True, container=None, stopped=False):
        work = self.workspace / ("job-" + "b" * 32)
        work.mkdir(mode=0o700)
        (work / "state").mkdir(mode=0o700)
        (work / "bundle").mkdir(mode=0o700)
        path = work / "bundle/config.json"
        path.write_bytes(b'{"synthetic-sensitive-config":true}')
        path.chmod(0o600)
        fd = os.open(work, os.O_RDONLY | os.O_DIRECTORY)
        try:
            write_marker(
                fd,
                engine=self.runtime.engine.check(),
                sha256=self.runtime.engine.sha256,
                prepared=prepared,
                container=container,
                stopped=stopped,
            )
        finally:
            os.close(fd)
        return work

    @asynccontextmanager
    async def contact(self):
        # A real TCP observer at the HTTPS origin: observing connection is enough
        # to detect forbidden pre-recovery service contact. It never completes a
        # TLS handshake or receives an authenticated application request.
        event = asyncio.Event()
        observations = []
        writers = []

        def connected(reader, writer):
            writers.append(writer)
            observations.append(tuple(entry.name for entry in self.workspace.iterdir()))
            event.set()

        server = await asyncio.start_server(connected, "127.0.0.1", 0)
        origin = "https://127.0.0.1:" + str(server.sockets[0].getsockname()[1])
        try:
            yield origin, event, observations
        finally:
            server.close()
            for writer in writers:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionError, OSError):
                    pass
            await server.wait_closed()

    async def launch(self, state):
        return await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "aweb_secrets_runner",
            "run",
            "--config",
            str(self.root / "runner.json"),
            "--state-dir",
            str(state),
            env={"PYTHONPATH": os.environ["PYTHONPATH"]},
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    async def stop(self, child):
        if child.returncode is None:
            child.send_signal(signal.SIGTERM)
        try:
            async with asyncio.timeout(3):
                return await child.communicate()
        finally:
            if child.returncode is None:
                child.kill()
                await child.communicate()

    async def test_stopped_state_is_removed_before_saved_report_contact_and_survives_restart(self):
        async with self.contact() as (origin, contacted, observations):
            state, journal, report = self.saved(origin)
            for container in (None, "job-" + "c" * 32):
                work = self.leftover(container=container, stopped=container is not None)
                child = await self.launch(state)
                try:
                    async with asyncio.timeout(3):
                        await contacted.wait()
                    self.assertEqual(observations[-1], ())
                    self.assertFalse(work.exists())
                finally:
                    output = await self.stop(child)
                self.assertEqual(child.returncode, 143)
                self.assertEqual(output, (b"", b""))
                self.assertEqual(Journal(journal.path).pending_results()[0].body, report)
                contacted.clear()
                # Recovery neither acks/rearms nor deletes the original receipt.
                with self.assertRaisesRegex(Refused, "assignment_replayed"):
                    journal.accept("dsp_" + "a" * 22, expires_at=time.time() + 300)

    async def test_uncertain_state_refuses_before_any_service_contact_or_journal_change(self):
        async with self.contact() as (origin, contacted, observations):
            state, journal, report = self.saved(origin)
            for prepared, container in ((False, None), (True, "job-" + "c" * 32)):
                work = self.leftover(prepared=prepared, container=container)
                child = await self.launch(state)
                try:
                    async with asyncio.timeout(3):
                        stdout, stderr = await child.communicate()
                    self.assertEqual(child.returncode, 1)
                    self.assertEqual((stdout, stderr), (b"", b"oci_recovery_required\n"))
                    self.assertFalse(contacted.is_set())
                    self.assertEqual(observations, [])
                    self.assertTrue((work / "bundle/config.json").exists())
                    self.assertEqual(Journal(journal.path).pending_results()[0].body, report)
                finally:
                    await self.stop(child)
                    # Test teardown owns these never-launched synthetic trees.
                    shutil.rmtree(work)

    async def test_active_workspace_refuses_before_service_contact(self):
        async with self.contact() as (origin, contacted, _):
            state, _, _ = self.saved(origin)
            with workspace_lock(self.workspace):
                child = await self.launch(state)
                try:
                    async with asyncio.timeout(3):
                        stdout, stderr = await child.communicate()
                    self.assertEqual(child.returncode, 1)
                    self.assertEqual((stdout, stderr), (b"", b"runner_busy\n"))
                    self.assertFalse(contacted.is_set())
                finally:
                    await self.stop(child)

    async def test_real_crashed_container_is_stopped_before_contact_without_reexecution(self):
        work, pids = await self.crashed_worker()
        try:
            async with self.contact() as (origin, contacted, observations):
                state, journal, report = self.saved(origin)
                child = await self.launch(state)
                try:
                    async with asyncio.timeout(5):
                        await contacted.wait()
                    self.assertEqual(observations[-1], ())
                    self.assertFalse(work.exists())
                    await self.assert_reaped(pids)
                    self.assertEqual(Journal(journal.path).pending_results()[0].body, report)
                finally:
                    output = await self.stop(child)
                self.assertEqual(child.returncode, 143)
                self.assertEqual(output, (b"", b""))
        finally:
            if work.exists():
                await recover(self.runtime)


if __name__ == "__main__":
    unittest.main()
