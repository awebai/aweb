"""Optional host observations cannot consume the primary verdict or archive."""

import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from vm_gate.errors import Infrastructure
from vm_gate.executor import Executor

SHA = "a" * 40


class ObservationTransport:
    def __init__(self, problem, *, bad_hash=False, primary=7):
        self.problem = problem
        self.bad_hash = bad_hash
        self.primary = primary
        self.observations = []
        self.downloaded = False
        data = b"unit\tFAILED\tunit.log\t1s\t900s\n"
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            member = tarfile.TarInfo(f"tmp/aweb-candidate-gate-{SHA}/summary.tsv")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        self.archive = stream.getvalue()

    def run(self, command, *, timeout, check):
        if "host_metrics.py" in command:
            self.observations.append((command, timeout, check))
            if self.problem == "transport":
                raise Infrastructure("SSH observation timed out")
            if self.problem == "collector":
                return SimpleNamespace(
                    returncode=1,
                    stdout="",
                    stderr="IsADirectoryError: metrics output\n",
                )
        if command == "cat /var/log/vm-gate/supervisor-receipt.json":
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps({"raw_exit": self.primary, "grace_expired": False}),
                stderr="",
            )
        if command.startswith("cat "):
            return SimpleNamespace(returncode=0, stdout="7\n", stderr="")
        if command.startswith("sha256sum "):
            digest = (
                "0" * 64 if self.bad_hash else hashlib.sha256(self.archive).hexdigest()
            )
            return SimpleNamespace(
                returncode=0, stdout=digest + "  evidence.tar.gz\n", stderr=""
            )
        if "bash /opt/vm-gate/launch.sh" in command:
            return SimpleNamespace(returncode=self.primary, stdout="", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def copy(self, source, target, *, timeout, download):
        if not download:
            raise AssertionError("control must exercise archive download")
        Path(target).write_bytes(self.archive)
        self.downloaded = True


class ExecutorMetricsTests(unittest.TestCase):
    def executor(self, directory, problem, **kwargs):
        executor = Executor(
            {"ledger": "/tmp/fixture/ledger", "owner": "fixture"},
            directory,
            {"sha": SHA},
            "exit 7",
            None,
        )
        executor.transport = ObservationTransport(problem, **kwargs)
        return executor

    def test_observation_failures_leave_primary_and_archive_reachable(self):
        for problem in ("collector", "transport", "local_io"):
            with self.subTest(problem=problem), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                if problem == "local_io":
                    for phase in ("before", "after"):
                        (directory / f"host-metrics-{phase}-observation.json").mkdir()
                executor = self.executor(directory, problem)
                self.assertEqual(executor.execute({}, 30), 7)
                result = executor.collect({}, 30)
                self.assertTrue(executor.transport.downloaded)
                self.assertEqual(result["stages"][0]["status"], "FAILED")
                self.assertEqual(
                    result["archive_sha256"],
                    hashlib.sha256(executor.transport.archive).hexdigest(),
                )
                self.assertEqual(len(executor.transport.observations), 2)
                for command, timeout, check in executor.transport.observations:
                    self.assertIn("timeout --signal=TERM --kill-after=1s 3s", command)
                    self.assertLessEqual(timeout, 5)
                    self.assertFalse(check)
                if problem != "local_io":
                    for phase in ("before", "after"):
                        observation = json.loads(
                            (
                                directory / f"host-metrics-{phase}-observation.json"
                            ).read_text()
                        )
                        self.assertNotEqual(observation["status"], "collected")
                        if problem == "collector":
                            self.assertIn("IsADirectoryError", observation["stderr"])
                        else:
                            self.assertEqual(observation["error"], "Infrastructure")

    def test_actual_execution_and_archive_errors_still_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            executor = self.executor(Path(tmp), "collector", primary=255)
            with self.assertRaisesRegex(Infrastructure, "SSH connection lost"):
                executor.execute({}, 30)
        with tempfile.TemporaryDirectory() as tmp:
            executor = self.executor(Path(tmp), "transport", bad_hash=True)
            with self.assertRaisesRegex(Infrastructure, "archive hash differs"):
                executor.collect({}, 30)


if __name__ == "__main__":
    unittest.main()
