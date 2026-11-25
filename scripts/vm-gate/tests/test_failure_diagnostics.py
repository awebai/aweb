"""Machine failure evidence is bound, bounded and cannot erase the verdict."""

import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from vm_gate.executor import Executor
from vm_gate.failure_diagnostics import capture, main

SHA = "a" * 40
RUN = "vm-fixture"


class FailureDiagnosticsTests(unittest.TestCase):
    def test_actual_root_journals_and_kernel_have_native_results(self):
        commands = []

        def runner(argv, **kwargs):
            commands.append((argv, kwargs))
            output = (
                json.dumps("/srv/docker root")
                if argv[:2] == ["docker", "info"]
                else "native diagnostic\n"
            )
            return subprocess.CompletedProcess(argv, 0, output, "")

        value = capture(source=SHA, run_id=RUN, phase="failure", runner=runner)
        self.assertEqual(
            (value["source"], value["run_id"], value["phase"]), (SHA, RUN, "failure")
        )
        self.assertEqual(value["docker_root"], "/srv/docker root")
        self.assertTrue(
            any(
                argv[:3] == ["df", "-P", "-B1"] and argv[-1] == "/srv/docker root"
                for argv, _ in commands
            )
        )
        self.assertTrue(any(argv[:2] == ["df", "-Pi"] for argv, _ in commands))
        self.assertTrue(
            any(
                "docker.service" in argv
                and "containerd.service" in argv
                and argv[0] == "journalctl"
                for argv, _ in commands
            )
        )
        self.assertTrue(any(argv[0] == "dmesg" for argv, _ in commands))
        for result in value["commands"]:
            self.assertEqual(result["exit"], 0)
            self.assertIn("started_utc", result)
            self.assertIn("wall_seconds", result)
        self.assertTrue(all(kwargs["timeout"] <= 2 for _, kwargs in commands))

    def test_timeouts_and_unresolved_root_stay_explicit(self):
        def runner(argv, **kwargs):
            raise subprocess.TimeoutExpired(
                argv,
                kwargs["timeout"],
                output=b"partial native\n",
                stderr=b"timeout evidence\n",
            )

        value = capture(source=SHA, run_id=RUN, phase="failure", runner=runner)
        self.assertIsNone(value["docker_root"])
        self.assertEqual(value["status"], "partial")
        self.assertTrue(all(row["timed_out"] for row in value["commands"]))
        self.assertTrue(all(row["exit"] is None for row in value["commands"]))
        self.assertFalse(any(row["argv"][0] == "df" for row in value["commands"]))

    def test_full_guest_disk_still_returns_evidence_to_pinned_caller(self):
        value = {"source": SHA, "run_id": RUN, "commands": [{"exit": 0}]}
        argv = [
            "failure_diagnostics",
            "--source",
            SHA,
            "--run-id",
            RUN,
            "--phase",
            "failure",
            "--output",
            "/owned/diagnostic.json",
        ]
        with (
            patch("sys.argv", argv),
            patch("vm_gate.failure_diagnostics.capture", return_value=value),
            patch.object(
                Path, "write_text", side_effect=OSError(28, "No space left on device")
            ),
            redirect_stdout(io.StringIO()) as stream,
        ):
            self.assertEqual(main(), 0)
        observed = json.loads(stream.getvalue())
        self.assertEqual(observed["commands"], value["commands"])
        self.assertEqual(observed["output_error"]["type"], "OSError")

    def test_diagnostic_transport_failure_preserves_primary_and_archive(self):
        from test_executor_metrics import ObservationTransport

        class BrokenDiagnosticTransport(ObservationTransport):
            def run(self, command, **kwargs):
                if "failure_diagnostics.py" in command:
                    raise subprocess.TimeoutExpired(command, kwargs["timeout"])
                return super().run(command, **kwargs)

        with tempfile.TemporaryDirectory() as tmp:
            executor = Executor(
                {"ledger": "/tmp/fixture/ledger", "owner": "fixture"},
                tmp,
                {"sha": SHA},
                "exit 7",
                None,
            )
            executor.transport = BrokenDiagnosticTransport(None)
            self.assertEqual(executor.execute(server={}, timeout=30), 7)
            value = executor.collect({}, 30)
            self.assertTrue(executor.transport.downloaded)
            self.assertEqual(value["stages"][0]["status"], "FAILED")
            for phase in ("before", "failure", "after"):
                record = json.loads(
                    (
                        Path(tmp) / f"machine-diagnostics-{phase}-observation.json"
                    ).read_text()
                )
                self.assertEqual(record["status"], "unavailable")

if __name__ == "__main__":
    unittest.main()
