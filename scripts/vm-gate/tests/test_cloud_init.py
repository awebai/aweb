import json
import base64
import time
from types import SimpleNamespace
from pathlib import Path
import subprocess
import tempfile
import unittest
from vm_gate.cloud_init import admit_status, observe_and_admit
from vm_gate.errors import Refused, Infrastructure
from vm_gate.native_executor import NativeARMExecutor
from vm_gate.cloud_init import MARKER

ALLOWED = ("WARNING", "explicitly reviewed harmless warning")


def status(**changes):
    return {"status": "done", "errors": [], "recoverable_errors": {}, **changes}


class CloudInit(unittest.TestCase):
    def test_done_clean(self):
        self.assertEqual(admit_status(status(), 0, 0, ()), [])

    def test_done_recoverable_exact_allowed(self):
        data = status(recoverable_errors={"WARNING": [ALLOWED[1]]})
        self.assertEqual(admit_status(data, 2, 2, {ALLOWED}), [ALLOWED])

    def test_unknown_recoverable_refuses_even_when_status_done(self):
        with self.assertRaises(Refused):
            admit_status(
                status(recoverable_errors={"WARNING": ["unknown warning"]}),
                2,
                2,
                {ALLOWED},
            )
        with self.assertRaises(Refused):
            admit_status(
                status(recoverable_errors={"WARNING": [ALLOWED[1] + " extra"]}),
                2,
                2,
                {ALLOWED},
            )

    def test_error_unfinished_malformed_and_unexplained_exit_refuse(self):
        for doc, code in [
            (status(status="error"), 1),
            (status(status="running"), 0),
            (status(errors=["critical"]), 0),
            (status(), 2),
            (status(recoverable_errors={"WARNING": 123}), 2),
        ]:
            with self.subTest(doc=doc, code=code), self.assertRaises(Refused):
                admit_status(doc, code, code, ())
        with self.assertRaises(Refused):
            admit_status(status(), 0, 1, ())

    def test_stage_errors_cannot_be_hidden_by_empty_aggregate(self):
        data = status(
            **{"modules-final": {"errors": ["hard failure"], "recoverable_errors": {}}}
        )
        with self.assertRaises(Refused):
            admit_status(data, 0, 0, ())

    def test_failure_diagnostics_are_retained_before_refusal(self):
        calls = []

        def run(args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(
                args,
                2,
                json.dumps(status(recoverable_errors={"WARNING": ["unknown"]}))
                if "--format" in args
                else "status: done\n",
                "",
            )

        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            log = root / "cloud.log"
            log.write_text("DEBUG ordinary\nWARNING unknown\n")
            with self.assertRaises(Refused):
                observe_and_admit(root / "evidence", run=run, warning_log=log)
            record = json.loads((root / "evidence/observation.json").read_text())
            self.assertEqual(record["wait_exit"], 2)
            self.assertEqual(record["status_exit"], 2)
            self.assertIn(
                "WARNING unknown", (root / "evidence/warnings.log").read_text()
            )
            self.assertTrue((root / "evidence/status.json").is_file())
            self.assertEqual(
                calls[1], ["cloud-init", "status", "--long", "--format", "json"]
            )

    def test_remote_refusal_exports_private_diagnostics_before_exception(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            bundle = {
                "status.json": json.dumps(
                    status(recoverable_errors={"WARNING": ["unknown"]})
                ),
                "warnings.log": "WARNING unknown\n",
                "observation.json": json.dumps(
                    {"admitted": False, "wait_exit": 2, "status_exit": 2}
                ),
            }
            remote = NativeARMExecutor(
                {}, root, {}, "make test-server-image-build", None
            )
            remote.deadline = time.monotonic() + 30
            output = (
                MARKER + base64.b64encode(json.dumps(bundle).encode()).decode() + "\n"
            )
            remote.transport = SimpleNamespace(
                run=lambda *args, **kwargs: subprocess.CompletedProcess(
                    [], 78, output, "refused"
                )
            )
            with self.assertRaises(Infrastructure):
                remote.run("probe", "directories")
            self.assertEqual(
                json.loads((root / "cloud-init/observation.json").read_text())[
                    "status_exit"
                ],
                2,
            )
            self.assertEqual(
                (root / "cloud-init/status.json").stat().st_mode & 0o777, 0o600
            )
            self.assertTrue((root / "directories.stdout").is_file())

    def test_embedded_cloud_probe_and_preparation_have_separate_checked_phases(self):
        remote = NativeARMExecutor(
            {}, Path("/unused"), {}, "make test-server-image-build", None
        )
        program = remote.directories_program()
        self.assertNotIn("apt-get", program)
        result = subprocess.run(
            ["bash", "-n"], input=program, text=True, capture_output=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
