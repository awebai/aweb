"""Real process-group termination, bounded escalation and collection ordering."""

import json
import os
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import test_lifecycle
from vm_gate import supervisor
from vm_gate.executor import Executor


class SupervisorTests(unittest.TestCase):
    def invoke(self, body, *, stop=False, grace=0.5):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        command = [
            sys.executable,
            "-m",
            "vm_gate.supervisor",
            "run",
            str(root),
            str(grace),
            "bash",
            "-c",
            body,
        ]
        child = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        try:
            if stop:
                deadline = time.monotonic() + 5
                while (
                    not (root / "ready").exists()
                    and child.poll() is None
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.01)
                self.assertTrue((root / "ready").exists())
                child.send_signal(signal.SIGTERM)
            stdout, stderr = child.communicate(timeout=5)
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate()
        receipt = json.loads((root / "supervisor-receipt.json").read_text())
        return child.returncode, receipt, root, stdout + stderr

    def test_normal_exit_is_preserved(self):
        code, receipt, _, output = self.invoke("exit 7")
        self.assertEqual(code, 7, output)
        self.assertEqual(receipt["child_exit"], 7)
        self.assertFalse(receipt["interrupted"])

    def test_term_allows_finalizer_before_completion_receipt(self):
        code, receipt, root, output = self.invoke(
            "trap 'echo finalized > \"$PWD/finalized\"; exit 143' TERM; touch ready; sleep 30",
            stop=True,
        )
        self.assertEqual(code, 143, output)
        self.assertTrue((root / "finalized").exists())
        self.assertEqual(receipt["signal"], signal.SIGTERM)
        self.assertFalse(receipt["grace_expired"])
        self.assertTrue(receipt["group_settled"])
        self.assertEqual((root / "gate-exit").read_text().strip(), "143")

    def test_interrupted_process_exit_does_not_attest_gate_cleanup(self):
        code, receipt, _, output = self.invoke(
            "trap 'exit 143' TERM; touch ready; sleep 30", stop=True
        )
        self.assertEqual(code, 143, output)
        self.assertTrue(receipt["group_settled"])
        self.assertFalse(receipt["finalized"])

    def test_gate_cleanup_receipt_is_required_and_bound_to_run(self):
        scripts = Path(__file__).resolve().parents[2]

        def write(
            root,
            *,
            cleanup_status=0,
            receipt_run="this-run",
            cleanup="passed",
            writer_exit=0,
        ):
            # The gate's own writers produce both files the receipt is read from.
            subprocess.run(
                [
                    "bash",
                    "-c",
                    'source "$1/candidate-cleanup.sh"; source "$1/candidate-record.sh"; '
                    'write_cleanup_verdict "$2" >/dev/null 2>&1; '
                    'run_id="$3" candidate_writer_status="$5" '
                    'write_candidate_interruption 143 "$4"',
                    "receipt",
                    str(scripts),
                    str(cleanup_status),
                    receipt_run,
                    cleanup,
                    str(writer_exit),
                ],
                env=dict(os.environ, LOG_DIR=str(root)),
                check=True,
            )

        def status(registry):
            return supervisor.cleanup_receipts(registry, True)[0]["status"]

        cases = {
            "passed": ({}, "passed"),
            "wrong run in receipt": ({"receipt_run": "other-run"}, "absent"),
            "cleanup failed": ({"cleanup_status": 1, "cleanup": "failed"}, "absent"),
            # The interruption receipt is checked on its own, not through the verdict.
            "interrupted cleanup failed": ({"cleanup": "failed"}, "absent"),
            "writer failed": ({"writer_exit": 1}, "absent"),
        }
        for name, (fields, expected) in cases.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                registry = root / "registry"
                registry.write_text("this-run\t" + str(root) + "\n")
                (root / "summary.tsv").write_text("")
                write(root, **fields)
                # The directory must belong to this run before any receipt counts.
                (root / "run-id").write_text("other-run\n")
                self.assertEqual(status(registry), "absent")
                (root / "run-id").write_text("this-run\n")
                self.assertEqual(status(registry), expected)

    def test_signal_resistant_group_is_killed_within_grace(self):
        started = time.monotonic()
        code, receipt, _, output = self.invoke(
            "trap '' TERM; touch ready; while :; do sleep 30; done",
            stop=True,
            grace=0.15,
        )
        self.assertEqual(code, 143, output)
        self.assertTrue(receipt["grace_expired"])
        self.assertEqual(receipt["child_exit"], -signal.SIGKILL)
        self.assertLess(time.monotonic() - started, 4)

    def test_stop_identity_refuses_reused_pid(self):
        with self.assertRaisesRegex(ValueError, "PID identity changed"):
            supervisor.validate_identity(
                {"pid": os.getpid(), "uid": 1000, "start_ticks": "wrong"}, "/unrelated"
            )

    def test_timeout_is_inside_runuser_and_has_grace(self):
        class Transport:
            def __init__(self):
                self.commands = []

            def run(self, command, **kwargs):
                self.commands.append(command)
                return subprocess.CompletedProcess(
                    [],
                    0,
                    json.dumps({"grace_expired": False, "raw_exit": 7})
                    if "cat /var/log/vm-gate/supervisor" in command
                    else "7\n"
                    if command.startswith("cat ")
                    else "",
                    "",
                )

        with tempfile.TemporaryDirectory() as temporary:
            remote = Executor(
                {"ledger": "/ledger/rows", "owner": "operator"},
                temporary,
                {"sha": "a" * 40},
                "exit 7",
                None,
            )
            remote.transport = Transport()
            self.assertEqual(remote.execute(server={}, timeout=60), 7)
            command = next(
                c for c in remote.transport.commands if "vm_gate.supervisor run" in c
            )
            argv = shlex.split(command)
            # The gate user's process runs under the timeout, and the timeout
            # leaves the supervisor its kill grace before SIGKILL.
            user = argv.index("runuser")
            self.assertEqual(argv[user : user + 4], ["runuser", "-u", "gateuser", "--"])
            limit = argv.index("timeout")
            self.assertGreater(limit, user)
            self.assertEqual(
                argv[limit : limit + 8],
                [
                    "timeout",
                    "--signal=TERM",
                    f"--kill-after={supervisor.TIMEOUT_KILL_GRACE}s",
                    "60",
                    "python3",
                    "-m",
                    "vm_gate.supervisor",
                    "run",
                ],
            )
            self.assertGreater(supervisor.TIMEOUT_KILL_GRACE, supervisor.GRACE)


class StopOrderingTests(unittest.TestCase):
    def test_operator_interrupt_stops_before_collect_and_delete(self):
        events = []

        class Interrupted(test_lifecycle.Remote):
            def execute(self, server, timeout):
                raise KeyboardInterrupt

            def stop(self, server, timeout):
                events.append("stop")
                return {"finalized": False, "reason": "no receipt before bounded grace"}

            def collect(self, server, timeout):
                events.append("collect")
                return super().collect(server, timeout)

        fixture = test_lifecycle.LifecycleTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        result = fixture.run_session(Interrupted())
        self.assertEqual(events, ["stop", "collect"])
        self.assertFalse(result["remote_stop"]["finalized"])
        self.assertTrue(result["partial_evidence"])
        self.assertNotEqual(result["exit"], 0)
        self.assertEqual(fixture.backend.items, [])
