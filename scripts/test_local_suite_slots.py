"""Real process/lock controls; service boundaries are held without starting Docker."""

from pathlib import Path
import os
import json
import queue
import signal
import subprocess
import sys
import tempfile
import threading
import unittest

from local_suite_slots import Scope, SuiteLabel, pytest_scope, slot_file
from test_server_local import DATABASE_URLS

ROOT = Path(__file__).resolve().parents[1]
DRIVER = r"""
import importlib.util, os, sys
from contextlib import contextmanager
from pathlib import Path
sys.path.insert(0, str(Path.cwd() / "scripts"))
if importlib.util.find_spec("local_suite_slots") is not None:
    import local_suite_slots
    local_suite_slots.SLOT_DIRECTORY = Path(sys.argv[1])
os.umask(0o077)
runner = sys.argv[2]
if runner in ("slot-whole", "slot-focused"):
    scope = local_suite_slots.Scope(runner.removeprefix("slot-"))
    with local_suite_slots.suite_slot(
        scope=scope, label=local_suite_slots.SuiteLabel.SERVER, root=Path.cwd(),
    ):
        print("ACTIVE", flush=True)
        raise SystemExit(int(sys.stdin.readline()))
if runner == "portable":
    import runpy
    path = Path.cwd() / "scripts/test-egress/docker.py"
    evidence = Path(sys.argv[1]).parent
    sys.argv = [str(path), "--evidence", str(evidence)]
    runpy.run_path(str(path), run_name="__main__")
import test_server_local as local
if runner == "server":
    @contextmanager
    def services(**kwargs):
        print("ACTIVE", flush=True)
        try:
            yield kwargs["environ"]
        finally:
            print("CLEANUP", flush=True)
    def suites(**kwargs):
        return int(sys.stdin.readline())
    local.local_services = services
    local.run_suites = suites
    raise SystemExit(local.main())
import test_user_paths_local as paths
def admission():
    print("ACTIVE", flush=True)
    sys.stdin.readline()
    raise SystemExit(0)
paths.check_docker = admission
raise SystemExit(paths.main())
"""


class SlotProcesses(unittest.TestCase):
    def setUp(self):
        self.directory = (
            Path(self.enterContext(tempfile.TemporaryDirectory())) / "slots"
        )

    def start(self, *, runner=SuiteLabel.SERVER, selection="", slot_count=None):
        env = dict(
            os.environ,
            LOCAL_PYTEST_ARGS=selection,
            OATS_INSTANCE="slot-control",
            LOCAL_TEST_SUITE="server",
            LOCAL_TEST_WORKERS="4",
        )
        for key in (*DATABASE_URLS, "PGHOST", "PGPORT", "TEST_DB_HOST", "TEST_DB_PORT"):
            env.pop(key, None)
        env.pop("PYTEST_ADDOPTS", None)
        env.pop("AWEB_LOCAL_SUITE_SLOTS", None)
        if slot_count is not None:
            env["AWEB_LOCAL_SUITE_SLOTS"] = slot_count
        process = subprocess.Popen(
            [sys.executable, "-c", DRIVER, str(self.directory), str(runner)],
            cwd=ROOT,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        events = queue.Queue()

        def read():
            for line in process.stdout:
                events.put(line.rstrip())
            events.put("EOF")

        reader = threading.Thread(target=read)
        reader.start()

        def cleanup():
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            reader.join(timeout=5)
            self.assertFalse(reader.is_alive(), "child output reader did not finish")
            process.stdin.close()
            process.stdout.close()

        self.addCleanup(cleanup)
        return process, events

    def event(self, events):
        lines = []
        while True:
            line = events.get(timeout=10)
            lines.append(line)
            if line in ("ACTIVE", "EOF") or line.startswith(
                "Waiting for local suite slot"
            ):
                return line, lines

    def holders(self, *, runner=SuiteLabel.SERVER):
        holders = []
        for _ in range(3):
            process, events = self.start(runner=runner)
            self.assertEqual(self.event(events)[0], "ACTIVE")
            self.assertIsNone(process.poll())
            holders.append((process, events))
        return holders

    def release(self, process):
        process.stdin.write("0\n")
        process.stdin.flush()
        self.assertEqual(process.wait(timeout=5), 0)

    def test_fourth_cross_runner_waits_until_holder_finishes(self):
        holders = self.holders()
        fourth, events = self.start(runner=SuiteLabel.USER_PATHS)
        line, trace = self.event(events)
        self.assertTrue(line.startswith("Waiting for local suite slot"), trace)
        for holder, _ in holders:
            self.assertIn(str(holder.pid), line)
        self.assertIn("slot-control", line)
        self.assertEqual(self.directory.stat().st_mode & 0o777, 0o777)
        for path in self.directory.glob("slot-*.lock"):
            self.assertEqual(path.stat().st_mode & 0o777, 0o666)
            value = json.loads(path.read_text())
            self.assertEqual(value["repo"], "aweb")
            self.assertEqual(value["label"], "server")
            self.assertRegex(value["source_sha"], r"^[0-9a-f]{40}$")
            self.assertIn("+00:00", value["started_utc"])
        self.release(holders[2][0])
        self.assertEqual(self.event(events)[0], "ACTIVE")
        self.release(fourth)

    def test_focused_scope_waits_for_a_whole_slot(self):
        holders = self.holders(runner="slot-whole")
        focused, events = self.start(runner="slot-focused")
        line, trace = self.event(events)
        self.assertTrue(line.startswith("Waiting for local suite slot"), trace)
        self.assertIsNone(focused.poll())
        self.release(holders[0][0])
        line, trace = self.event(events)
        self.assertEqual(line, "ACTIVE", trace)
        self.assertTrue(any("acquired: server" in event for event in trace), trace)
        holder = json.loads((self.directory / "slot-0.lock").read_text())
        self.assertEqual(holder["label"], "server")
        self.assertEqual(holder["scope"], "focused")
        self.release(focused)

    @unittest.skipUnless(
        sys.platform == "darwin", "Portable slot admission is on macOS"
    )
    def test_portable_runner_waits_before_entering_its_run(self):
        holders = self.holders(runner="slot-whole")
        portable, events = self.start(runner="portable")
        line, trace = self.event(events)
        self.assertTrue(line.startswith("Waiting for local suite slot"), trace)
        self.assertIsNone(portable.poll())
        self.release(holders[0][0])
        line, trace = self.event(events)
        self.assertEqual(line, "EOF", trace)
        # An existing evidence directory refuses before any Docker call.
        self.assertEqual(portable.wait(timeout=5), 1)
        acquired = next(
            i for i, event in enumerate(trace) if "acquired: portable" in event
        )
        released = next(
            i for i, event in enumerate(trace) if "released: portable" in event
        )
        refusal = next(i for i, event in enumerate(trace) if "FileExistsError" in event)
        self.assertLess(acquired, released)
        self.assertLess(released, refusal)

    def test_reporting_combinations_wait_when_all_slots_are_held(self):
        self.holders()
        for selection in (
            "--no-header --junitxml report.xml",
            "-vvvv --junitxml report.xml",
        ):
            with self.subTest(selection=selection):
                whole, events = self.start(selection=selection)
                event, trace = self.event(events)
                self.assertTrue(event.startswith("Waiting for local suite slot"), trace)
                whole.terminate()
                self.assertEqual(whole.wait(timeout=5), 143)

    def test_failure_releases_after_caller_cleanup(self):
        holders = self.holders()
        waiting, events = self.start()
        self.assertTrue(
            self.event(events)[0].startswith("Waiting for local suite slot")
        )
        holder, holder_events = holders[0]
        holder.stdin.write("42\n")
        holder.stdin.flush()
        self.assertEqual(holder.wait(timeout=5), 42)
        lines = []
        while True:
            line = holder_events.get(timeout=5)
            lines.append(line)
            if line == "EOF":
                break
        release = next(i for i, line in enumerate(lines) if "released:" in line)
        self.assertLess(lines.index("CLEANUP"), release)
        self.assertEqual(self.event(events)[0], "ACTIVE")
        self.release(waiting)

    def test_invalid_capacity_refuses_before_service_entry(self):
        for count in ("0", "-1", "not-a-count"):
            with self.subTest(count=count):
                child, events = self.start(slot_count=count)
                event, lines = self.event(events)
                self.assertEqual(event, "EOF")
                self.assertEqual(child.wait(timeout=5), 2)
                self.assertNotIn("ACTIVE", lines)
                self.assertIn("Set AWEB_LOCAL_SUITE_SLOTS", "\n".join(lines))
        self.assertFalse(self.directory.exists())

    def test_capacity_override_uses_same_persistent_files(self):
        holder, events = self.start(slot_count="1")
        self.assertEqual(self.event(events)[0], "ACTIVE")
        waiting, events = self.start(slot_count="1")
        self.assertTrue(
            self.event(events)[0].startswith("Waiting for local suite slot")
        )
        inode = (self.directory / "slot-0.lock").stat().st_ino
        self.release(holder)
        self.assertEqual(self.event(events)[0], "ACTIVE")
        self.assertEqual((self.directory / "slot-0.lock").stat().st_ino, inode)
        self.release(waiting)
        self.assertEqual(
            [path.name for path in self.directory.iterdir()], ["slot-0.lock"]
        )

    def test_interrupted_and_killed_holders_release_kernel_lock(self):
        holders = self.holders()
        holder = holders[0][0]
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGKILL):
            waiting, events = self.start()
            self.assertTrue(
                self.event(events)[0].startswith("Waiting for local suite slot")
            )
            holder.send_signal(number)
            expected = -signal.SIGKILL if number == signal.SIGKILL else 128 + number
            self.assertEqual(holder.wait(timeout=5), expected)
            self.assertEqual(self.event(events)[0], "ACTIVE")
            # Occupy that slot for the next iteration too.
            holder = waiting


class SelectionScope(unittest.TestCase):
    def test_slot_descriptor_is_not_inherited_across_exec(self):
        with tempfile.TemporaryDirectory() as directory:
            with slot_file(Path(directory) / "slot-0.lock") as stream:
                result = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        "import os,sys; "
                        "\ntry: os.fstat(int(sys.argv[1]))"
                        "\nexcept OSError: sys.exit(0)"
                        "\nsys.exit(1)",
                        str(stream.fileno()),
                    ],
                    close_fds=False,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(os.get_inheritable(stream.fileno()))

    def test_only_actual_selection_is_classified_as_focused(self):
        for arguments in (
            [],
            ["tests"],
            ["tests/", "-q"],
            ["./tests/.", "-q"],
            ["--", "tests"],
            [".", "--durations=0"],
            ["--junitxml", "tests/report.xml"],
            ["--no-header", "--junitxml", "report.xml"],
            ["-vvvv", "--junitxml", "report.xml"],
            ["--no-header", "--durations", "0", "--junitxml", "report.xml"],
            ["--junitxml=tests/report.xml"],
            ["-q", "--durations", "0"],
            ["-k", ""],
        ):
            with self.subTest(arguments=arguments):
                self.assertIs(pytest_scope(arguments), Scope.WHOLE)
        for arguments in (
            ["tests/test_mail.py"],
            ["--", "tests/test_mail.py"],
            ["--deselect=x"],
            ["-q", "tests/test_mail.py::test_send"],
            ["tests/messaging"],
            ["-k", "mail"],
            ["--no-header", "-k", "mail"],
            ["-vvvv", "--junitxml", "report.xml", "tests/test_mail.py"],
            ["-kmail"],
            ["-m", "native"],
            ["--deselect=tests/test_mail.py::test_send"],
        ):
            with self.subTest(arguments=arguments):
                self.assertIs(pytest_scope(arguments), Scope.FOCUSED)


if __name__ == "__main__":
    unittest.main()
