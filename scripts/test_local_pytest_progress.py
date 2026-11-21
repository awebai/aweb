"""Actual pytest/xdist interruption through the local runner; no Docker services."""

from pathlib import Path
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET

from test_server_local import Suite

ROOT = Path(__file__).resolve().parents[1]
DRIVER = """
import os,signal,sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import test_server_local as local
for sig in (signal.SIGINT, signal.SIGTERM):
    signal.signal(sig, local.interrupted)
try:
    status = local.run_suites(suite=local.Suite(sys.argv[2]), workers=2,
        arguments=['-s'], environ=dict(os.environ))
except local.Interrupted as exc:
    status = 128 + exc.number
raise SystemExit(status)
"""


REPORT_ORDER = """
from pathlib import Path
import os
import time
import pytest

@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_logreport(report):
    controller = not os.environ.get('PYTEST_XDIST_WORKER')
    completed = report.nodeid.endswith('test_00_completed')
    if controller and completed and report.when == 'call' and Path('hold-report').exists():
        Path('report-held').touch()
        deadline = time.monotonic() + 15
        while not Path('release-report').exists():
            if time.monotonic() >= deadline:
                raise RuntimeError('controller report was not released')
            time.sleep(0.01)
    yield
    # The outer wrapper returns after every report consumer, including JUnit.
    if controller and completed and report.when == 'teardown':
        Path('controller-completed').touch()
"""


class LocalPytestProgress(unittest.TestCase):
    def start(self, *, suite: Suite, body: str, hold_completed_report: bool = False):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        reports = root / "reports"
        scripts = root / "scripts"
        scripts.mkdir()
        for name in (
            "test_server_local.py",
            "local_suite_slots.py",
            "local_pytest_progress.py",
        ):
            if (ROOT / "scripts" / name).exists():
                (scripts / name).write_bytes((ROOT / "scripts" / name).read_bytes())
        (root / "test_probe.py").write_text(body)
        (root / "conftest.py").write_text(REPORT_ORDER)
        if hold_completed_report:
            (root / "hold-report").touch()
        guard = f"{sys.executable} {ROOT / 'scripts/test-egress/native.py'} --"
        (root / "Makefile").write_text(
            "prepare-server-node:\n\t@true\n"
            + f"test-server:\n\t@{guard} {sys.executable} -m pytest -q -n 2 --dist loadscope test_probe.py\n"
            + f"test-awid:\n\t@{guard} {sys.executable} -m pytest -q test_probe.py\n"
        )
        env = dict(os.environ, LOCAL_TEST_REPORT_DIR=str(reports), PYTHONUNBUFFERED="1")
        for name in (
            "PYTEST_ADDOPTS",
            "PYTEST_PLUGINS",
            "PYTHONPATH",
            "PYTEST_XDIST_WORKER",
        ):
            env.pop(name, None)
        env["PRIVATE_TEST_SENTINEL"] = "private-value-must-not-enter-metadata"
        output = self.enterContext((root / "launcher.log").open("w"))
        child = subprocess.Popen(
            [sys.executable, "-c", DRIVER, str(scripts), suite.value],
            cwd=root,
            env=env,
            stdout=output,
            stderr=subprocess.STDOUT,
            text=True,
        )

        def cleanup():
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)

        self.addCleanup(cleanup)
        return child, root, reports / suite.value

    def await_file(self, child, root, name):
        deadline = time.monotonic() + 15
        while not (root / name).exists():
            if child.poll() is not None:
                self.fail((root / "launcher.log").read_text())
            if time.monotonic() >= deadline:
                self.fail(f"real pytest did not reach {name}")
            time.sleep(0.02)

    def await_call(self, child, root):
        self.await_file(child, root, "active")
        if (root / "hold-report").exists():
            self.await_file(child, root, "report-held")
            self.assertFalse((root / "controller-completed").exists())
            # Force worker execution ahead of controller report delivery, then
            # release that delivery. Worker progress alone cannot acknowledge JUnit.
            (root / "release-report").touch()
        self.await_file(child, root, "controller-completed")

    def test_interruption_retains_live_node_phase_and_pytest_junit(self):
        body = """
from pathlib import Path
import threading

def test_00_completed():
    assert 2 + 2 == 4

def test_10_wait():
    print('LIVE_NATIVE_OUTPUT', flush=True)
    Path('active').touch()
    threading.Event().wait()
"""
        for suite, number in (
            (Suite.SERVER, signal.SIGINT),
            (Suite.REGISTRY, signal.SIGTERM),
        ):
            with self.subTest(suite=suite, signal=number):
                child, root, report = self.start(
                    suite=suite, body=body, hold_completed_report=suite is Suite.SERVER
                )
                self.await_call(child, root)
                states = [
                    json.loads(p.read_text()) for p in report.glob("worker-*.json")
                ]
                current = [
                    s
                    for s in states
                    if s["nodeid"].endswith("test_10_wait") and s["phase"] == "call"
                ]
                live_log = (
                    (report / "pytest.log").read_text()
                    if (report / "pytest.log").exists()
                    else ""
                )
                child.send_signal(number)
                self.assertEqual(
                    child.wait(timeout=15),
                    128 + number,
                    (root / "launcher.log").read_text(),
                )
                self.assertEqual(
                    len(current), 1, "interrupted run has no worker node/phase identity"
                )
                self.assertIsInstance(current[0]["pid"], int)
                self.assertTrue(
                    live_log, "pytest output must be retained before interruption"
                )
                if suite is Suite.REGISTRY:
                    self.assertIn("LIVE_NATIVE_OUTPUT", live_log)
                cases = list(ET.parse(report / "cases.xml").iter("testcase"))
                self.assertTrue(
                    any(c.get("name") == "test_00_completed" for c in cases)
                )
                events = [
                    json.loads(line)
                    for line in (report / "progress.jsonl").read_text().splitlines()
                ]
                self.assertEqual(
                    {
                        e["phase"]
                        for e in events
                        if e["nodeid"].endswith("test_00_completed") and "duration" in e
                    },
                    {"setup", "call", "teardown"},
                )
                for state in states:
                    with self.assertRaises(ProcessLookupError):
                        os.kill(state["pid"], 0)
                self.assertNotIn(
                    "private-value-must-not-enter-metadata",
                    (report / "progress.jsonl").read_text(),
                )

    def test_normal_pass_and_failure_retain_native_results(self):
        for expression, expected in (("True", 0), ("False", 2)):
            with self.subTest(expression=expression):
                child, root, report = self.start(
                    suite=Suite.REGISTRY,
                    body=f"def test_result():\n    assert {expression}\n",
                )
                self.assertEqual(
                    child.wait(timeout=15),
                    expected,
                    (root / "launcher.log").read_text(),
                )
                cases = list(ET.parse(report / "cases.xml").iter("testcase"))
                self.assertEqual(len(cases), 1)
                self.assertEqual(
                    cases[0].find("failure") is not None, expression == "False"
                )
                self.assertIn("slowest durations", (report / "pytest.log").read_text())
                self.assertEqual(report.stat().st_mode & 0o777, 0o700)
                for file in report.iterdir():
                    if file.name != "cases.xml":
                        self.assertEqual(file.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
