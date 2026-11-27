"""Explicit native acceptance: real DB use and cleanup after success/failure/signals.

Run directly with server/.venv/bin/python after local Docker execution is authorized.
This file is outside the ordinary no-services script discovery.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import test_server_local as local  # noqa: E402

# Set when run directly; discovery of the no-services controls skips this file.
RUN_DIRECTLY = False

DRIVER = """
import asyncio, os, signal, sys
sys.path.insert(0, "scripts")
import asyncpg
import test_server_local as local
for number in (signal.SIGINT, signal.SIGTERM):
    signal.signal(number, local.interrupted)
try:
    with local.local_services(workers=1, project=sys.argv[1], environ=dict(os.environ)) as env:
        async def query():
            connection = await asyncpg.connect(env["TEST_DATABASE_URL"])
            try:
                assert await connection.fetchval("SELECT 41 + 1") == 42
                await connection.execute("CREATE TABLE local_cleanup_witness (id integer)")
            finally:
                await connection.close()
        asyncio.run(query())
        print("NATIVE_DATABASE_READY", flush=True)
        if sys.argv[2] == "wait":
            local.invoke([sys.executable, "-c", "import time; time.sleep(300)"], timeout=None)
        else:
            raise SystemExit(int(sys.argv[2]))
except local.Interrupted as exc:
    raise SystemExit(128 + exc.number)
"""


class NativeLocalServices(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not RUN_DIRECTLY:
            raise unittest.SkipTest("explicit native acceptance: run this file directly")

    def test_disk_floor_refuses_before_creating_a_project(self):
        # Reach the guard even when whole-suite slots are occupied; no suite runs.
        env = dict(
            os.environ,
            AWEB_GATE_MIN_FREE_GB="1000000000",
            LOCAL_PYTEST_ARGS="tests/test_mail_send_retry.py",
        )
        for key in (
            *local.DATABASE_URLS,
            "PGHOST",
            "PGPORT",
            "TEST_DB_HOST",
            "TEST_DB_PORT",
        ):
            env.pop(key, None)
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/test_server_local.py")],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("docker system prune", result.stderr)
        self.assertIn("fstrim", result.stderr)
        self.assertNotIn("Local test project:", result.stdout)

    def test_real_database_cleanup_for_normal_failure_int_and_term(self):
        selected = local.check_docker()
        for outcome in (0, 42, signal.SIGINT, signal.SIGTERM):
            with (
                self.subTest(outcome=outcome),
                tempfile.TemporaryDirectory() as directory,
            ):
                project = "aw-local-proof-" + uuid.uuid4().hex[:12]
                path = Path(directory) / "run.log"
                expected = (
                    128 + int(outcome)
                    if isinstance(outcome, signal.Signals)
                    else outcome
                )
                argument = (
                    "wait" if isinstance(outcome, signal.Signals) else str(outcome)
                )
                with path.open("w") as output:
                    process = subprocess.Popen(
                        [sys.executable, "-c", DRIVER, project, argument],
                        cwd=ROOT,
                        stdout=output,
                        stderr=subprocess.STDOUT,
                    )
                    try:
                        deadline = time.monotonic() + 180
                        while "NATIVE_DATABASE_READY" not in path.read_text():
                            if (
                                process.poll() is not None
                                or time.monotonic() >= deadline
                            ):
                                self.fail(path.read_text())
                            time.sleep(0.1)
                        if isinstance(outcome, signal.Signals):
                            process.send_signal(outcome)
                        self.assertEqual(
                            process.wait(timeout=90), expected, path.read_text()
                        )
                        self.assertIn("Local project cleanup PASSED:", path.read_text())
                        with local.pinned_docker_environment(environ=selected):
                            local.assert_project_absent(project)
                    finally:
                        if process.poll() is None:
                            process.terminate()
                            process.wait(timeout=100)
                print(
                    f"Native {project}: database used, exit {expected}, containers/networks/volumes absent",
                    flush=True,
                )


if __name__ == "__main__":
    RUN_DIRECTLY = True
    unittest.main()
