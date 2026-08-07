#!/usr/bin/env python3
"""The AC pin adapter, against a real git repository.

Real clone, commit, push and read-back into a local bare remote - no network.
The point being proved is that AC's source pins actually move, since AC picks
up a published server or awid only when they do.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ADAPTER = REPO_ROOT / "scripts" / "pointer-adapter-ac-pin.py"

OLD_SHA = "1111111111111111111111111111111111111111"
NEW_SHA = "3f7a1c9e4b02d85617fa03cc9b1e4d7a5806e2f1"

PIN_TOML = f'''[aweb]
git_sha = "{OLD_SHA}"
'''

UV_LOCK = '''version = 1

[[package]]
name = "awid-service"
version = "0.5.14"

[[package]]
name = "something-else"
version = "1.0.0"
'''


def git(*args, cwd):
    subprocess.run(["git", *args], cwd=str(cwd), check=True,
                   capture_output=True, text=True)


class AcPinAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.remote = root / "remote.git"
        seed = root / "seed"
        (seed / "backend").mkdir(parents=True)
        (seed / "release-pin.toml").write_text(PIN_TOML)
        (seed / "backend" / "uv.lock").write_text(UV_LOCK)
        git("init", "-q", "-b", "main", cwd=seed)
        git("-c", "user.email=t@t", "-c", "user.name=t", "add", ".", cwd=seed)
        git("-c", "user.email=t@t", "-c", "user.name=t",
            "commit", "-qm", "seed", cwd=seed)
        git("init", "-q", "--bare", str(self.remote), cwd=root)
        git("remote", "add", "origin", str(self.remote), cwd=seed)
        git("push", "-q", "origin", "main", cwd=seed)
        self.addCleanup(self.tmp.cleanup)

    def run_adapter(self, operation, updates=None, expect_failure=False):
        command = [sys.executable, str(ADAPTER), operation, "--component", "ac-pin"]
        if updates is not None:
            command += ["--updates", json.dumps(updates)]
        env = {**os.environ, "AC_REMOTE": str(self.remote)}
        result = subprocess.run(command, capture_output=True, text=True, env=env)
        if expect_failure:
            self.assertNotEqual(result.returncode, 0)
            return result.stderr
        if result.returncode != 0:
            raise AssertionError(f"{operation} failed: {result.stderr}")
        return json.loads(result.stdout)

    def test_read_reports_both_pins(self):
        self.assertEqual(
            self.run_adapter("read")["advertised"],
            {"server": OLD_SHA, "awid-pypi": "0.5.14"},
        )

    def test_apply_moves_the_server_commit_pin(self):
        self.run_adapter("apply", {"server": NEW_SHA})
        self.assertEqual(self.run_adapter("read")["advertised"]["server"], NEW_SHA)

    def test_apply_moves_the_awid_lock_version(self):
        self.run_adapter("apply", {"awid-pypi": "0.5.15"})
        after = self.run_adapter("read")["advertised"]
        self.assertEqual(after["awid-pypi"], "0.5.15")
        self.assertEqual(after["server"], OLD_SHA, "untouched pins stay put")

    def test_both_pins_move_together(self):
        self.run_adapter("apply", {"server": NEW_SHA, "awid-pypi": "0.5.15"})
        self.assertEqual(
            self.run_adapter("read")["advertised"],
            {"server": NEW_SHA, "awid-pypi": "0.5.15"},
        )

    def test_a_version_is_refused_for_the_commit_pin(self):
        """The aweb pin holds a commit. Writing a version there would put a
        value in the field that the field cannot mean."""
        stderr = self.run_adapter("apply", {"server": "1.26.36"}, expect_failure=True)
        self.assertIn("holds a commit", stderr)

    def test_the_adapter_is_executable(self):
        """The driver execs this path. It writes aweb-cloud's production pins,
        and its sibling adapter already shipped once as 100644, so a silent mode
        regression here has to be caught by something."""
        self.assertTrue(os.access(ADAPTER, os.X_OK), f"{ADAPTER} must be executable")

    def test_an_unknown_component_is_refused(self):
        stderr = self.run_adapter("apply", {"channel": "1.7.4"}, expect_failure=True)
        self.assertIn("channel", stderr)

    def test_apply_is_idempotent(self):
        self.run_adapter("apply", {"server": NEW_SHA})
        self.run_adapter("apply", {"server": NEW_SHA})
        self.assertEqual(self.run_adapter("read")["advertised"]["server"], NEW_SHA)


if __name__ == "__main__":
    unittest.main()
