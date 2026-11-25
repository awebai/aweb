#!/usr/bin/env python3
"""Commits through the repository's pre-commit hook in a scratch clone.

Runs ruff with uvx at the version server/uv.lock pins, so it needs network
access or a warm uv cache. It runs in pull-request CI, not in the gate.
"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UNFORMATTED_PY = "def f( a,b ):\n  return {'a':a,'b':b}\n"
FORMATTED_PY = 'def f(a, b):\n    return {"a": a, "b": b}\n'
UNFORMATTED_GO = "package fixture\nfunc F( ) int { return 1 }\n"


def git(root, *argv, check=True):
    return subprocess.run(
        ["git", *argv], cwd=root, check=check, capture_output=True, text=True
    )


class PreCommitHook(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        git(self.root, "init", "-qb", "main")
        git(self.root, "config", "user.name", "fixture")
        git(self.root, "config", "user.email", "fixture@example.test")
        for path in (".githooks/pre-commit", "server/uv.lock", "Makefile"):
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / path, target)
        subprocess.run(
            ["make", "-s", "setup"], cwd=self.root, check=True, capture_output=True
        )
        git(self.root, "add", ".")
        git(self.root, "commit", "--no-verify", "-qm", "hook fixture")

    def commit(self, *paths):
        git(self.root, "add", *paths)
        return git(self.root, "commit", "-qm", "fixture", check=False)

    def test_staged_python_and_go_are_committed_formatted(self):
        (self.root / "scripts").mkdir()
        (self.root / "scripts/fixture.py").write_text(UNFORMATTED_PY)
        (self.root / "cli/go").mkdir(parents=True)
        (self.root / "cli/go/fixture.go").write_text(UNFORMATTED_GO)
        result = self.commit("scripts/fixture.py", "cli/go/fixture.go")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(git(self.root, "show", "HEAD:scripts/fixture.py").stdout, FORMATTED_PY)
        self.assertEqual(
            git(self.root, "show", "HEAD:cli/go/fixture.go").stdout,
            "package fixture\n\nfunc F() int { return 1 }\n",
        )
        self.assertEqual(git(self.root, "status", "--porcelain").stdout, "")

    def test_a_partially_staged_file_is_refused(self):
        path = self.root / "scripts/fixture.py"
        path.parent.mkdir()
        path.write_text(UNFORMATTED_PY)
        git(self.root, "add", "scripts/fixture.py")
        path.write_text(UNFORMATTED_PY + "x = 1\n")
        result = git(self.root, "commit", "-qm", "fixture", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stage them fully first", result.stderr)
        self.assertIn("scripts/fixture.py", result.stderr)


if __name__ == "__main__":
    unittest.main()
