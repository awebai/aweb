"""Real Git controls for the reviewed baseline supplied to candidate checks."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CandidateMainReference(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.repo = self.directory / "source"
        self.repo.mkdir()
        self.git("init", "-qb", "candidate")
        (self.repo / "baseline").write_text("reviewed\n")
        self.git("add", ".")
        self.git(
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.test",
            "commit",
            "-qm",
            "reviewed",
        )
        self.main = self.git("rev-parse", "HEAD")
        self.git("update-ref", "refs/remotes/origin/main", self.main)
        (self.repo / "baseline").write_text("candidate\n")
        self.git(
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.test",
            "commit",
            "-qam",
            "candidate",
        )
        self.candidate = self.git("rev-parse", "HEAD")
        self.git("checkout", "--detach", "--quiet", self.candidate)
        self.work = self.directory / "work"
        self.work.mkdir()

    def git(self, *arguments: str) -> str:
        return subprocess.check_output(
            ["git", "-C", str(self.repo), *arguments], text=True, stderr=subprocess.PIPE
        ).strip()

    def materialize(self) -> subprocess.CompletedProcess[str]:
        source = (ROOT / "scripts/candidate-docker-gate.sh").read_text()
        fragment = source.split('checkout="$work/aweb"\n', 1)[1].split(
            "\nrecord_input() {", 1
        )[0]
        return subprocess.run(
            [
                "bash",
                "-c",
                'set -euo pipefail\nrefuse() { echo "$*" >&2; exit 2; }\ncheckout="$work/aweb"\n'
                + fragment,
            ],
            env=dict(
                os.environ,
                ROOT=str(self.repo),
                work=str(self.work),
                SOURCE_SHA=self.candidate,
                SYNCHRONIZED_MAIN_SHA=self.main,
            ),
            text=True,
            capture_output=True,
            timeout=20,
        )

    def test_detached_gate_clone_retains_reviewed_main_not_candidate(self) -> None:
        result = self.materialize()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        actual = subprocess.run(
            [
                "git",
                "-C",
                str(self.work / "aweb"),
                "rev-parse",
                "--verify",
                "refs/remotes/origin/main",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(actual.returncode, 0, actual.stderr)
        self.assertEqual(actual.stdout.strip(), self.main)
        self.assertNotEqual(self.main, self.candidate)

    def test_changed_source_main_refuses_before_clone(self) -> None:
        self.git("update-ref", "refs/remotes/origin/main", self.candidate)
        result = self.materialize()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "Synchronize main and start a new gate invocation.", result.stderr
        )
        self.assertFalse((self.work / "aweb").exists())

    def test_missing_source_main_refuses_before_clone(self) -> None:
        self.git("update-ref", "-d", "refs/remotes/origin/main")
        result = self.materialize()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "Synchronize main and start a new gate invocation.", result.stderr
        )
        self.assertFalse((self.work / "aweb").exists())


if __name__ == "__main__":
    unittest.main()
