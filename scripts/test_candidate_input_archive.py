#!/usr/bin/env python3
"""Exercise the gate's input snapshot with real Git and the platform tar."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CandidateInputArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.repo = self.root / "source"
        self.repo.mkdir()
        self.git("init", "-qb", "main")
        (self.repo / "a").mkdir()
        (self.repo / "a" / "input.txt").write_bytes(b"committed input\n")
        self.git("add", ".")
        self.git(
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.test",
            "commit",
            "-qm",
            "one-file input",
        )
        self.sha = self.git("rev-parse", "HEAD").strip()
        self.work = self.root / "candidate"
        self.work.mkdir()
        self.logs = self.root / "logs"
        self.logs.mkdir()

    def git(self, *args: str) -> str:
        return subprocess.check_output(
            ["git", "-C", str(self.repo), *args], text=True, stderr=subprocess.PIPE
        )

    def record_input(self, *, path: Path) -> subprocess.CompletedProcess[str]:
        source = (ROOT / "scripts/candidate-docker-gate.sh").read_text()
        # Run the actual owner under its production shell options. Neither Git
        # nor tar is substituted: macOS bsdtar may stop at the archive EOF marker.
        function = (
            "record_input() {"
            + source.split("\nrecord_input() {", 1)[1].split(
                '\nrecord_input blueprints "$LIBRARY_E2E_BLUEPRINT_SRC"', 1
            )[0]
        )
        return subprocess.run(
            [
                "bash",
                "-c",
                'set -euo pipefail\nrefuse() { echo "$*" >&2; exit 2; }\n'
                + function
                + '\nrecord_input blueprints "$input_path"\nprintf completed > "$work/completed"\n',
            ],
            env=dict(
                os.environ,
                work=str(self.work),
                LOG_DIR=str(self.logs),
                blueprints_input_sha=self.sha,
                input_path=str(path),
            ),
            capture_output=True,
            text=True,
            timeout=20,
        )

    def test_subtree_snapshot_succeeds_with_platform_tar(self) -> None:
        result = self.record_input(path=self.repo / "a")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            (self.work / "inputs/blueprints/input.txt").read_bytes(),
            b"committed input\n",
        )
        self.assertEqual((self.logs / "blueprints-sha").read_text(), self.sha + "\n")
        self.assertTrue((self.work / "completed").exists())

    def test_repository_snapshot_preserves_the_tree_root(self) -> None:
        result = self.record_input(path=self.repo)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            (self.work / "inputs/blueprints/a/input.txt").read_bytes(),
            b"committed input\n",
        )
        self.assertEqual((self.logs / "blueprints-sha").read_text(), self.sha + "\n")

    def test_archive_error_still_stops_input_materialization(self) -> None:
        # A clean checkout can contain an ignored directory absent from its tree.
        # Exercise a real archive failure, rather than replacing Git with a stub.
        ignored = self.repo / "ignored"
        ignored.mkdir()
        (self.repo / ".git/info/exclude").write_text("/ignored/\n")
        result = self.record_input(path=ignored)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("not a valid object name", result.stderr)
        self.assertFalse((self.work / "completed").exists())


if __name__ == "__main__":
    unittest.main()
