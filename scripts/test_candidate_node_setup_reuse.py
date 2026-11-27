"""Node dependencies are prepared once per gate run."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NodeSetupReuseTests(unittest.TestCase):
    def exercise(self, stages):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "bin"
            binary.mkdir()
            make = binary / "make"
            make.write_text('#!/bin/sh\nprintf "%s\\n" "$1" >> "$CALLS"\n')
            make.chmod(0o755)
            docker = binary / "docker"
            docker.write_text("#!/bin/sh\nexit 0\n")
            docker.chmod(0o755)
            env = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ["PATH"])
            env.update(
                CANDIDATE_LOG_DIR=str(root),
                CALLS=str(root / "calls"),
                BUILDX_BUILDER="fixture-only",
            )
            result = subprocess.run(
                ["bash", str(ROOT / "scripts/candidate-suite.sh"), stages],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
            )
            return (
                result,
                (root / "calls").read_text().splitlines(),
                (root / "summary.tsv").read_text(),
                (root / "unit.log").read_text(),
            )

    def test_later_artifact_stage_reuses_the_successful_unit_node_setup(self):
        result, calls, summary, _ = self.exercise("unit artifacts")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calls.count("_candidate-node-deps"), 1)
        self.assertIn("artifacts\tPASSED\tartifacts.log", summary)


if __name__ == "__main__":
    unittest.main()
