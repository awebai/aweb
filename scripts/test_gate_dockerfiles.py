"""The gate's images set ownership and modes when files are created, never afterwards."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILES = [*sorted((ROOT / "candidate-gate").glob("Dockerfile*")), ROOT / "scripts/test-egress/Dockerfile"]
# chown or chmod with -R, --recursive, or R among combined short flags.
RECURSIVE = re.compile(r"\b(chown|chmod)\b(?:\s+-[A-Za-z]*R[A-Za-z]*\b|\s+--recursive\b|[^\n&;|]*\s(?:-[A-Za-z]*R[A-Za-z]*|--recursive)\b)")


class GateDockerfiles(unittest.TestCase):
    def test_the_pattern_finds_recursive_ownership_and_mode_changes(self):
        for line in ("RUN chown -R 1000:1000 /src", "RUN chmod -R a+rX /opt", "&& chmod --recursive 0755 x", "chown -hR a b", "chmod a+rX -R /opt"):
            self.assertTrue(RECURSIVE.search(line), line)
        for line in ("RUN chmod 0644 /opt/x", "COPY --chown=1000:1000 . .", "install -d -o 1000 /src"):
            self.assertFalse(RECURSIVE.search(line), line)

    def test_no_gate_dockerfile_changes_ownership_or_modes_recursively(self):
        self.assertGreaterEqual(len(DOCKERFILES), 2)
        for path in DOCKERFILES:
            for number, line in enumerate(path.read_text().splitlines(), 1):
                with self.subTest(path=path.relative_to(ROOT).as_posix(), line=number):
                    self.assertIsNone(RECURSIVE.search(line), line)


if __name__ == "__main__":
    unittest.main()
