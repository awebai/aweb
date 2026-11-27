#!/usr/bin/env python3
"""The root Makefile's entry points resolve, as make itself reads them."""

from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]

# A rule line in make's printed database: "name: prerequisites".
RULE = re.compile(r"^([^\s#=:%][^\s#=:]*):(?:\s|$)")


def database():
    """make's own database of the root Makefile, read without running a recipe."""
    result = subprocess.run(
        ["make", "--no-print-directory", "-pq", "-f", "Makefile", ".DEFAULT"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return result.stdout


class MakefileTargetTests(unittest.TestCase):
    def test_make_test_resolves_every_prerequisite(self):
        result = subprocess.run(
            ["make", "--no-print-directory", "-n", "test"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_every_phony_name_is_a_target(self):
        # make lists every name it has seen; a name the Makefile defines has
        # prerequisites or a recipe, which make marks "commands to execute".
        targets = set()
        phony = set()
        name = None
        for line in database().splitlines():
            if line.startswith(".PHONY:"):
                phony.update(line.split(":", 1)[1].split())
                name = None
                continue
            match = RULE.match(line)
            if match:
                name = match.group(1)
                if line.split(":", 1)[1].strip():
                    targets.add(name)
            elif not line.strip():
                name = None
            elif name and "commands to execute" in line:
                targets.add(name)
        self.assertTrue(phony)
        self.assertEqual(sorted(phony - targets), [])


if __name__ == "__main__":
    unittest.main()
