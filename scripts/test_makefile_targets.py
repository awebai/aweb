#!/usr/bin/env python3
"""The root Makefile's entry points resolve, as make itself reads them."""

import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

# A rule line in make's printed database: "name: prerequisites".
RULE = re.compile(r"^([^\s#=:%][^\s#=:]*):(?:\s|$)")
# make marks a target's recipe in its database: "commands to execute" up to
# GNU Make 4.2, "recipe to execute" from 4.3.
RECIPE = ("commands to execute", "recipe to execute")


def make(directory, *args):
    # make translates its database headings with gettext; the C locale keeps
    # the English markers this file reads.
    return subprocess.run(
        ["make", "--no-print-directory", *args],
        cwd=directory,
        capture_output=True,
        text=True,
        timeout=60,
        env=dict(os.environ, LC_ALL="C"),
    )


def phony_names_without_a_target(directory, goal):
    """The .PHONY names that make's database of the Makefile does not define.

    make lists every name it has seen; a name the Makefile defines has
    prerequisites or a recipe. The database is read through a real goal with
    -n, so no recipe runs.
    """
    result = make(directory, "-pn", goal)
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    targets = set()
    phony = set()
    name = None
    for line in result.stdout.splitlines():
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
        elif name and any(marker in line for marker in RECIPE):
            targets.add(name)
    if not phony:
        raise AssertionError("make printed no .PHONY names")
    return sorted(phony - targets)


# A Makefile with the defect this file guards against: two target names
# joined into one in a prerequisite list, and another pair in .PHONY. A joined
# name that is itself declared .PHONY passes make -n, so each check covers a
# case the other cannot.
JOINED = """\
.PHONY: help test-a test-ctest-b
help:
\t@echo help
test: test-a test-btest-c
test-a:
\t@echo a
test-b:
\t@echo b
test-c:
\t@echo c
"""


class MakefileTargetTests(unittest.TestCase):
    def test_make_test_resolves_every_prerequisite(self):
        result = make(ROOT, "-n", "test")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_every_phony_name_is_a_target(self):
        self.assertEqual(phony_names_without_a_target(ROOT, "help"), [])

    def test_a_joined_target_name_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / "Makefile").write_text(JOINED)
            self.assertNotEqual(make(temp, "-n", "test").returncode, 0)
            self.assertEqual(
                phony_names_without_a_target(temp, "help"), ["test-ctest-b"]
            )


if __name__ == "__main__":
    unittest.main()
