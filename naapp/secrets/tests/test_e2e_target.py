"""The candidate gate runs this package's `make e2e`: each journey it must
qualify is one that target runs."""

import shlex
import subprocess
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]


def e2e_journeys() -> set[str]:
    # make's own dry run: the commands the target would run, not its text.
    recipe = subprocess.run(["make", "-n", "e2e"], cwd=PACKAGE, text=True, capture_output=True, check=True).stdout
    return {word for line in recipe.splitlines() for word in shlex.split(line) if word.startswith("tests/test_e2e_")}


def test_the_gate_runs_the_owner_acts_and_the_protected_revoke_journeys():
    assert e2e_journeys() == {"tests/test_e2e_owner_acts.py", "tests/test_e2e_protected_revoke.py"}
    for journey in e2e_journeys():
        assert (PACKAGE / journey).is_file(), journey
