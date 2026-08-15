"""The aben gate's module list and the modules on disk, checked against
each other.

Gate scope has now failed twice in this epic. column-b was a row that
could never pass where it ran, and release-aben silently omitted the
whole continue pipeline - which meant the literal ARTIFACTS pin, the
guard against unacknowledged changes to the canonical record, could not
fire for about a day. Both are the same defect: an instrument that
cannot run is indistinguishable from one that ran and passed.

A list that only ever agrees with itself cannot catch either. So this
checks the list against the WORLD: every release test module on disk is
either in the gate target or declared out of it WITH A REASON, and
every module the target names exists. A new module cannot be silently
left out, and a deleted one cannot linger.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
E2E = REPO_ROOT / "scripts" / "e2e"
MAKEFILE = REPO_ROOT / "Makefile"

# Modules deliberately outside the aben gate, each with the reason it is
# out. A module may be absent from the gate; it may not be absent from
# this decision.
DECLARED_OUT_OF_GATE = {
    "test_release_column_b_assembly": (
        "recorded-halves replay, not the shipping product - removed from "
        "the gate map deliberately; runs as make test-column-b"
    ),
    "test_release_gate_contract": (
        "the gate runner's own contract, a tooling test - runs in PR "
        "checks, not inside the release gate it describes"
    ),
    "test_release_gate_docker_boundaries": (
        "needs a built image and a docker daemon the gate container "
        "does not provide; runs against the image after it is built"
    ),
    "test_release_local_gate_contract": (
        "the local gate wrapper's contract, a tooling test with its own "
        "target"
    ),
}


def _target_modules() -> set[str]:
    """The modules `make test-release-aben` actually runs."""

    text = MAKEFILE.read_text()
    start = text.index("\ntest-release-aben:")
    end = text.index("\n\n", start)
    body = text[start:end]
    return set(re.findall(r"scripts\.e2e\.(test_release_[A-Za-z0-9_]+)", body))


def _disk_modules() -> set[str]:
    """Every python release test module present in the tree."""

    return {
        path.stem
        for path in E2E.glob("test_release_*.py")
    }


class GateScope(unittest.TestCase):
    def test_every_module_on_disk_is_in_the_gate_or_declared_out(self) -> None:
        undeclared = _disk_modules() - _target_modules() - set(DECLARED_OUT_OF_GATE)
        self.assertEqual(
            undeclared, set(),
            "these release test modules are in neither the aben gate nor "
            "the declared exclusions - a module that is silently outside "
            "the gate is a test nobody runs at release time: "
            f"{sorted(undeclared)}",
        )

    def test_every_module_the_target_names_exists(self) -> None:
        missing = _target_modules() - _disk_modules()
        self.assertEqual(
            missing, set(),
            f"the gate names modules that do not exist: {sorted(missing)}",
        )

    def test_no_exclusion_is_stale(self) -> None:
        # An exclusion for a module that no longer exists, or that is
        # now IN the gate, is a stale decision reading as a live one.
        stale = set(DECLARED_OUT_OF_GATE) - _disk_modules()
        self.assertEqual(stale, set(), f"exclusions for absent modules: {sorted(stale)}")
        contradictory = set(DECLARED_OUT_OF_GATE) & _target_modules()
        self.assertEqual(
            contradictory, set(),
            f"declared out of the gate AND in it: {sorted(contradictory)}",
        )

    def test_the_continue_pipeline_is_in_the_gate(self) -> None:
        """The specific regression, pinned by name.

        test_release_train holds the continue pipeline's publication,
        ordering, recovery and falsified-binding evidence AND the
        literal ARTIFACTS pin. It was outside the gate while the record
        changed twice."""

        self.assertIn("test_release_train", _target_modules())

    def test_this_guard_runs_INSIDE_the_gate(self) -> None:
        """A guard that is not in the gate does not run at release
        time, which is the exact defect it exists to catch. Declaring
        itself out on the grounds that its membership check would be
        self-referential would have reproduced the bug in the fix."""

        self.assertIn("test_release_gate_scope", _target_modules())

    def test_every_exclusion_carries_a_reason(self) -> None:
        for module, reason in DECLARED_OUT_OF_GATE.items():
            with self.subTest(module=module):
                self.assertTrue(reason.strip(), module)


if __name__ == "__main__":
    unittest.main()
