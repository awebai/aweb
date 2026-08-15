"""A fixture module may not initialise a repository on its own.

`init.defaultBranch` and git identity are set on a developer host and
absent in the gate container. A module that runs `git init` without
pinning them passes where it is written and fails where it runs - which
has now happened four times in this epic, most recently in D3's own
test, where an unpinned bare remote left a clone with an unborn HEAD and
`rev-parse HEAD` exited 128.

Every previous instance was fixed by adding the pinning to that module.
That is agreement, and agreement holds only until the next module: the
hardening is currently copied into five modules and has ALREADY drifted
into three variants - two identity strings, and some doing an extra
post-init step. So this refuses a NEW module that initialises a
repository without going through `fixture_git`, which is the remedy that
holds once rather than at every future call site.

The five existing copies are listed as a migration backlog rather than
silently tolerated. Consolidating them means reconciling their drift,
which is a real refactor and not one to do mid-release; the list is the
record that it is owed, and it may only shrink.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

E2E = Path(__file__).resolve().parent
sys.path.insert(0, str(E2E))

# Modules carrying their own copy of the pinning, predating fixture_git.
# This list is a debt, not a permission: entries come off it as they are
# migrated, and nothing may be added.
LEGACY_OWN_PINNING = {
    "test_release_aw_checkout.py",
    "test_release_normalizer_assembly.py",
    "test_release_normalizer_capture_repo.py",
    "test_release_source_tag.py",
    "test_release_train.py",
}

# Modules that invoke `git init` through a path this check cannot follow
# (a shell script, a helper under test). Each needs a reason.
DECLARED_EXCEPTIONS = {
    "test_oats_pinned_checkout.py": "drives a real pinned upstream checkout, not a fixture",
    "test_aw_a2a_release_workflows.py": "runs the workflow's own extracted bash block",
    "test_release_gate_contract.py": "asserts on gate scripts rather than building fixtures",
    "test_release_local_gate_contract.py": "same, for the local gate",
    "test_pointer_adapter_marketplace.py": "exercises the pointer adapter's own git usage",
    "test_pointer_adapter_ac_pin.py": "same, for the AC pin adapter",
    "test_release_column_b_assembly.py": "assembles evidence from a real checkout",
    "test_release_normalizer_canonical_entry.py": "reads the canonical record, no fixture repo",
    "test_release_prepare_projection.py": "projects over a real checkout",
    "test_release_status_terminal.py": "builds status rows, no fixture repo",
    "test_release_train_anchor_resolver.py": "resolves anchors in a real checkout",
}

_INIT = re.compile(r'"init"')
# An IMPORT, not a mention. The first version of this check tested
# `"fixture_git" in text`, which a COMMENT naming the module satisfied -
# so the detector for the copied-hardening defect was itself vacuous,
# and a mutation removing the real import left it green. Caught by
# running that mutation rather than by reading the check.
_IMPORTS_OWNER = re.compile(r"(?m)^\s*(?:from\s+fixture_git\s+import|import\s+fixture_git)\b")


class FixtureGitOwnership(unittest.TestCase):
    def _modules_that_init(self) -> set[str]:
        found = set()
        for path in sorted(E2E.glob("test_*.py")):
            if _INIT.search(path.read_text()):
                found.add(path.name)
        return found

    def test_no_new_module_initialises_a_repository_on_its_own(self) -> None:
        offenders = []
        for name in sorted(self._modules_that_init()):
            if name in LEGACY_OWN_PINNING or name in DECLARED_EXCEPTIONS:
                continue
            if not _IMPORTS_OWNER.search((E2E / name).read_text()):
                offenders.append(name)
        self.assertEqual(
            offenders, [],
            "these modules initialise a repository without fixture_git - "
            "they will pass here and fail in the gate container: "
            f"{offenders}",
        )

    def test_the_legacy_list_only_names_modules_that_still_exist(self) -> None:
        # A stale entry would silently grant an exemption to nothing, and
        # hide that the debt was already paid.
        for name in sorted(LEGACY_OWN_PINNING):
            with self.subTest(module=name):
                self.assertTrue((E2E / name).is_file(), name)

    def test_every_legacy_module_really_does_pin_the_default_branch(self) -> None:
        """The exemption is for carrying a COPY, not for carrying
        nothing. A module on this list that lost its pinning would be
        exempted from the check precisely when it needs it."""

        for name in sorted(LEGACY_OWN_PINNING):
            with self.subTest(module=name):
                text = (E2E / name).read_text()
                self.assertIn("initial-branch", text, name)
                self.assertIn("user.email=", text, name)

    def test_the_owner_pins_both_host_dependent_settings(self) -> None:
        """The whole point of the owner, asserted on the owner itself
        rather than assumed from its name."""

        import subprocess
        import tempfile

        from fixture_git import git

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            git("init", "-q", "repo", cwd=root)
            repo = root / "repo"
            branch = subprocess.run(
                ["git", "symbolic-ref", "--short", "HEAD"],
                cwd=repo, capture_output=True, text=True, check=True,
            ).stdout.strip()
            self.assertEqual(branch, "main")

            # Identity: a commit must succeed with NO user configured,
            # which is the container's condition.
            (repo / "f").write_text("x\n")
            git("add", ".", cwd=repo)
            git("commit", "-qm", "committed without host identity", cwd=repo)
            self.assertTrue(git("rev-parse", "HEAD", cwd=repo))

    def test_a_bare_remote_is_cloneable_which_is_the_failure_that_happened(
        self,
    ) -> None:
        """The exact live failure, as a test of the owner: an unpinned
        bare remote gets HEAD on a branch nothing is pushed to, so the
        clone checks out nothing and rev-parse HEAD exits 128."""

        import tempfile

        from fixture_git import git

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            git("init", "--bare", "-q", "origin.git", cwd=root)
            git("init", "-q", "seed", cwd=root)
            (root / "seed" / "f").write_text("x\n")
            git("add", ".", cwd=root / "seed")
            git("commit", "-qm", "seed", cwd=root / "seed")
            git("remote", "add", "origin", str(root / "origin.git"),
                cwd=root / "seed")
            git("push", "-q", "origin", "HEAD:main", cwd=root / "seed")
            git("clone", "-q", str(root / "origin.git"), "clone", cwd=root)
            # The assertion that errored in the gate.
            self.assertTrue(git("rev-parse", "HEAD", cwd=root / "clone"))


if __name__ == "__main__":
    unittest.main()
