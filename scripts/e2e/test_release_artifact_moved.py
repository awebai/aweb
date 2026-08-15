"""Did this artifact move? One owner, consumed by capture and by the
publication workflow (aben D1).

`aw-release.yml` derives its version from the WORLD - latest published
tag plus one - so every release-branch move at a new SHA minted a new
aw-cli whether or not `cli/go` had changed. It published 1.34.8 from a
tree byte-identical to 1.34.7. Its own tag preflight could not catch
that: `max(published)+1` can never already exist, so the guard was
structurally incapable of firing.

The five other publication workflows read their version out of the
COMMITTED tree, which is why none of them can mint - they re-derive a
version that is already public and the exact-publish triple adopts or
refuses. This closes the difference by giving aw the same question the
others answer implicitly, and answering it from the CANONICAL scope:
a workflow that wrote `cli/go` itself would be one more copy of a fact
the record already owns, which is the defect family this whole cycle
has been removing.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
# fixture_git lives beside this module; the suite loads it as
# scripts.e2e.<name>, so the package directory is not on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import release_normalizer_capture as cap  # noqa: E402
import release_train as rt  # noqa: E402
from fixture_git import git as _fixture_git  # noqa: E402

MOVED_SCRIPT = REPO_ROOT / "scripts" / "release_artifact_moved.py"


def _git(cwd: Path, *args: str) -> str:
    """Through the one owner - see fixture_git."""

    return _fixture_git(*args, cwd=cwd)


class ArtifactMovement(unittest.TestCase):
    """Two artifacts, one fixture, opposite answers - which no
    hardcoded path can produce."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.origin = root / "origin.git"
        self.repo = root / "checkout"
        _git(Path(self.tmp.name), "init", "--bare", "-q", str(self.origin))
        _git(Path(self.tmp.name), "init", "-q", str(self.repo))
        _git(self.repo, "config", "user.name", "fixture")
        _git(self.repo, "config", "user.email", "fixture@example.invalid")
        self._write("cli/go/main.go", "package main\n")
        self._write(
            "cli/go/npm/aw/package.json", '{\n  "version": "0.0.0"\n}\n'
        )
        self._write("server/app.py", "x = 1\n")
        self._write("server/pyproject.toml", '[project]\nversion = "1.0.0"\n')
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-qm", "published state")
        _git(self.repo, "remote", "add", "origin", str(self.origin))
        _git(self.repo, "push", "-q", "origin", "HEAD:main")
        for tag in ("aw-v1.0.0", "server-v1.0.0"):
            _git(self.repo, "tag", tag)
            _git(self.repo, "push", "-q", "origin", f"refs/tags/{tag}")
        self.specs = {s.name: s for s in cap.derive_capture_specs(rt.ARTIFACTS)}

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write(self, relative: str, text: str) -> None:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def _commit(self, relative: str, text: str) -> None:
        self._write(relative, text)
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-qm", f"change {relative}")

    def _moved(self, artifact: str) -> bool:
        refs = cap.remote_ref_snapshot(self.repo)
        return cap.anchor_movement(
            self.repo, self.specs[artifact], refs
        ).changed

    def test_an_untouched_tree_has_not_moved(self) -> None:
        # HEAD is the tagged commit: this is every ordinary release
        # where aw is not part of the change.
        self.assertFalse(self._moved("aw-cli"))
        self.assertFalse(self._moved("aweb-server"))

    def test_a_change_moves_only_the_artifact_that_owns_the_path(self) -> None:
        """The discriminating test: one edit, two artifacts, opposite
        answers. A helper that hardcoded cli/go would pass the first
        assertion and fail the second - and a helper that answered
        'changed' for everything would pass the second and fail the
        first."""

        self._commit("cli/go/main.go", "package main // edited\n")
        self.assertTrue(self._moved("aw-cli"))
        self.assertFalse(self._moved("aweb-server"))

        self._commit("server/app.py", "x = 2\n")
        self.assertTrue(self._moved("aweb-server"))

    def test_a_change_outside_every_scope_moves_nothing(self) -> None:
        self._commit("docs/readme.md", "prose\n")
        self.assertFalse(self._moved("aw-cli"))
        self.assertFalse(self._moved("aweb-server"))

    def test_the_owned_version_field_alone_is_not_movement(self) -> None:
        # The normalizer's own version patch must not read as content,
        # or the fixed point could never be reached.
        self._commit(
            "cli/go/npm/aw/package.json", '{\n  "version": "9.9.9"\n}\n'
        )
        self.assertFalse(self._moved("aw-cli"))

    def test_no_anchor_tag_at_all_reads_as_moved(self) -> None:
        """Conservative direction: with nothing to compare against, the
        artifact is treated as changed. Refusing to publish a first
        release would be worse than publishing one."""

        _git(self.repo, "push", "-q", "origin", "--delete", "refs/tags/aw-v1.0.0")
        self.assertTrue(self._moved("aw-cli"))

    def test_capture_and_the_workflow_ask_the_same_function(self) -> None:
        """Not two implementations that agree today. The assembly path
        must reach the same owner the CLI does, so a change to movement
        cannot apply to one and not the other."""

        import inspect

        source = inspect.getsource(cap.assemble_captured_world)
        self.assertIn("anchor_movement(", source)
        self.assertNotIn("content_changed(", source)


class MovedCommand(unittest.TestCase):
    """The workflow invokes a real script, so the script's contract is
    tested by running it - not by asserting the YAML mentions it."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.origin = root / "origin.git"
        self.repo = root / "checkout"
        _git(Path(self.tmp.name), "init", "--bare", "-q", str(self.origin))
        _git(Path(self.tmp.name), "init", "-q", str(self.repo))
        _git(self.repo, "config", "user.name", "fixture")
        _git(self.repo, "config", "user.email", "fixture@example.invalid")
        path = self.repo / "cli/go/npm/aw"
        path.mkdir(parents=True)
        (self.repo / "cli/go/main.go").write_text("package main\n")
        (path / "package.json").write_text('{\n  "version": "0.0.0"\n}\n')
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-qm", "published state")
        _git(self.repo, "remote", "add", "origin", str(self.origin))
        _git(self.repo, "push", "-q", "origin", "HEAD:main")
        _git(self.repo, "tag", "aw-v1.0.0")
        _git(self.repo, "push", "-q", "origin", "refs/tags/aw-v1.0.0")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(MOVED_SCRIPT), *args],
            cwd=self.repo,
            capture_output=True,
            text=True,
        )

    def test_unmoved_prints_unmoved_and_succeeds(self) -> None:
        result = self._run("aw-cli")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "unmoved")

    def test_moved_prints_moved(self) -> None:
        (self.repo / "cli/go/main.go").write_text("package main // edited\n")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-qm", "edit")
        result = self._run("aw-cli")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "moved")

    def test_an_unknown_artifact_refuses_rather_than_guessing(self) -> None:
        result = self._run("not-an-artifact")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not-an-artifact", result.stderr)

    def test_an_unreadable_remote_refuses_and_never_says_unmoved(self) -> None:
        """Observation failure is never permission to write - and here
        it is never permission NOT to. A helper that reported 'unmoved'
        when it could not read the anchors would silently suppress a
        real release."""

        _git(self.repo, "remote", "set-url", "origin", str(
            Path(self.tmp.name) / "gone.git"
        ))
        result = self._run("aw-cli")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("unmoved", result.stdout)


if __name__ == "__main__":
    unittest.main()
