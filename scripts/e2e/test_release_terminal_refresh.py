"""The terminal sweep reads tags from a checkout that must be current.

The live release reported "ABSENT source tag awid-service-v0.5.17 (no
such tag in the fetched checkout)" for a tag origin was already
serving: the publication workflow pushed it after the checkout's last
fetch, so the sweep read a stale local copy and called a published
anchor missing.

That is the TAG race, and it is a different mechanism from the REGISTRY
race where a remote has not finished serving a member. Both present as
ABSENT, which is why fixing only the registry one would leave this open
and looking fixed. This one is staleness in our own working copy, and
the fix is a read before a read.

source_tag_row reads locally by design - under the tag ruling identity
is answered from a repository fetched once, not by a round trip per
artifact - so the fix belongs at the sweep, not in the row builder.
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

import release_status_builders as builders  # noqa: E402
import release_train as rt  # noqa: E402
from fixture_git import git as _fixture_git  # noqa: E402


def _git(cwd: Path, *args: str) -> str:
    """Through the one owner: init.defaultBranch and identity differ
    between this host and the gate container, and an unpinned bare
    remote leaves a clone with an unborn HEAD."""

    return _fixture_git(*args, cwd=cwd)


class TerminalRefresh(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.origin = root / "origin.git"
        self.checkout = root / "checkout"
        _git(Path(self.tmp.name), "init", "--bare", "-q", str(self.origin))
        seed = root / "seed"
        _git(Path(self.tmp.name), "init", "-q", str(seed))
        _git(seed, "config", "user.name", "fixture")
        _git(seed, "config", "user.email", "fixture@example.invalid")
        (seed / "file").write_text("published\n")
        _git(seed, "add", ".")
        _git(seed, "commit", "-qm", "published")
        self.sha = _git(seed, "rev-parse", "HEAD")
        _git(seed, "remote", "add", "origin", str(self.origin))
        _git(seed, "push", "-q", "origin", "HEAD:main")
        self.seed = seed
        _git(Path(self.tmp.name), "clone", "-q", str(self.origin), str(self.checkout))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _publish_tag_after_the_checkout_was_fetched(self, tag: str) -> None:
        """What the publication workflow does while the walk runs."""

        _git(self.seed, "tag", tag, self.sha)
        _git(self.seed, "push", "-q", "origin", f"refs/tags/{tag}")

    def test_a_tag_pushed_after_the_fetch_reads_absent_until_refreshed(
        self,
    ) -> None:
        tag = "awid-service-v0.5.17"
        self._publish_tag_after_the_checkout_was_fetched(tag)

        # CONTROL: without the refresh the sweep calls a published
        # anchor missing. This is the live failure, reproduced - if this
        # assertion ever stops holding, the test below proves nothing.
        stale = builders.source_tag_row(
            self.checkout, tag, expected_identity=self.sha
        )
        self.assertEqual(stale.state, "observed-absent")
        self.assertIn("fetched checkout", stale.evidence)

        rt.refresh_source_refs({"aweb": self.checkout})

        fresh = builders.source_tag_row(
            self.checkout, tag, expected_identity=self.sha
        )
        self.assertEqual(fresh.state, "observed-present")
        self.assertEqual(fresh.evidence, f"peeled to expected {self.sha}")

    def test_refresh_is_a_read_and_never_moves_the_working_tree(self) -> None:
        """It changes what we READ, not what we WRITE - the whole reason
        this one is safe to land mid-release. A refresh that could move
        HEAD or touch tracked files would be a different change."""

        tag = "skills-v0.2.13"
        self._publish_tag_after_the_checkout_was_fetched(tag)
        before_head = _git(self.checkout, "rev-parse", "HEAD")
        before_tree = _git(self.checkout, "status", "--porcelain")

        rt.refresh_source_refs({"aweb": self.checkout})

        self.assertEqual(_git(self.checkout, "rev-parse", "HEAD"), before_head)
        self.assertEqual(_git(self.checkout, "status", "--porcelain"), before_tree)

    def test_an_unreachable_remote_never_fails_the_sweep(self) -> None:
        """A refresh is best-effort: the rows are the authority, and a
        transient fetch failure must not convert a complete world into a
        crash. The rows that follow will report what they observe."""

        _git(self.checkout, "remote", "set-url", "origin", str(
            Path(self.tmp.name) / "does-not-exist.git"
        ))
        rt.refresh_source_refs({"aweb": self.checkout})

    def test_every_named_root_is_refreshed_not_only_the_first(self) -> None:
        """The sweep reads anchors from aweb, ac and aw. Refreshing one
        would fix the artifact that happened to be first and leave the
        others reading stale - the shape of a fix that looks applied."""

        second = Path(self.tmp.name) / "second"
        _git(Path(self.tmp.name), "clone", "-q", str(self.origin), str(second))
        tag = "a2a-gw-v1.27.2"
        self._publish_tag_after_the_checkout_was_fetched(tag)

        rt.refresh_source_refs({"aweb": self.checkout, "aw": second})

        for name, root in (("aweb", self.checkout), ("aw", second)):
            with self.subTest(root=name):
                row = builders.source_tag_row(
                    root, tag, expected_identity=self.sha
                )
                self.assertEqual(row.state, "observed-present")


if __name__ == "__main__":
    unittest.main()
