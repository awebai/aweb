"""The source tag is a publication output (aben, Juan's tag ruling).

Under the ruling a release's identity IS the tag in its own
repository, so the AC tag stops being bookkeeping and becomes an
output the release produces, adopted exact-match on retry exactly like
the release branch pointer. These tests drive it against a real local
git remote - no mocks - because the failure modes that matter are
git's, not ours.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_train as rt  # noqa: E402


def git(*args: str, cwd: Path) -> str:
    """Identity is passed here AND stamped into every repository this
    initialises: production code under test runs git in these
    repositories too, and a developer host has a global git config
    where the gate container has none."""

    result = subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
        cwd=cwd, check=True, capture_output=True, text=True,
    )
    if args and args[0] == "init" and "--bare" not in args:
        candidates = [cwd] + [
            Path(a) if Path(a).is_absolute() else cwd / a
            for a in args[1:] if not a.startswith("-")
        ]
        target = next(
            (c for c in reversed(candidates) if (c / ".git").exists()), cwd
        )
        for key, value in (("user.email", "t@t"), ("user.name", "t")):
            subprocess.run(["git", "config", key, value], cwd=target,
                           check=True, capture_output=True)
    return result.stdout.strip()


class SourceTagPublication(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.remote = root / "remote.git"
        git("init", "-q", "--bare", str(self.remote), cwd=root)
        self.work = root / "work"
        git("init", "-q", str(self.work), cwd=root)
        (self.work / "f.txt").write_text("one\n")
        git("add", "-A", cwd=self.work)
        git("commit", "-q", "-m", "one", cwd=self.work)
        git("remote", "add", "origin", str(self.remote), cwd=self.work)
        git("push", "-q", "origin", "HEAD:main", cwd=self.work)
        self.first = git("rev-parse", "HEAD", cwd=self.work)
        (self.work / "f.txt").write_text("two\n")
        git("commit", "-q", "-am", "two", cwd=self.work)
        git("push", "-q", "origin", "HEAD:main", cwd=self.work)
        self.second = git("rev-parse", "HEAD", cwd=self.work)

    def remote_tag_commit(self, tag: str) -> str | None:
        out = git("ls-remote", "--tags", "origin", cwd=self.work)
        direct = peeled = None
        for line in out.splitlines():
            sha, ref = line.split(None, 1)
            name = ref.strip().removeprefix("refs/tags/")
            if name == f"{tag}^{{}}":
                peeled = sha
            elif name == tag:
                direct = sha
        return peeled or direct

    def test_tag_is_pushed_at_the_exact_sha_and_is_annotated(self) -> None:
        rt.publish_source_tag(self.work, "v0.7.15", self.second)
        self.assertEqual(self.remote_tag_commit("v0.7.15"), self.second)
        # Annotated, matching AC's own 13 existing release tags: the
        # peeled ref must exist, which only an annotated tag produces.
        refs = git("ls-remote", "--tags", "origin", cwd=self.work)
        self.assertIn("refs/tags/v0.7.15^{}", refs)

    def test_retry_adopts_an_identical_existing_tag(self) -> None:
        rt.publish_source_tag(self.work, "v0.7.15", self.second)
        # The retry path: continue re-runs after a partial failure and
        # must not treat its own completed work as a conflict.
        rt.publish_source_tag(self.work, "v0.7.15", self.second)
        self.assertEqual(self.remote_tag_commit("v0.7.15"), self.second)

    def test_a_tag_at_a_different_commit_refuses_by_name(self) -> None:
        rt.publish_source_tag(self.work, "v0.7.15", self.first)
        with self.assertRaises(rt.ValidationError) as caught:
            rt.publish_source_tag(self.work, "v0.7.15", self.second)
        message = str(caught.exception)
        self.assertIn("v0.7.15", message)
        self.assertIn(self.first[:12], message)
        self.assertIn(self.second[:12], message)
        # ...and it did NOT move the existing tag.
        self.assertEqual(self.remote_tag_commit("v0.7.15"), self.first)

    def test_the_published_tag_name_is_DERIVED_not_literal(self) -> None:
        """The link the other tests leave open.

        Every test above names the tag "v0.7.15" literally, so none of
        them notices if ac-image's canonical prefix is renamed. This
        one composes the name the way continue does - from
        release_tag_prefix over the canonical entry - so it pins that
        publication DERIVES the name rather than hardcoding one.

        What it does NOT do, measured rather than assumed: it does not
        catch the rename either. Both sides of its comparison move
        together, which is the same trap it was written to close. The
        rename is caught by the literal pin in
        test_anchor_is_an_exact_tagged_union - verified by mutating the
        prefix to "ac-v" and observing which suite goes red. Recorded
        here so the next reader does not credit this test with a
        guarantee it has not got."""

        version = "0.7.15"
        tag = rt.release_tag_prefix(rt._artifact("ac-image"), "awebai/ac") + version
        rt.publish_source_tag(self.work, tag, self.second)
        remote = git("ls-remote", "--tags", "origin", cwd=self.work)
        self.assertIn(f"refs/tags/{tag}", remote, remote)
        self.assertEqual(self.remote_tag_commit(tag), self.second)
        # ...and it is the version-namespace shape the reconciler will
        # read back, so publication and discovery agree by construction.
        self.assertEqual(
            tag, rt._artifact("ac-image").anchor.value + version
        )

    def test_a_malformed_sha_is_refused_before_any_remote_write(self) -> None:
        with self.assertRaises(rt.ValidationError):
            rt.publish_source_tag(self.work, "v0.7.15", "not-a-sha")
        self.assertIsNone(self.remote_tag_commit("v0.7.15"))


if __name__ == "__main__":
    unittest.main()
