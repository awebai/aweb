"""Repository-side capture (aben R3): content_changed against the anchor
commit over the canonical scope, manifest version reads, and anchor tag
discovery - hermetic against a real local git remote.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_normalizer_capture as cap  # noqa: E402


def git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


class RepoCapture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.remote = root / "remote.git"
        git("init", "-q", "--bare", str(self.remote), cwd=root)
        self.work = root / "work"
        git("init", "-q", str(self.work), cwd=root)
        (self.work / "pkg").mkdir()
        (self.work / "pkg" / "code.py").write_text("v1\n")
        (self.work / "pkg" / "pyproject.toml").write_text(
            '[project]\nname = "pkg"\nversion = "1.0.0"\n'
        )
        (self.work / "other.txt").write_text("x\n")
        git("add", "-A", cwd=self.work)
        git("commit", "-q", "-m", "one", cwd=self.work)
        git("remote", "add", "origin", str(self.remote), cwd=self.work)
        git("push", "-q", "origin", "HEAD:main", cwd=self.work)
        git("tag", "pkg-v1.0.0", cwd=self.work)
        git("push", "-q", "origin", "refs/tags/pkg-v1.0.0", cwd=self.work)
        self.anchor_sha = git("rev-parse", "HEAD", cwd=self.work)

    def tearDown(self):
        self._tmp.cleanup()

    def test_anchor_tags_discovered_with_peeled_identities(self) -> None:
        tags = cap.discover_anchor_tags(self.work, "pkg-v")
        self.assertEqual(tags, {"1.0.0": self.anchor_sha})

    def test_unchanged_scope_is_not_content_changed(self) -> None:
        self.assertFalse(
            cap.content_changed(
                self.work, self.anchor_sha, scope=("pkg/",),
                excluded=("pkg/pyproject.toml",),
            )
        )

    def test_scope_change_is_detected(self) -> None:
        (self.work / "pkg" / "code.py").write_text("v2\n")
        git("add", "-A", cwd=self.work)
        git("commit", "-q", "-m", "two", cwd=self.work)
        self.assertTrue(
            cap.content_changed(
                self.work, self.anchor_sha, scope=("pkg/",),
                excluded=("pkg/pyproject.toml",),
            )
        )

    def test_out_of_scope_change_is_not_movement(self) -> None:
        (self.work / "other.txt").write_text("y\n")
        git("add", "-A", cwd=self.work)
        git("commit", "-q", "-m", "two", cwd=self.work)
        self.assertFalse(
            cap.content_changed(
                self.work, self.anchor_sha, scope=("pkg/",),
                excluded=("pkg/pyproject.toml",),
            )
        )

    def test_excluded_manifest_change_is_not_movement(self) -> None:
        # The fixed-point construction: a version bump alone never
        # re-triggers content change.
        (self.work / "pkg" / "pyproject.toml").write_text(
            '[project]\nname = "pkg"\nversion = "1.0.1"\n'
        )
        git("add", "-A", cwd=self.work)
        git("commit", "-q", "-m", "bump", cwd=self.work)
        self.assertFalse(
            cap.content_changed(
                self.work, self.anchor_sha, scope=("pkg/",),
                excluded=("pkg/pyproject.toml",),
            )
        )

    def test_manifest_version_reads_toml_and_json(self) -> None:
        self.assertEqual(
            cap.manifest_version(self.work / "pkg" / "pyproject.toml"), "1.0.0"
        )
        pkg_json = self.work / "package.json"
        pkg_json.write_text('{"name": "x", "version": "2.3.4"}\n')
        self.assertEqual(cap.manifest_version(pkg_json), "2.3.4")

    def test_annotated_anchor_tag_peels(self) -> None:
        (self.work / "pkg" / "code.py").write_text("v2\n")
        git("add", "-A", cwd=self.work)
        git("commit", "-q", "-m", "two", cwd=self.work)
        sha2 = git("rev-parse", "HEAD", cwd=self.work)
        git("tag", "-a", "-m", "note", "pkg-v1.0.1", cwd=self.work)
        git("push", "-q", "origin", "refs/tags/pkg-v1.0.1", cwd=self.work)
        tags = cap.discover_anchor_tags(self.work, "pkg-v")
        self.assertEqual(tags["1.0.1"], sha2)

    def test_non_grammar_tag_is_excluded_not_fatal(self) -> None:
        git("tag", "pkg-vlatest", cwd=self.work)
        git("push", "-q", "origin", "refs/tags/pkg-vlatest", cwd=self.work)
        tags = cap.discover_anchor_tags(self.work, "pkg-v")
        self.assertEqual(set(tags), {"1.0.0"})


if __name__ == "__main__":
    unittest.main()
