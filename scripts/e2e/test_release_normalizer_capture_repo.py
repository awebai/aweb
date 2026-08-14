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

    def test_dependency_only_manifest_change_is_movement(self) -> None:
        # A3: the manifest stays IN scope with only the owned version
        # field masked; a dependency edit is shipped content.
        (self.work / "pkg" / "pyproject.toml").write_text(
            '[project]\nname = "pkg"\nversion = "1.0.0"\n'
            'dependencies = ["dep>=2"]\n'
        )
        git("add", "-A", cwd=self.work)
        git("commit", "-q", "-m", "dep floor", cwd=self.work)
        self.assertTrue(
            cap.content_changed(
                self.work, self.anchor_sha, scope=("pkg/",),
                excluded=(), masked=("pkg/pyproject.toml",),
            )
        )

    def test_version_only_manifest_change_is_masked_not_movement(self) -> None:
        # The fixed-point half: the normalizer's own version patch must
        # not read back as content change.
        (self.work / "pkg" / "pyproject.toml").write_text(
            '[project]\nname = "pkg"\nversion = "1.0.1"\n'
        )
        git("add", "-A", cwd=self.work)
        git("commit", "-q", "-m", "bump", cwd=self.work)
        self.assertFalse(
            cap.content_changed(
                self.work, self.anchor_sha, scope=("pkg/",),
                excluded=(), masked=("pkg/pyproject.toml",),
            )
        )

    def test_package_json_dependency_change_is_movement_version_is_not(self) -> None:
        pkg_json = self.work / "pkg" / "package.json"
        pkg_json.write_text(
            '{\n  "name": "pkg",\n  "version": "2.0.0",\n'
            '  "dependencies": {"dep": "^1"}\n}\n'
        )
        git("add", "-A", cwd=self.work)
        git("commit", "-q", "-m", "npm manifest", cwd=self.work)
        anchor = git("rev-parse", "HEAD", cwd=self.work)
        pkg_json.write_text(
            '{\n  "name": "pkg",\n  "version": "2.0.1",\n'
            '  "dependencies": {"dep": "^1"}\n}\n'
        )
        git("add", "-A", cwd=self.work)
        git("commit", "-q", "-m", "bump only", cwd=self.work)
        self.assertFalse(
            cap.content_changed(
                self.work, anchor, scope=("pkg/",),
                excluded=(), masked=("pkg/package.json",),
            )
        )
        pkg_json.write_text(
            '{\n  "name": "pkg",\n  "version": "2.0.1",\n'
            '  "dependencies": {"dep": "^2"}\n}\n'
        )
        git("add", "-A", cwd=self.work)
        git("commit", "-q", "-m", "dep moves", cwd=self.work)
        self.assertTrue(
            cap.content_changed(
                self.work, anchor, scope=("pkg/",),
                excluded=(), masked=("pkg/package.json",),
            )
        )

    def test_json_mask_is_structural_not_first_occurrence(self) -> None:
        # release-review's A3 hardening: a dependencies block placed
        # BEFORE the top-level version must not absorb the mask - a
        # first-occurrence mask would normalize the dependency's version
        # and read a dependency move as silence, the phantom direction.
        pkg_json = self.work / "pkg" / "package.json"
        pkg_json.write_text(
            '{\n  "overrides": {\n    "dep": {\n      "version": "9.9.9"\n'
            '    }\n  },\n  "version": "2.0.0"\n}\n'
        )
        git("add", "-A", cwd=self.work)
        git("commit", "-q", "-m", "deps before version", cwd=self.work)
        anchor = git("rev-parse", "HEAD", cwd=self.work)
        pkg_json.write_text(
            '{\n  "overrides": {\n    "dep": {\n      "version": "9.9.10"\n'
            '    }\n  },\n  "version": "2.0.0"\n}\n'
        )
        git("add", "-A", cwd=self.work)
        git("commit", "-q", "-m", "nested dep version moves", cwd=self.work)
        self.assertTrue(
            cap.content_changed(
                self.work, anchor, scope=("pkg/",),
                excluded=(), masked=("pkg/package.json",),
            )
        )
        pkg_json.write_text(
            '{\n  "overrides": {\n    "dep": {\n      "version": "9.9.10"\n'
            '    }\n  },\n  "version": "2.0.1"\n}\n'
        )
        git("add", "-A", cwd=self.work)
        git("commit", "-q", "-m", "own version bump only", cwd=self.work)
        anchor2 = git("rev-parse", "HEAD~1", cwd=self.work)
        self.assertFalse(
            cap.content_changed(
                self.work, anchor2, scope=("pkg/",),
                excluded=(), masked=("pkg/package.json",),
            )
        )

    def test_manifest_absent_at_anchor_is_movement(self) -> None:
        # A masked file that did not exist at the anchor is new content.
        (self.work / "pkg" / "package.json").write_text(
            '{"name": "pkg", "version": "0.1.0"}\n'
        )
        git("add", "-A", cwd=self.work)
        git("commit", "-q", "-m", "new manifest", cwd=self.work)
        self.assertTrue(
            cap.content_changed(
                self.work, self.anchor_sha, scope=("pkg/",),
                excluded=(), masked=("pkg/package.json",),
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
