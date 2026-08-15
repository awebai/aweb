"""Captured-world assembly from canonical metadata (aben R3).

assemble_captured_world walks the canonical ARTIFACTS entries and builds
the CapturedWorld the pure normalizer consumes: anchors from the
repository, registry occupancy through injected discoverers, manifest
versions from version_source, content_changed against the newest anchor
commit over the canonical scope with the fixed-point exclusions.
Hermetic: a real local git remote plus injected registry discoverers.
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
    # The default branch is PINNED here, not at call sites: git's
    # init.defaultBranch differs between a developer host and the gate
    # container, and an unpinned bare remote ends up with HEAD on a
    # branch nothing was pushed to - so a later clone checks out
    # NOTHING and `commit -am` fails with "nothing to commit". Same
    # shape as the identity: a host setting the container does not have.
    if args and args[0] == "init" and not any(
        a in ("-b", "--initial-branch") for a in args
    ):
        args = (args[0], "-b", "main") + tuple(args[1:])
    return subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


class Assembly(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.remote = root / "remote.git"
        git("init", "-q", "--bare", str(self.remote), cwd=root)
        self.repo = root / "repo"
        git("init", "-q", str(self.repo), cwd=root)
        (self.repo / "pkg").mkdir()
        (self.repo / "pkg" / "code.py").write_text("v1\n")
        (self.repo / "pkg" / "pyproject.toml").write_text(
            '[project]\nname = "pkg"\nversion = "1.0.0"\n'
        )
        git("add", "-A", cwd=self.repo)
        git("commit", "-q", "-m", "one", cwd=self.repo)
        git("remote", "add", "origin", str(self.remote), cwd=self.repo)
        git("push", "-q", "origin", "HEAD:main", cwd=self.repo)
        git("tag", "pkg-v1.0.0", cwd=self.repo)
        git("push", "-q", "origin", "refs/tags/pkg-v1.0.0", cwd=self.repo)
        self.sha = git("rev-parse", "HEAD", cwd=self.repo)

        self.spec = cap.CaptureSpec(
            name="pkg",
            repo_key="aweb",
            manifest_path="pkg/pyproject.toml",
            derivation="manifest",
            scope=("pkg/",),
            excluded=(),
            masked=("pkg/pyproject.toml",),
            tag_prefixes={},
            anchor_kind="tag_pattern",
            anchor_value="pkg-v",
            unit_targets=("pypi:pkg",),
        )

    def tearDown(self):
        self._tmp.cleanup()

    def assemble(self, discoverers=None):
        return cap.assemble_captured_world(
            specs=[self.spec],
            repo_roots={"aweb": self.repo},
            discover_target=discoverers
            or (lambda target: {"1.0.0": None}),
            equality_groups=(),
            compatibility="none",
        )

    def test_clean_world_assembles_unmoved_inputs(self) -> None:
        world = self.assemble()
        artifact = world.artifacts["pkg"]
        self.assertEqual(artifact.manifest_version, "1.0.0")
        self.assertFalse(artifact.content_changed)
        self.assertEqual(artifact.anchor_versions, {"1.0.0": self.sha})
        self.assertEqual(artifact.members[0].occupied, {"1.0.0": None})

    def test_scope_change_flows_into_the_world(self) -> None:
        (self.repo / "pkg" / "code.py").write_text("v2\n")
        git("add", "-A", cwd=self.repo)
        git("commit", "-q", "-m", "two", cwd=self.repo)
        world = self.assemble()
        self.assertTrue(world.artifacts["pkg"].content_changed)

    def test_discoverer_occupancy_reaches_members(self) -> None:
        world = self.assemble(
            discoverers=lambda target: {"1.0.0": None, "1.0.1": None}
        )
        self.assertEqual(
            world.artifacts["pkg"].members[0].occupied,
            {"1.0.0": None, "1.0.1": None},
        )

    def test_no_anchor_yet_means_content_changed_from_origin(self) -> None:
        # A brand-new artifact with no published anchor: everything it
        # has is new content.
        spec = cap.CaptureSpec(
            name="fresh",
            repo_key="aweb",
            manifest_path="pkg/pyproject.toml",
            derivation="manifest",
            scope=("pkg/",),
            excluded=(),
            masked=("pkg/pyproject.toml",),
            tag_prefixes={},
            anchor_kind="tag_pattern",
            anchor_value="fresh-v",
            unit_targets=("pypi:fresh",),
        )
        world = cap.assemble_captured_world(
            specs=[spec],
            repo_roots={"aweb": self.repo},
            discover_target=lambda target: {},
            equality_groups=(),
            compatibility="none",
        )
        self.assertTrue(world.artifacts["fresh"].content_changed)


class TagHistoryVersionSource(unittest.TestCase):
    """The first real prepare stopped aw-cli with
    manifest-version-behind-public because capture read
    cli/go/npm/aw/package.json - a PUBLISH-TIME PLACEHOLDER reading
    0.0.0 - as its version, and the movement table compared that
    against the published 1.34.7. aw-cli's version source is the aw-v
    tag history (docs/release.md's artifact table says so); the
    placeholder was never a version at all."""

    def test_tag_history_version_comes_from_the_tags_not_the_placeholder(self) -> None:
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "r"
            repo.mkdir()

            def run_git(*args):
                subprocess.run(
                    ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
                    cwd=repo, check=True, capture_output=True,
                )

            run_git("init", "-q", "-b", "main")
            manifest = repo / "cli" / "go" / "npm" / "aw"
            manifest.mkdir(parents=True)
            # The real placeholder shape, verbatim.
            (manifest / "package.json").write_text('{"name": "aw", "version": "0.0.0"}\n')
            run_git("add", "-A")
            run_git("commit", "-q", "-m", "cli")
            for tag in ("aw-v1.34.5", "aw-v1.34.6", "aw-v1.34.7"):
                run_git("tag", tag)
            run_git("remote", "add", "origin", str(repo))
            spec = cap.CaptureSpec(
                name="aw-cli", repo_key="aweb",
                manifest_path="cli/go/npm/aw/package.json",
                derivation="tag-history", scope=("cli/go/",), excluded=(),
                masked=("cli/go/npm/aw/package.json",),
                tag_prefixes={},
                anchor_kind="tag_pattern", anchor_value="aw-v",
                unit_targets=("npm:@awebai/aw",),
            )
            world = cap.assemble_captured_world(
                specs=[spec], repo_roots={"aweb": repo},
                discover_target=lambda target: {"1.34.7": None},
                equality_groups=(), compatibility="none",
            )
        captured = world.artifacts["aw-cli"]
        self.assertEqual(captured.manifest_version, "1.34.7")
        self.assertNotEqual(captured.manifest_version, "0.0.0")


class OnlyMalformedAnchors(unittest.TestCase):
    """C5, plan-critic's pkg-v0.3 reproduction: a repository whose only
    anchor tag is a near-match must reach the reconciler's named stop,
    never a ValueError from an empty max.

    The narrowing SUPERSEDES this case's original rationale (their
    ruling says so): a near-match is no longer stopped for being
    malformed, it is stopped for being unplaceable - this unit carries
    no conforming version to compare it against, so it cannot be proven
    below anything. Where a conforming candidate does exist, the same
    tag would be history.
    """

    def test_world_with_only_near_match_anchors_stops_by_name(self) -> None:
        import subprocess
        import tempfile

        import release_normalizer as rn

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "r"
            repo.mkdir()

            def run_git(*args):
                subprocess.run(
                    ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
                    cwd=repo,
                    check=True,
                    capture_output=True,
                )

            run_git("init", "-q", "-b", "main")
            (repo / "pkg").mkdir()
            (repo / "pkg" / "pyproject.toml").write_text(
                '[project]\nname = "pkg"\nversion = "0.3.1"\n'
            )
            run_git("add", "-A")
            run_git("commit", "-q", "-m", "x")
            run_git("tag", "pkg-v0.3")
            run_git("remote", "add", "origin", str(repo))
            spec = cap.CaptureSpec(
                name="pkg",
                repo_key="aweb",
                manifest_path="pkg/pyproject.toml",
                derivation="manifest",
                scope=("pkg/",),
                excluded=(),
                masked=("pkg/pyproject.toml",),
                tag_prefixes={},
                anchor_kind="tag_pattern",
                anchor_value="pkg-v",
                unit_targets=("pypi:pkg",),
            )
            world = cap.assemble_captured_world(
                specs=[spec],
                repo_roots={"aweb": repo},
                discover_target=lambda target: {},
                equality_groups=(),
                compatibility="none",
            )
            result = rn.normalize(world)
        self.assertEqual(result.outcome, "stop")
        self.assertIn(
            ("malformed-version-candidate", "pkg"),
            [(s.code, s.artifact) for s in result.stops],
        )


if __name__ == "__main__":
    unittest.main()
