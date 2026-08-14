"""R6: the Column B red-first assembly (aben design section 9).

B1 runs the real engine against the real repositories at the pinned
historical SHAs with dev2's recorded registry halves: the normalizer
must emit the exact expected patch, per artifact, per version - a
resolver emitting any other version fails the fixture. The
no-scope-change control variant must yield no row for that artifact.

Requires the local aweb/ac repositories to contain the pinned commits
(they are ancestors of main); skips only if a checkout genuinely lacks
them, and says so.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_normalizer as rn  # noqa: E402
import release_normalizer_capture as cap  # noqa: E402

FIXTURES = REPO_ROOT / "scripts" / "e2e" / "fixtures" / "aben-column-b"
AWEB_B1_SHA = "5a55f7ce6b4dbb86dc2901f7c687e172e39db3af"
AC_B1_SHA = "47060200c53d30835cbb35cbcb5d073cbe3dc5d3"


def historical_checkout(source: Path, sha: str, destination: Path) -> Path:
    subprocess.run(
        ["git", "clone", "-q", "--shared", "--no-checkout", str(source), str(destination)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(destination), "checkout", "-q", sha],
        check=True,
        capture_output=True,
    )
    # The historical tree needs an origin for anchor-tag discovery; the
    # source repository's refs serve as that origin.
    subprocess.run(
        ["git", "-C", str(destination), "remote", "set-url", "origin", str(source)],
        check=True,
        capture_output=True,
    )
    return destination


def registry_half(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())["artifacts"]


class B1NarrowCard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        root = Path(cls._tmp.name)
        ac_source = REPO_ROOT.parent / "ac-worktree"
        for repo, sha in ((REPO_ROOT, AWEB_B1_SHA), (ac_source, AC_B1_SHA)):
            probe = subprocess.run(
                ["git", "-C", str(repo), "cat-file", "-e", f"{sha}^{{commit}}"],
                capture_output=True,
            )
            if probe.returncode != 0:
                raise unittest.SkipTest(
                    f"{repo} lacks pinned commit {sha[:8]} - B1 needs the history"
                )
        cls.aweb = historical_checkout(REPO_ROOT, AWEB_B1_SHA, root / "aweb")
        cls.ac = historical_checkout(ac_source, AC_B1_SHA, root / "ac")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def normalize_b1(self, fixture_name: str) -> rn.NormalizerResult:
        recorded = registry_half(fixture_name)
        specs = cap.derive_capture_specs(__import__("release_train").ARTIFACTS)
        # Only the three B1 artifacts are under test; the rest of the
        # world is held reconciled-at-manifest so their rows are quiet.
        world_artifacts = {}
        for spec in specs:
            repo = {"aweb": self.aweb, "ac": self.ac}[spec.repo_key]
            manifest = cap.manifest_version(repo / spec.manifest_path)
            if spec.name in recorded:
                members = [
                    rn.UnitMember(m["name"], dict(m["occupied"]))
                    for m in recorded[spec.name]["members"]
                ]
                anchors = dict(recorded[spec.name]["anchor_versions"])
                anchor_commit = anchors.get(max(anchors)) if anchors else None
                changed = (
                    cap.content_changed(
                        repo,
                        anchor_commit,
                        scope=spec.scope,
                        excluded=spec.excluded,
                    )
                    if anchor_commit
                    else True
                )
            else:
                members = [rn.UnitMember(t, {manifest: None}) for t in spec.unit_targets]
                anchors = {manifest: "f" * 40}
                changed = False
            world_artifacts[spec.name] = rn.CapturedArtifact(
                manifest_version=manifest,
                content_changed=changed,
                derivation=spec.derivation,
                members=members,
                anchor_versions=anchors,
            )
        world = rn.CapturedWorld(
            artifacts=world_artifacts,
            equality_groups=(
                ("awid-service", "awid-image"),
                ("aweb-server", "a2a-gateway-image"),
            ),
            compatibility="none",
        )
        return rn.normalize(world)

    def test_b1_emits_the_exact_expected_patch(self) -> None:
        result = self.normalize_b1("b1-narrow-card.json")
        patches = {name: (a, b) for name, a, b in result.patches}
        self.assertEqual(patches.get("awid-service"), ("0.5.15", "0.5.16"))
        self.assertEqual(patches.get("awid-image"), ("0.5.15", "0.5.16"))
        self.assertEqual(patches.get("ac-image"), ("0.7.14", "0.7.15"))
        self.assertEqual(result.outcome, "patch-needed")

    def test_b1_control_no_scope_change_yields_no_ac_row(self) -> None:
        # The control variant anchors AC's scope at the fixture commit
        # itself: no content since the anchor, no AC row in the patch.
        recorded = registry_half("b1-narrow-card.json")
        recorded["ac-image"]["anchor_versions"] = {"0.7.14": AC_B1_SHA}
        control = FIXTURES / "b1-narrow-card.control.json"
        control.write_text(json.dumps({"artifacts": recorded}))
        try:
            result = self.normalize_b1("b1-narrow-card.control.json")
            patch_names = {name for name, _a, _b in result.patches}
            self.assertNotIn("ac-image", patch_names)
            self.assertIn("awid-service", patch_names)
        finally:
            control.unlink()


if __name__ == "__main__":
    unittest.main()
