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


def load_world(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())["artifacts"]


def reconcile_recorded(artifacts: dict, name: str, intent: str):
    recorded = artifacts[name]
    return rn.reconcile_unit(
        members=[
            rn.UnitMember(m["name"], dict(m["occupied"]))
            for m in recorded["members"]
        ],
        anchor_versions=dict(recorded["anchor_versions"]),
        manifest_intent=intent,
    )


class B2StaleCliVersion(unittest.TestCase):
    PRIMARY = "b2-stale-cli-version.json"
    CONTROL = "b2-stale-cli-version.control-unpublished.json"
    # The row's premise, and it holds in both arms: the manifest still
    # carries the pre-authorized 1.34.5. Everything the derivation reads
    # beyond it comes from the fixture, so the fixture is the only thing
    # that differs between the two arms.
    MANIFEST_INTENT = "1.34.5"

    def derive(self, fixture_name: str) -> rn.MovementDecision:
        artifacts = load_world(fixture_name)
        recorded = artifacts["aw-cli"]
        reconciliation = reconcile_recorded(artifacts, "aw-cli", self.MANIFEST_INTENT)
        self.assertEqual(reconciliation.state, "reconciled")
        occupied = frozenset(
            v for m in recorded["members"] for v in m["occupied"]
        ) | set(recorded["anchor_versions"])
        return rn.movement_decision(
            content_changed=True,
            manifest_version=self.MANIFEST_INTENT,
            reconciled_p=reconciliation.p,
            occupied_versions=occupied,
            compatibility="none",
            derivation="tag-history",
        )

    def test_recorded_world_rederives_the_next_free_patch(self) -> None:
        decision = self.derive(self.PRIMARY)
        self.assertEqual(decision.kind, "moving")
        self.assertEqual(decision.version, "1.34.6")

    def test_control_unpublished_accepts_the_original_intent(self) -> None:
        decision = self.derive(self.CONTROL)
        self.assertEqual(decision.kind, "moving")
        self.assertEqual(decision.version, "1.34.5")

    def test_the_control_differs_only_in_whether_1_34_5_occupies(self) -> None:
        # The control's discriminating power is exactly this property,
        # and nothing else in the pair enforces it: a control that also
        # drops the prior history answers a different question (the
        # no-history refusal) while still looking like a control.
        primary = load_world(self.PRIMARY)["aw-cli"]
        control = load_world(self.CONTROL)["aw-cli"]
        without_the_candidate = {
            "members": [
                {
                    "name": m["name"],
                    "occupied": {
                        v: i for v, i in m["occupied"].items() if v != "1.34.5"
                    },
                }
                for m in primary["members"]
            ],
            "anchor_versions": {
                v: i
                for v, i in primary["anchor_versions"].items()
                if v != "1.34.5"
            },
        }
        self.assertEqual(
            {k: control[k] for k in without_the_candidate}, without_the_candidate
        )


class B4ImpossibleShape(unittest.TestCase):
    MANIFESTS = {"aweb-server": "1.27.2", "a2a-gateway-image": "1.27.3"}

    def group(self, artifacts, manifests):
        return rn.group_decision(
            members=[
                rn.GroupMember(
                    name=name,
                    reconciliation=reconcile_recorded(
                        artifacts, name, manifests[name]
                    ),
                    content_changed=True,
                )
                for name in ("aweb-server", "a2a-gateway-image")
            ],
            manifest_versions=manifests,
            compatibility="none",
        )

    def test_the_impossible_shape_refuses_before_any_card(self) -> None:
        artifacts = load_world("b4-impossible-pre-registered-shape.json")
        decision = self.group(artifacts, self.MANIFESTS)
        self.assertEqual(decision.kind, "stop")
        self.assertEqual(decision.stop, "equality-invariant-violated")

    def test_control_lagging_absent_reuses_m_with_no_patch(self) -> None:
        artifacts = load_world(
            "b4-impossible-pre-registered-shape.control-lagging-absent.json"
        )
        manifests = {"aweb-server": "1.27.2", "a2a-gateway-image": "1.27.2"}
        decision = self.group(artifacts, manifests)
        self.assertEqual(decision.kind, "shared-candidate")
        self.assertEqual(decision.version, "1.27.2")
        self.assertIsNone(decision.patch)
        self.assertIn("a2a-gateway-image", decision.recovering)

    def test_control_lagging_conflicting_mints_once_with_driver(self) -> None:
        artifacts = load_world(
            "b4-impossible-pre-registered-shape.control-lagging-conflicting.json"
        )
        manifests = {"aweb-server": "1.27.2", "a2a-gateway-image": "1.27.2"}
        decision = self.group(artifacts, manifests)
        self.assertEqual(decision.kind, "shared-candidate")
        self.assertEqual(decision.version, "1.27.3")
        self.assertEqual(
            decision.patch,
            (
                ("a2a-gateway-image", "1.27.2", "1.27.3"),
                ("aweb-server", "1.27.2", "1.27.3"),
            ),
        )
        self.assertEqual(decision.driver, "a2a-gateway-image")


class NormalizerDriftRow(unittest.TestCase):
    """The drift stop's data half: the world moved between capture and
    the exit re-observation - version-occupied by its real name, never a
    silent regeneration. The double-compute half is the seam test in
    test_release_normalizer_orchestration (deliberately no data: identical
    inputs are the point)."""

    def test_exit_reobservation_race_stops_by_its_real_name(self) -> None:
        import release_normalizer_run as run

        document = json.loads((FIXTURES / "normalizer-drift.json").read_text())
        capture_world_data = document["artifacts"]["awid-service"]
        exit_world_data = document["exit_reobservation"]["artifacts"]["awid-service"]

        def world(recorded, manifest, changed):
            return rn.CapturedWorld(
                artifacts={
                    "awid-service": rn.CapturedArtifact(
                        manifest_version=manifest,
                        content_changed=changed,
                        derivation="manifest",
                        members=[
                            rn.UnitMember(m["name"], dict(m["occupied"]))
                            for m in recorded["members"]
                        ],
                        anchor_versions=dict(recorded["anchor_versions"]),
                    )
                },
                equality_groups=(),
                compatibility="none",
            )

        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "pyproject.toml"
            manifest.write_text('[project]\nname = "awid-service"\nversion = "0.5.15"\n')

            def reobserve(result):
                exit_occupied = {
                    v
                    for m in exit_world_data["members"]
                    for v in m["occupied"]
                }
                stops = []
                for name, artifact in result.artifacts.items():
                    if artifact.disposition == "moving" and artifact.version in exit_occupied:
                        stops.append(rn.Stop("version-occupied", name))
                return stops

            def recapture():
                import tomllib

                version = tomllib.load(manifest.open("rb"))["project"]["version"]
                return world(capture_world_data, version, changed=True)

            outcome = run.run_normalizer(
                capture=lambda: world(capture_world_data, "0.5.15", changed=True),
                manifest_paths={"awid-service": manifest},
                reobserve=reobserve,
                normalize=rn.normalize,
                recapture=recapture,
            )
        self.assertEqual(outcome.exit_code, run.STOP)
        self.assertIn("version-occupied", outcome.report)
