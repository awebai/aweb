"""The normalizer's orchestration (aben R3, design sections 6 and 8).

run_normalizer: capture once, compute twice from the captured world
(byte-identical or the drift stop), apply allowlisted patches to the
working tree only, fixed-point second pass, exit re-observation, stdout
report, and the three exit codes. Hermetic: capture and re-observation
are injected callables; the working tree is a real temporary repo.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_normalizer as rn  # noqa: E402
import release_normalizer_run as run  # noqa: E402


def captured_world(manifest: str, *, changed: bool) -> rn.CapturedWorld:
    return rn.CapturedWorld(
        artifacts={
            "pkg": rn.CapturedArtifact(
                manifest_version=manifest,
                content_changed=changed,
                derivation="manifest",
                members=[rn.UnitMember("pypi:pkg", {"1.0.0": None})],
                anchor_versions={"1.0.0": "sha-a"},
            )
        },
        equality_groups=(),
        compatibility="none",
    )


class Orchestration(unittest.TestCase):
    def setUp(self):
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "pkg").mkdir()
        self.manifest = self.root / "pkg" / "pyproject.toml"
        self.manifest.write_text('[project]\nname = "pkg"\nversion = "1.0.0"\n')

    def tearDown(self):
        self._tmp.cleanup()

    def live_recapture(self, *, changed: bool):
        def recapture():
            import tomllib

            with self.manifest.open("rb") as handle:
                version = tomllib.load(handle)["project"]["version"]
            return captured_world(version, changed=changed)

        return recapture

    def outcome(self, world, *, reobserve=None, recapture=None):
        return run.run_normalizer(
            capture=lambda: world,
            manifest_paths={"pkg": self.manifest},
            reobserve=reobserve or (lambda result, world=None: []),
            normalize=rn.normalize,
            recapture=recapture,
        )

    def test_normal_form_exits_zero_and_edits_nothing(self) -> None:
        before = self.manifest.read_text()
        outcome = self.outcome(captured_world("1.0.0", changed=False))
        self.assertEqual(outcome.exit_code, 0)
        self.assertEqual(self.manifest.read_text(), before)
        self.assertIn("normal form", outcome.report)

    def test_patch_needed_edits_working_tree_and_reports_diff(self) -> None:
        outcome = self.outcome(
            captured_world("1.0.0", changed=True),
            recapture=self.live_recapture(changed=True),
        )
        self.assertEqual(outcome.exit_code, run.PATCH_NEEDED)
        self.assertIn('version = "1.0.1"', self.manifest.read_text())
        self.assertIn("pkg", outcome.report)
        self.assertIn("1.0.0 -> 1.0.1", outcome.report)
        self.assertIn("review", outcome.report.lower())

    def test_stop_exits_nonzero_naming_the_code(self) -> None:
        outcome = self.outcome(captured_world("0.9.0", changed=False))
        self.assertEqual(outcome.exit_code, run.STOP)
        self.assertIn("manifest-version-behind-public", outcome.report)

    def test_nondeterministic_compute_is_the_drift_stop(self) -> None:
        calls = {"n": 0}

        def flapping_normalize(world):
            calls["n"] += 1
            manifest = "1.0.0" if calls["n"] == 1 else "1.0.9"
            return rn.normalize(captured_world(manifest, changed=False))

        outcome = run.run_normalizer(
            capture=lambda: captured_world("1.0.0", changed=False),
            manifest_paths={"pkg": self.manifest},
            reobserve=lambda result, world=None: [],
            normalize=flapping_normalize,
        )
        self.assertEqual(outcome.exit_code, run.STOP)
        self.assertIn("normalizer-nondeterminism", outcome.report)

    def test_world_moved_reobservation_wired(self) -> None:
        outcome = run.run_normalizer(
            capture=lambda: captured_world("1.0.0", changed=False),
            manifest_paths={"pkg": self.manifest},
            reobserve=lambda result, world=None: [rn.Stop("version-occupied", "pkg")],
            normalize=rn.normalize,
        )
        self.assertEqual(outcome.exit_code, run.STOP)
        self.assertIn("version-occupied", outcome.report)
        # The code alone is not actionable. This assertion is the one
        # this test was missing when the live prepare printed a bare
        # "STOP version-occupied" and the operator had no subject.
        self.assertIn("version-occupied (pkg)", outcome.report)

    def test_every_stop_rendering_path_names_its_artifact(self) -> None:
        """One owner for stop rendering. The runner rendered stops in
        four places and only one of them kept the artifact, so which
        stops were actionable depended on WHICH PATH produced them -
        the same duplicate-derivation family as the tag prefix and the
        version source. The live prepare hit a lossy path.

        Each case below reaches a different rendering site."""

        stop = rn.Stop("version-occupied", "pkg")
        pristine = self.manifest.read_text()

        def reset():
            # Each case applies patches to the SAME working tree; a case
            # that starts from the previous one's patched manifest is
            # measuring the wrong thing.
            self.manifest.write_text(pristine)
            return True

        # Exit re-observation after a normal-form pass.
        reset()
        normal_form = run.run_normalizer(
            capture=lambda: captured_world("1.0.0", changed=False),
            manifest_paths={"pkg": self.manifest},
            reobserve=lambda result, world=None: [stop],
            normalize=rn.normalize,
        )
        # Exit re-observation after a patch was applied - the path the
        # real prepare took, and the one that printed bare.
        reset()
        after_patch = run.run_normalizer(
            capture=lambda: captured_world("1.0.0", changed=True),
            manifest_paths={"pkg": self.manifest},
            reobserve=lambda result, world=None: [stop],
            normalize=rn.normalize,
            recapture=self.live_recapture(changed=True),
        )
        # A stop raised by the SECOND pass over the patched tree.
        reset()
        followup = run.run_normalizer(
            capture=lambda: captured_world("1.0.0", changed=True),
            manifest_paths={"pkg": self.manifest},
            reobserve=lambda result, world=None: [],
            normalize=rn.normalize,
            recapture=self.live_recapture(changed=False),
        )
        # The engine's own stops, before any patch.
        reset()
        engine = run.run_normalizer(
            capture=lambda: captured_world("0.9.0", changed=False),
            manifest_paths={"pkg": self.manifest},
            reobserve=lambda result, world=None: [],
            normalize=rn.normalize,
        )

        for label, outcome in (
            ("normal-form exit", normal_form),
            ("post-patch exit", after_patch),
            ("followup stop", followup),
            ("engine stop", engine),
        ):
            with self.subTest(path=label):
                self.assertEqual(outcome.exit_code, run.STOP)
                stop_lines = [
                    line for line in outcome.report.splitlines()
                    if line.startswith("STOP ")
                ]
                self.assertTrue(stop_lines, f"{label}: no STOP line at all")
                for line in stop_lines:
                    # Actionable means one of two shapes: the artifact
                    # in parentheses, or a self-describing detail after
                    # a colon. A bare "STOP code" is neither.
                    self.assertRegex(
                        line, r"^STOP [a-z-]+(?: \(.+\)|: .+)",
                        f"{label}: unattributed stop line {line!r}",
                    )

    def test_the_patch_moves_every_declared_version_mirror(self) -> None:
        """The defect the live prepare found AFTER reaching normal form.

        skills carries its version in package.json AND in
        .claude-plugin/plugin.json. The normalizer patched the first
        and left the second at 0.2.12, and prepare refused: "committed
        plugin.json version '0.2.12' must equal package.json version
        '0.2.13'". Refusing was correct - it is a self-contradicting
        tree - but the patch should not have produced one.

        A patched manifest must carry its declared mirrors with it."""

        import json

        mirror = self.root / "pkg" / ".claude-plugin" / "plugin.json"
        mirror.parent.mkdir(parents=True)
        mirror.write_text(json.dumps({"version": "1.0.0"}, indent=2) + "\n")

        outcome = run.run_normalizer(
            capture=lambda: captured_world("1.0.0", changed=True),
            manifest_paths={"pkg": self.manifest},
            version_mirrors={"pkg": (mirror,)},
            reobserve=lambda result, world=None: [],
            normalize=rn.normalize,
            recapture=self.live_recapture(changed=True),
        )
        self.assertEqual(outcome.exit_code, run.PATCH_NEEDED, outcome.report)
        self.assertIn('version = "1.0.1"', self.manifest.read_text())
        self.assertEqual(
            json.loads(mirror.read_text())["version"], "1.0.1",
            "the mirror was left behind - the tree contradicts itself",
        )

    def test_a_lagging_mirror_is_reconciled_even_with_no_version_move(
        self,
    ) -> None:
        """The state my first mirror fix could not escape.

        Mirrors were synced only as part of a version PATCH. So a tree
        whose manifest already sits at the target version while its
        mirror lags produces no patch, no sync, and a guard that
        refuses forever - which is precisely the state a half-applied
        patch leaves behind, and it is unrecoverable except by hand.

        A mirror disagreeing with its manifest is itself a reason to
        patch, independent of whether the version moves."""

        import json

        # The mirror LAGS its manifest. The manifest is already at the
        # published-and-intended version, so nothing moves and nothing
        # would patch - which is how the lag becomes permanent.
        mirror = self.root / "pkg" / ".claude-plugin" / "plugin.json"
        mirror.parent.mkdir(parents=True)
        mirror.write_text(json.dumps({"version": "0.9.0"}, indent=2) + "\n")
        self.manifest.write_text(
            '[project]\nname = "pkg"\nversion = "1.0.0"\n'
        )

        outcome = run.run_normalizer(
            capture=lambda: captured_world("1.0.0", changed=False),
            manifest_paths={"pkg": self.manifest},
            version_mirrors={"pkg": (mirror,)},
            reobserve=lambda result, world=None: [],
            normalize=rn.normalize,
            recapture=self.live_recapture(changed=False),
        )
        self.assertEqual(outcome.exit_code, run.PATCH_NEEDED, outcome.report)
        self.assertEqual(json.loads(mirror.read_text())["version"], "1.0.0")
        self.assertIn("mirror", outcome.report.lower(), outcome.report)

    def test_fixed_point_failure_is_named(self) -> None:
        # A patched world that still wants a patch on the second pass is
        # non-convergent normalization. Simulate by a capture whose
        # manifest read is stale (never reflects the applied patch).
        outcome = run.run_normalizer(
            capture=lambda: captured_world("1.0.0", changed=True),
            manifest_paths={"pkg": self.manifest},
            reobserve=lambda result, world=None: [],
            normalize=rn.normalize,
            recapture=lambda: captured_world("1.0.0", changed=True),
        )
        self.assertEqual(outcome.exit_code, run.STOP)
        self.assertIn("non-convergent", outcome.report)

    def test_fixed_point_success_recaptures_patched_manifest(self) -> None:
        def recapture():
            import tomllib

            with self.manifest.open("rb") as handle:
                manifest = tomllib.load(handle)["project"]["version"]
            return captured_world(manifest, changed=True)

        outcome = run.run_normalizer(
            capture=lambda: captured_world("1.0.0", changed=True),
            manifest_paths={"pkg": self.manifest},
            reobserve=lambda result, world=None: [],
            normalize=rn.normalize,
            recapture=recapture,
        )
        self.assertEqual(outcome.exit_code, run.PATCH_NEEDED)


if __name__ == "__main__":
    unittest.main()
