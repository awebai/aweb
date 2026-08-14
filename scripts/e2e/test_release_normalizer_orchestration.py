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
