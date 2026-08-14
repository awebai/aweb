"""Entry-point routing contract (aben R3): every canonical unit target
spelling routes to a discoverer, and unknown spellings raise."""

from __future__ import annotations

import sys
import unittest
from unittest import mock
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_normalizer_capture as cap  # noqa: E402
import release_normalizer_main as main  # noqa: E402
import release_train as rt  # noqa: E402


class Routing(unittest.TestCase):
    def test_every_canonical_unit_target_routes(self) -> None:
        # Image targets carry their revision identity out of discovery;
        # listing-only targets (pypi/npm/github) are identityless.
        specs = cap.derive_capture_specs(rt.ARTIFACTS)
        with mock.patch.multiple(
            cap,
            discover_pypi_versions=lambda *a, **k: {"1.0.0"},
            discover_npm_versions=lambda *a, **k: {"1.0.0"},
            discover_ghcr_versions=lambda *a, **k: {"1.0.0"},
            discover_github_release_versions=lambda *a, **k: {"1.0.0"},
            read_oci_revision=lambda *a, **k: "a" * 40,
        ):
            for spec in specs:
                for target in spec.unit_targets:
                    with self.subTest(target=target):
                        occupied = main.route_discovery(
                            target,
                            timeout=1,
                            ghcr_token="",
                            gh_token="",
                            bases=main.registry_bases(),
                        )
                        expected = (
                            {"1.0.0": "a" * 40}
                            if target.startswith("ghcr.io/")
                            else {"1.0.0": None}
                        )
                        self.assertEqual(occupied, expected)

    def test_unknown_spelling_raises_not_skips(self) -> None:
        with self.assertRaises(ValueError):
            main.route_discovery(
                "render:something",
                timeout=1,
                ghcr_token="",
                gh_token="",
                bases=main.registry_bases(),
            )

    def test_exit_reobservation_covers_every_declared_target(self) -> None:
        # A4: the exit re-observation must ask about EVERY unit target,
        # not the primary alone - a composite whose intent got occupied
        # on a secondary member mid-run is the same race with the same
        # name.
        specs = cap.derive_capture_specs(rt.ARTIFACTS)
        skills_spec = next(s for s in specs if s.name == "skills")
        secondary = skills_spec.unit_targets[1]
        queried: list[str] = []

        def discover(target: str):
            queried.append(target)
            return {"0.2.14": None} if target == secondary else {}

        rn = __import__("release_normalizer")
        result = rn.NormalizerResult(
            outcome="patch-needed",
            artifacts={
                "skills": rn.ArtifactResult(
                    disposition="moving", version="0.2.14"
                )
            },
            patches=(("skills", "0.2.13", "0.2.14"),),
            stops=(),
        )
        stops = main.reobserve_result(result, specs, discover)
        self.assertEqual([(s.code, s.artifact) for s in stops],
                         [("version-occupied", "skills")])
        self.assertEqual(set(queried), set(skills_spec.unit_targets))

    def test_default_invariant_commands_are_the_designed_three(self) -> None:
        # A4: the env override exists for hermetic entry tests; the
        # production defaults are the design's exact selectors, pinned
        # here so the override can never quietly become the real path.
        root = Path("/x")
        commands = main.invariant_commands(root)
        by_label = {label: (argv, cwd) for label, argv, cwd in commands}
        self.assertEqual(
            set(by_label), {"python-locks", "migration-chain", "suite-map"}
        )
        self.assertEqual(
            by_label["python-locks"][0], ("bash", "scripts/check-python-locks.sh")
        )
        self.assertEqual(by_label["python-locks"][1], root)
        self.assertIn(
            "tests/test_package_data.py::"
            "test_canonical_chain_starts_with_reset_baseline_then_forward_migrations",
            by_label["migration-chain"][0],
        )
        self.assertEqual(by_label["migration-chain"][1], root / "server")
        self.assertIn(
            "scripts.e2e.test_release_gate_contract."
            "ThinReleaseWorkflowContractTests."
            "test_dead_hosted_gate_and_component_paths_are_deleted",
            by_label["suite-map"][0],
        )

    def test_recovery_reobservation_classifies_progress_vs_conflict(self) -> None:
        # C5: a recovery candidate's occupancy may only have grown
        # identically to what capture saw - a member completing with a
        # captured identity is progress; a changed identity on an
        # already-occupied member, or a foreign identity appearing, is
        # registry-conflict, never silence.
        rn = __import__("release_normalizer")
        specs = cap.derive_capture_specs(rt.ARTIFACTS)
        good = "a" * 40
        foreign = "b" * 40

        def world_with(occupied_by_target):
            return rn.CapturedWorld(
                artifacts={
                    "a2a-gateway-image": rn.CapturedArtifact(
                        manifest_version="1.27.2",
                        content_changed=True,
                        derivation="manifest",
                        members=[
                            rn.UnitMember(name, dict(occ))
                            for name, occ in occupied_by_target.items()
                        ],
                        anchor_versions={"1.27.1": good},
                    )
                },
                equality_groups=(),
                compatibility="none",
            )

        result = rn.NormalizerResult(
            outcome="normal-form",
            artifacts={
                "a2a-gateway-image": rn.ArtifactResult(
                    disposition="moving-with-recovery",
                    version="1.27.2",
                    previous_complete_anchor=("1.27.1", good),
                )
            },
            patches=(),
            stops=(),
        )
        target = "ghcr.io/awebai/a2a-gateway"
        captured = world_with({target: {"1.27.2": good}})

        # Unchanged occupancy: no stop.
        stops = main.reobserve_result(
            result, specs, lambda t: {"1.27.2": good}, captured
        )
        self.assertEqual(stops, [])
        # Occupancy APPEARED since capture: nothing has published yet at
        # this phase, so any growth is the world moving - conflict, and
        # the rerun recomputes.
        empty_capture = world_with({target: {}})
        stops = main.reobserve_result(
            result, specs, lambda t: {"1.27.2": good}, empty_capture
        )
        self.assertEqual(
            [(s.code, s.artifact) for s in stops],
            [("registry-conflict", "a2a-gateway-image")],
        )
        # Identity changed under the run: conflict.
        stops = main.reobserve_result(
            result, specs, lambda t: {"1.27.2": foreign}, captured
        )
        self.assertEqual(
            [(s.code, s.artifact) for s in stops],
            [("registry-conflict", "a2a-gateway-image")],
        )
        # Occupancy VANISHED since capture: the same movement, the same
        # name.
        stops = main.reobserve_result(
            result, specs, lambda t: {}, captured
        )
        self.assertEqual(
            [(s.code, s.artifact) for s in stops],
            [("registry-conflict", "a2a-gateway-image")],
        )

    def test_equality_groups_are_the_canonical_pairs(self) -> None:
        self.assertEqual(
            main.EQUALITY_GROUPS,
            (("awid-service", "awid-image"), ("aweb-server", "a2a-gateway-image")),
        )


if __name__ == "__main__":
    unittest.main()
