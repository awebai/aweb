"""Entry-point routing contract (aben R3): every canonical unit target
spelling routes to a discoverer, and unknown spellings raise."""

from __future__ import annotations

import os
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
        # EVERY target is identityless out of discovery. Discovery
        # reports OCCUPANCY - which versions are published, the one
        # fact git cannot answer - and nothing else. Identity comes
        # from the tag in the artifact's own repository, which is
        # asserted at the capture seam (IdentityIsTheTag), not here.
        specs = cap.derive_capture_specs(rt.ARTIFACTS)
        with mock.patch.multiple(
            cap,
            discover_pypi_versions=lambda *a, **k: {"1.0.0"},
            discover_npm_versions=lambda *a, **k: {"1.0.0"},
            discover_ghcr_versions=lambda *a, **k: {"1.0.0"},
            discover_github_release_versions=lambda *a, **k: {"1.0.0"},
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
                        self.assertEqual(occupied, {"1.0.0": None})

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

    def test_complete_group_member_at_m_is_unmoved_not_moving(self) -> None:
        """The live world, measured: in the (aweb-server,
        a2a-gateway-image) group at shared manifest M=1.27.2, the a2a
        member is COMPLETE at M (refs/tags/a2a-gw-v1.27.2 exists) and
        aweb-server is ABSENT at M (no server-v1.27.2, pypi aweb 1.27.2
        404) and complete only at 1.27.1.

        Design section 3 step 3 marks only the LAGGING members
        moving/recovery at M; a member already complete at M is not
        moving, because M is not a version it is about to take - its
        occupancy of M is the PRECONDITION for sharing M. Labelling it
        moving made the exit re-observation read its own existing
        release as a collision, and the real prepare stopped
        version-occupied on a world that is exactly the design's
        reuse-M case.

        group_decision was already correct and its own control passed:
        the defect was one layer out, in turning that decision into
        dispositions, which is why this test runs the seam - normalize
        feeding the real re-observation over the real unit targets.
        """

        rn = __import__("release_normalizer")
        specs = cap.derive_capture_specs(rt.ARTIFACTS)
        server_target = rt._artifact("aweb-server").occupancy_unit[0]
        a2a_target = rt._artifact("a2a-gateway-image").occupancy_unit[0]
        a2a_sha = "e5524b4b" + "0" * 32

        world = rn.CapturedWorld(
            artifacts={
                "aweb-server": rn.CapturedArtifact(
                    manifest_version="1.27.2",
                    # The awid floor bump is a real content change.
                    content_changed=True,
                    derivation="manifest",
                    members=[rn.UnitMember(server_target, {"1.27.1": None})],
                    anchor_versions={"1.27.1": "s" * 40},
                ),
                "a2a-gateway-image": rn.CapturedArtifact(
                    manifest_version="1.27.2",
                    content_changed=False,
                    derivation="manifest",
                    members=[rn.UnitMember(a2a_target, {"1.27.2": a2a_sha})],
                    anchor_versions={"1.27.2": a2a_sha},
                ),
            },
            equality_groups=(("aweb-server", "a2a-gateway-image"),),
            compatibility="none",
        )

        result = rn.normalize(world)
        self.assertEqual(result.outcome, "normal-form")
        self.assertEqual(result.patches, ())
        self.assertEqual(
            result.artifacts["aweb-server"].disposition, "moving-with-recovery"
        )
        self.assertEqual(result.artifacts["aweb-server"].version, "1.27.2")
        self.assertEqual(
            result.artifacts["a2a-gateway-image"].disposition, "unmoved"
        )
        self.assertEqual(
            result.artifacts["a2a-gateway-image"].version, "1.27.2"
        )

        # The decisive assertion: over the SAME world the run observed,
        # the exit re-observation must produce no stop. This is the
        # assertion the live prepare failed.
        occupancy = {server_target: {"1.27.1": None}, a2a_target: {"1.27.2": a2a_sha}}
        stops = main.reobserve_result(
            result, specs, lambda t: occupancy.get(t, {}), world
        )
        self.assertEqual([(s.code, s.artifact) for s in stops], [])

    def test_offline_is_scoped_to_the_invariant_that_resolves(self) -> None:
        """UV_OFFLINE belongs to the check that RESOLVES.

        check-python-locks.sh runs `uv lock` and `uv lock --check`;
        proving those succeed offline is the point of the same-cycle
        lock property. The migration invariant runs `uv run --frozen`,
        which cannot resolve at all - offline there only blocks
        INSTALL, so the check passes or fails on whether the local uv
        cache happens to hold a dependency. That fired in the live run:
        the phase stopped invariant-failed after the lock regeneration
        pulled in a package the cache lacked, and it passed on the next
        run only because a diagnostic had warmed the cache."""

        commands = main.invariant_commands(Path("/x"))
        offline_by_label = {c.label: c.offline for c in commands}
        self.assertTrue(offline_by_label["python-locks"])
        self.assertFalse(offline_by_label["migration-chain"])
        for command in commands:
            if command.offline:
                continue
            with self.subTest(label=command.label):
                # A command exempted from offline must be one that
                # cannot resolve; --frozen is what guarantees that.
                if any(part == "uv" for part in command.argv):
                    self.assertIn("--frozen", command.argv, command.label)

    def test_a_failed_invariant_carries_the_reason_it_captured(self) -> None:
        """The phase captures the invariant's output and then threw it
        away, returning a bare label. Recovering the reason took a
        manual re-run of a command the phase had already run - and an
        operator has no way to know it is recoverable at all."""

        import json

        override = json.dumps([
            {
                "label": "always-fails",
                "argv": ["bash", "-c", "echo NEEDLE-on-stdout; exit 3"],
                "cwd": ".",
            }
        ])
        with mock.patch.dict(
            os.environ, {"AWEB_NORMALIZER_INVARIANT_COMMANDS": override}
        ):
            stop = main.run_invariants(Path("."))
        self.assertIsNotNone(stop)
        assert stop is not None
        self.assertEqual(stop.code, "invariant-failed")
        self.assertEqual(stop.artifact, "always-fails")
        self.assertIn("NEEDLE-on-stdout", stop.detail or "")

    def test_default_invariant_commands_are_the_designed_three(self) -> None:
        # A4: the env override exists for hermetic entry tests; the
        # production defaults are the design's exact selectors, pinned
        # here so the override can never quietly become the real path.
        root = Path("/x")
        commands = main.invariant_commands(root)
        by_label = {c.label: (c.argv, c.cwd) for c in commands}
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
