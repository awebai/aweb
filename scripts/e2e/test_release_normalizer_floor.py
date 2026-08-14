"""A4: the same-cycle consumer floor is part of the pure computation.

Design section 4, R1: when awid-service moves to M, server's floor
literal := M and server/uv.lock re-locks. The floor edit changes
aweb-server's shipped content, so the induced server (and, by equality,
gateway) movement must come out of normalize()'s FIRST computation -
otherwise the fixed-point pass discovers it one pass late and stops
non-convergent. A world with no floor knowledge (None, the direct-built
fixture default) induces nothing; a captured world that could not find
the literal stops by name rather than silently skipping the policy.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_normalizer as rn  # noqa: E402


def artifact(manifest: str, *, changed: bool, occupied: dict, anchors: dict):
    return rn.CapturedArtifact(
        manifest_version=manifest,
        content_changed=changed,
        derivation="manifest",
        members=[rn.UnitMember("t", dict(occupied))],
        anchor_versions=dict(anchors),
    )


def world(*, floor, awid_changed=True, server_changed=False) -> rn.CapturedWorld:
    sha = "a" * 40
    return rn.CapturedWorld(
        artifacts={
            "awid-service": artifact(
                "0.5.15", changed=awid_changed,
                occupied={"0.5.15": None}, anchors={"0.5.15": sha},
            ),
            "awid-image": artifact(
                "0.5.15", changed=awid_changed,
                occupied={"0.5.15": sha}, anchors={"0.5.15": sha},
            ),
            "aweb-server": artifact(
                "1.27.1", changed=server_changed,
                occupied={"1.27.1": None}, anchors={"1.27.1": sha},
            ),
            "a2a-gateway-image": artifact(
                "1.27.1", changed=server_changed,
                occupied={"1.27.1": sha}, anchors={"1.27.1": sha},
            ),
        },
        equality_groups=(
            ("awid-service", "awid-image"),
            ("aweb-server", "a2a-gateway-image"),
        ),
        compatibility="none",
        server_awid_floor=floor,
    )


class InducedFloorMovement(unittest.TestCase):
    def test_awid_move_induces_floor_patch_and_server_cascade(self) -> None:
        result = rn.normalize(world(floor="0.5.15"))
        self.assertEqual(result.outcome, "patch-needed")
        self.assertEqual(
            result.floor_patches, (("aweb-server", "0.5.15", "0.5.16"),)
        )
        patch_names = {name for name, _f, _t in result.patches}
        self.assertIn("aweb-server", patch_names)
        self.assertIn("a2a-gateway-image", patch_names)
        self.assertEqual(result.artifacts["aweb-server"].disposition, "moving")

    def test_floor_already_at_target_induces_nothing(self) -> None:
        result = rn.normalize(world(floor="0.5.16"))
        self.assertEqual(result.floor_patches, ())
        patch_names = {name for name, _f, _t in result.patches}
        self.assertNotIn("aweb-server", patch_names)

    def test_unmoved_awid_never_touches_the_floor(self) -> None:
        result = rn.normalize(world(floor="0.5.14", awid_changed=False))
        self.assertEqual(result.floor_patches, ())
        self.assertEqual(result.artifacts["awid-service"].disposition, "unmoved")

    def test_unknown_floor_is_no_policy_not_a_silent_zero(self) -> None:
        # Direct-built fixture worlds (b1, b4) carry no floor knowledge;
        # None means the policy is out of scope, not satisfied.
        result = rn.normalize(world(floor=None))
        self.assertEqual(result.floor_patches, ())
        self.assertEqual(result.outcome, "patch-needed")

    def test_missing_floor_literal_stops_by_name_when_awid_moves(self) -> None:
        # Captured worlds always supply the literal or the empty marker;
        # empty + a moving awid is a named stop, never a skipped policy.
        result = rn.normalize(world(floor=""))
        self.assertEqual(result.outcome, "stop")
        self.assertIn(
            ("floor-literal-missing", "aweb-server"),
            [(s.code, s.artifact) for s in result.stops],
        )

    def test_floor_patch_is_in_the_serialized_determinism_surface(self) -> None:
        # The double-compute comparison must cover the floor patch, or
        # nondeterminism there escapes the drift stop.
        a = rn.normalize(world(floor="0.5.15")).serialize()
        b = rn.normalize(world(floor="0.5.15")).serialize()
        self.assertEqual(a, b)
        self.assertIn(b"floor_patches", a)


if __name__ == "__main__":
    unittest.main()
