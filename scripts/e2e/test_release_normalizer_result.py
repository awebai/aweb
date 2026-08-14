"""The normalizer's aggregated result over a captured world (aben R3).

normalize() composes reconciliation, equality groups, and the movement
table into one complete result object from a CAPTURED world snapshot -
no I/O - which is what makes the determinism check meaningful: computing
twice from the same snapshot must be byte-identical.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_normalizer as rn  # noqa: E402


def world(**overrides):
    """A minimal two-artifact captured world: one plain artifact and one
    equality group, healthy by default."""
    base = dict(
        artifacts={
            "aweb-server": rn.CapturedArtifact(
                manifest_version="1.27.2",
                content_changed=False,
                derivation="manifest",
                members=[rn.UnitMember("pypi:aweb", {"1.27.2": None})],
                anchor_versions={"1.27.2": "sha-s"},
            ),
            "a2a-gateway-image": rn.CapturedArtifact(
                manifest_version="1.27.2",
                content_changed=False,
                derivation="manifest",
                members=[rn.UnitMember("ghcr:a2a", {"1.27.2": "sha-s"})],
                anchor_versions={"1.27.2": "sha-s"},
            ),
        },
        equality_groups=(("aweb-server", "a2a-gateway-image"),),
        compatibility="none",
    )
    base.update(overrides)
    return rn.CapturedWorld(**base)


class NormalizeResult(unittest.TestCase):
    def test_healthy_world_is_normal_form(self) -> None:
        result = rn.normalize(world())
        self.assertEqual(result.outcome, "normal-form")
        self.assertEqual(result.artifacts["aweb-server"].disposition, "unmoved")
        self.assertEqual(result.patches, ())
        self.assertEqual(result.stops, ())

    def test_group_content_change_yields_patch_needed(self) -> None:
        w = world()
        w.artifacts["a2a-gateway-image"] = rn.CapturedArtifact(
            manifest_version="1.27.2",
            content_changed=True,
            derivation="manifest",
            members=[rn.UnitMember("ghcr:a2a", {"1.27.2": "sha-s"})],
            anchor_versions={"1.27.2": "sha-s"},
        )
        result = rn.normalize(w)
        self.assertEqual(result.outcome, "patch-needed")
        self.assertEqual(
            result.patches,
            (
                ("a2a-gateway-image", "1.27.2", "1.27.3"),
                ("aweb-server", "1.27.2", "1.27.3"),
            ),
        )
        self.assertEqual(result.artifacts["aweb-server"].version, "1.27.3")

    def test_any_stop_yields_stop_outcome_with_names(self) -> None:
        w = world()
        w.artifacts["aweb-server"] = rn.CapturedArtifact(
            manifest_version="1.27.3",  # contentless pre-declare
            content_changed=False,
            derivation="manifest",
            members=[rn.UnitMember("pypi:aweb", {"1.27.2": None})],
            anchor_versions={"1.27.2": "sha-s"},
        )
        result = rn.normalize(w)
        self.assertEqual(result.outcome, "stop")
        self.assertTrue(result.stops)
        self.assertIn("equality-invariant-violated", {s.code for s in result.stops})

    def test_recovery_disposition_flows_to_the_result(self) -> None:
        w = world()
        w.artifacts["a2a-gateway-image"] = rn.CapturedArtifact(
            manifest_version="1.27.2",
            content_changed=True,
            derivation="manifest",
            members=[rn.UnitMember("ghcr:a2a", {"1.27.1": "sha-prev"})],
            anchor_versions={"1.27.2": "sha-s", "1.27.1": "sha-prev"},
        )
        result = rn.normalize(w)
        self.assertEqual(result.outcome, "normal-form")
        self.assertEqual(
            result.artifacts["a2a-gateway-image"].disposition,
            "moving-with-recovery",
        )
        self.assertEqual(
            result.artifacts["a2a-gateway-image"].previous_complete_anchor,
            ("1.27.1", "sha-prev"),
        )

    def test_serialization_is_deterministic_and_complete(self) -> None:
        # The double-compute check's foundation: same captured world,
        # byte-identical serialized result; and every result field
        # appears in the serialization (nothing silently dropped).
        a = rn.normalize(world()).serialize()
        b = rn.normalize(world()).serialize()
        self.assertEqual(a, b)
        for field in ("outcome", "artifacts", "patches", "stops"):
            self.assertIn(field.encode(), a)


if __name__ == "__main__":
    unittest.main()
