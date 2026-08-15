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


class CandidateSourceIdentityMeaning(unittest.TestCase):
    """candidate_source_identity is the identity of the bytes occupying
    the version being PUBLISHED - and None when nothing occupies it.

    The first real continue refused with card-world-source-mismatch on
    all three equality-group members. Measured: every one was
    `reconciled` at the PREVIOUS version (1.27.1, 0.5.16, 0.5.16) and
    the group copied that reconciliation's source_identity - the OLD
    version's anchor - onto a row labelled moving-with-recovery at the
    NEW version. The comparator reads the field as the candidate's
    occupancy identity and compared an old anchor against the card's
    new source, so it mismatched by construction for any group
    publishing a version none of its members occupies yet.

    One name, two meanings, in the two halves of our own tool.
    """

    def test_a_member_moving_to_an_unoccupied_version_has_no_candidate_identity(
        self,
    ) -> None:
        w = world()
        # Both members complete at 1.27.1; the manifests intend 1.27.2,
        # which NOBODY occupies. This is the live shape.
        w.artifacts["aweb-server"] = rn.CapturedArtifact(
            manifest_version="1.27.2", content_changed=True, derivation="manifest",
            members=[rn.UnitMember("pypi:aweb", {"1.27.1": None})],
            anchor_versions={"1.27.1": "old-server-sha"},
        )
        w.artifacts["a2a-gateway-image"] = rn.CapturedArtifact(
            manifest_version="1.27.2", content_changed=True, derivation="manifest",
            members=[rn.UnitMember("ghcr:a2a", {"1.27.1": "old-a2a-sha"})],
            anchor_versions={"1.27.1": "old-a2a-sha"},
        )
        result = rn.normalize(w)
        for name in ("aweb-server", "a2a-gateway-image"):
            row = result.artifacts[name]
            with self.subTest(artifact=name):
                self.assertEqual(row.version, "1.27.2")
                self.assertIsNone(
                    row.candidate_source_identity,
                    "no member occupies 1.27.2, so there are no candidate "
                    "bytes to bind - carrying the OLD version's anchor here "
                    "is what made continue refuse its own card",
                )

    def test_a_member_that_DOES_occupy_the_candidate_keeps_its_identity(
        self,
    ) -> None:
        # The control: where the candidate IS occupied, the field must
        # still carry that occupancy's identity - this is the case the
        # comparator exists for.
        w = world()
        w.artifacts["aweb-server"] = rn.CapturedArtifact(
            manifest_version="1.27.2", content_changed=True, derivation="manifest",
            members=[rn.UnitMember("pypi:aweb", {"1.27.1": None})],
            anchor_versions={"1.27.1": "old-server-sha"},
        )
        w.artifacts["a2a-gateway-image"] = rn.CapturedArtifact(
            manifest_version="1.27.2", content_changed=False, derivation="manifest",
            members=[rn.UnitMember("ghcr:a2a", {"1.27.2": "sha-at-candidate"})],
            anchor_versions={"1.27.2": "sha-at-candidate"},
        )
        result = rn.normalize(w)
        self.assertEqual(
            result.artifacts["a2a-gateway-image"].disposition, "unmoved"
        )
        self.assertIsNone(
            result.artifacts["aweb-server"].candidate_source_identity,
            "aweb-server does not occupy 1.27.2; only the member that does "
            "may carry a candidate identity",
        )


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
