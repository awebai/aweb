"""A5: prepare consumes the normalizer projection (shipment finding 2).

The card is constructed FROM the NormalizerResult - every disposition
shape including moving-with-recovery reaches card rows - and the
production entry computes that projection in the same command. A card
row whose disposition requires an anchor fails closed at construction
when the projection cannot supply an identityful one.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_normalizer as rn  # noqa: E402
import release_train as rt  # noqa: E402

SHA = "a" * 40


def projection(**overrides) -> rn.NormalizerResult:
    versions = {
        "aweb-server": "1.27.2",
        "awid-service": "0.5.16",
        "awid-image": "0.5.16",
        "aw-cli": "1.34.6",
        "channel-plugin": "1.7.7",
        "pi-extension": "0.3.7",
        "skills": "0.2.13",
        "a2a-gateway-image": "1.27.2",
        "ac-image": "0.7.15",
    }
    artifacts = {
        name: rn.ArtifactResult(disposition="moving", version=version)
        for name, version in versions.items()
    }
    artifacts.update(overrides)
    return rn.NormalizerResult(
        outcome="patch-needed", artifacts=artifacts, patches=(), stops=()
    )


class SelectionsFromProjection(unittest.TestCase):
    def test_every_disposition_shape_reaches_card_rows(self) -> None:
        result = projection(
            **{
                "aw-cli": rn.ArtifactResult(
                    disposition="unmoved",
                    version="1.34.6",
                    previous_complete_anchor=("1.34.6", SHA),
                ),
                "a2a-gateway-image": rn.ArtifactResult(
                    disposition="moving-with-recovery",
                    version="1.27.2",
                    previous_complete_anchor=("1.27.1", SHA),
                ),
                "aweb-server": rn.ArtifactResult(
                    disposition="moving-with-recovery",
                    version="1.27.2",
                    previous_complete_anchor=("1.27.1", SHA),
                ),
            }
        )
        rows = {s.name: s for s in rt.selections_from_projection(result)}
        self.assertEqual(len(rows), 9)
        self.assertEqual(rows["awid-service"].disposition, "moving")
        self.assertTrue(rows["awid-service"].moves)
        self.assertIsNone(rows["awid-service"].previous_complete_anchor)
        unmoved = rows["aw-cli"]
        self.assertEqual(unmoved.disposition, "unmoved")
        self.assertFalse(unmoved.moves)
        self.assertEqual(unmoved.previous_complete_anchor.version, "1.34.6")
        self.assertEqual(unmoved.previous_complete_anchor.kind, "tag")
        self.assertEqual(unmoved.previous_complete_anchor.source_identity, SHA)
        recovery = rows["a2a-gateway-image"]
        self.assertEqual(recovery.disposition, "moving-with-recovery")
        self.assertTrue(recovery.moves)
        self.assertEqual(recovery.previous_complete_anchor.version, "1.27.1")

    def test_oci_anchor_kind_comes_from_the_canonical_entry(self) -> None:
        result = projection(
            **{
                "ac-image": rn.ArtifactResult(
                    disposition="unmoved",
                    version="0.7.14",
                    previous_complete_anchor=("0.7.14", SHA),
                )
            }
        )
        rows = {s.name: s for s in rt.selections_from_projection(result)}
        self.assertEqual(
            rows["ac-image"].previous_complete_anchor.kind, "oci-revision-label"
        )

    def test_identityless_anchor_fails_closed_at_construction(self) -> None:
        result = projection(
            **{
                "aw-cli": rn.ArtifactResult(
                    disposition="unmoved",
                    version="1.34.6",
                    previous_complete_anchor=("1.34.6", None),
                )
            }
        )
        with self.assertRaises(rt.ValidationError) as caught:
            rt.selections_from_projection(result)
        self.assertIn("aw-cli", str(caught.exception))

    def test_missing_artifact_row_fails_closed(self) -> None:
        result = projection()
        del result.artifacts["skills"]
        with self.assertRaises(rt.ValidationError) as caught:
            rt.selections_from_projection(result)
        self.assertIn("skills", str(caught.exception))

    def test_card_bytes_round_trip_all_dispositions(self) -> None:
        # The projection's shapes survive into the card's on-disk bytes.
        import tempfile

        result = projection(
            **{
                "aw-cli": rn.ArtifactResult(
                    disposition="unmoved",
                    version="1.34.6",
                    previous_complete_anchor=("1.34.6", SHA),
                ),
                "aweb-server": rn.ArtifactResult(
                    disposition="moving-with-recovery",
                    version="1.27.2",
                    previous_complete_anchor=("1.27.1", SHA),
                ),
                "a2a-gateway-image": rn.ArtifactResult(
                    disposition="moving-with-recovery",
                    version="1.27.2",
                    previous_complete_anchor=("1.27.1", SHA),
                ),
            }
        )
        card = rt.ReleaseCard(
            aweb_sha=SHA,
            ac_base_sha=SHA,
            artifacts=rt.selections_from_projection(result),
            compatibility="none",
            gates=(
                rt.GateEvidence(
                    name="aweb-clean-gate",
                    sha=SHA,
                    result="passed",
                    reference="fixture",
                    suites=("fixture-suite",),
                ),
            ),
            purpose="projection round trip",
            deployments=rt.DeploymentSet(
                production=True, awid_site=False, aweb_site=False
            ),
            final_ac_sha=None,
            production_correction_pending=True,
        )
        import subprocess

        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(
                ["git", "init", "-q", tmp], check=True, capture_output=True
            )
            path = rt.write_card(Path(tmp), card)
            body = path.read_text()
        self.assertIn('"disposition":"moving-with-recovery"', body)
        self.assertIn('"disposition":"unmoved"', body)
        self.assertIn('"1.27.1"', body)


if __name__ == "__main__":
    unittest.main()
