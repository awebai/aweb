"""Continue-start re-derivation comparison (aben R4, design section 7).

verify_card_against_world: the card's projection against a freshly
computed normalizer result, byte-equal everywhere except the monotone
progress transitions; any other difference stops in the reconciler's
vocabulary. Pure over the two objects.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_continue_check as rcc  # noqa: E402
import release_normalizer as rn  # noqa: E402


def card_row(name, version, disposition, anchor=None):
    return rcc.CardRow(
        name=name,
        version=version,
        disposition=disposition,
        previous_complete_anchor=anchor,
    )


def result_row(version, disposition, anchor=None):
    return rn.ArtifactResult(
        disposition=disposition,
        version=version,
        previous_complete_anchor=anchor,
    )


def verify(card_rows, result_rows, *, expected_sources=None, patches=()):
    result = rn.NormalizerResult(
        outcome="normal-form",
        artifacts=result_rows,
        patches=tuple(patches),
        stops=(),
    )
    return rcc.verify_card_against_world(
        card_rows, result, expected_sources=expected_sources or {}
    )


GOOD = "c" * 40
WRONG = "d" * 40


class SourceBinding(unittest.TestCase):
    """A6, the shipment gate's wrong-source probe: a completion is
    accepted only from the source the card names. The expected identity
    per artifact derives from the card's SHAs; an anchor from anywhere
    else is the named source mismatch, and a completion whose expected
    source cannot be derived yet is unproven, never accepted."""

    def test_moving_completed_by_the_wrong_source_stops(self) -> None:
        stops = verify(
            [card_row("aweb-server", "1.2.3", "moving")],
            {"aweb-server": result_row("1.2.3", "unmoved", ("1.2.3", WRONG))},
            expected_sources={"aweb-server": GOOD},
        )
        self.assertEqual(
            [(s.code, s.artifact) for s in stops],
            [("card-world-source-mismatch", "aweb-server")],
        )

    def test_recovery_completed_by_the_wrong_source_stops(self) -> None:
        stops = verify(
            [
                card_row(
                    "a2a-gateway-image",
                    "1.2.3",
                    "moving-with-recovery",
                    ("1.2.2", GOOD),
                )
            ],
            {
                "a2a-gateway-image": result_row(
                    "1.2.3", "unmoved", ("1.2.3", WRONG)
                )
            },
            expected_sources={"a2a-gateway-image": GOOD},
        )
        self.assertEqual(
            [(s.code, s.artifact) for s in stops],
            [("card-world-source-mismatch", "a2a-gateway-image")],
        )

    def test_completion_from_the_named_source_is_progress(self) -> None:
        stops = verify(
            [card_row("aweb-server", "1.2.3", "moving")],
            {"aweb-server": result_row("1.2.3", "unmoved", ("1.2.3", GOOD))},
            expected_sources={"aweb-server": GOOD},
        )
        self.assertEqual(stops, [])

    def test_completion_with_underivable_expected_source_is_unproven(self) -> None:
        stops = verify(
            [card_row("ac-image", "0.7.15", "moving")],
            {"ac-image": result_row("0.7.15", "unmoved", ("0.7.15", WRONG))},
            expected_sources={"ac-image": None},
        )
        self.assertEqual(
            [(s.code, s.artifact) for s in stops],
            [("card-world-source-unproven", "ac-image")],
        )

    def test_extra_fresh_artifact_stops(self) -> None:
        stops = verify(
            [card_row("aweb-server", "1.2.3", "moving")],
            {
                "aweb-server": result_row("1.2.3", "moving"),
                "stowaway": result_row("9.9.9", "moving"),
            },
        )
        self.assertEqual(
            [(s.code, s.artifact) for s in stops],
            [("card-world-extra-artifact", "stowaway")],
        )

    def test_fresh_patch_wish_is_drift(self) -> None:
        stops = verify(
            [card_row("aweb-server", "1.2.3", "moving")],
            {"aweb-server": result_row("1.2.3", "moving")},
            patches=(("aweb-server", "1.2.3", "1.2.4"),),
        )
        self.assertEqual(
            [(s.code, s.artifact) for s in stops],
            [("card-world-patch-drift", None)],
        )

    def test_expected_sources_derive_from_the_card_shas(self) -> None:
        import release_train as rt

        card = rt.ReleaseCard(
            aweb_sha=GOOD,
            ac_base_sha="e" * 40,
            artifacts=tuple(
                rt.ArtifactSelection(name=name, version="1.0.0", moves=True)
                for name in rt.CARD_ARTIFACT_ORDER
            ),
            compatibility="none",
            gates=(
                rt.GateEvidence(
                    name="aweb-clean-gate",
                    sha=GOOD,
                    result="passed",
                    reference="fixture",
                    suites=("s",),
                ),
            ),
            purpose="source derivation",
            deployments=rt.DeploymentSet(
                production=True, awid_site=False, aweb_site=False
            ),
            final_ac_sha=None,
            production_correction_pending=True,
        )
        expected = rt.expected_completion_sources(card)
        self.assertEqual(expected["aweb-server"], GOOD)
        self.assertEqual(expected["aw-cli"], GOOD)
        # The card's own validator keeps final_ac_sha pending, so an AC
        # image completion is UNPROVABLE at continue start - exactly the
        # fail-closed shape the wrong-source probe demanded: the derived
        # SHA exists only at run time, never on the card.
        self.assertIsNone(expected["ac-image"], "underived AC stays unproven")


class Rederivation(unittest.TestCase):
    def test_identical_worlds_pass(self) -> None:
        stops = verify(
            [card_row("pkg", "1.2.3", "moving")],
            {"pkg": result_row("1.2.3", "moving")},
        )
        self.assertEqual(stops, [])

    def test_progress_absent_to_complete_is_allowed(self) -> None:
        # Completion is progress only when it binds to the card's own
        # source (A6); the legit case supplies it.
        stops = verify(
            [card_row("pkg", "1.2.3", "moving")],
            {"pkg": result_row("1.2.3", "unmoved", ("1.2.3", "sha-x"))},
            expected_sources={"pkg": "sha-x"},
        )
        self.assertEqual(stops, [])

    def test_progress_absent_to_recoverable_is_allowed(self) -> None:
        stops = verify(
            [card_row("pkg", "1.2.3", "moving")],
            {"pkg": result_row("1.2.3", "moving-with-recovery", ("1.2.2", "sha-p"))},
        )
        self.assertEqual(stops, [])

    def test_progress_recoverable_to_complete_is_allowed(self) -> None:
        stops = verify(
            [
                card_row(
                    "pkg",
                    "1.2.3",
                    "moving-with-recovery",
                    ("1.2.2", "sha-p"),
                )
            ],
            {"pkg": result_row("1.2.3", "unmoved", ("1.2.3", "sha-x"))},
            expected_sources={"pkg": "sha-x"},
        )
        self.assertEqual(stops, [])

    def test_version_drift_stops(self) -> None:
        stops = verify(
            [card_row("pkg", "1.2.3", "moving")],
            {"pkg": result_row("1.2.4", "moving")},
        )
        self.assertEqual([s.code for s in stops], ["card-world-version-drift"])

    def test_regression_unmoved_to_moving_stops(self) -> None:
        stops = verify(
            [card_row("pkg", "1.2.3", "unmoved", ("1.2.3", "sha-x"))],
            {"pkg": result_row("1.2.3", "moving")},
        )
        self.assertEqual([s.code for s in stops], ["card-world-disposition-drift"])

    def test_anchor_identity_drift_stops(self) -> None:
        stops = verify(
            [card_row("pkg", "1.2.3", "unmoved", ("1.2.3", "sha-x"))],
            {"pkg": result_row("1.2.3", "unmoved", ("1.2.3", "sha-DIFFERENT"))},
        )
        self.assertEqual([s.code for s in stops], ["card-world-anchor-drift"])

    def test_missing_artifact_in_result_stops(self) -> None:
        stops = verify([card_row("pkg", "1.2.3", "moving")], {})
        self.assertEqual([s.code for s in stops], ["card-world-artifact-missing"])

    def test_result_stop_propagates(self) -> None:
        result = rn.NormalizerResult(
            outcome="stop",
            artifacts={},
            patches=(),
            stops=(rn.Stop("version-occupied", "pkg"),),
        )
        stops = rcc.verify_card_against_world(
            [card_row("pkg", "1.2.3", "moving")], result
        )
        self.assertIn("version-occupied", [s.code for s in stops])

    def test_fresh_unmoved_row_without_anchor_stops_not_skips(self) -> None:
        # alice's finding: the guard must be correct on its own terms,
        # not correct-because-no-other-path-constructs-this. A fresh
        # unmoved row with a missing anchor is anchorless, named.
        stops = verify(
            [card_row("pkg", "1.2.3", "unmoved", ("1.2.3", "sha-x"))],
            {"pkg": result_row("1.2.3", "unmoved", None)},
        )
        self.assertEqual([s.code for s in stops], ["card-world-anchor-missing"])

    def test_fresh_unmoved_row_with_identityless_anchor_stops(self) -> None:
        stops = verify(
            [card_row("pkg", "1.2.3", "unmoved", ("1.2.3", "sha-x"))],
            {"pkg": result_row("1.2.3", "unmoved", ("1.2.3", None))},
        )
        self.assertEqual([s.code for s in stops], ["card-world-anchor-missing"])



if __name__ == "__main__":
    unittest.main()
