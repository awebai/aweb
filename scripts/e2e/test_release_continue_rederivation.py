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


def verify(card_rows, result_rows):
    result = rn.NormalizerResult(
        outcome="normal-form",
        artifacts=result_rows,
        patches=(),
        stops=(),
    )
    return rcc.verify_card_against_world(card_rows, result)


class Rederivation(unittest.TestCase):
    def test_identical_worlds_pass(self) -> None:
        stops = verify(
            [card_row("pkg", "1.2.3", "moving")],
            {"pkg": result_row("1.2.3", "moving")},
        )
        self.assertEqual(stops, [])

    def test_progress_absent_to_complete_is_allowed(self) -> None:
        stops = verify(
            [card_row("pkg", "1.2.3", "moving")],
            {"pkg": result_row("1.2.3", "unmoved", ("1.2.3", "sha-x"))},
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


if __name__ == "__main__":
    unittest.main()
