"""Card schema extension (aben R4, design section 7).

ArtifactSelection gains the disposition enum as a strict extension of
moves and the previous_complete_anchor tagged variant - REQUIRED for
unmoved and moving-with-recovery, FORBIDDEN for moving - with the closed
schema validated to nested exact keys and types.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_train as rt  # noqa: E402


def selection(disposition: str, anchor=None):
    return rt.ArtifactSelection(
        name="aweb-server",
        version="1.27.2",
        moves=disposition != "unmoved",
        disposition=disposition,
        previous_complete_anchor=anchor,
    )


class CardSchemaExtension(unittest.TestCase):
    def test_moving_forbids_the_anchor(self) -> None:
        selection("moving")  # fine
        with self.assertRaises(rt.ValidationError):
            selection("moving", anchor=rt.PreviousCompleteAnchor("1.27.1", "tag", "x" * 40))

    def test_unmoved_requires_the_anchor(self) -> None:
        with self.assertRaises(rt.ValidationError):
            selection("unmoved")
        selection(
            "unmoved",
            anchor=rt.PreviousCompleteAnchor("1.27.2", "tag", "a" * 40),
        )

    def test_recovery_requires_the_anchor(self) -> None:
        with self.assertRaises(rt.ValidationError):
            selection("moving-with-recovery")
        selection(
            "moving-with-recovery",
            anchor=rt.PreviousCompleteAnchor("1.27.1", "tag", "a" * 40),
        )

    def test_disposition_enum_is_closed(self) -> None:
        with self.assertRaises(rt.ValidationError):
            selection("sideways")

    def test_moves_stays_consistent_with_disposition(self) -> None:
        # Strict extension: moves is derived truth, not a second axis.
        with self.assertRaises(rt.ValidationError):
            rt.ArtifactSelection(
                name="aweb-server",
                version="1.27.2",
                moves=False,
                disposition="moving",
                previous_complete_anchor=None,
            )

    def test_anchor_variant_kinds_are_closed_and_typed(self) -> None:
        with self.assertRaises(rt.ValidationError):
            rt.PreviousCompleteAnchor("1.27.1", "vibes", "a" * 40)
        with self.assertRaises(rt.ValidationError):
            rt.PreviousCompleteAnchor("not-a-version", "tag", "a" * 40)
        oci = rt.PreviousCompleteAnchor("0.7.14", "oci-revision-label", "b" * 40)
        self.assertEqual(oci.kind, "oci-revision-label")

    def test_default_disposition_derives_from_moves_for_compatibility(self) -> None:
        # Existing constructors that pass only moves keep working: the
        # strict extension defaults disposition from moves, requiring an
        # anchor only when explicitly unmoved-with-anchor semantics are
        # in play (the train's card generation supplies them after R4).
        legacy = rt.ArtifactSelection(name="skills", version="0.2.12", moves=True)
        self.assertEqual(legacy.disposition, "moving")


if __name__ == "__main__":
    unittest.main()
