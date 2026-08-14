"""Anchor reconciliation classification (aben R3, design section 2).

Pure-function fixtures for reconcile_unit: the four-state model over a
publication unit's member observations plus the recoverable-versus-
conflicting fork, with history below P never stopping and every terminal
condition carrying its stable code.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_normalizer as rn  # noqa: E402


def member(name: str, versions: dict[str, str | None]):
    """versions maps version -> source identity (None = the member kind
    carries no observable source identity, e.g. pypi/npm listings)."""
    return rn.UnitMember(name=name, occupied=versions)


class Reconciliation(unittest.TestCase):
    def test_all_members_and_anchor_at_p_is_reconciled(self) -> None:
        r = rn.reconcile_unit(
            members=[
                member("npm:a", {"1.2.3": None}),
                member("github:rel", {"1.2.3": "sha-x"}),
            ],
            anchor_versions={"1.2.3": "sha-x"},
            manifest_intent="1.2.3",
        )
        self.assertEqual(r.state, "reconciled")
        self.assertEqual(r.p, "1.2.3")
        self.assertEqual(r.source_identity, "sha-x")

    def test_history_below_p_never_stops(self) -> None:
        r = rn.reconcile_unit(
            members=[
                member("npm:a", {"1.2.3": None, "1.0.0": None}),
                member("github:rel", {"1.2.3": "sha-x"}),  # 1.0.0 absent here
            ],
            anchor_versions={"1.2.3": "sha-x", "1.0.0": "sha-old"},
            manifest_intent="1.2.3",
        )
        self.assertEqual(r.state, "reconciled")

    def test_missing_member_with_matching_intent_is_recoverable(self) -> None:
        # One member occupied at P, sibling absent, candidate equals the
        # reviewed manifest intent, occupied member's identity matches
        # the anchor: the e5524b4b state, and it must NOT be terminal.
        r = rn.reconcile_unit(
            members=[
                member("github:rel", {"1.2.3": "sha-x", "1.2.2": "sha-prev"}),
                member("npm:a", {"1.2.2": None}),
            ],
            anchor_versions={"1.2.3": "sha-x", "1.2.2": "sha-prev"},
            manifest_intent="1.2.3",
        )
        self.assertEqual(r.state, "recoverable-partial")
        self.assertEqual(r.p, "1.2.2")  # previous COMPLETE anchored version
        self.assertEqual(r.candidate, "1.2.3")

    def test_missing_member_regardless_of_anchor_is_partial(self) -> None:
        # Anchor presence must not exempt a missing required member.
        r = rn.reconcile_unit(
            members=[
                member("github:rel", {"1.2.3": "sha-x"}),
                member("npm:a", {}),
            ],
            anchor_versions={"1.2.3": "sha-x"},
            manifest_intent="1.2.3",
        )
        self.assertIn(r.state, ("recoverable-partial", "conflicting-partial"))

    def test_partial_with_different_intent_is_conflicting(self) -> None:
        r = rn.reconcile_unit(
            members=[
                member("github:rel", {"1.2.3": "sha-x"}),
                member("npm:a", {}),
            ],
            anchor_versions={"1.2.3": "sha-x", "1.2.2": "sha-prev"},
            manifest_intent="1.2.4",
        )
        self.assertEqual(r.state, "conflicting-partial")

    def test_identity_mismatch_at_candidate_is_conflicting(self) -> None:
        r = rn.reconcile_unit(
            members=[
                member("github:rel", {"1.2.3": "sha-DIFFERENT"}),
                member("npm:a", {}),
            ],
            anchor_versions={"1.2.3": "sha-x", "1.2.2": "sha-prev"},
            manifest_intent="1.2.3",
        )
        self.assertEqual(r.state, "conflicting-partial")

    def test_partial_without_previous_complete_p_is_conflicting(self) -> None:
        # Recovery needs the previous complete anchored P as the
        # content-diff anchor; without one the state is ambiguous.
        r = rn.reconcile_unit(
            members=[
                member("github:rel", {"1.2.3": "sha-x"}),
                member("npm:a", {}),
            ],
            anchor_versions={"1.2.3": "sha-x"},
            manifest_intent="1.2.3",
        )
        self.assertEqual(r.state, "conflicting-partial")

    def test_anchor_only_at_p_is_partial(self) -> None:
        r = rn.reconcile_unit(
            members=[
                member("npm:a", {"1.2.2": None}),
                member("github:rel", {"1.2.2": "sha-prev"}),
            ],
            anchor_versions={"1.2.3": "sha-x", "1.2.2": "sha-prev"},
            manifest_intent="1.2.3",
        )
        self.assertEqual(r.state, "recoverable-partial")

    def test_all_members_but_no_anchor_is_anchorless(self) -> None:
        r = rn.reconcile_unit(
            members=[
                member("npm:a", {"1.2.3": None}),
                member("github:rel", {"1.2.3": "sha-x"}),
            ],
            anchor_versions={},
            manifest_intent="1.2.3",
        )
        self.assertEqual(r.state, "stop")
        self.assertEqual(r.stop, "anchorless-version")

    def test_pypi_style_identityless_occupancy_is_provisionally_recoverable(self) -> None:
        # Occupancy without source identity can reserve the number but
        # never prove conflict; recoverability stays provisional for the
        # staged-byte check at publication.
        r = rn.reconcile_unit(
            members=[
                member("pypi:a", {"1.2.3": None, "1.2.2": None}),
                member("github:rel", {"1.2.2": "sha-prev"}),
            ],
            anchor_versions={"1.2.3": "sha-x", "1.2.2": "sha-prev"},
            manifest_intent="1.2.3",
        )
        self.assertEqual(r.state, "recoverable-partial")
        self.assertTrue(r.provisional)

    def test_malformed_candidate_in_version_namespace_stops(self) -> None:
        r = rn.reconcile_unit(
            members=[member("npm:a", {"1.2.3-rc1": None})],
            anchor_versions={},
            manifest_intent="1.2.3",
        )
        self.assertEqual(r.state, "stop")
        self.assertEqual(r.stop, "malformed-version-candidate")


if __name__ == "__main__":
    unittest.main()
