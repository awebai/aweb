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

    def test_anchorless_at_intent_with_identity_is_the_conflicting_fork(self) -> None:
        # Refined during R6 assembly (the b4 lagging-conflicting control):
        # occupied at the INTENDED version by identityful bytes with no
        # anchor means the source cannot be bound - the conflicting fork,
        # which the equality group's mint path consumes. The flat
        # anchorless stop remains for the other-intent and identityless
        # cases below.
        r = rn.reconcile_unit(
            members=[
                member("npm:a", {"1.2.3": None}),
                member("github:rel", {"1.2.3": "sha-x"}),
            ],
            anchor_versions={},
            manifest_intent="1.2.3",
        )
        self.assertEqual(r.state, "conflicting-partial")
        self.assertEqual(r.source_identity, "sha-x")

    def test_anchorless_at_other_intent_still_stops(self) -> None:
        r = rn.reconcile_unit(
            members=[member("github:rel", {"1.2.3": "sha-x"})],
            anchor_versions={},
            manifest_intent="1.2.4",
        )
        self.assertEqual(r.state, "stop")
        self.assertEqual(r.stop, "anchorless-version")

    def test_anchorless_identityless_still_stops(self) -> None:
        r = rn.reconcile_unit(
            members=[member("pypi:a", {"1.2.3": None})],
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

    def test_malformed_candidate_below_the_candidate_is_history(self) -> None:
        # The design's own principle - "absence below P is history, never
        # a stop" - applied to malformed candidates, which it was not.
        # ghcr.io/awebai/ac really does serve a years-old two-component
        # tag 0.3; it cannot collide with anything current, so it is
        # logged like latest and sha-*, never a halt.
        sha = "a" * 40
        r = rn.reconcile_unit(
            members=[member("ghcr.io/awebai/ac", {"0.3": sha, "0.7.14": sha})],
            anchor_versions={"0.7.14": sha},
            manifest_intent="0.7.14",
        )
        self.assertEqual(r.state, "reconciled", r)
        self.assertEqual(r.p, "0.7.14")

    def test_malformed_candidate_at_or_above_the_candidate_still_stops(self) -> None:
        # The discriminating control: a near-version that COULD bear on
        # the decision still halts, so the narrowing is a narrowing and
        # not a removal.
        sha = "a" * 40
        r = rn.reconcile_unit(
            members=[member("ghcr.io/awebai/ac", {"0.7.15-rc1": sha, "0.7.14": sha})],
            anchor_versions={"0.7.14": sha},
            manifest_intent="0.7.14",
        )
        self.assertEqual(r.state, "stop")
        self.assertEqual(r.stop, "malformed-version-candidate")

    def test_plan_critic_boundary_cases_are_pinned(self) -> None:
        # The binding conditions: only a FIRST DIFFERING component that
        # is lower makes a malformed spelling history. Equal-but-
        # incomplete and equal-with-suffix are ambiguous and stop -
        # padding them into history is the move the ruling forbids.
        sha = "a" * 40
        def reconcile(extra):
            occupied = {"0.7.15": sha}
            occupied.update({e: sha for e in extra})
            return rn.reconcile_unit(
                members=[member("ghcr.io/awebai/ac", occupied)],
                anchor_versions={"0.7.15": sha},
                manifest_intent="0.7.15",
            )
        self.assertEqual(reconcile(["0.3"]).state, "reconciled", "0.3 is history")
        self.assertEqual(reconcile(["0.7"]).stop, "malformed-version-candidate")
        self.assertEqual(
            reconcile(["0.7.15rc1"]).stop, "malformed-version-candidate"
        )
        # And the comparison itself, at the unit that decides it.
        self.assertTrue(rn.malformed_is_history((0, 3), (0, 7, 15)))
        self.assertFalse(rn.malformed_is_history((0, 7), (0, 7, 15)))
        self.assertFalse(rn.malformed_is_history((0, 7, 15, 1), (0, 7, 15)))
        self.assertFalse(rn.malformed_is_history((0, 8), (0, 7, 15)))
        self.assertFalse(rn.malformed_is_history(None, (0, 7, 15)))

    def test_ignored_history_is_never_evidence_for_anything(self) -> None:
        # The ruling's last condition: ignored history must never become
        # P, a content anchor, previous-complete evidence, or recovery
        # evidence. The malformed spelling here sorts LAST as a string,
        # so a leak would be visible.
        sha, other = "a" * 40, "b" * 40
        r = rn.reconcile_unit(
            members=[member("ghcr.io/awebai/ac", {"0.9": other, "0.7.14": sha, "0.7.15": sha})],
            anchor_versions={"0.7.14": sha, "0.7.15": sha},
            manifest_intent="0.7.15",
        )
        # 0.9 sorts above 0.7.x, so it must STOP rather than be adopted.
        self.assertEqual(r.stop, "malformed-version-candidate")
        below = rn.reconcile_unit(
            members=[member("ghcr.io/awebai/ac", {"0.3": other, "0.7.14": sha, "0.7.15": sha})],
            anchor_versions={"0.7.14": sha, "0.7.15": sha},
            manifest_intent="0.7.15",
        )
        self.assertEqual(below.state, "reconciled")
        self.assertEqual(below.p, "0.7.15")
        self.assertEqual(below.candidate, "0.7.15")
        self.assertNotEqual(below.source_identity, other, "history is not identity evidence")

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
