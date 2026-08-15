"""Produced versus expected: an extra publication fails as loudly as a
missing one (aben D2).

The terminal sweep asks whether the card's version is PRESENT. Registry
versions are immutable, so that question can never notice a version the
card did not name sitting beside it - the live sweep printed

    PRESENT github:awebai/aw release v1.34.7 (release object served ...)

in the same minute a publication workflow minted 1.34.8, and nothing in
the walk was capable of seeing it. Two people then read 1.34.8 as
someone else's release, because an out-of-card publication is
indistinguishable from ordinary world state once it exists.

So the check is stated in the other direction: for EVERY artifact -
moving and unmoved alike, since a version above a moving row's target is
equally unauthorised - no version above the card's may exist. That needs
no separate snapshot, because for an unmoved artifact the card's version
IS the world's version at card time.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_train as rt  # noqa: E402


def _selection(name: str, version: str, moves: bool) -> rt.ArtifactSelection:
    return rt.ArtifactSelection(
        name=name,
        version=version,
        moves=moves,
        previous_complete_anchor=(
            None
            if moves
            else rt.PreviousCompleteAnchor(
                version=version, kind="tag", source_identity="c" * 40
            )
        ),
    )


def _card(*rows: tuple[str, str, bool]) -> rt.ReleaseCard:
    """A complete card - every artifact must appear - with the named
    rows overriding the quiet default."""

    overrides = {name: (version, moves) for name, version, moves in rows}
    return rt.ReleaseCard.create(
        aweb_sha="a" * 40,
        ac_base_sha="b" * 40,
        artifacts=tuple(
            _selection(name, *overrides.get(name, ("1.0.0", False)))
            for name in rt.CARD_ARTIFACT_ORDER
        ),
        compatibility="none",
        gates=(
            rt.GateEvidence(
                "aweb-clean-docker",
                "a" * 40,
                "passed",
                "logs/aweb-gate.log",
                ("unit",),
            ),
        ),
        purpose="exercise the produced-versus-expected invariant",
        # The card infers production exactly from AC image movement.
        deployments=rt.DeploymentSet(
            overrides.get("ac-image", ("", False))[1], False, False
        ),
        final_ac_sha=None,
        production_correction_pending=False,
    )


class UnauthorizedPublication(unittest.TestCase):
    def _findings(self, card, world: dict[str, set[str]]) -> list[str]:
        """world maps a unit target to the versions it serves."""

        def discover(target, **_kwargs):
            return {version: None for version in world.get(target, set())}

        return rt.unauthorized_publications(card, discover=discover)

    def test_a_version_above_an_unmoved_row_is_named(self) -> None:
        """The live defect. aw-cli was unmoved at 1.34.7 and the branch
        move minted 1.34.8."""

        card = _card(("aw-cli", "1.34.7", False))
        findings = self._findings(
            card, {"github:awebai/aw:release": {"1.34.7", "1.34.8"}}
        )
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("aw-cli", findings[0])
        self.assertIn("1.34.8", findings[0])
        self.assertIn("1.34.7", findings[0])

    def test_the_card_s_own_version_is_not_a_finding(self) -> None:
        """CONTROL: the same artifact, the same check, a world that
        contains exactly what was authorised."""

        card = _card(("aw-cli", "1.34.7", False))
        self.assertEqual(
            self._findings(card, {"github:awebai/aw:release": {"1.34.7"}}), []
        )

    def test_older_versions_are_not_findings(self) -> None:
        # Every prior release is still served; only what is ABOVE the
        # card's version can be an unauthorised publication.
        card = _card(("aw-cli", "1.34.7", False))
        self.assertEqual(
            self._findings(
                card,
                {"github:awebai/aw:release": {"1.34.5", "1.34.6", "1.34.7"}},
            ),
            [],
        )

    def test_a_moving_row_is_checked_too(self) -> None:
        """release-review's sharpening: a version above a MOVING row's
        target is equally unauthorised, so the invariant is stated for
        every artifact rather than only the unmoved ones."""

        card = _card(("ac-image", "0.7.15", True))
        clean = self._findings(card, {"ghcr.io/awebai/ac": {"0.7.14", "0.7.15"}})
        self.assertEqual(clean, [])
        dirty = self._findings(
            card, {"ghcr.io/awebai/ac": {"0.7.15", "0.7.16"}}
        )
        self.assertEqual(len(dirty), 1, dirty)
        self.assertIn("0.7.16", dirty[0])

    def test_every_artifact_is_checked_not_only_the_first(self) -> None:
        card = _card(
            ("aw-cli", "1.34.7", False),
            ("ac-image", "0.7.15", True),
        )
        findings = self._findings(
            card,
            {
                "github:awebai/aw:release": {"1.34.8"},
                "ghcr.io/awebai/ac": {"0.7.16"},
            },
        )
        self.assertEqual(len(findings), 2, findings)
        self.assertTrue(any("aw-cli" in line for line in findings))
        self.assertTrue(any("ac-image" in line for line in findings))

    def test_every_unit_member_is_checked_not_only_the_primary(self) -> None:
        """aw-cli's mint appeared in seven npm packages as well as the
        GitHub release. Checking only the primary target would report
        the artifact clean when six of its members carry a version
        nobody authorised."""

        card = _card(("aw-cli", "1.34.7", False))
        findings = self._findings(
            card, {"npm:@awebai/aw-linux-x64": {"1.34.7", "1.34.8"}}
        )
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("@awebai/aw-linux-x64", findings[0])

    def test_a_non_conforming_tag_is_not_read_as_a_higher_version(self) -> None:
        # Near-misses are the reconciler's named stop, not this check's
        # business - and must never crash it.
        card = _card(("ac-image", "0.7.15", True))
        self.assertEqual(
            self._findings(
                card,
                {"ghcr.io/awebai/ac": {"0.7.15", "0.7.16rc1", "latest"}},
            ),
            [],
        )

    def test_an_unreadable_target_refuses_rather_than_reporting_clean(
        self,
    ) -> None:
        """Observation failure is never permission to write, and it is
        never permission to declare DONE either. A target that cannot be
        read must block, not pass silently - otherwise the invariant
        reports its strongest result exactly when it saw nothing."""

        card = _card(("aw-cli", "1.34.7", False))

        def discover(target, **_kwargs):
            raise rt.ObservationUnavailable(f"{target} is unreachable")

        findings = rt.unauthorized_publications(card, discover=discover)
        self.assertTrue(findings)
        self.assertTrue(
            any("unreachable" in line or "could not" in line for line in findings),
            findings,
        )


if __name__ == "__main__":
    unittest.main()
