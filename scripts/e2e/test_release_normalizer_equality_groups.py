"""Equality-group shared-candidate algorithm (aben R3, design section 3).

The awid-service/awid-image and aweb-server/a2a-gateway-image groups
share one version. The algorithm must reuse a safe shared candidate M
before minting, mark lagging members for recovery at M, and mint one
shared next patch only when M cannot serve - with both phantom-release
controls from the final seam 2 amendment.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_normalizer as rn  # noqa: E402


def group_member(
    name: str,
    *,
    reconciled: str,  # the member's own unit reconciliation state
    p: str | None,
    candidate: str | None = None,
    content_changed: bool = False,
):
    return rn.GroupMember(
        name=name,
        reconciliation=rn.Reconciliation(
            state=reconciled, p=p, candidate=candidate
        ),
        content_changed=content_changed,
    )


class EqualityGroups(unittest.TestCase):
    def test_manifest_inequality_is_the_invariant_stop(self) -> None:
        d = rn.group_decision(
            members=[
                group_member("aweb-server", reconciled="reconciled", p="1.27.2"),
                group_member("a2a-gateway-image", reconciled="reconciled", p="1.27.1"),
            ],
            manifest_versions={"aweb-server": "1.27.2", "a2a-gateway-image": "1.27.3"},
            compatibility="none",
        )
        self.assertEqual(d.kind, "stop")
        self.assertEqual(d.stop, "equality-invariant-violated")

    def test_control_lagging_member_recovers_at_m_with_no_patch(self) -> None:
        # Phantom-release control 1 (fails on the withdrawn rule): server
        # complete at M, gateway complete only through the prior version,
        # both manifests already M -> recovery at M, NO patch, no bump.
        d = rn.group_decision(
            members=[
                group_member("aweb-server", reconciled="reconciled", p="1.27.2"),
                group_member(
                    "a2a-gateway-image",
                    reconciled="recoverable-partial",
                    p="1.27.1",
                    candidate="1.27.2",
                    content_changed=True,
                ),
            ],
            manifest_versions={"aweb-server": "1.27.2", "a2a-gateway-image": "1.27.2"},
            compatibility="none",
        )
        self.assertEqual(d.kind, "shared-candidate")
        self.assertEqual(d.version, "1.27.2")
        self.assertIsNone(d.patch)
        self.assertEqual(d.recovering, ("a2a-gateway-image",))

    def test_control_conflicting_member_mints_one_shared_patch(self) -> None:
        # Phantom-release control 2: the lagging member CONFLICTS at M ->
        # one shared next patch, both manifests moved exactly once,
        # labeled by the driving member.
        d = rn.group_decision(
            members=[
                group_member("aweb-server", reconciled="reconciled", p="1.27.2"),
                group_member(
                    "a2a-gateway-image",
                    reconciled="conflicting-partial",
                    p="1.27.1",
                    candidate="1.27.2",
                    content_changed=True,
                ),
            ],
            manifest_versions={"aweb-server": "1.27.2", "a2a-gateway-image": "1.27.2"},
            compatibility="none",
        )
        self.assertEqual(d.kind, "shared-candidate")
        self.assertEqual(d.version, "1.27.3")
        self.assertEqual(
            d.patch,
            (("a2a-gateway-image", "1.27.2", "1.27.3"), ("aweb-server", "1.27.2", "1.27.3")),
        )
        self.assertEqual(d.driver, "a2a-gateway-image")

    def test_both_current_and_unchanged_is_unmoved(self) -> None:
        d = rn.group_decision(
            members=[
                group_member("awid-service", reconciled="reconciled", p="0.5.16"),
                group_member("awid-image", reconciled="reconciled", p="0.5.16"),
            ],
            manifest_versions={"awid-service": "0.5.16", "awid-image": "0.5.16"},
            compatibility="none",
        )
        self.assertEqual(d.kind, "unmoved")

    def test_content_change_on_one_side_mints_for_both_with_driver_label(self) -> None:
        # The bundled-server case: image content moved, service did not.
        d = rn.group_decision(
            members=[
                group_member("awid-service", reconciled="reconciled", p="0.5.16"),
                group_member(
                    "awid-image",
                    reconciled="reconciled",
                    p="0.5.16",
                    content_changed=True,
                ),
            ],
            manifest_versions={"awid-service": "0.5.16", "awid-image": "0.5.16"},
            compatibility="none",
        )
        self.assertEqual(d.kind, "shared-candidate")
        self.assertEqual(d.version, "0.5.17")
        self.assertEqual(d.driver, "awid-image")

    def test_compat_break_stops_before_minting(self) -> None:
        d = rn.group_decision(
            members=[
                group_member("awid-service", reconciled="reconciled", p="0.5.16"),
                group_member(
                    "awid-image",
                    reconciled="reconciled",
                    p="0.5.16",
                    content_changed=True,
                ),
            ],
            manifest_versions={"awid-service": "0.5.16", "awid-image": "0.5.16"},
            compatibility="db-break",
        )
        self.assertEqual(d.kind, "stop")
        self.assertEqual(d.stop, "compat-version-decision-needed")

    def test_member_stop_propagates(self) -> None:
        d = rn.group_decision(
            members=[
                group_member("awid-service", reconciled="stop", p=None),
                group_member("awid-image", reconciled="reconciled", p="0.5.16"),
            ],
            manifest_versions={"awid-service": "0.5.16", "awid-image": "0.5.16"},
            compatibility="none",
        )
        self.assertEqual(d.kind, "stop")


if __name__ == "__main__":
    unittest.main()
