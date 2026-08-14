"""The movement/version table as a pure function (aben R3, design section 3).

Every row of the five-case table, the CLI exception, and the named stops
are asserted here against release_normalizer.movement_decision - a pure
function over (content_changed, manifest_version, reconciled_p,
occupied_versions, compatibility, derivation_kind). No I/O.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_normalizer as rn  # noqa: E402


def decide(
    *,
    content_changed: bool,
    manifest: str,
    published: str,
    occupied: frozenset[str] = frozenset(),
    compatibility: str = "none",
    derivation: str = "manifest",
):
    return rn.movement_decision(
        content_changed=content_changed,
        manifest_version=manifest,
        reconciled_p=published,
        occupied_versions=occupied | {published},
        compatibility=compatibility,
        derivation=derivation,
    )


class MovementTable(unittest.TestCase):
    def test_unchanged_and_equal_is_unmoved(self) -> None:
        d = decide(content_changed=False, manifest="1.2.3", published="1.2.3")
        self.assertEqual(d.kind, "unmoved")

    def test_unchanged_but_ahead_is_the_contentless_stop(self) -> None:
        d = decide(content_changed=False, manifest="1.2.4", published="1.2.3")
        self.assertEqual(d.kind, "stop")
        self.assertEqual(d.stop, "contentless-or-predeclared-version")

    def test_unchanged_but_behind_is_its_own_named_stop(self) -> None:
        d = decide(content_changed=False, manifest="1.2.2", published="1.2.3")
        self.assertEqual(d.kind, "stop")
        self.assertEqual(d.stop, "manifest-version-behind-public")

    def test_changed_with_free_greater_manifest_moves_at_it(self) -> None:
        d = decide(content_changed=True, manifest="1.3.0", published="1.2.3")
        self.assertEqual(d.kind, "moving")
        self.assertEqual(d.version, "1.3.0")
        self.assertIsNone(d.patch)

    def test_changed_with_occupied_manifest_is_version_occupied(self) -> None:
        d = decide(
            content_changed=True,
            manifest="1.3.0",
            published="1.2.3",
            occupied=frozenset({"1.3.0"}),
        )
        self.assertEqual(d.kind, "stop")
        self.assertEqual(d.stop, "version-occupied")

    def test_changed_with_stale_manifest_patches_to_exact_next(self) -> None:
        d = decide(content_changed=True, manifest="1.2.3", published="1.2.3")
        self.assertEqual(d.kind, "moving")
        self.assertEqual(d.version, "1.2.4")
        self.assertEqual(d.patch, ("1.2.3", "1.2.4"))

    def test_next_patch_occupied_is_version_occupied(self) -> None:
        d = decide(
            content_changed=True,
            manifest="1.2.3",
            published="1.2.3",
            occupied=frozenset({"1.2.4"}),
        )
        self.assertEqual(d.kind, "stop")
        self.assertEqual(d.stop, "version-occupied")

    def test_compat_break_never_mints_mechanically(self) -> None:
        d = decide(
            content_changed=True,
            manifest="1.2.3",
            published="1.2.3",
            compatibility="server-break",
        )
        self.assertEqual(d.kind, "stop")
        self.assertEqual(d.stop, "compat-version-decision-needed")

    def test_compat_break_accepts_a_human_chosen_free_version(self) -> None:
        # The stop is for MINTING; a reviewed greater free manifest is a
        # human decision already made.
        d = decide(
            content_changed=True,
            manifest="2.0.0",
            published="1.2.3",
            compatibility="server-break",
        )
        self.assertEqual(d.kind, "moving")
        self.assertEqual(d.version, "2.0.0")

    def test_cli_derivation_rederives_over_occupied_intent(self) -> None:
        # The CLI exception (B2): tag-history derivation re-derives the
        # next free patch mechanically instead of stopping on occupancy.
        d = decide(
            content_changed=True,
            manifest="1.34.5",
            published="1.34.5",
            derivation="tag-history",
        )
        self.assertEqual(d.kind, "moving")
        self.assertEqual(d.version, "1.34.6")

    def test_cli_derivation_walks_past_multiple_occupied(self) -> None:
        d = decide(
            content_changed=True,
            manifest="1.34.5",
            published="1.34.5",
            occupied=frozenset({"1.34.6", "1.34.7"}),
            derivation="tag-history",
        )
        self.assertEqual(d.kind, "moving")
        self.assertEqual(d.version, "1.34.8")

    def test_non_monotonic_manifest_refuses(self) -> None:
        # C=true, M>P but M below some occupied greater version: accepting
        # it would publish under the reconciled maximum.
        d = decide(
            content_changed=True,
            manifest="1.2.5",
            published="1.2.3",
            occupied=frozenset({"1.3.0"}),
        )
        self.assertEqual(d.kind, "stop")
        self.assertEqual(d.stop, "version-occupied")


class VersionGrammar(unittest.TestCase):
    def test_strict_numeric_grammar(self) -> None:
        for good in ("0.0.1", "1.27.2", "v1.2.3"):
            self.assertIsNotNone(rn.parse_version(good), good)
        for bad in ("1.2", "1.2.3-rc1", "1.2.3.4", "latest", "sha-abc"):
            self.assertIsNone(rn.parse_version(bad), bad)

    def test_ordering_is_numeric_not_lexical(self) -> None:
        self.assertLess(rn.parse_version("1.9.0"), rn.parse_version("1.10.0"))


if __name__ == "__main__":
    unittest.main()
