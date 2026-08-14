"""Entry-point routing contract (aben R3): every canonical unit target
spelling routes to a discoverer, and unknown spellings raise."""

from __future__ import annotations

import sys
import unittest
from unittest import mock
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_normalizer_capture as cap  # noqa: E402
import release_normalizer_main as main  # noqa: E402
import release_train as rt  # noqa: E402


class Routing(unittest.TestCase):
    def test_every_canonical_unit_target_routes(self) -> None:
        # Image targets carry their revision identity out of discovery;
        # listing-only targets (pypi/npm/github) are identityless.
        specs = cap.derive_capture_specs(rt.ARTIFACTS)
        with mock.patch.multiple(
            cap,
            discover_pypi_versions=lambda *a, **k: {"1.0.0"},
            discover_npm_versions=lambda *a, **k: {"1.0.0"},
            discover_ghcr_versions=lambda *a, **k: {"1.0.0"},
            discover_github_release_versions=lambda *a, **k: {"1.0.0"},
            read_oci_revision=lambda *a, **k: "a" * 40,
        ):
            for spec in specs:
                for target in spec.unit_targets:
                    with self.subTest(target=target):
                        occupied = main.route_discovery(
                            target,
                            timeout=1,
                            ghcr_token="",
                            gh_token="",
                            bases=main.registry_bases(),
                        )
                        expected = (
                            {"1.0.0": "a" * 40}
                            if target.startswith("ghcr.io/")
                            else {"1.0.0": None}
                        )
                        self.assertEqual(occupied, expected)

    def test_unknown_spelling_raises_not_skips(self) -> None:
        with self.assertRaises(ValueError):
            main.route_discovery(
                "render:something",
                timeout=1,
                ghcr_token="",
                gh_token="",
                bases=main.registry_bases(),
            )

    def test_equality_groups_are_the_canonical_pairs(self) -> None:
        self.assertEqual(
            main.EQUALITY_GROUPS,
            (("awid-service", "awid-image"), ("aweb-server", "a2a-gateway-image")),
        )


if __name__ == "__main__":
    unittest.main()
