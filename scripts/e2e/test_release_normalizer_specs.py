"""Capture specs derive from the canonical ARTIFACTS entries (aben R3).

The one-owner rule: derive_capture_specs reads the canonical metadata
and produces the assembly's inputs; these fixtures pin that derivation
to the real entries, so a canonical change flows into capture or fails
loudly - never a parallel table.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_normalizer_capture as cap  # noqa: E402
import release_train as rt  # noqa: E402


class SpecDerivation(unittest.TestCase):
    def setUp(self):
        self.specs = {s.name: s for s in cap.derive_capture_specs(rt.ARTIFACTS)}

    def test_every_versioned_artifact_yields_exactly_one_spec(self) -> None:
        self.assertEqual(
            set(self.specs),
            {
                "aweb-server",
                "awid-service",
                "awid-image",
                "aw-cli",
                "channel-plugin",
                "pi-extension",
                "skills",
                "a2a-gateway-image",
                "ac-image",
            },
        )

    def test_specs_mirror_canonical_fields_not_restate_them(self) -> None:
        for name, spec in self.specs.items():
            entry = next(a for a in rt.ARTIFACTS if a.key == name)
            with self.subTest(artifact=name):
                self.assertEqual(spec.scope, entry.content_scope)
                self.assertEqual(spec.anchor_kind, entry.anchor.kind)
                self.assertEqual(spec.anchor_value, entry.anchor.value)
                self.assertEqual(spec.unit_targets, entry.occupancy_unit)
                self.assertEqual(spec.repo_key, entry.repository)

    def test_excluded_is_version_source_plus_owned_locks(self) -> None:
        server = self.specs["aweb-server"]
        self.assertIn("server/pyproject.toml", server.excluded)
        self.assertIn("server/uv.lock", server.excluded)

    def test_cli_derivation_kind_follows_version_source(self) -> None:
        self.assertEqual(self.specs["aw-cli"].derivation, "tag-history")
        self.assertEqual(self.specs["aweb-server"].derivation, "manifest")

    def test_every_spec_manifest_path_exists_in_this_repository(self) -> None:
        # B1's lesson made permanent: a guessed path passes mirroring
        # tests and fails only at capture time; existence is the check.
        for name, spec in self.specs.items():
            if spec.repo_key != "aweb":
                continue
            with self.subTest(artifact=name):
                self.assertTrue(
                    (REPO_ROOT / spec.manifest_path).is_file(),
                    f"{name}: {spec.manifest_path} does not exist",
                )

    def test_a2a_manifest_resolves_the_equals_indirection(self) -> None:
        self.assertEqual(
            self.specs["a2a-gateway-image"].manifest_path, "server/pyproject.toml"
        )


if __name__ == "__main__":
    unittest.main()
