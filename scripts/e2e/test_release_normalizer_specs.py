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

    def test_locks_are_excluded_and_the_manifest_is_masked_not_excluded(self) -> None:
        # A3: excluding the whole manifest hid dependency-only changes
        # (the gate's blind-spot probe). Generated locks stay excluded
        # wholesale; the manifest is masked - in scope with only the
        # owned version field normalized.
        server = self.specs["aweb-server"]
        self.assertIn("server/uv.lock", server.excluded)
        self.assertNotIn("server/pyproject.toml", server.excluded)
        self.assertEqual(server.masked, ("server/pyproject.toml",))

    def test_release_tag_prefix_has_exactly_one_owner(self) -> None:
        """The first real prepare read skills' github member as EMPTY
        because discovery stripped a bare "v" on its own authority
        while the status builder looked up skills-v{version} from the
        canonical record - two derivations of one fact, disagreeing.
        The owner is release_tag_prefix; discovery and read-back must
        both resolve through it."""

        import release_train as rt

        skills = rt._artifact("skills")
        aw = rt._artifact("aw-cli")
        # A release in the artifact's OWN source repository carries its
        # canonical anchor prefix; an external product repository tags
        # bare v.
        self.assertEqual(
            rt.release_tag_prefix(skills, "awebai/aweb"), "skills-v"
        )
        self.assertEqual(rt.release_tag_prefix(aw, "awebai/aw"), "v")
        # And every github target in the canonical inventory resolves
        # through the owner - no target left to a local guess.
        for entry in rt.ARTIFACTS:
            for target in entry.occupancy_unit or ():
                if not target.startswith("github:"):
                    continue
                _, repository, _channel = target.split(":", 2)
                prefix = rt.release_tag_prefix(entry, repository)
                self.assertTrue(prefix, target)
                spec = self.specs[entry.key]
                self.assertEqual(
                    spec.tag_prefixes[target], prefix,
                    f"{target}: capture spec disagrees with the owner",
                )

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
