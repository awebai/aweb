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

    def test_declared_exclusions_are_verified_against_the_real_manifests(
        self,
    ) -> None:
        """Every content exclusion must be provably non-shipping.

        The live patch wanted channel-plugin 1.7.7 whose only in-scope
        change was channel/test/integration.test.ts: outside
        package.json's `files` allowlist and outside tsconfig's
        `include`, so the published bytes were identical either way.

        This reads the REAL package.json and tsconfig.json rather than
        restating the declaration, so an exclusion that stops being
        true - someone adds test/ to `files`, or a build starts
        consuming it - fails here instead of silently suppressing a
        real release."""

        import json
        import re

        checked = 0
        for entry in rt.ARTIFACTS:
            for excluded in entry.content_exclusions:
                package_dir = REPO_ROOT / excluded.rstrip("/").rsplit("/", 1)[0]
                manifest = package_dir / "package.json"
                if not manifest.is_file():
                    continue
                relative = excluded.rstrip("/").rsplit("/", 1)[1]
                with self.subTest(artifact=entry.key, path=excluded):
                    files = json.loads(manifest.read_text()).get("files")
                    self.assertIsNotNone(
                        files, f"{manifest} has no files allowlist"
                    )
                    self.assertNotIn(
                        relative, files,
                        f"{excluded} IS published - it must not be excluded",
                    )
                    tsconfig = package_dir / "tsconfig.json"
                    if tsconfig.is_file():
                        raw = re.sub(r"(?m)//.*$", "", tsconfig.read_text())
                        config = json.loads(raw)
                        self.assertIn(
                            relative, config.get("exclude", []),
                            f"{excluded} is compiled - it can reach dist",
                        )
                    checked += 1
        self.assertGreater(checked, 0, "no exclusion was actually verified")

    def test_exclusions_live_inside_their_artifact_scope(self) -> None:
        # An exclusion outside the scope excludes nothing and is a typo
        # that would read as deliberate.
        for entry in rt.ARTIFACTS:
            for excluded in entry.content_exclusions:
                with self.subTest(artifact=entry.key, path=excluded):
                    self.assertTrue(
                        any(excluded.startswith(s) for s in entry.content_scope),
                        f"{excluded} is not inside {entry.content_scope}",
                    )

    def test_version_mirrors_are_canonical_and_cover_the_plugin_pairs(
        self,
    ) -> None:
        """An artifact whose version appears in more than one committed
        file must declare every one of them.

        The live prepare reached NORMAL FORM and then refused:
        "skills committed plugin.json version '0.2.12' must equal
        package.json version '0.2.13'". The normalizer had patched the
        artifact's declared manifest and left its .claude-plugin mirror
        behind, because the coupling was known only to the guard that
        enforces it - one fact with two implementations, the guard
        reading it and the patcher ignoring it.

        The record owns it now, and check_plugin_equality derives its
        pairs from the record rather than restating them."""

        mirrors = {
            entry.key: entry.version_mirrors
            for entry in rt.ARTIFACTS
            if entry.version_mirrors
        }
        self.assertEqual(
            mirrors,
            {
                "channel-plugin": ("channel/.claude-plugin/plugin.json",),
                "skills": ("packages/claude-skills/.claude-plugin/plugin.json",),
            },
        )
        # Every declared mirror exists, and carries a version field -
        # a mirror path that is wrong fails here rather than at the
        # next release.
        import json

        for key, paths in mirrors.items():
            for relative in paths:
                with self.subTest(artifact=key, mirror=relative):
                    path = REPO_ROOT / relative
                    self.assertTrue(path.is_file(), relative)
                    self.assertIn("version", json.loads(path.read_text()))

    def test_the_plugin_equality_guard_reads_the_canonical_mirrors(self) -> None:
        # The guard's pairs must BE the record's mirrors, not a second
        # list that happens to agree today.
        pairs = rt.plugin_equality_pairs()
        self.assertEqual(
            {(name, mirror) for name, mirror, _package in pairs},
            {
                (entry.key, mirror)
                for entry in rt.ARTIFACTS
                for mirror in entry.version_mirrors
            },
        )
        for name, _mirror, package in pairs:
            self.assertEqual(package, rt._artifact(name).version_source)

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
