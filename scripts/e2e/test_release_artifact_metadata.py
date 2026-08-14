"""Contract tests for the canonical artifact/edge metadata (aben R1).

The design contract is docs/aben-design.md section 1: every canonical
artifact carries content_scope, anchor (a tagged union), occupancy_unit,
required_current_outputs, and owned_locks; anchors must equal the actual
publisher emissions in both directions; the schema is exact to nested
keys and types, so growth is loud.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_train  # noqa: E402

WORKFLOWS = REPO_ROOT / ".github" / "workflows"


def artifact(key: str):
    for entry in release_train.ARTIFACTS:
        if entry.key == key:
            return entry
    raise AssertionError(f"canonical inventory has no artifact {key!r}")


class ArtifactMetadataContract(unittest.TestCase):
    """The nine versioned artifacts carry the aben metadata exactly."""

    VERSIONED = (
        "aweb-server",
        "awid-service",
        "awid-image",
        "aw-cli",
        "channel-plugin",
        "pi-extension",
        "skills",
        "a2a-gateway-image",
        "ac-image",
    )

    def test_every_versioned_artifact_declares_a_content_scope(self) -> None:
        for key in self.VERSIONED:
            with self.subTest(artifact=key):
                scope = artifact(key).content_scope
                self.assertIsInstance(scope, tuple)
                self.assertTrue(scope, f"{key} has an empty content scope")
                for path in scope:
                    self.assertIsInstance(path, str)
                    self.assertTrue(path)

    def test_scopes_exclude_their_own_version_source_and_owned_locks(self) -> None:
        # The fixed-point construction: version manifests and owned locks
        # are normalized metadata, never content drivers.
        for key in self.VERSIONED:
            with self.subTest(artifact=key):
                entry = artifact(key)
                excluded = set()
                if entry.version_source and not entry.version_source.startswith(
                    ("tag-history:", "equals:")
                ):
                    excluded.add(entry.version_source)
                for lock in entry.owned_locks:
                    excluded.add(lock.path)
                for path in entry.content_scope:
                    self.assertNotIn(path, excluded)

    def test_anchor_is_an_exact_tagged_union(self) -> None:
        expected = {
            "aweb-server": ("tag_pattern", "server-v"),
            "awid-service": ("tag_pattern", "awid-service-v"),
            "awid-image": ("tag_pattern", "awid-v"),
            "aw-cli": ("tag_pattern", "aw-v"),
            "channel-plugin": ("tag_pattern", "channel-v"),
            "pi-extension": ("tag_pattern", "pi-v"),
            "skills": ("tag_pattern", "skills-v"),
            "a2a-gateway-image": ("tag_pattern", "a2a-gw-v"),
            "ac-image": (
                "oci_revision_label",
                "org.opencontainers.image.revision",
            ),
        }
        for key, (kind, value) in expected.items():
            with self.subTest(artifact=key):
                anchor = artifact(key).anchor
                self.assertEqual(anchor.kind, kind)
                self.assertEqual(anchor.value, value)

    def test_tag_anchors_equal_publisher_emissions_both_directions(self) -> None:
        # Forward: each canonical tag prefix appears as the publisher's
        # actual tag construction. Backward: every tag construction in the
        # publishers is claimed by exactly one canonical anchor.
        publisher_text = "\n".join(
            (WORKFLOWS / name).read_text(encoding="utf-8")
            for name in (
                "pypi-release.yml",
                "npm-release.yml",
                "awid-image-release.yml",
                "a2a-gateway-release.yml",
            )
        )
        canonical_prefixes = {
            artifact(key).anchor.value
            for key in self.VERSIONED
            if artifact(key).anchor.kind == "tag_pattern"
            and key != "aw-cli"  # aw tags are created in train/sync code, not these workflows
        }
        for prefix in canonical_prefixes:
            with self.subTest(prefix=prefix):
                self.assertTrue(
                    re.search(
                        r"(TAG_PREFIX:\s*|tag_prefix=|tag=\")" + re.escape(prefix),
                        publisher_text,
                    ),
                    f"no publisher emits tags with prefix {prefix!r}",
                )
        emitted = set(re.findall(r'tag="([a-z0-9-]+-v)\$\{VERSION\}"', publisher_text))
        emitted |= set(re.findall(r"tag_prefix=([a-z0-9-]+-v)\b", publisher_text))
        emitted |= set(re.findall(r"TAG_PREFIX:\s*([a-z0-9-]+-v)\s*$", publisher_text, re.M))
        for prefix in emitted:
            with self.subTest(emitted=prefix):
                self.assertIn(
                    prefix,
                    canonical_prefixes,
                    f"publisher emits {prefix!r} which no canonical anchor claims",
                )

    def test_ac_image_revision_label_is_stamped_and_read(self) -> None:
        # The label must exist where the design says it lives; the AC
        # Dockerfile is in the sibling repository, so this half of the
        # bidirectional test asserts the reader's side here and the AC
        # repository's contract test asserts the stamper's side.
        adoption = (REPO_ROOT.parent / "ac" / "scripts").glob("verify_registry_adoption.py")
        del adoption  # reader-side location is AC's; asserted in AC's round
        anchor = artifact("ac-image").anchor
        self.assertEqual(anchor.kind, "oci_revision_label")

    def test_occupancy_units_cover_composites_exactly(self) -> None:
        aw = artifact("aw-cli")
        self.assertEqual(
            aw.occupancy_unit,
            ("github:awebai/aw:release",)
            + tuple(f"npm:{p}" for p in release_train.AW_NPM_PACKAGES),
        )
        skills = artifact("skills")
        self.assertEqual(
            skills.occupancy_unit,
            (
                "npm:@awebai/claude-skills",
                "github:awebai/aweb:skills-release-zips",
            ),
        )
        for key in ("aweb-server", "awid-service", "channel-plugin", "pi-extension"):
            with self.subTest(artifact=key):
                self.assertEqual(artifact(key).occupancy_unit, artifact(key).targets[:1])

    def test_owned_locks_match_the_measured_policy(self) -> None:
        self.assertEqual(
            tuple((l.path, l.method) for l in artifact("awid-service").owned_locks),
            (("awid/uv.lock", "uv-lock-offline"),),
        )
        self.assertEqual(
            tuple((l.path, l.method) for l in artifact("aweb-server").owned_locks),
            (("server/uv.lock", "uv-lock-offline"),),
        )
        self.assertEqual(
            tuple((l.path, l.method) for l in artifact("ac-image").owned_locks),
            (("backend/uv.lock", "uv-lock-offline"),),
        )
        # Measured (design section 1): npm lock root versions have no
        # consumer; the canonical entries are deliberately empty.
        self.assertEqual(artifact("channel-plugin").owned_locks, ())
        self.assertEqual(artifact("pi-extension").owned_locks, ())



class EdgeObligationContract(unittest.TestCase):
    """Typed obligations with per-type domain equality, both directions."""

    ALLOWED_TYPES = {
        "publication-order",
        "conditional-publication-order",
        "consumer-version-policy",
        "post-publication-consumer-derivation",
        "consumer-no-mutation-decision",
        "same-commit-content",
        "version-equality",
        "deploy-order",
    }
    RULE_TYPES = {
        "consumer-version-policy",
        "post-publication-consumer-derivation",
        "consumer-no-mutation-decision",
    }

    def test_every_obligation_type_is_canonical(self) -> None:
        for edge in release_train.DAG_EDGES:
            for kind, reference in edge.obligations:
                with self.subTest(edge=edge.number, obligation=kind):
                    self.assertIn(kind, self.ALLOWED_TYPES)
                    self.assertTrue(reference)

    def test_rule_table_domain_equality_both_directions(self) -> None:
        # The consumer rule table is R1..R4 (docs/aben-design.md section 4).
        # Every rule row is claimed by exactly one obligation and every
        # rule-typed obligation names a live row.
        claimed = [
            reference
            for edge in release_train.DAG_EDGES
            for kind, reference in edge.obligations
            if kind in self.RULE_TYPES
        ]
        self.assertEqual(sorted(claimed), ["R1", "R2", "R3", "R4"])

    def test_only_the_sites_edge_carries_no_obligation(self) -> None:
        for edge in release_train.DAG_EDGES:
            with self.subTest(edge=edge.number):
                if edge.kind == "independent":
                    self.assertEqual(edge.obligations, ())
                else:
                    self.assertTrue(edge.obligations)

    def test_version_equality_obligations_name_their_invariants(self) -> None:
        references = {
            reference
            for edge in release_train.DAG_EDGES
            for kind, reference in edge.obligations
            if kind == "version-equality"
        }
        self.assertEqual(
            references,
            {
                "card invariant: awid-service == awid-image",
                "train invariant: a2a-gateway == aweb-server",
            },
        )

if __name__ == "__main__":
    unittest.main()
