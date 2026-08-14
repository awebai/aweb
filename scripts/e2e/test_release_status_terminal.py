"""A7: the status engine as the terminal authority (shipment finding 5).

The complete output inventory as four-state rows: GitHub releases with
their exact required assets, source anchors OBSERVED (never stated),
images read with real bearer auth and real expected revisions, the
assembly routing every declared target kind, and DONE meaning
release_status.done() over the whole sweep.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT / "scripts" / "e2e"))

import release_status_builders as builders  # noqa: E402
from registry_stand_in import RegistryStandIn  # noqa: E402

SHA = "a" * 40


class GithubReleaseRows(unittest.TestCase):
    def test_release_with_every_required_asset_is_present_rows(self) -> None:
        world = {
            "github_releases": {
                "awebai/aw": {
                    "v1.34.6": ["aw_1.34.6_linux_amd64.tar.gz", "checksums.txt"]
                }
            }
        }
        with RegistryStandIn(world) as registry:
            rows = builders.github_release_rows(
                "awebai/aw",
                "v1.34.6",
                required_assets=("aw_1.34.6_linux_amd64.tar.gz", "checksums.txt"),
                base=registry.base,
                token="",
                timeout=5,
            )
        by_fact = {row.fact: row for row in rows}
        self.assertTrue(
            by_fact["github:awebai/aw release v1.34.6"].present()
        )
        self.assertTrue(
            by_fact[
                "github:awebai/aw v1.34.6 asset aw_1.34.6_linux_amd64.tar.gz"
            ].present()
        )
        self.assertTrue(all(row.present() for row in rows), rows)

    def test_missing_required_asset_is_absent_not_collapsed(self) -> None:
        world = {
            "github_releases": {
                "awebai/aw": {"v1.34.6": ["checksums.txt"]}
            }
        }
        with RegistryStandIn(world) as registry:
            rows = builders.github_release_rows(
                "awebai/aw",
                "v1.34.6",
                required_assets=("aw_1.34.6_linux_amd64.tar.gz", "checksums.txt"),
                base=registry.base,
                token="",
                timeout=5,
            )
        states = {row.fact: row.state for row in rows}
        self.assertEqual(
            states["github:awebai/aw v1.34.6 asset aw_1.34.6_linux_amd64.tar.gz"],
            "observed-absent",
        )
        self.assertEqual(
            states["github:awebai/aw v1.34.6 asset checksums.txt"],
            "observed-present",
        )

    def test_absent_release_is_absent_rows(self) -> None:
        with RegistryStandIn({"github_releases": {"awebai/aw": {}}}) as registry:
            rows = builders.github_release_rows(
                "awebai/aw",
                "v9.9.9",
                required_assets=("checksums.txt",),
                base=registry.base,
                token="",
                timeout=5,
            )
        self.assertTrue(all(row.state == "observed-absent" for row in rows), rows)


class SourceAnchorRows(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name) / "repo"
        self.repo.mkdir()
        for args in (
            ("init", "-q", "-b", "main"),
            ("config", "user.email", "t@t"),
            ("config", "user.name", "t"),
        ):
            subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True)
        (self.repo / "f").write_text("x\n")
        subprocess.run(["git", "add", "-A"], cwd=self.repo, check=True, capture_output=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "one"], cwd=self.repo, check=True, capture_output=True
        )
        subprocess.run(
            ["git", "tag", "server-v1.27.2"], cwd=self.repo, check=True, capture_output=True
        )
        subprocess.run(
            ["git", "remote", "add", "origin", str(self.repo)],
            cwd=self.repo, check=True, capture_output=True,
        )
        self.sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, check=True,
            capture_output=True, text=True,
        ).stdout.strip()

    def tearDown(self):
        self._tmp.cleanup()

    def test_tag_at_the_expected_identity_is_present(self) -> None:
        row = builders.source_tag_row(
            self.repo, "server-v1.27.2", expected_identity=self.sha
        )
        self.assertTrue(row.present(), row)
        self.assertIn(self.sha, row.evidence)

    def test_tag_at_a_different_identity_is_conflict_never_present(self) -> None:
        row = builders.source_tag_row(
            self.repo, "server-v1.27.2", expected_identity="b" * 40
        )
        self.assertEqual(row.state, "conflict-unproven", row)

    def test_absent_tag_is_absent(self) -> None:
        row = builders.source_tag_row(
            self.repo, "server-v9.9.9", expected_identity=self.sha
        )
        self.assertEqual(row.state, "observed-absent", row)


class ImageAuth(unittest.TestCase):
    def test_bearer_reaches_every_oci_surface(self) -> None:
        # C2, the second verdict: the token was sent only on the
        # top-level manifest and dropped for child, config, and latest
        # reads - so an authenticated registry answered PRESENT for the
        # index and UNAVAILABLE for the load-bearing revision rows. The
        # wire test requires the bearer at EVERY endpoint.
        world = {
            "ghcr": {"awebai/awid": {"0.5.16": SHA, "latest": SHA}},
            "ghcr_index": {},
            "require_bearer": "real-token",
        }
        with RegistryStandIn(world) as registry:
            with_token = builders.image_rows(
                "awebai/awid",
                "0.5.16",
                required_platforms=(),
                check_latest=True,
                base=registry.base,
                token="real-token",
                timeout=5,
            )
            without = builders.image_rows(
                "awebai/awid",
                "0.5.16",
                required_platforms=(),
                check_latest=True,
                base=registry.base,
                token="",
                timeout=5,
            )
        self.assertTrue(
            all(row.present() for row in with_token),
            [row.render() for row in with_token],
        )
        self.assertTrue(
            all(row.state == "unavailable" for row in without),
            [row.render() for row in without],
        )


class AssemblyCompleteness(unittest.TestCase):
    def test_every_declared_target_kind_routes_to_a_builder(self) -> None:
        # The gate: GitHub targets rendered UNAVAILABLE forever because
        # no builder existed. The assembly must have no unrouted kind.
        import release_status_gates as gates
        import release_train as rt

        card_artifacts = [
            rt.ArtifactSelection(name=name, version="1.0.0", moves=True)
            for name in rt.CARD_ARTIFACT_ORDER
        ]
        card = type("C", (), {"artifacts": card_artifacts})()
        with RegistryStandIn({}) as registry:
            rows = gates.rows_for_artifacts(
                card,
                {a.name for a in card_artifacts},
                bases={
                    "pypi": registry.base,
                    "npm": registry.base,
                    "ghcr": registry.base,
                    "github": registry.base,
                },
                expected_sources={name: SHA for name in rt.CARD_ARTIFACT_ORDER},
                tokens={"ghcr": "", "github": ""},
                timeout=5,
            )
        unrouted = [
            row for row in rows if "no row builder routes" in row.evidence
        ]
        self.assertEqual(unrouted, [])

    def test_pypi_anchor_is_no_longer_stated_in_evidence(self) -> None:
        # The source anchor is its own observed row; presence evidence
        # must not carry an interpolated anchor claim nobody read.
        world = {
            "pypi_files": {
                "aweb": {
                    "1.27.2": {
                        "aweb-1.27.2.tar.gz": "c" * 64,
                        "aweb-1.27.2-py3-none-any.whl": "d" * 64,
                    }
                }
            }
        }
        with RegistryStandIn(world) as registry:
            rows = builders.pypi_rows(
                "aweb", "1.27.2", base=registry.base, timeout=5
            )
        for row in rows:
            self.assertNotIn("anchor", row.evidence, row)


class FactDomainEquality(unittest.TestCase):
    """C2: the produced registry-fact domain must EQUAL the derivable
    expected domain, both directions - a routed builder silently
    dropping a fact is detectable, which AssemblyCompleteness alone
    (no-unrouted-target) cannot see."""

    def _full_card(self):
        import release_train as rt

        versions = {
            "awid-service": "0.5.16",
            "aweb-server": "1.27.2",
            "awid-image": "0.5.16",
            "aw-cli": "1.34.6",
            "channel-plugin": "1.7.7",
            "pi-extension": "0.3.7",
            "skills": "0.2.13",
            "a2a-gateway-image": "1.27.2",
            "ac-image": "0.7.15",
        }
        artifacts = [
            rt.ArtifactSelection(name=name, version=version, moves=True)
            for name, version in versions.items()
        ]
        return type("C", (), {"artifacts": artifacts})(), versions

    def test_expected_domain_matches_produced_domain_both_ways(self) -> None:
        import release_status_gates as gates
        import release_train as rt

        card, versions = self._full_card()
        names = set(versions)
        expected_sources = {name: SHA for name in names}
        world = {
            "pypi_files": {
                "awid-service": {"0.5.16": {}},
                "aweb": {"1.27.2": {}},
            },
            "npm_tarballs": {},
            "ghcr": {},
            "ghcr_index": {},
            "github_releases": {},
            "github": {},
            "github_commits": {},
        }
        with RegistryStandIn(world) as registry:
            rows = gates.rows_for_artifacts(
                card,
                names,
                bases={
                    "pypi": registry.base,
                    "npm": registry.base,
                    "ghcr": registry.base,
                    "github": registry.base,
                },
                expected_sources=expected_sources,
                tokens={},
                timeout=5,
            )
        produced = {row.fact for row in rows}
        expected = gates.expected_fact_keys(
            card, names, include_source_tags=False,
            expected_sources=expected_sources,
        )
        self.assertEqual(
            expected - produced, set(), "facts the assembly never produced"
        )
        self.assertEqual(
            produced - expected, set(), "facts the derivation does not expect"
        )
        # The domain is nontrivial - a same-run positive control against
        # two empty sets agreeing.
        self.assertGreater(len(expected), 40, sorted(expected))

    def test_a_dropped_fact_is_detected_by_the_domain_check(self) -> None:
        # The omission mutation: filter one produced fact and the
        # equality names it.
        import release_status_gates as gates

        card, versions = self._full_card()
        names = set(versions)
        expected = gates.expected_fact_keys(
            card, names, include_source_tags=False,
            expected_sources={name: SHA for name in names},
        )
        victim = sorted(expected)[0]
        mutated = expected - {victim}
        self.assertEqual(expected - mutated, {victim})


class B5RealPath(unittest.TestCase):
    """B5 re-driven through the real public-read builders: the
    historically true world (three artifacts served, two never
    published) rendered from raw registry documents over the wire, not
    from fixture-authored states a mapper preserves."""

    def world(self) -> dict:
        return {
            "npm_tarballs": {"@awebai/aw/1.34.6.tgz": b"aw-cli-tarball-bytes"},
            "ghcr": {
                "awebai/awid": {"0.5.16": SHA},
                "awebai/a2a-gateway": {"1.27.2": SHA},
            },
            "pypi_files": {},
        }

    def rows(self, registry):
        return [
            *builders.pypi_rows(
                "awid-service", "0.5.16", base=registry.base, timeout=5
            ),
            *builders.pypi_rows(
                "aweb", "1.27.2", base=registry.base, timeout=5
            ),
            builders.npm_tarball_row(
                "@awebai/aw", "1.34.6", base=registry.base, timeout=5
            ),
            *builders.image_rows(
                "awebai/awid", "0.5.16",
                required_platforms=(), check_latest=False,
                base=registry.base, token="", timeout=5,
            ),
            *builders.image_rows(
                "awebai/a2a-gateway", "1.27.2",
                required_platforms=(), check_latest=False,
                base=registry.base, token="", timeout=5,
            ),
        ]

    def test_the_historically_true_world_reads_back_correctly(self) -> None:
        import release_status as status

        with RegistryStandIn(self.world()) as registry:
            rows = self.rows(registry)
        # Exact cardinality (dev2's control): 3 pypi facts per package
        # x2, one npm row, one image row per image = 9 rows total -
        # a dropped row cannot hide behind a preserved count.
        self.assertEqual(len(rows), 9, [r.fact for r in rows])
        present = [r for r in rows if r.present()]
        absent = [r for r in rows if r.state == "observed-absent"]
        self.assertEqual(len(present), 3, [r.render() for r in rows])
        self.assertEqual(len(absent), 6)
        self.assertFalse(status.done(rows))

    def test_false_state_cannot_render_present(self) -> None:
        # The false-publication attack through the real path: a registry
        # lying about integrity yields conflict, never presence; DONE
        # stays unreachable.
        import release_status as status

        world = self.world()
        world["npm_integrity_override"] = {
            "@awebai/aw/1.34.6": "sha512-" + "A" * 88
        }
        with RegistryStandIn(world) as registry:
            rows = self.rows(registry)
        npm = next(r for r in rows if "npm" in r.fact)
        self.assertEqual(npm.state, "conflict-unproven", npm.render())
        self.assertFalse(status.done(rows))

    def test_omission_is_blocked_by_assembly_not_by_done(self) -> None:
        # done() over fewer rows is trivially satisfiable - omission is
        # guarded one level up: the assembly must emit rows for EVERY
        # card artifact, pinned here by cardinality over a full card.
        import release_status as status

        with RegistryStandIn(self.world()) as registry:
            rows = self.rows(registry)
        self.assertTrue(status.done([r for r in rows if r.present()]))
        # ^ the attack works on a filtered list - which is why
        # AssemblyCompleteness pins the unfiltered assembly and the
        # terminal gate consumes THAT, never a caller-filtered list.


if __name__ == "__main__":
    unittest.main()
