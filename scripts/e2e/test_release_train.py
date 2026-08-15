#!/usr/bin/env python3
"""Behavioral contract for the fixed two-repository release train foundation.

The tests use real temporary git repositories, subprocesses, and a loopback HTTP
server.  Nothing contacts or mutates GitHub, a public registry, AC, Render, or a
production service.
"""

from __future__ import annotations

import dataclasses
import inspect
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_train as rt


def _test_anchor(version: str) -> "rt.PreviousCompleteAnchor":
    return rt.PreviousCompleteAnchor(version, "tag", "f" * 40)


def _unmoved(item):
    import dataclasses as _dc
    return _dc.replace(
        item,
        moves=False,
        disposition="unmoved",
        previous_complete_anchor=_test_anchor(item.version),
    )


def _fixture_projection(aweb_root, environment, *, unmoved=()):
    """An all-moving normalizer projection over the fixture checkouts'
    real manifest versions; names in `unmoved` become unmoved rows with
    the fixture anchor identity. Stands in for the normalizer phase the
    production entry runs (its own contract lives in the canonical-entry
    suite)."""

    import release_normalizer as rn

    prepared = rt.prepare_environment(aweb_root, environment)
    artifacts = {}
    for name in rt.CARD_ARTIFACT_ORDER:
        version = rt._read_manifest_version(prepared, rt._artifact(name))
        if name in unmoved:
            artifacts[name] = rn.ArtifactResult(
                disposition="unmoved",
                version=version,
                previous_complete_anchor=(version, "f" * 40),
            )
        else:
            artifacts[name] = rn.ArtifactResult(
                disposition="moving", version=version
            )
    return rn.NormalizerResult(
        outcome="patch-needed", artifacts=artifacts, patches=(), stops=()
    )



VERSIONS = {
    "awid-service": "0.5.15",
    "aweb-server": "1.27.1",
    "awid-image": "0.5.15",
    "aw-cli": "1.34.2",
    "channel-plugin": "1.7.6",
    "pi-extension": "0.3.6",
    "skills": "0.2.12",
    "a2a-gateway-image": "1.27.1",
    "ac-image": "0.7.12",
}
DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64


def git(*args: str, cwd: Path) -> str:
    """Run git in a fixture repository.

    Identity is set HERE and stamped into every repository this helper
    initialises, rather than at call sites. Two reasons, both learned
    from a gate failure: a call site can forget, and - more
    importantly - PRODUCTION code under test runs git in these
    repositories too (publish_source_tag's annotated tag, continue's
    derive commit), so the identity has to live in the REPOSITORY, not
    only in this helper. A developer host has a global git config and
    the gate container has none, so a bare commit passes everywhere it
    is written and fails where it counts.
    """

    result = subprocess.run(
        ["git", "-c", "user.email=fixture@aweb.ai", "-c", "user.name=aweb fixture",
         *args],
        cwd=cwd, check=True, capture_output=True, text=True,
    )
    if args and args[0] == "init" and "--bare" not in args:
        # Bare repositories are skipped above: nothing commits in one,
        # so an identity there would be decoration.
        # Resolve the new repository by what ACTUALLY became one -
        # parsing the argv would have to know that -b takes a value,
        # and getting that wrong points the config at a branch name.
        candidates = [cwd] + [
            Path(a) if Path(a).is_absolute() else cwd / a
            for a in args[1:]
            if not a.startswith("-")
        ]
        target = next(
            (c for c in reversed(candidates) if (c / ".git").exists()), cwd
        )
        subprocess.run(["git", "config", "user.email", "fixture@aweb.ai"],
                       cwd=target, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "aweb fixture"],
                       cwd=target, check=True, capture_output=True)
    return result.stdout.strip()


class FixedContractTests(unittest.TestCase):
    def test_work_commands_get_a_multi_hour_bound_observations_keep_theirs(self) -> None:
        # Gate suites, publishes and deploys run for hours; a registry read
        # that takes that long is a hang, not work.
        self.assertGreaterEqual(rt.WORK_TIMEOUT, 4 * 3600)
        with self.assertRaises(rt.ValidationError):
            rt.observe_registry_presence(
                "http://127.0.0.1:9/never-dialed", "1.0.0", timeout=rt.WORK_TIMEOUT
            )
        for function in (rt.prepare, rt.continue_train):
            parameters = inspect.signature(function).parameters
            self.assertEqual(
                parameters["work_timeout"].default,
                rt.WORK_TIMEOUT,
                function.__name__,
            )
        for function in (rt.prepare, rt.continue_train, rt.run_gate_once):
            source = inspect.getsource(function)
            bounds = re.findall(r"run_command\(.*?\btimeout=(\w+)", source, re.S)
            self.assertTrue(bounds, function.__name__)
            self.assertEqual(set(bounds), {"work_timeout"}, function.__name__)

    def test_literal_artifact_rows_and_outputs_are_exact(self) -> None:
        self.assertEqual(
            rt.AW_NPM_PACKAGES,
            (
                "@awebai/aw",
                "@awebai/aw-linux-x64",
                "@awebai/aw-linux-arm64",
                "@awebai/aw-darwin-x64",
                "@awebai/aw-darwin-arm64",
                "@awebai/aw-windows-x64",
                "@awebai/aw-windows-arm64",
            ),
        )
        self.assertEqual(rt.AW_BINARIES, ("aw", "aweb-a2a-gw"))
        self.assertEqual(
            rt.SKILL_SOURCES,
            (
                "aweb-coordination",
                "aweb-messaging",
                "aweb-team-membership",
                "aweb-bootstrap",
                "aweb-identity",
            ),
        )
        self.assertEqual(
            rt.SKILL_ZIPS,
            (
                "aweb-coordination.zip",
                "aweb-messaging.zip",
                "aweb-team-membership.zip",
                "aweb-bootstrap.zip",
                "aweb-identity.zip",
            ),
        )
        self.assertEqual(rt.OCI_PLATFORMS, ("linux/amd64", "linux/arm64"))
        self.assertEqual(
            rt.ARTIFACTS,
            (
                rt.Artifact(
                    "aweb-server",
                    "aweb",
                    "aweb server",
                    ("pypi:aweb",),
                    "server/pyproject.toml",
                    content_scope=("server/",),
                    anchor=rt.Anchor("tag_pattern", "server-v"),
                    occupancy_unit=("pypi:aweb",),
                    owned_locks=(rt.OwnedLock("server/uv.lock", "uv-lock-offline"),),
                ),
                rt.Artifact(
                    "awid-service",
                    "aweb",
                    "AWID service",
                    ("pypi:awid-service",),
                    "awid/pyproject.toml",
                    content_scope=("awid/",),
                    anchor=rt.Anchor("tag_pattern", "awid-service-v"),
                    occupancy_unit=("pypi:awid-service",),
                    owned_locks=(rt.OwnedLock("awid/uv.lock", "uv-lock-offline"),),
                ),
                rt.Artifact(
                    "awid-image",
                    "aweb",
                    "AWID image",
                    ("ghcr.io/awebai/awid",),
                    "awid/pyproject.toml",
                    platforms=rt.OCI_PLATFORMS,
                    bundled_inputs=("server-source",),
                    content_scope=("awid/", "server/"),
                    anchor=rt.Anchor("tag_pattern", "awid-v"),
                    occupancy_unit=("ghcr.io/awebai/awid",),
                    required_current_outputs=rt.OCI_PLATFORMS,
                    promises_latest=True,
                ),
                rt.Artifact(
                    "aw-cli",
                    "aweb",
                    "aw CLI",
                    ("github:awebai/aw:release",)
                    + tuple(f"npm:{package}" for package in rt.AW_NPM_PACKAGES),
                    "tag-history:aw-v*",
                    outputs=rt.AW_BINARIES,
                    external_repository="awebai/aw",
                    content_scope=("cli/go/",),
                    anchor=rt.Anchor("tag_pattern", "aw-v"),
                    occupancy_unit=("github:awebai/aw:release",)
                    + tuple(f"npm:{package}" for package in rt.AW_NPM_PACKAGES),
                    required_current_outputs=rt.AW_RELEASE_ASSETS,
                ),
                rt.Artifact(
                    "channel-plugin",
                    "aweb",
                    "channel plugin",
                    ("npm:@awebai/claude-channel",),
                    "channel/package.json",
                    bundled_inputs=("channel-core",),
                    content_scope=("channel/", "channel-core/"),
                    content_exclusions=("channel/test/", "channel-core/test/"),
                    version_mirrors=("channel/.claude-plugin/plugin.json",),
                    anchor=rt.Anchor("tag_pattern", "channel-v"),
                    occupancy_unit=("npm:@awebai/claude-channel",),
                ),
                rt.Artifact(
                    "pi-extension",
                    "aweb",
                    "Pi extension",
                    ("npm:@awebai/pi",),
                    "pi-extension/package.json",
                    bundled_inputs=("channel-core",) + rt.SKILL_SOURCES,
                    content_scope=("pi-extension/", "channel-core/", "skills/"),
                    content_exclusions=("pi-extension/test/", "channel-core/test/"),
                    anchor=rt.Anchor("tag_pattern", "pi-v"),
                    occupancy_unit=("npm:@awebai/pi",),
                ),
                rt.Artifact(
                    "skills",
                    "aweb",
                    "skills",
                    (
                        "npm:@awebai/claude-skills",
                        "github:awebai/aweb:skills-release-zips",
                    ),
                    "packages/claude-skills/package.json",
                    outputs=rt.SKILL_ZIPS,
                    bundled_inputs=rt.SKILL_SOURCES,
                    content_scope=("packages/claude-skills/", "skills/"),
                    version_mirrors=(
                        "packages/claude-skills/.claude-plugin/plugin.json",
                    ),
                    anchor=rt.Anchor("tag_pattern", "skills-v"),
                    occupancy_unit=(
                        "npm:@awebai/claude-skills",
                        "github:awebai/aweb:skills-release-zips",
                    ),
                    required_current_outputs=rt.SKILL_ZIPS,
                ),
                rt.Artifact(
                    "a2a-gateway-image",
                    "aweb",
                    "a2a-gateway image",
                    ("ghcr.io/awebai/a2a-gateway",),
                    "equals:server/pyproject.toml",
                    platforms=rt.OCI_PLATFORMS,
                    content_scope=("cli/go/",),
                    anchor=rt.Anchor("tag_pattern", "a2a-gw-v"),
                    occupancy_unit=("ghcr.io/awebai/a2a-gateway",),
                    required_current_outputs=rt.OCI_PLATFORMS,
                    promises_latest=True,
                ),
                rt.Artifact(
                    "awid-site",
                    "aweb",
                    "awid.ai site",
                    ("render-static:deploy-awid-landing",),
                    None,
                ),
                rt.Artifact(
                    "ac-image",
                    "ac",
                    "product image",
                    ("ghcr.io/awebai/ac",),
                    "backend/pyproject.toml",
                    platforms=rt.OCI_PLATFORMS,
                    content_scope=("backend/", "frontend/", "Dockerfile.release"),
                    # Juan's tag ruling: a release's identity is the
                    # tag in its own repository, ac-image included.
                    anchor=rt.Anchor("tag_pattern", "v"),
                    occupancy_unit=("ghcr.io/awebai/ac",),
                    required_current_outputs=rt.OCI_PLATFORMS,
                    owned_locks=(rt.OwnedLock("backend/uv.lock", "uv-lock-offline"),),
                ),
                rt.Artifact(
                    "ac-production",
                    "ac",
                    "production deploy",
                    ("render:aweb-cloud:image-digest",),
                    "image:ghcr.io/awebai/ac@digest",
                ),
                rt.Artifact(
                    "aweb-site",
                    "ac",
                    "aweb.ai site",
                    ("render-static:deploy-landing",),
                    None,
                ),
            ),
        )

    def test_literal_ten_edge_order_is_exact(self) -> None:
        self.assertEqual(
            tuple(
                (edge.number, edge.kind, edge.nodes, edge.rule)
                for edge in rt.DAG_EDGES
            ),
            (
                (
                    1,
                    "ordering",
                    ("awid-service", "aweb-server"),
                    "public PyPI AWID dependency floor before aweb",
                ),
                (
                    2,
                    "ordering",
                    ("aw-cli-npm-set", "pi-extension"),
                    "all seven aw npm packages served before Pi when its floor moves",
                ),
                (
                    3,
                    "ordering",
                    ("channel-plugin", "skills", "marketplace-pointer"),
                    "channel and skills served before marketplace advance",
                ),
                (
                    4,
                    "ordering",
                    (
                        "intended-aweb-awid-public",
                        "ac-dependency-commit",
                        "ac-gate",
                    ),
                    "public packages before derived AC dependency commit and gate",
                ),
                (
                    5,
                    "ordering",
                    ("ac-image", "ac-production", "digest-health-verification"),
                    "AC image before deploy before digest and health verification",
                ),
                (
                    6,
                    "same-commit",
                    ("channel-core", "channel-plugin", "pi-extension"),
                    "one channel-core input in channel and Pi",
                ),
                (
                    7,
                    "same-commit",
                    ("skill-source-set", "pi-extension", "skills", "skills-zips"),
                    "the same five skill sources in every output",
                ),
                (
                    8,
                    "same-commit",
                    ("server-source", "awid-image"),
                    "server source in the same-commit AWID image",
                ),
                (
                    9,
                    "equality",
                    ("a2a-gateway-image", "aweb-server"),
                    "a2a-gateway version equals server version",
                ),
                (
                    10,
                    "independent",
                    ("awid-site", "aweb-site"),
                    "both site branch pushes are independent of the artifact train",
                ),
            ),
        )

    def test_only_the_fixed_git_local_card_path_exists(self) -> None:
        self.assertEqual(rt.CARD_GIT_PATH, "aweb-release-card.json")
        self.assertEqual(
            {
                name: value
                for name, value in vars(rt).items()
                if name.endswith(("_GIT_PATH", "_STATE_PATH"))
            },
            {"CARD_GIT_PATH": "aweb-release-card.json"},
        )
        self.assertFalse(hasattr(rt, "validate_fixed_contract"))
        self.assertFalse(hasattr(rt, "ContractError"))


class ValidationTests(unittest.TestCase):
    def test_strict_shas_versions_and_lines(self) -> None:
        sha = "3f7a1c9e4b02d85617fa03cc9b1e4d7a5806e2f1"
        self.assertEqual(rt.validate_sha(sha, "source"), sha)
        self.assertEqual(rt.validate_version("1.2.3", "server"), "1.2.3")
        self.assertEqual(rt.validate_version("1.2.3-rc.1", "server"), "1.2.3-rc.1")
        self.assertEqual(rt.validate_line("release security fix", "purpose"),
                         "release security fix")
        self.assertEqual(rt.validate_compatibility("none"), "none")
        self.assertEqual(rt.validate_compatibility("drops removed v1 field"),
                         "drops removed v1 field")

        for bad in ("a" * 39, "A" * 40, "0" * 40, "g" * 40, " a" * 20):
            with self.subTest(sha=bad):
                with self.assertRaises(rt.ValidationError):
                    rt.validate_sha(bad, "source")
        for bad in ("v1.2.3", "1.2", "01.2.3", "1.2.3 ", "latest"):
            with self.subTest(version=bad):
                with self.assertRaises(rt.ValidationError):
                    rt.validate_version(bad, "server")
        for bad in ("", " ", "two\nlines", " leading", "trailing "):
            with self.subTest(line=bad):
                with self.assertRaises(rt.ValidationError):
                    rt.validate_line(bad, "purpose")
        for bad in ("NONE", "two\nlines", ""):
            with self.subTest(compatibility=bad):
                with self.assertRaises(rt.ValidationError):
                    rt.validate_compatibility(bad)


class CardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / "repo"
        self.repo.mkdir()
        git("init", "-q", "-b", "main", cwd=self.repo)
        git("config", "user.email", "release-test@example.invalid", cwd=self.repo)
        git("config", "user.name", "Release Test", cwd=self.repo)
        (self.repo / "source").write_text("one\n")
        git("add", "source", cwd=self.repo)
        git("commit", "-qm", "first", cwd=self.repo)
        self.aweb_sha = git("rev-parse", "HEAD", cwd=self.repo)
        (self.repo / "source").write_text("two\n")
        git("commit", "-qam", "second", cwd=self.repo)
        self.ac_sha = git("rev-parse", "HEAD", cwd=self.repo)
        self.addCleanup(self.tmp.cleanup)

    def card(self, **changes: object) -> rt.ReleaseCard:
        values: dict[str, object] = {
            "aweb_sha": self.aweb_sha,
            "ac_base_sha": self.ac_sha,
            "artifacts": tuple(
                rt.ArtifactSelection(name, VERSIONS[name], True)
                for name in rt.CARD_ARTIFACT_ORDER
            ),
            "compatibility": "none",
            "gates": (
                rt.GateEvidence(
                    "aweb-clean-docker",
                    self.aweb_sha,
                    "passed",
                    "logs/aweb-gate.log",
                    ("unit", "journeys", "artifact-builds"),
                ),
                rt.GateEvidence(
                    "compatibility",
                    self.aweb_sha,
                    "not-relevant",
                    "logs/compatibility.log",
                    ("boundary-selection",),
                ),
            ),
            "purpose": "release the reviewed reliability fixes",
            "deployments": rt.DeploymentSet(True, True, False),
            "final_ac_sha": None,
            "production_correction_pending": True,
        }
        values.update(changes)
        return rt.ReleaseCard.create(**values)

    def test_card_path_is_one_fixed_git_local_file(self) -> None:
        expected = git(
            "rev-parse", "--git-path", rt.CARD_GIT_PATH, cwd=self.repo
        )
        expected_path = Path(expected)
        if not expected_path.is_absolute():
            expected_path = self.repo / expected_path
        self.assertEqual(rt.card_path(self.repo), expected_path.resolve())
        self.assertNotEqual(rt.card_path(self.repo), self.repo / rt.CARD_GIT_PATH)

    def test_canonical_write_read_and_idempotent_same_card(self) -> None:
        card = self.card()
        path = rt.write_card(self.repo, card)
        first = path.read_bytes()
        self.assertEqual(first, card.canonical_bytes())
        self.assertEqual(rt.read_card(self.repo), card)
        self.assertEqual(rt.write_card(self.repo, card), path)
        self.assertEqual(path.read_bytes(), first)

    def test_unknown_or_malformed_card_fields_are_refused(self) -> None:
        path = rt.card_path(self.repo)
        path.parent.mkdir(parents=True, exist_ok=True)
        document = self.card().to_dict()
        document["release_id"] = "forbidden"
        path.write_text(json.dumps(document))
        with self.assertRaisesRegex(rt.CardFormatError, "unknown.*release_id"):
            rt.read_card(self.repo)

        document = self.card().to_dict()
        document["artifacts"][0]["extra"] = True
        path.write_text(json.dumps(document))
        with self.assertRaisesRegex(rt.CardFormatError, "unknown.*extra"):
            rt.read_card(self.repo)

        path.write_text('{"purpose":"first","purpose":"second"}')
        with self.assertRaisesRegex(rt.CardFormatError, "duplicate.*purpose"):
            rt.read_card(self.repo)

        path.write_text("not json")
        with self.assertRaisesRegex(rt.CardFormatError, "malformed"):
            rt.read_card(self.repo)

    def test_every_material_change_is_detected(self) -> None:
        original = self.card()
        selection = list(original.artifacts)
        selection[0] = _unmoved(selection[0])
        changes = {
            "purpose": self.card(purpose="a different release purpose"),
            "compatibility": self.card(compatibility="drops a removed field"),
            "sha": self.card(ac_base_sha=self.aweb_sha),
            "artifact set": self.card(artifacts=tuple(selection)),
        }
        for label, changed in changes.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(rt.MaterialMismatch, label.split()[0]):
                    rt.assert_material_matches(original, changed)

    def test_changed_existing_card_is_refused(self) -> None:
        rt.write_card(self.repo, self.card())
        with self.assertRaisesRegex(rt.MaterialMismatch, "purpose"):
            rt.write_card(
                self.repo,
                self.card(purpose="a materially different purpose"),
            )

    def test_done_consumes_the_card_and_replay_is_refused(self) -> None:
        card = self.card()
        path = rt.write_card(self.repo, card)
        rt.consume_card(self.repo, card)
        self.assertFalse(path.exists())
        with self.assertRaisesRegex(rt.CardUnavailable, "missing or consumed"):
            rt.consume_card(self.repo, card)
        self.assertFalse(any(path.parent.glob("*release*state*")))

    def test_card_enforces_complete_ordered_set_and_equal_versions(self) -> None:
        original = self.card()
        with self.assertRaisesRegex(rt.ValidationError, "artifact order"):
            self.card(artifacts=tuple(reversed(original.artifacts)))
        with self.assertRaisesRegex(rt.ValidationError, "a2a-gateway.*server"):
            self.card(
                artifacts=tuple(
                    dataclasses.replace(item, version="9.9.9")
                    if item.name == "a2a-gateway-image"
                    else item
                    for item in original.artifacts
                )
            )
        with self.assertRaisesRegex(rt.ValidationError, "AWID service.*image"):
            self.card(
                artifacts=tuple(
                    dataclasses.replace(item, version="9.9.9")
                    if item.name == "awid-image"
                    else item
                    for item in original.artifacts
                )
            )
        with self.assertRaisesRegex(rt.ValidationError, "final AC SHA.*pending"):
            self.card(final_ac_sha=self.aweb_sha)

    def test_production_and_first_correction_are_inferred_from_ac_image(self) -> None:
        original = self.card()
        ac_not_moving = tuple(
            _unmoved(item)
            if item.name == "ac-image"
            else item
            for item in original.artifacts
        )
        with self.assertRaisesRegex(rt.ValidationError, "production deployment"):
            self.card(artifacts=ac_not_moving)
        with self.assertRaisesRegex(rt.ValidationError, "production correction"):
            self.card(
                artifacts=ac_not_moving,
                deployments=rt.DeploymentSet(False, True, False),
            )


class _RegistryHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == "/absent":
            self.send_error(404)
            return
        if self.path == "/unavailable":
            self.send_error(503)
            return
        if self.path == "/slow":
            time.sleep(0.2)
            body = json.dumps(
                {"state": "present", "version": "1.2.3", "digest": DIGEST}
            ).encode()
        elif self.path == "/declared-absent":
            body = json.dumps({"state": "absent"}).encode()
        elif self.path == "/exact":
            body = json.dumps(
                {"state": "present", "version": "1.2.3", "digest": DIGEST}
            ).encode()
        elif self.path == "/conflict":
            body = json.dumps(
                {"state": "present", "version": "1.2.3", "digest": OTHER_DIGEST}
            ).encode()
        elif self.path == "/malformed":
            body = b'{"state":"present","version":"1.2.3"}'
        elif self.path == "/unknown":
            body = json.dumps({"state": "absent", "error": "offline"}).encode()
        else:
            self.send_error(500)
            return
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, _format: str, *args: object) -> None:
        pass


class BoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _RegistryHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_registry_absence_exact_adoption_and_conflict_are_distinct(self) -> None:
        self.assertEqual(
            rt.observe_registry(
                self.base_url + "/absent", "1.2.3", DIGEST, timeout=1
            ),
            rt.RegistryOutcome.ABSENT,
        )
        self.assertEqual(
            rt.observe_registry(
                self.base_url + "/exact", "1.2.3", DIGEST, timeout=1
            ),
            rt.RegistryOutcome.EXACT,
        )
        self.assertEqual(
            rt.observe_registry(
                self.base_url + "/conflict", "1.2.3", DIGEST, timeout=1
            ),
            rt.RegistryOutcome.CONFLICT,
        )

    def test_timeout_or_unavailability_is_never_misread_as_absence(self) -> None:
        for path, timeout in (("/unavailable", 1), ("/slow", 0.02)):
            with self.subTest(path=path):
                with self.assertRaises(rt.ObservationUnavailable):
                    rt.observe_registry(
                        self.base_url + path, "1.2.3", DIGEST, timeout=timeout
                    )

    def test_malformed_or_self_declared_absence_is_refused(self) -> None:
        for path in ("/malformed", "/unknown", "/declared-absent"):
            with self.subTest(path=path):
                with self.assertRaises(rt.ObservationMalformed):
                    rt.observe_registry(
                        self.base_url + path, "1.2.3", DIGEST, timeout=1
                    )

    def test_fake_executable_boundary_has_bounded_failures(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            program = Path(tmp) / "boundary.py"
            program.write_text(
                "import sys,time\n"
                "mode=sys.argv[1]\n"
                "if mode == 'slow': time.sleep(0.2)\n"
                "if mode == 'fail': raise SystemExit(7)\n"
                "print('boundary-ok')\n"
            )
            result = rt.run_command(
                [sys.executable, str(program), "ok"], cwd=Path(tmp), timeout=1
            )
            self.assertEqual(result.stdout.strip(), "boundary-ok")
            with self.assertRaisesRegex(rt.CommandFailed, "exit 7"):
                rt.run_command(
                    [sys.executable, str(program), "fail"],
                    cwd=Path(tmp),
                    timeout=1,
                )
            with self.assertRaisesRegex(rt.CommandUnavailable, "timed out"):
                rt.run_command(
                    [sys.executable, str(program), "slow"],
                    cwd=Path(tmp),
                    timeout=0.02,
                )
            with self.assertRaisesRegex(rt.CommandUnavailable, "not available"):
                rt.run_command(
                    [str(Path(tmp) / "missing")], cwd=Path(tmp), timeout=1
                )


class PrepareEnvironmentTests(unittest.TestCase):
    """release-prepare refuses every unfit environment naming the exact fix.

    Real temporary repositories with bare remotes whose paths end in
    awebai/aweb and awebai/ac, so the genuine origin check passes without any
    test-only injection.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.aweb_remote = root / "origins/awebai/aweb.git"
        self.ac_remote = root / "origins/awebai/ac.git"
        for remote in (self.aweb_remote, self.ac_remote):
            remote.parent.mkdir(parents=True, exist_ok=True)
            git("init", "--bare", str(remote), cwd=root)
        self.aweb = root / "work/aweb"
        self.ac = root / "work/ac"
        for repo, remote, seed in (
            (self.aweb, self.aweb_remote, "server/pyproject.toml"),
            (self.ac, self.ac_remote, "backend/pyproject.toml"),
        ):
            repo.mkdir(parents=True)
            git("init", "-b", "main", cwd=repo)
            git("config", "user.email", "test@example.com", cwd=repo)
            git("config", "user.name", "Test", cwd=repo)
            seed_path = repo / seed
            seed_path.parent.mkdir(parents=True, exist_ok=True)
            seed_path.write_text('[project]\nversion = "1.0.0"\n')
            git("add", ".", cwd=repo)
            git("commit", "-m", "base", cwd=repo)
            git("remote", "add", "origin", str(remote), cwd=repo)
            git("push", "-u", "origin", "main", cwd=repo)
            git("fetch", "origin", cwd=repo)

    def _environment(self, **overrides: str) -> dict[str, str]:
        environment = {"PURPOSE": "test release", "COMPAT_BREAK": "none"}
        environment.update(overrides)
        return environment

    def _prepare(self, repo_root: Path | None = None, **overrides: str):
        environment = self._environment(**overrides)
        try:
            projection = _fixture_projection(self.aweb, environment)
        except rt.ReleaseTrainError:
            # Environment-refusal cases raise again inside prepare,
            # which is the behavior under test; the projection is not
            # reached.
            projection = None
        return rt.prepare(
            repo_root or self.aweb,
            environment,
            projection=projection,
            gate_command=("true",),
            timeout=30,
        )

    def test_refuses_a_non_root_working_directory_naming_the_fix(self) -> None:
        subdir = self.aweb / "server"
        with self.assertRaises(rt.ValidationError) as caught:
            self._prepare(repo_root=subdir)
        self.assertIn("canonical aweb repository root", str(caught.exception))
        self.assertIn(str(self.aweb), str(caught.exception))

    def test_refuses_a_foreign_origin_naming_the_expected_one(self) -> None:
        git("remote", "set-url", "origin", str(self.tmp.name), cwd=self.aweb)
        with self.assertRaises(rt.ValidationError) as caught:
            self._prepare()
        self.assertIn("awebai/aweb", str(caught.exception))

    def test_refuses_a_missing_sibling_ac_checkout(self) -> None:
        (self.ac / ".git").rename(self.ac / ".git-hidden")
        with self.assertRaises(rt.ValidationError) as caught:
            self._prepare()
        self.assertIn("../ac", str(caught.exception))

    def test_refuses_dirty_and_untracked_trees_naming_the_repository(self) -> None:
        (self.aweb / "server/pyproject.toml").write_text("dirty\n")
        with self.assertRaises(rt.ValidationError) as caught:
            self._prepare()
        self.assertIn("aweb", str(caught.exception))
        git("checkout", "--", ".", cwd=self.aweb)
        (self.ac / "untracked.txt").write_text("stray\n")
        with self.assertRaises(rt.ValidationError) as caught:
            self._prepare()
        self.assertIn("ac", str(caught.exception))

    def test_requires_purpose_and_compat_break_single_lines(self) -> None:
        with self.assertRaises(rt.ValidationError):
            self._prepare(PURPOSE="")
        with self.assertRaises(rt.ValidationError):
            self._prepare(PURPOSE="two\nlines")
        with self.assertRaises(rt.ValidationError):
            self._prepare(COMPAT_BREAK="")
        with self.assertRaises(rt.ValidationError):
            self._prepare(COMPAT_BREAK="breaks\neverything")

    def test_refuses_an_unpushed_or_non_main_override_sha(self) -> None:
        (self.aweb / "local.txt").write_text("local\n")
        git("add", ".", cwd=self.aweb)
        git("commit", "-m", "unpushed", cwd=self.aweb)
        unpushed = git("rev-parse", "HEAD", cwd=self.aweb)
        git("reset", "--hard", "HEAD~1", cwd=self.aweb)
        with self.assertRaises(rt.ValidationError) as caught:
            self._prepare(AWEB_SHA=unpushed)
        self.assertIn("origin/main", str(caught.exception))
        with self.assertRaises(rt.ValidationError):
            self._prepare(AWEB_SHA="abc123")


class _PresenceHandler(BaseHTTPRequestHandler):
    present: dict[str, dict] = {}

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        evidence = type(self).present.get(self.path)
        if evidence is None:
            self.send_error(404)
            return
        body = json.dumps(evidence).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *args: object) -> None:
        pass


class _PipelineFixture(unittest.TestCase):
    """Shared fixture: two repositories with bare remotes, a loopback
    registry, and a fake gate command."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _PresenceHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.registry = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self) -> None:
        _PresenceHandler.present = {}
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.aweb_remote = root / "origins/awebai/aweb.git"
        self.ac_remote = root / "origins/awebai/ac.git"
        for remote in (self.aweb_remote, self.ac_remote):
            remote.parent.mkdir(parents=True, exist_ok=True)
            git("init", "--bare", str(remote), cwd=root)
        self.aweb = root / "work/aweb"
        self.ac = root / "work/ac"
        for repo, remote in ((self.aweb, self.aweb_remote), (self.ac, self.ac_remote)):
            repo.mkdir(parents=True)
            git("init", "-b", "main", cwd=repo)
            git("config", "user.email", "test@example.com", cwd=repo)
            git("config", "user.name", "Test", cwd=repo)
            git("remote", "add", "origin", str(remote), cwd=repo)
        def manifest(repo: Path, path: str, body: str) -> None:
            target = repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body)
        for path, version in (
            ("server/pyproject.toml", "1.27.2"),
            ("awid/pyproject.toml", "0.5.16"),
        ):
            manifest(self.aweb, path, f'[project]\nversion = "{version}"\n')
        for path, version in (
            ("channel/package.json", "1.7.7"),
            ("channel/.claude-plugin/plugin.json", "1.7.7"),
            ("pi-extension/package.json", "0.3.7"),
            ("packages/claude-skills/package.json", "0.2.13"),
            ("packages/claude-skills/.claude-plugin/plugin.json", "0.2.13"),
        ):
            manifest(self.aweb, path, json.dumps({"version": version}))
        manifest(self.aweb, "awid/site/index.html", "<html>awid</html>")
        manifest(self.ac, "backend/pyproject.toml", '[project]\nversion = "0.7.13"\n')
        manifest(self.ac, "site/index.html", "<html>aweb</html>")
        for repo in (self.aweb, self.ac):
            git("add", ".", cwd=repo)
            git("commit", "-m", "base", cwd=repo)
            git("push", "-u", "origin", "main", cwd=repo)
            git("fetch", "origin", cwd=repo)
        git("tag", "aw-v1.34.3", cwd=self.aweb)
        # aw-cli moves only when the synced cli/go tree changed since the
        # newest tag; give the fixture a real cli-scope change so the
        # derived next version is 1.34.4 everywhere it always was.
        manifest(self.aweb, "cli/go/main.go", "package main\n")
        git("add", ".", cwd=self.aweb)
        git("commit", "-m", "cli change", cwd=self.aweb)
        git("push", "origin", "main", cwd=self.aweb)
        git("fetch", "origin", cwd=self.aweb)
        # The aw product checkout: the third member of the run trio.
        # Its tree is a copy of aweb's cli/go plus the external repo's
        # own .github, which is the shape MEASURED on the real
        # awebai/aw - so the binding this fixture proves is the binding
        # production performs, not a convenient one.
        self.aw = root / "work/aw"
        (self.aw / ".github").mkdir(parents=True)
        (self.aw / ".github" / "ci.yml").write_text("on: push\n")
        (self.aw / "main.go").write_text("package main\n")
        git("init", "-b", "main", cwd=self.aw)
        git("add", ".", cwd=self.aw)
        git("commit", "-m", "sync", cwd=self.aw)
        git("tag", "-a", "v1.34.4", "-m", "v1.34.4", cwd=self.aw)
        os.environ["AWEB_NORMALIZER_AW_ROOT"] = str(self.aw)
        self.addCleanup(os.environ.pop, "AWEB_NORMALIZER_AW_ROOT", None)

        gate = Path(self.tmp.name) / "gate.py"
        gate.write_text(
            "import json\n"
            'print(json.dumps({"suites": ["make-test", "cli-e2e"], '
            '"reference": "fixture-gate.log"}))\n'
        )
        self.gate_command = (sys.executable, str(gate))

    def _prepare(self, *, unmoved=(), projection=None, gate=None, **overrides: str):
        environment = {"PURPOSE": "fixture release", "COMPAT_BREAK": "none"}
        environment.update(overrides)
        return rt.prepare(
            self.aweb,
            environment,
            projection=projection
            if projection is not None
            else _fixture_projection(self.aweb, environment, unmoved=unmoved),
            gate_command=gate or self.gate_command,
            timeout=30,
        )



class PreparePipelineTests(_PipelineFixture):
    """prepare selects, checks, gates, and writes the card atomically."""

    def test_prepare_generates_the_card_and_touches_nothing_outward(self) -> None:
        before = {
            remote: git("ls-remote", str(remote), cwd=self.aweb)
            for remote in (self.aweb_remote, self.ac_remote)
        }
        card = self._prepare()
        self.assertTrue(all(item.moves for item in card.artifacts))
        self.assertEqual(card.deployments.production, True)
        self.assertTrue(card.deployments.awid_site)
        self.assertTrue(card.deployments.aweb_site)
        self.assertEqual(
            {item.name: item.version for item in card.artifacts}["aw-cli"], "1.34.4"
        )
        self.assertIsNone(card.final_ac_sha)
        self.assertTrue(card.production_correction_pending)
        stored = rt.read_card(self.aweb)
        self.assertEqual(stored, card)
        for remote, listing in before.items():
            self.assertEqual(git("ls-remote", str(remote), cwd=self.aweb), listing)
        for repo in (self.aweb, self.ac):
            self.assertEqual(git("status", "--porcelain", cwd=repo), "")

    def test_projection_base_mismatch_refuses_by_name(self) -> None:
        # C4: a projection computed from one commit cannot become a card
        # selecting another - refused naming both worlds, before any
        # gate runs.
        environment = {"PURPOSE": "fixture release", "COMPAT_BREAK": "none"}
        with self.assertRaises(rt.ValidationError) as caught:
            rt.prepare(
                self.aweb,
                environment,
                projection=_fixture_projection(self.aweb, environment),
                projection_base={"aweb": "e" * 40},
                gate_command=self.gate_command,
                timeout=30,
            )
        self.assertIn("projection-base-mismatch", str(caught.exception))
        self.assertIn("e" * 40, str(caught.exception))
        with self.assertRaises(rt.CardUnavailable):
            rt.read_card(self.aweb)

    def test_unmoved_projection_rows_reach_the_card_unmoved(self) -> None:
        # The sweep semantics themselves live in the normalizer (proven
        # at the canonical entry); the train's surviving claim is that
        # an unmoved projection row reaches the card unmoved, anchored.
        card = self._prepare(unmoved=("awid-service",))
        by_name = {item.name: item for item in card.artifacts}
        self.assertFalse(by_name["awid-service"].moves)
        self.assertIsNotNone(by_name["awid-service"].previous_complete_anchor)
        self.assertTrue(by_name["aweb-server"].moves)

    def test_stopped_projection_never_becomes_a_card(self) -> None:
        # Registry conflicts stop inside the normalizer; the train's
        # guard is that a projection carrying stops is refused by name
        # and leaves no card, even if a caller bypasses the phase gate.
        import release_normalizer as rn

        stopped = rn.NormalizerResult(
            outcome="stop",
            artifacts={},
            patches=(),
            stops=(rn.Stop("registry-conflict", "awid-service"),),
        )
        with self.assertRaises(rt.ValidationError) as caught:
            self._prepare(projection=stopped)
        self.assertIn("registry-conflict", str(caught.exception))
        self.assertIn("awid-service", str(caught.exception))
        with self.assertRaises(rt.CardUnavailable):
            rt.read_card(self.aweb)

    def test_plugin_version_drift_refuses(self) -> None:
        plugin = self.aweb / "channel/.claude-plugin/plugin.json"
        plugin.write_text(json.dumps({"version": "9.9.9"}))
        git("add", ".", cwd=self.aweb)
        git("commit", "-m", "drift", cwd=self.aweb)
        git("push", "origin", "main", cwd=self.aweb)
        with self.assertRaises(rt.ValidationError) as caught:
            self._prepare()
        self.assertIn("plugin.json", str(caught.exception))

    def test_unmoved_composite_keeps_its_served_version_in_the_card(self) -> None:
        # Contentless-release prevention lives in the normalizer's
        # movement table (tag-history rows, proven in its suites); the
        # card must carry the composite's SERVED version when the
        # projection says unmoved, not a freshly minted one.
        import release_normalizer as rn

        environment = {"PURPOSE": "fixture release", "COMPAT_BREAK": "none"}
        projection = _fixture_projection(self.aweb, environment)
        projection.artifacts["aw-cli"] = rn.ArtifactResult(
            disposition="unmoved",
            version="1.34.4",
            previous_complete_anchor=("1.34.4", "f" * 40),
        )
        card = self._prepare(projection=projection)
        by_name = {item.name: item for item in card.artifacts}
        self.assertEqual(by_name["aw-cli"].version, "1.34.4")
        self.assertFalse(by_name["aw-cli"].moves)

    def test_gate_failure_leaves_no_card(self) -> None:
        gate = Path(self.tmp.name) / "failing-gate.py"
        gate.write_text("raise SystemExit(1)\n")
        with self.assertRaises(rt.CommandFailed):
            self._prepare(gate=(sys.executable, str(gate)))
        with self.assertRaises(rt.CardUnavailable):
            rt.read_card(self.aweb)

    def test_gate_runs_under_the_work_timeout_not_the_observation_bound(self) -> None:
        slow = Path(self.tmp.name) / "slow-gate.py"
        slow.write_text(
            "import json, time\n"
            "time.sleep(3)\n"
            'print(json.dumps({"suites": ["make-test"], "reference": "slow.log"}))\n'
        )
        environment = {"PURPOSE": "fixture release", "COMPAT_BREAK": "none"}
        with self.assertRaises(rt.CommandUnavailable) as caught:
            rt.prepare(
                self.aweb,
                environment,
                projection=_fixture_projection(self.aweb, environment),
                gate_command=(sys.executable, str(slow)),
                timeout=30,
                work_timeout=1,
            )
        self.assertIn("timed out", str(caught.exception))
        with self.assertRaises(rt.CardUnavailable):
            rt.read_card(self.aweb)
        # A work bound above the 600s observation cap is accepted and reaches
        # the gate; refusing it here is the defect this test pins.
        card = rt.prepare(
            self.aweb,
            environment,
            projection=_fixture_projection(self.aweb, environment),
            gate_command=self.gate_command,
            timeout=30,
            work_timeout=700,
        )
        self.assertTrue(all(item.moves for item in card.artifacts))

    def test_retry_reuses_only_byte_identical_material(self) -> None:
        first = self._prepare()
        second = self._prepare()
        self.assertEqual(first, second)
        with self.assertRaises(rt.MaterialMismatch):
            self._prepare(PURPOSE="a different purpose")

    def test_prepare_replaces_a_card_whose_ac_main_moved_past_it(self) -> None:
        stale = self._prepare()
        (self.ac / "backend/app.py").write_text("not a dependency-only change\n")
        git("add", ".", cwd=self.ac)
        git("commit", "-m", "ac main moves past the card", cwd=self.ac)
        git("push", "origin", "main", cwd=self.ac)
        git("fetch", "origin", cwd=self.ac)
        fresh = self._prepare()
        self.assertNotEqual(fresh.ac_base_sha, stale.ac_base_sha)
        self.assertEqual(
            fresh.ac_base_sha, git("rev-parse", "origin/main", cwd=self.ac)
        )
        self.assertEqual(rt.read_card(self.aweb), fresh)

    def test_prepare_replaces_a_card_the_mains_have_moved_past(self) -> None:
        stale = self._prepare()
        (self.aweb / "server/README.md").write_text("moved\n")
        git("add", ".", cwd=self.aweb)
        git("commit", "-m", "main moves past the card", cwd=self.aweb)
        git("push", "origin", "main", cwd=self.aweb)
        git("fetch", "origin", cwd=self.aweb)
        # No continue can execute the stored card once main has moved past
        # its recorded SHAs, so prepare must replace it itself rather than
        # refuse until an operator remembers to delete a file.
        fresh = self._prepare()
        self.assertNotEqual(fresh.aweb_sha, stale.aweb_sha)
        self.assertEqual(
            fresh.aweb_sha, git("rev-parse", "origin/main", cwd=self.aweb)
        )
        self.assertEqual(rt.read_card(self.aweb), fresh)



class ContinuePhaseTests(_PipelineFixture):
    """continue reads the fixed card, re-observes material, and moves
    fast-forward-only; every mismatch invalidates rather than improvises."""

    def _card(self):
        return self._prepare()

    def test_continue_refuses_without_a_card(self) -> None:
        with self.assertRaises(rt.CardUnavailable):
            rt.continue_environment(self.aweb)

    def test_continue_re_observes_material_and_accepts_the_card(self) -> None:
        card = self._card()
        observed = rt.continue_environment(self.aweb)
        self.assertEqual(observed.card, card)

    def test_local_checkout_not_at_the_card_sha_stops_by_name(self) -> None:
        # C4: the re-derivation claims capture over the exact card SHAs;
        # a local checkout detached elsewhere (remote refs untouched, so
        # the environment's remote checks pass) must stop
        # card-checkout-mismatch before any capture, and a dirty tree
        # stops card-checkout-dirty - never a silent capture of the
        # wrong tree.
        self._card()
        environment = rt.continue_environment(self.aweb)
        git("checkout", "-q", "--detach", "HEAD~1", cwd=self.aweb)
        try:
            stops = rt._default_rederive(environment)
            self.assertIn(
                ("card-checkout-mismatch", "aweb"),
                [(s.code, s.artifact) for s in stops],
            )
        finally:
            git("checkout", "-q", "main", cwd=self.aweb)
        (self.aweb / "dirty.txt").write_text("x\n")
        try:
            stops = rt._default_rederive(environment)
            self.assertIn(
                ("card-checkout-dirty", "aweb"),
                [(s.code, s.artifact) for s in stops],
            )
        finally:
            (self.aweb / "dirty.txt").unlink()

    def test_moved_aweb_main_invalidates_the_card(self) -> None:
        self._card()
        (self.aweb / "moved.txt").write_text("moved\n")
        git("add", ".", cwd=self.aweb)
        git("commit", "-m", "moved", cwd=self.aweb)
        git("push", "origin", "main", cwd=self.aweb)
        with self.assertRaises(rt.MaterialMismatch) as caught:
            rt.continue_environment(self.aweb)
        self.assertIn("fresh prepare", str(caught.exception))

    def test_fast_forward_release_creates_and_advances_only(self) -> None:
        card = self._card()
        prepared = rt.continue_environment(self.aweb)
        rt.fast_forward_release(self.aweb, "release", card.aweb_sha)
        listed = git("ls-remote", "origin", "refs/heads/release", cwd=self.aweb)
        self.assertEqual(listed.split()[0], card.aweb_sha)
        # Idempotent re-run adopts the exact match.
        rt.fast_forward_release(self.aweb, "release", card.aweb_sha)
        # A non-fast-forward target refuses without force.
        git("update-ref", "refs/heads/divergent", card.aweb_sha, cwd=self.aweb)
        (self.aweb / "diverge.txt").write_text("x\n")
        git("add", ".", cwd=self.aweb)
        git("commit", "-m", "diverge", cwd=self.aweb)
        divergent = git("rev-parse", "HEAD", cwd=self.aweb)
        git("push", "origin", f"{divergent}:refs/heads/release-divergent", cwd=self.aweb)
        with self.assertRaises(rt.ValidationError) as caught:
            rt.fast_forward_release(self.aweb, "release-divergent", card.aweb_sha)
        self.assertIn("fast-forward", str(caught.exception))
        del prepared


class _PublicApiHandler(BaseHTTPRequestHandler):
    """Serves the real public read-API shapes: PyPI JSON, npm version JSON,
    GHCR token+manifest, GitHub release-by-tag."""

    state: dict[str, tuple[int, dict]] = {}
    authorization: str | None = None

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path.startswith("/token?"):
            type(self).authorization = self.headers.get("Authorization")
        status, payload = type(self).state.get(self.path, (404, {}))
        body = json.dumps(payload).encode()
        if status != 200:
            self.send_error(status)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *args: object) -> None:
        pass


class PublicAdapterTests(unittest.TestCase):
    """Per-kind read-only adapters behind the fixed observation semantics:
    HTTP 404 is the only absence, non-200 is unavailable, and served
    evidence must name exactly the queried version."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _PublicApiHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        base = f"http://127.0.0.1:{cls.server.server_port}"
        cls.bases = {"pypi": base, "npm": base, "ghcr": base, "github": base}

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self) -> None:
        _PublicApiHandler.state = {}

    def _observe(self, target: str, version: str) -> bool:
        return rt.observe_public_target(
            target, version, bases=self.bases, timeout=10
        )

    def test_pypi_present_absent_and_version_mismatch(self) -> None:
        _PublicApiHandler.state["/pypi/aweb/1.27.2/json"] = (
            200, {"info": {"version": "1.27.2"}}
        )
        self.assertTrue(self._observe("pypi:aweb", "1.27.2"))
        self.assertFalse(self._observe("pypi:aweb", "1.27.3"))
        _PublicApiHandler.state["/pypi/aweb/9.9.9/json"] = (
            200, {"info": {"version": "1.0.0"}}
        )
        with self.assertRaises(rt.ObservationMalformed):
            self._observe("pypi:aweb", "9.9.9")

    def test_npm_scoped_package_paths_are_quoted(self) -> None:
        _PublicApiHandler.state["/@awebai%2Fpi/0.3.7"] = (
            200, {"version": "0.3.7"}
        )
        self.assertTrue(self._observe("npm:@awebai/pi", "0.3.7"))
        self.assertFalse(self._observe("npm:@awebai/pi", "0.3.8"))

    def test_ghcr_token_exchange_sends_credentials_when_supplied(self) -> None:
        import os
        from unittest.mock import patch

        _PublicApiHandler.state[
            "/token?scope=repository:awebai/ac:pull&service=ghcr.io"
        ] = (200, {"token": "t"})
        _PublicApiHandler.state["/v2/awebai/ac/manifests/0.7.13"] = (
            200, {"manifests": []}
        )
        _PublicApiHandler.authorization = None
        with patch.dict(os.environ, {"AWEB_GHCR_READ_TOKEN": "sekret"}):
            self.assertTrue(self._observe("ghcr.io/awebai/ac", "0.7.13"))
        recorded = _PublicApiHandler.authorization
        self.assertIsNotNone(recorded)
        self.assertTrue(recorded.startswith("Basic "), recorded)
        import base64
        self.assertEqual(
            base64.b64decode(recorded.split()[1]).decode(), "token:sekret"
        )

    def test_ghcr_manifest_via_anonymous_token(self) -> None:
        _PublicApiHandler.state[
            "/token?scope=repository:awebai/awid:pull&service=ghcr.io"
        ] = (200, {"token": "fixture-token"})
        _PublicApiHandler.state["/v2/awebai/awid/manifests/0.5.16"] = (
            200, {"manifests": []}
        )
        self.assertTrue(self._observe("ghcr.io/awebai/awid", "0.5.16"))
        self.assertFalse(self._observe("ghcr.io/awebai/awid", "0.5.17"))

    def test_github_release_tags_per_repository(self) -> None:
        _PublicApiHandler.state["/repos/awebai/aw/releases/tags/v1.34.4"] = (
            200, {"tag_name": "v1.34.4"}
        )
        self.assertTrue(self._observe("github:awebai/aw:release", "1.34.4"))
        self.assertFalse(self._observe("github:awebai/aw:release", "1.34.5"))
        _PublicApiHandler.state[
            "/repos/awebai/aweb/releases/tags/skills-v0.2.13"
        ] = (200, {"tag_name": "skills-v0.2.13"})
        self.assertTrue(
            self._observe("github:awebai/aweb:skills-release-zips", "0.2.13")
        )

    def test_unavailable_is_never_absence(self) -> None:
        _PublicApiHandler.state["/pypi/aweb/1.27.2/json"] = (503, {})
        with self.assertRaises(rt.ObservationUnavailable):
            self._observe("pypi:aweb", "1.27.2")

    def test_unknown_target_kind_is_refused(self) -> None:
        with self.assertRaises(rt.ValidationError):
            self._observe("render-static:deploy-awid-landing", "1.0.0")


class _SpoolHandler(BaseHTTPRequestHandler):
    """Registry read fixture backed by a spool directory, so the fake
    workflow executable can publish across process boundaries."""

    spool: Path | None = None

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        spool = type(self).spool
        record = None
        if spool is not None:
            candidate = spool / urllib_quote(self.path)
            if candidate.exists():
                record = candidate.read_bytes()
        if record is None:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(record)))
        self.end_headers()
        self.wfile.write(record)

    def log_message(self, _format: str, *args: object) -> None:
        pass


def urllib_quote(path: str) -> str:
    from urllib.parse import quote

    return quote(path, safe="")


_PUBLISH_SCRIPT = '''
import json, sys
from pathlib import Path
from urllib.parse import quote
spool = Path(sys.argv[1])
artifact, version = sys.argv[2], sys.argv[3]
log = Path(sys.argv[1]).with_name("workflow-log.txt")
log.open("a").write(f"{artifact} {version}\\n")
paths = {
    "awid-service": [(f"/pypi/awid-service/{version}/json", {"info": {"version": version}})],
    "aweb-server": [(f"/pypi/aweb/{version}/json", {"info": {"version": version}})],
    "awid-image": [
        ("/token?scope=repository:awebai/awid:pull&service=ghcr.io", {"token": "t"}),
        (f"/v2/awebai/awid/manifests/{version}", {"manifests": []}),
    ],
    "aw-cli": [(f"/repos/awebai/aw/releases/tags/v{version}", {"tag_name": version})],
    "channel-plugin": [(f"/@awebai%2Fclaude-channel/{version}", {"version": version})],
    "pi-extension": [(f"/@awebai%2Fpi/{version}", {"version": version})],
    "skills": [
        (f"/@awebai%2Fclaude-skills/{version}", {"version": version}),
        (f"/repos/awebai/aweb/releases/tags/skills-v{version}", {"tag_name": version}),
    ],
    "a2a-gateway-image": [
        ("/token?scope=repository:awebai/a2a-gateway:pull&service=ghcr.io", {"token": "t"}),
        (f"/v2/awebai/a2a-gateway/manifests/{version}", {"manifests": []}),
    ],
    "ac-image": [
        ("/token?scope=repository:awebai/ac:pull&service=ghcr.io", {"token": "t"}),
        (f"/v2/awebai/ac/manifests/{version}", {"manifests": []}),
    ],
}
for path, payload in paths[artifact]:
    (spool / quote(path, safe="")).write_text(json.dumps(payload))
# The typed remote-completion record (A8): the monitor's stdout IS the
# record; the fixture publishes at the checkout's own HEAD.
import subprocess
sha = subprocess.run(
    ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True
).stdout.strip()
print(json.dumps({"workflow": "fixture.yml", "run_sha": sha, "conclusion": "success"}))
'''


class _FlakyRegistryHandler(BaseHTTPRequestHandler):
    """Serves the token, then 503s the manifest N times before serving it."""

    unavailable_remaining = 0
    request_times: list[float] = []

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        cls = type(self)
        if self.path.startswith("/token"):
            body = json.dumps({"token": "t"}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        cls.request_times.append(time.monotonic())
        if cls.unavailable_remaining > 0:
            cls.unavailable_remaining -= 1
            self.send_error(503)
            return
        body = json.dumps({"manifests": []}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *args: object) -> None:
        pass


class PublicTargetPollTests(unittest.TestCase):
    """The long wait tolerates transient unavailability and backs off; a
    single 429/5xx inside an hours-long window must not stop the train."""

    def setUp(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _FlakyRegistryHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.server.server_close)
        self.bases = {"ghcr": f"http://127.0.0.1:{self.server.server_port}"}
        _FlakyRegistryHandler.unavailable_remaining = 0
        _FlakyRegistryHandler.request_times = []

    def test_transient_unavailability_inside_the_window_is_survived(self) -> None:
        _FlakyRegistryHandler.unavailable_remaining = 3
        with unittest.mock.patch.multiple(
            rt,
            POLL_INITIAL_INTERVAL_SECONDS=0.02,
            POLL_MAX_INTERVAL_SECONDS=0.05,
        ):
            rt._poll_public_target(
                "ghcr.io/awebai/ac", "0.7.14", bases=self.bases,
                timeout=5, wait_seconds=20.0,
            )
        self.assertGreaterEqual(len(_FlakyRegistryHandler.request_times), 4)

    def test_exhausted_window_names_the_last_transient_error(self) -> None:
        _FlakyRegistryHandler.unavailable_remaining = 10_000
        with unittest.mock.patch.multiple(
            rt,
            POLL_INITIAL_INTERVAL_SECONDS=0.01,
            POLL_MAX_INTERVAL_SECONDS=0.02,
        ):
            with self.assertRaises(rt.ObservationUnavailable) as caught:
                rt._poll_public_target(
                    "ghcr.io/awebai/ac", "0.7.14", bases=self.bases,
                    timeout=5, wait_seconds=0.2,
                )
        self.assertIn("503", str(caught.exception))

    def test_backoff_grows_toward_the_cap(self) -> None:
        _FlakyRegistryHandler.unavailable_remaining = 6
        with unittest.mock.patch.multiple(
            rt,
            POLL_INITIAL_INTERVAL_SECONDS=0.02,
            POLL_MAX_INTERVAL_SECONDS=0.2,
        ):
            rt._poll_public_target(
                "ghcr.io/awebai/ac", "0.7.14", bases=self.bases,
                timeout=5, wait_seconds=30.0,
            )
        times = _FlakyRegistryHandler.request_times
        self.assertGreaterEqual(len(times), 7)
        first_gap = times[1] - times[0]
        last_gap = times[-1] - times[-2]
        self.assertGreater(last_gap, first_gap * 2)


class ContinueTrainTests(_PipelineFixture):
    """A full fixture continue reaches DONE without touching anything real;
    partial prior state adopts; consumption refuses replay."""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.spool_server = ThreadingHTTPServer(("127.0.0.1", 0), _SpoolHandler)
        cls.spool_thread = threading.Thread(
            target=cls.spool_server.serve_forever, daemon=True
        )
        cls.spool_thread.start()
        cls.spool_base = f"http://127.0.0.1:{cls.spool_server.server_port}"

    def test_ac_predecessor_gate_refuses_before_derivation(self) -> None:
        # aben design section 8: a non-present predecessor row must stop
        # the walk BEFORE the derive command runs - proven by tripwire.
        self._prepare()
        marker = Path(self.tmp.name) / "derive-ran"
        tripwire = Path(self.tmp.name) / "derive-tripwire.py"
        tripwire.write_text(
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('ran')\n"
        )
        with self.assertRaises(rt.ValidationError) as caught:
            rt.continue_train(
                self.aweb,
                marketplace_command=self.marketplace_command,
                correction_command=self.correction_command,
                rederive=lambda environment: [],
                marketplace_gate=lambda card, bases, timeout: [],
                ac_predecessor_gate=lambda card, bases, timeout: [
                    "pypi:aweb wheel (absent)"
                ],
                bases={
                    "pypi": self.spool_base,
                    "npm": self.spool_base,
                    "ghcr": self.spool_base,
                    "github": self.spool_base,
                },
                workflow_command=self.workflow_command,
                derive_command=(sys.executable, str(tripwire)),
                ac_gate_command=self.ac_gate_command,
                migrate_command=self.migrate_command,
                deploy_command=self.deploy_command,
                verify_command=self.verify_command,
                digest_command=self.digest_command,
                timeout=60,
            )
        self.assertIn("predecessor rows not present", str(caught.exception))
        self.assertIn("pypi:aweb wheel", str(caught.exception))
        self.assertFalse(marker.exists(), "derive ran despite the gate")

    def test_marketplace_gate_refuses_before_the_pointer_mutation(self) -> None:
        self._prepare()
        marker = Path(self.tmp.name) / "marketplace-ran"
        tripwire = Path(self.tmp.name) / "marketplace-tripwire.py"
        tripwire.write_text(
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('ran')\n"
        )
        with self.assertRaises(rt.ValidationError) as caught:
            rt.continue_train(
                self.aweb,
                rederive=lambda environment: [],
                marketplace_gate=lambda card, bases, timeout: [
                    "npm:@awebai/claude-skills tarball (unproven)"
                ],
                ac_predecessor_gate=lambda card, bases, timeout: [],
                bases={
                    "pypi": self.spool_base,
                    "npm": self.spool_base,
                    "ghcr": self.spool_base,
                    "github": self.spool_base,
                },
                workflow_command=self.workflow_command,
                derive_command=self.derive_command,
                ac_gate_command=self.ac_gate_command,
                migrate_command=self.migrate_command,
                deploy_command=self.deploy_command,
                verify_command=self.verify_command,
                digest_command=self.digest_command,
                marketplace_command=(sys.executable, str(tripwire)),
                correction_command=self.correction_command,
                timeout=60,
            )
        self.assertIn("marketplace mutation refused", str(caught.exception))
        self.assertFalse(marker.exists(), "marketplace ran despite the gate")

    def test_continue_rederivation_drift_refuses_before_the_release_move(self) -> None:
        # aben design section 7: an injected drift stop must refuse
        # BEFORE the release fast-forward - the first irreversible edge -
        # leaving both release pointers untouched.
        self._prepare()
        with self.assertRaises(rt.ValidationError) as caught:
            rt.continue_train(
                self.aweb,
                marketplace_command=self.marketplace_command,
                correction_command=self.correction_command,
                rederive=lambda environment: [
                    __import__("release_normalizer").Stop(
                        "card-world-version-drift", "aweb-server"
                    )
                ],
                bases={
                    "pypi": self.spool_base,
                    "npm": self.spool_base,
                    "ghcr": self.spool_base,
                    "github": self.spool_base,
                },
                workflow_command=self.workflow_command,
                derive_command=self.derive_command,
                ac_gate_command=self.ac_gate_command,
                migrate_command=self.migrate_command,
                deploy_command=self.deploy_command,
                verify_command=self.verify_command,
                digest_command=self.digest_command,
                timeout=60,
            )
        self.assertIn("card-world-version-drift", str(caught.exception))
        aweb_release = git(
            "ls-remote", "origin", "refs/heads/release", cwd=self.aweb
        )
        self.assertEqual(aweb_release, "")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.spool_server.shutdown()
        cls.spool_server.server_close()
        cls.spool_server.server_close()
        cls.spool_thread.join(timeout=2)
        super().tearDownClass()

    def setUp(self) -> None:
        super().setUp()
        self.spool = Path(self.tmp.name) / "spool"
        self.spool.mkdir()
        _SpoolHandler.spool = self.spool
        # Real GHCR answers token exchanges regardless of manifest presence.
        for repository in ("awebai/awid", "awebai/a2a-gateway", "awebai/ac"):
            token_path = f"/token?scope=repository:{repository}:pull&service=ghcr.io"
            (self.spool / urllib_quote(token_path)).write_text(
                json.dumps({"token": "t"})
            )
        publish = Path(self.tmp.name) / "publish.py"
        publish.write_text(_PUBLISH_SCRIPT)
        self.workflow_command = (sys.executable, str(publish), str(self.spool))
        derive = Path(self.tmp.name) / "derive.py"
        derive.write_text(
            "import sys\nfrom pathlib import Path\n"
            "root = Path(sys.argv[1])\n"
            "(root / 'backend/pyproject.toml').write_text("
            "'[project]\\nversion = \"0.7.13\"\\n# floors bumped\\n')\n"
            "(root / 'backend/uv.lock').write_text('lock v2\\n')\n"
        )
        self.derive_command = (sys.executable, str(derive), str(self.ac))
        ac_gate = Path(self.tmp.name) / "ac-gate.py"
        ac_gate.write_text("print('AC gate 16/16 PASSED')\n")
        self.ac_gate_command = (sys.executable, str(ac_gate))
        provider_log = Path(self.tmp.name) / "provider-log.txt"
        provider = Path(self.tmp.name) / "provider.py"
        provider.write_text(
            "import sys\nfrom pathlib import Path\n"
            f"Path({str(provider_log)!r}).open('a').write(' '.join(sys.argv[1:]) + chr(10))\n"
        )
        self.provider_log = provider_log
        self.migrate_command = (sys.executable, str(provider), "migrate")
        self.deploy_command = (sys.executable, str(provider), "deploy")
        self.verify_command = (sys.executable, str(provider), "verify")
        digest = Path(self.tmp.name) / "digest.py"
        digest.write_text(f"print('{DIGEST}')\n")
        self.digest_command = (sys.executable, str(digest))
        marketplace = Path(self.tmp.name) / "marketplace.py"
        self.marketplace_marker = Path(self.tmp.name) / "marketplace-applied"
        marketplace.write_text(
            "from pathlib import Path\n"
            f"Path({str(self.marketplace_marker)!r}).write_text('applied')\n"
        )
        self.marketplace_command = (sys.executable, str(marketplace))
        self.correction_command = (sys.executable, str(provider), "correction")
        # The AC release-branch push builds and serves the image in reality;
        # the spool serves it so the digest edge's wait observes it.
        (self.spool / urllib_quote("/v2/awebai/ac/manifests/0.7.13")).write_text(
            json.dumps({"manifests": []})
        )
        # The uv.lock must exist at the base so the derive diff stays inside
        # the allowlist.
        (self.ac / "backend/uv.lock").write_text("lock v1\n")
        git("add", ".", cwd=self.ac)
        git("commit", "-m", "lock", cwd=self.ac)
        git("push", "origin", "main", cwd=self.ac)
        git("fetch", "origin", cwd=self.ac)
        # Site deploy branches exist at the served commits (the restored
        # live state): create them at the current main tips, then land a
        # site-source change on each main so both sites genuinely move.
        for repo in (self.aweb, self.ac):
            main_sha = git("rev-parse", "origin/main", cwd=repo)
            branch = "deploy-awid-landing" if repo is self.aweb else "deploy-landing"
            git("push", "origin", f"{main_sha}:refs/heads/{branch}", cwd=repo)
        (self.aweb / "awid/site/index.html").write_text("<html>awid v2</html>")
        (self.ac / "site/index.html").write_text("<html>aweb v2</html>")
        for repo in (self.aweb, self.ac):
            git("add", ".", cwd=repo)
            git("commit", "-m", "site change", cwd=repo)
            git("push", "origin", "main", cwd=repo)
            git("fetch", "origin", cwd=repo)

    def _continue(self, terminal_gate=None):
        return rt.continue_train(
            self.aweb,
            rederive=lambda environment: [],
            marketplace_command=self.marketplace_command,
            correction_command=self.correction_command,
            marketplace_gate=lambda card, bases, timeout: [],
            ac_predecessor_gate=lambda card, bases, timeout: [],
            terminal_gate=terminal_gate
            or (lambda environment, ac_derived, effect_rows, bases, timeout: []),
            bases={
                "pypi": self.spool_base,
                "npm": self.spool_base,
                "ghcr": self.spool_base,
                "github": self.spool_base,
            },
            workflow_command=self.workflow_command,
            derive_command=self.derive_command,
            ac_gate_command=self.ac_gate_command,
            migrate_command=self.migrate_command,
            deploy_command=self.deploy_command,
            verify_command=self.verify_command,
            digest_command=self.digest_command,
            timeout=60,
        )

    def test_continue_publishes_the_AC_SOURCE_TAG_at_the_derived_sha(self) -> None:
        """The link a source regex was standing in for.

        publish_source_tag is tested against a real remote, but every
        one of those tests names the tag literally - so nothing
        behavioural asserted that CONTINUE passes it the name derived
        from the canonical record. That gap fails in both directions: a
        refactor threading the root through a variable would break the
        regex while the code stayed correct, and a real divergence
        between the record and what continue pushes would not
        necessarily break it.

        This asserts the tag that actually lands on the AC remote,
        against the name DERIVED from release_tag_prefix - so the
        record and the publication are compared rather than each
        checked against itself."""

        card = self._prepare()
        summary = self._continue()
        self.assertEqual(summary["status"], "DONE")

        version = next(
            a.version for a in card.artifacts if a.name == "ac-image"
        )
        expected_tag = (
            rt.release_tag_prefix(rt._artifact("ac-image"), "awebai/ac") + version
        )
        listing = git("ls-remote", "--tags", "origin", cwd=self.ac)
        self.assertIn(
            f"refs/tags/{expected_tag}", listing,
            f"continue did not publish {expected_tag}; remote has:\n{listing}",
        )
        # ...at the EXACT final derived SHA - the same commit the image
        # is built from and the release branch points at, not whatever
        # HEAD happened to be afterwards.
        peeled = [
            line.split()[0]
            for line in listing.splitlines()
            if line.endswith(f"refs/tags/{expected_tag}^{{}}")
        ]
        self.assertEqual(len(peeled), 1, f"tag is not annotated:\n{listing}")
        self.assertEqual(peeled[0], summary["final_ac_sha"])

    def test_the_tag_names_the_derived_sha_even_when_HEAD_moves_after(
        self,
    ) -> None:
        """The control that makes "at the EXACT derived SHA" mean
        something.

        In the ordinary fixture HEAD and the derived SHA are the same
        commit, so tagging at HEAD passes - I mutated the code to tag
        HEAD and the assertion stayed green, which is the vacuous shape
        this epic keeps finding. Here the AC gate commits, so HEAD
        moves AFTER the derived SHA is computed and the two values
        differ. The tag must still name the commit the image is built
        from and the release branch points at.
        """

        card = self._prepare()
        # A gate that writes: any step committing after derive moves
        # HEAD away from the release identity.
        moving_gate = Path(self.tmp.name) / "moving_gate.py"
        moving_gate.write_text(
            "import subprocess, pathlib\n"
            "p = pathlib.Path('gate-artifact.txt'); p.write_text('gate ran\\n')\n"
            "subprocess.run(['git','add','-A'], check=True)\n"
            "subprocess.run(['git','-c','user.email=t@t','-c','user.name=t',\n"
            "                'commit','-m','gate artifact'], check=True)\n"
        )
        self.ac_gate_command = (sys.executable, str(moving_gate))
        summary = self._continue()
        self.assertEqual(summary["status"], "DONE")

        derived = summary["final_ac_sha"]
        head = git("rev-parse", "HEAD", cwd=self.ac)
        self.assertNotEqual(
            head, derived,
            "the fixture failed to move HEAD - this control proves nothing",
        )

        version = next(a.version for a in card.artifacts if a.name == "ac-image")
        tag = rt.release_tag_prefix(rt._artifact("ac-image"), "awebai/ac") + version
        listing = git("ls-remote", "--tags", "origin", cwd=self.ac)
        peeled = [
            line.split()[0]
            for line in listing.splitlines()
            if line.endswith(f"refs/tags/{tag}^{{}}")
        ]
        self.assertEqual(len(peeled), 1, listing)
        self.assertEqual(
            peeled[0], derived,
            "the tag names HEAD rather than the derived release commit",
        )

    def test_the_source_tag_is_published_BEFORE_the_terminal_sweep(self) -> None:
        """Ordering, asserted where it is consumed rather than by
        reading the sequence in the source.

        The terminal sweep proves DONE by reading the source tag back.
        If the tag were pushed after the sweep - or not at all - the
        sweep would be proving a world that did not yet exist. So the
        assertion is made FROM INSIDE the gate: at the moment the
        sweep runs, the tag must already be on the AC remote, naming
        the derived SHA.

        Card and recovery are covered by their own tests; this is the
        third of boundary 2's words that nothing else pins."""

        card = self._prepare()
        version = next(a.version for a in card.artifacts if a.name == "ac-image")
        tag = rt.release_tag_prefix(rt._artifact("ac-image"), "awebai/ac") + version
        seen = {}

        def gate(environment, ac_derived, effect_rows, bases, timeout):
            listing = git("ls-remote", "--tags", "origin", cwd=self.ac)
            seen["listing"] = listing
            seen["derived"] = ac_derived
            return []

        summary = self._continue(terminal_gate=gate)
        self.assertEqual(summary["status"], "DONE")
        self.assertIn("listing", seen, "the terminal gate never ran")
        self.assertIn(
            f"refs/tags/{tag}", seen["listing"],
            "the terminal sweep ran BEFORE the source tag was published:\n"
            + seen["listing"],
        )
        peeled = [
            line.split()[0]
            for line in seen["listing"].splitlines()
            if line.endswith(f"refs/tags/{tag}^{{}}")
        ]
        self.assertEqual(peeled, [seen["derived"]])

    def test_continue_is_retryable_over_the_tag_it_already_pushed(self) -> None:
        """The retry path, with its premise corrected.

        A SUCCESSFUL continue consumes the card, so re-running after
        DONE is not the retry case - my first version of this test
        asserted that and errored on a consumed card. The real case is
        a continue that FAILS after the tag push: the card survives, and
        the re-run meets a tag it pushed itself. That must be adopted,
        not read as a conflicting tag from somewhere else."""

        card = self._prepare()
        version = next(a.version for a in card.artifacts if a.name == "ac-image")
        tag = rt.release_tag_prefix(rt._artifact("ac-image"), "awebai/ac") + version

        blocked = [True]

        def gate(environment, ac_derived, effect_rows, bases, timeout):
            if blocked[0]:
                blocked[0] = False
                # The gate returns BLOCKING STRINGS, not rows.
                return ["fixture blocker: failing the first attempt on purpose"]
            return []

        with self.assertRaises(rt.ValidationError):
            self._continue(terminal_gate=gate)

        # The tag is already published, and the card survived.
        after_failure = git("ls-remote", "--tags", "origin", cwd=self.ac)
        self.assertIn(f"refs/tags/{tag}", after_failure)

        summary = self._continue(terminal_gate=gate)
        self.assertEqual(summary["status"], "DONE")
        # Adopted, not duplicated or moved.
        self.assertEqual(git("ls-remote", "--tags", "origin", cwd=self.ac),
                         after_failure)

    def test_full_fixture_continue_reaches_done_in_order(self) -> None:
        card = self._prepare()
        summary = self._continue()
        self.assertEqual(summary["status"], "DONE")
        # aweb release advanced to the card SHA.
        release = git("ls-remote", "origin", "refs/heads/release", cwd=self.aweb)
        self.assertEqual(release.split()[0], card.aweb_sha)
        # The derived AC commit is on main, allowlisted, parented on the base.
        ac_main = git("rev-parse", "origin/main", cwd=self.ac)
        self.assertEqual(summary["final_ac_sha"], ac_main)
        parent = git("rev-parse", f"{ac_main}^", cwd=self.ac)
        self.assertEqual(parent, card.ac_base_sha)
        changed = git(
            "diff", "--name-only", f"{card.ac_base_sha}..{ac_main}", cwd=self.ac
        ).splitlines()
        self.assertEqual(
            sorted(changed), ["backend/pyproject.toml", "backend/uv.lock"]
        )
        # AC release advanced to the derived commit.
        ac_release = git("ls-remote", "origin", "refs/heads/release", cwd=self.ac)
        self.assertEqual(ac_release.split()[0], ac_main)
        # Provider order: migrate, then the production step - which for
        # a card with the correction pending is first-correction, the
        # digest pin with auto-deploy off - then verify.
        provider = [
            line.split() for line in self.provider_log.read_text().splitlines()
        ]
        self.assertEqual(
            [line[0] for line in provider], ["migrate", "correction", "verify"]
        )
        self.assertEqual(provider[1][1], DIGEST)
        self.assertEqual(provider[2][1], DIGEST)
        self.assertEqual(summary["ac_image_digest"], DIGEST)
        # Publication order followed the DAG: AWID before aweb server.
        workflow_log = (self.spool.with_name("workflow-log.txt")).read_text().splitlines()
        published = [line.split()[0] for line in workflow_log]
        self.assertLess(
            published.index("awid-service"), published.index("aweb-server")
        )
        # Sites moved fast-forward to the exact main commits.
        awid_site = git(
            "ls-remote", "origin", "refs/heads/deploy-awid-landing", cwd=self.aweb
        )
        self.assertEqual(awid_site.split()[0], card.aweb_sha)
        aweb_site = git(
            "ls-remote", "origin", "refs/heads/deploy-landing", cwd=self.ac
        )
        self.assertEqual(aweb_site.split()[0], ac_main)
        # The card is consumed; replay refuses.
        with self.assertRaises(rt.CardUnavailable):
            self._continue()

    def test_gate_failure_stops_before_ac_release_and_keeps_the_card(self) -> None:
        self._prepare()
        failing = Path(self.tmp.name) / "failing-ac-gate.py"
        failing.write_text("raise SystemExit(1)\n")
        with self.assertRaises(rt.CommandFailed):
            rt.continue_train(
                self.aweb,
                rederive=lambda environment: [],
                marketplace_command=self.marketplace_command,
                correction_command=self.correction_command,
                marketplace_gate=lambda card, bases, timeout: [],
                ac_predecessor_gate=lambda card, bases, timeout: [],
                terminal_gate=lambda environment, ac_derived, effect_rows, bases, timeout: [],
                bases={
                    "pypi": self.spool_base,
                    "npm": self.spool_base,
                    "ghcr": self.spool_base,
                    "github": self.spool_base,
                },
                workflow_command=self.workflow_command,
                derive_command=self.derive_command,
                ac_gate_command=(sys.executable, str(failing)),
                migrate_command=self.migrate_command,
                deploy_command=self.deploy_command,
                verify_command=self.verify_command,
                digest_command=self.digest_command,
                timeout=60,
            )
        ac_release = git("ls-remote", "origin", "refs/heads/release", cwd=self.ac)
        self.assertEqual(ac_release, "")
        self.assertFalse(self.provider_log.exists())
        rt.read_card(self.aweb)

    def test_no_floor_moves_skips_derivation_and_releases_ac_at_the_base(self) -> None:
        from urllib.parse import quote

        del quote
        card = self._prepare(unmoved=("awid-service", "aweb-server"))
        moves = {item.name: item.moves for item in card.artifacts}
        self.assertFalse(moves["awid-service"])
        self.assertFalse(moves["aweb-server"])
        for path, version in (
            ("/pypi/awid-service/0.5.16/json", "0.5.16"),
            ("/pypi/aweb/1.27.2/json", "1.27.2"),
        ):
            (self.spool / urllib_quote(path)).write_text(
                json.dumps({"info": {"version": version}})
            )
        marker = Path(self.tmp.name) / "derive-invoked"
        tripwire = Path(self.tmp.name) / "derive-tripwire.py"
        tripwire.write_text(
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('invoked')\n"
            "raise SystemExit(1)\n"
        )
        summary = rt.continue_train(
            self.aweb,
            rederive=lambda environment: [],
            marketplace_command=self.marketplace_command,
            correction_command=self.correction_command,
            marketplace_gate=lambda card, bases, timeout: [],
            ac_predecessor_gate=lambda card, bases, timeout: [],
            terminal_gate=lambda environment, ac_derived, effect_rows, bases, timeout: [],
            bases={
                "pypi": self.spool_base,
                "npm": self.spool_base,
                "ghcr": self.spool_base,
                "github": self.spool_base,
            },
            workflow_command=self.workflow_command,
            derive_command=(sys.executable, str(tripwire)),
            ac_gate_command=self.ac_gate_command,
            migrate_command=self.migrate_command,
            deploy_command=self.deploy_command,
            verify_command=self.verify_command,
            digest_command=self.digest_command,
            timeout=60,
        )
        self.assertEqual(summary["status"], "DONE")
        self.assertFalse(marker.exists(), "derivation ran despite no floor moves")
        self.assertEqual(summary["final_ac_sha"], card.ac_base_sha)
        ac_release = git("ls-remote", "origin", "refs/heads/release", cwd=self.ac)
        self.assertEqual(ac_release.split()[0], card.ac_base_sha)

    def test_ac_gate_runs_under_the_work_timeout(self) -> None:
        self._prepare()
        slow = Path(self.tmp.name) / "slow-ac-gate.py"
        slow.write_text("import time\ntime.sleep(3)\n")
        with self.assertRaises(rt.CommandUnavailable) as caught:
            rt.continue_train(
                self.aweb,
                rederive=lambda environment: [],
                marketplace_command=self.marketplace_command,
                correction_command=self.correction_command,
                marketplace_gate=lambda card, bases, timeout: [],
                ac_predecessor_gate=lambda card, bases, timeout: [],
                terminal_gate=lambda environment, ac_derived, effect_rows, bases, timeout: [],
                bases={
                    "pypi": self.spool_base,
                    "npm": self.spool_base,
                    "ghcr": self.spool_base,
                    "github": self.spool_base,
                },
                workflow_command=self.workflow_command,
                derive_command=self.derive_command,
                ac_gate_command=(sys.executable, str(slow)),
                migrate_command=self.migrate_command,
                deploy_command=self.deploy_command,
                verify_command=self.verify_command,
                digest_command=self.digest_command,
                timeout=60,
                work_timeout=1,
            )
        self.assertIn("timed out", str(caught.exception))
        # The stop keeps the card and touches nothing past the gate edge.
        self.assertFalse(self.provider_log.exists())
        rt.read_card(self.aweb)

    def test_prepare_preserves_a_card_whose_derived_child_is_mid_continue(self) -> None:
        card = self._prepare()
        failing = Path(self.tmp.name) / "failing-ac-gate.py"
        failing.write_text("raise SystemExit(1)\n")
        with self.assertRaises(rt.CommandFailed):
            rt.continue_train(
                self.aweb,
                rederive=lambda environment: [],
                marketplace_command=self.marketplace_command,
                correction_command=self.correction_command,
                marketplace_gate=lambda card, bases, timeout: [],
                ac_predecessor_gate=lambda card, bases, timeout: [],
                terminal_gate=lambda environment, ac_derived, effect_rows, bases, timeout: [],
                bases={
                    "pypi": self.spool_base,
                    "npm": self.spool_base,
                    "ghcr": self.spool_base,
                    "github": self.spool_base,
                },
                workflow_command=self.workflow_command,
                derive_command=self.derive_command,
                ac_gate_command=(sys.executable, str(failing)),
                migrate_command=self.migrate_command,
                deploy_command=self.deploy_command,
                verify_command=self.verify_command,
                digest_command=self.digest_command,
                timeout=60,
            )
        # AC main now sits at the derived dependency-only child, a state
        # continue adopts on retry. The stored card is still executable, so
        # prepare must refuse pointing at the resume, not destroy it.
        with self.assertRaises(rt.MaterialMismatch) as caught:
            self._prepare()
        self.assertIn("release-continue", str(caught.exception))
        self.assertEqual(rt.read_card(self.aweb), card)
        summary = self._continue()
        self.assertEqual(summary["status"], "DONE")

    def test_monitor_record_is_required_typed_and_source_bound(self) -> None:
        # A8: the workflow monitor's stdout must be the strictly typed
        # remote-completion record - each way it can lie has its own
        # named refusal, and an opaque successful subprocess is none of
        # them.
        good = '{"workflow": "w.yml", "run_sha": "%s", "conclusion": "success"}' % ("a" * 40)
        rt._require_monitor_record(good, "a" * 40)  # the legit record passes
        with self.assertRaisesRegex(rt.ObservationMalformed, "no remote-completion"):
            rt._require_monitor_record("", "a" * 40)
        with self.assertRaisesRegex(rt.ObservationMalformed, "not JSON"):
            rt._require_monitor_record("watching run 123", "a" * 40)
        with self.assertRaisesRegex(rt.ObservationMalformed, "wrong shape"):
            rt._require_monitor_record(
                '{"workflow": "w.yml", "conclusion": "success"}', "a" * 40
            )
        with self.assertRaisesRegex(rt.ObservationMalformed, "wrong shape"):
            rt._require_monitor_record(
                '{"workflow": "w", "run_sha": "x", "conclusion": "success", "extra": 1}',
                "a" * 40,
            )
        with self.assertRaisesRegex(rt.ValidationError, "not success"):
            rt._require_monitor_record(
                '{"workflow": "w.yml", "run_sha": "%s", "conclusion": "failure"}'
                % ("a" * 40),
                "a" * 40,
            )
        with self.assertRaisesRegex(rt.ValidationError, "but the card releases"):
            rt._require_monitor_record(
                '{"workflow": "w.yml", "run_sha": "%s", "conclusion": "success"}'
                % ("b" * 40),
                "a" * 40,
            )
        # release-review's A8 point, the ACCIDENT case: a retry loop or
        # echoing wrapper emits two records; last-line would let a late
        # success bury an earlier failure. The contract says the record
        # is the ONLY stdout - so exactly one line is enforced, not the
        # last of several.
        failure_then_success = (
            '{"workflow": "w.yml", "run_sha": "%s", "conclusion": "failure"}\n'
            '{"workflow": "w.yml", "run_sha": "%s", "conclusion": "success"}'
        ) % ("a" * 40, "a" * 40)
        with self.assertRaisesRegex(rt.ObservationMalformed, "exactly one"):
            rt._require_monitor_record(failure_then_success, "a" * 40)

    def test_fixed_continue_commands_are_the_reviewed_defaults(self) -> None:
        # A8: the env variables are hermetic-test seams; the production
        # defaults are the fixed repository commands, pinned here so an
        # override can never quietly become the real path.
        from unittest import mock

        clean = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("AWEB_RELEASE_")
        }
        with mock.patch.dict(os.environ, clean, clear=True):
            commands = rt.continue_commands()
        self.assertEqual(
            commands["AWEB_RELEASE_WORKFLOW_COMMAND"],
            ("bash", "scripts/release-workflow-monitor.sh"),
        )
        self.assertEqual(
            commands["AWEB_RELEASE_DERIVE_COMMAND"],
            ("python3", "scripts/derive_release_floors.py", "--ac-root", "."),
        )
        self.assertEqual(
            commands["AWEB_RELEASE_AC_GATE_COMMAND"],
            ("bash", "scripts/release-local-gate.sh"),
        )
        self.assertEqual(
            commands["AWEB_RELEASE_MIGRATE_COMMAND"],
            ("make", "prod-migrate-direct"),
        )
        self.assertEqual(
            commands["AWEB_RELEASE_MARKETPLACE_COMMAND"],
            (
                "python3",
                "scripts/pointer-adapter-marketplace-pointer.py",
                "apply",
            ),
        )
        self.assertEqual(
            commands["AWEB_RELEASE_CORRECTION_COMMAND"],
            (
                "python3",
                "scripts/render_release_client.py",
                "first-correction",
                "--digest",
            ),
        )
        # C1: operator env overrides are GONE - an env value must not
        # change what production resolves.
        with mock.patch.dict(
            os.environ, {"AWEB_RELEASE_MIGRATE_COMMAND": "echo hijacked"}
        ):
            self.assertEqual(
                rt.continue_commands()["AWEB_RELEASE_MIGRATE_COMMAND"],
                ("make", "prod-migrate-direct"),
            )
        self.assertEqual(
            commands["AWEB_RELEASE_DEPLOY_COMMAND"],
            ("python3", "scripts/render_release_client.py", "deploy", "--digest"),
        )
        self.assertEqual(
            commands["AWEB_RELEASE_VERIFY_COMMAND"][:3],
            ("python3", "scripts/render_release_client.py", "verify-deploy"),
        )
        self.assertEqual(commands["AWEB_RELEASE_VERIFY_COMMAND"][-1], "--digest")
        self.assertEqual(
            commands["AWEB_RELEASE_DIGEST_COMMAND"],
            (
                "python3",
                "scripts/verify_registry_adoption.py",
                "--image",
                "ghcr.io/awebai/ac",
                "--emit-digest",
            ),
        )

    def test_digest_argv_composed_by_the_train_executes_the_real_ac_contract(self) -> None:
        # C1, the critic's probe in both directions: the FIXED digest
        # command plus the train-appended card arguments must be
        # accepted and answer digest= against the real AC script; the
        # bare fixed tuple (the A8 defect) must be refused by argparse -
        # pinning that the appending is load-bearing.
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from registry_stand_in import RegistryStandIn

        ac_root = Path(__file__).resolve().parents[2].parent / "ac-worktree"
        script = ac_root / "scripts" / "verify_registry_adoption.py"
        if not script.exists():
            ac_root = Path(__file__).resolve().parents[2].parent / "ac"
            script = ac_root / "scripts" / "verify_registry_adoption.py"
        if not script.exists():
            self.fail(
                "no AC checkout with verify_registry_adoption.py beside this "
                "repository; the digest contract cannot be executed"
            )
        digest_value = "sha256:" + "ab" * 32
        world = {
            "ghcr_index": {
                "awebai/ac": {
                    "0.7.15": {
                        "digest": digest_value,
                        "platforms": [
                            ["linux", "amd64"],
                            ["linux", "arm64"],
                        ],
                    }
                }
            }
        }
        fixed = rt._CONTINUE_FIXED_COMMANDS["AWEB_RELEASE_DIGEST_COMMAND"]
        with RegistryStandIn(world) as registry:
            env = {
                **os.environ,
                "AC_REGISTRY_BASE": registry.base,
                "GH_TOKEN": "fixture-token",
            }
            composed = subprocess.run(
                [
                    *fixed,
                    "--version",
                    "0.7.15",
                    "--source-sha",
                    "c" * 40,
                ],
                cwd=ac_root,
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )
            bare = subprocess.run(
                list(fixed),
                cwd=ac_root,
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )
        self.assertEqual(
            composed.returncode,
            0,
            f"stdout:{composed.stdout} stderr:{composed.stderr}",
        )
        self.assertIn(f"digest={digest_value}", composed.stdout)
        self.assertEqual(
            bare.returncode, 2, "the bare fixed tuple must be refused"
        )
        self.assertIn("--version", bare.stderr)

    def test_full_fixture_continue_reaches_done_through_the_default_terminal_gate(self) -> None:
        # C2's capstone, the verdict's explicit demand: the full continue
        # fixture with the DEFAULT terminal gate - no injected empty
        # gate. Every registry fact the derivable domain requires is
        # served over the wire-protocol stand-in; the AC image's
        # revision label and the health SHA resolve DYNAMICALLY to the
        # commit this very run derives, written by the ac-gate stub.
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from registry_stand_in import RegistryStandIn

        card = self._prepare()
        sha = card.aweb_sha
        for tag in (
            "server-v1.27.2",
            "awid-service-v0.5.16",
            "awid-v0.5.16",
            "aw-v1.34.4",
            "channel-v1.7.7",
            "pi-v0.3.7",
            "skills-v0.2.13",
            "a2a-gw-v1.27.2",
        ):
            git("tag", "-f", tag, sha, cwd=self.aweb)
            git("push", "-qf", "origin", f"refs/tags/{tag}", cwd=self.aweb)
        rev_file = Path(self.tmp.name) / "derived-sha"
        gate_with_rev = Path(self.tmp.name) / "ac-gate-rev.py"
        gate_with_rev.write_text(
            "import subprocess\nfrom pathlib import Path\n"
            "sha = subprocess.run(['git', 'rev-parse', 'HEAD'],"
            " capture_output=True, text=True, check=True).stdout.strip()\n"
            f"Path({str(rev_file)!r}).write_text(sha)\n"
            "print('AC gate 16/16 PASSED')\n"
        )
        marketplace_read = Path(self.tmp.name) / "marketplace-read.py"
        marketplace_read.write_text(
            "import json\n"
            'print(json.dumps({"advertised": {"channel": "1.7.7", "skills": "0.2.13"}}))\n'
        )
        standing = Path(self.tmp.name) / "standing.py"
        standing.write_text("print('standing ok')\n")
        aw_assets = [
            f"aw_1.34.4_{platform}" for platform in (
                "linux_amd64.tar.gz", "linux_arm64.tar.gz",
                "darwin_amd64.tar.gz", "darwin_arm64.tar.gz",
                "windows_amd64.zip", "windows_arm64.zip",
            )
        ] + ["checksums.txt"]
        world = {
            "pypi_files": {
                "awid-service": {"0.5.16": {
                    "awid_service-0.5.16.tar.gz": "a" * 64,
                    "awid_service-0.5.16-py3-none-any.whl": "b" * 64,
                }},
                "aweb": {"1.27.2": {
                    "aweb-1.27.2.tar.gz": "c" * 64,
                    "aweb-1.27.2-py3-none-any.whl": "d" * 64,
                }},
            },
            "npm_tarballs": {
                f"{pkg}/{version}.tgz": f"{pkg}-{version}".encode()
                for pkg, version in (
                    ("@awebai/aw", "1.34.4"),
                    ("@awebai/aw-linux-x64", "1.34.4"),
                    ("@awebai/aw-linux-arm64", "1.34.4"),
                    ("@awebai/aw-darwin-x64", "1.34.4"),
                    ("@awebai/aw-darwin-arm64", "1.34.4"),
                    ("@awebai/aw-windows-x64", "1.34.4"),
                    ("@awebai/aw-windows-arm64", "1.34.4"),
                    ("@awebai/claude-channel", "1.7.7"),
                    ("@awebai/pi", "0.3.7"),
                    ("@awebai/claude-skills", "0.2.13"),
                )
            },
            "ghcr_index": {
                "awebai/awid": {"0.5.16": {
                    "digest": "sha256:" + "1" * 64,
                    "platforms": [["linux", "amd64"], ["linux", "arm64"]],
                }},
                "awebai/a2a-gateway": {"1.27.2": {
                    "digest": "sha256:" + "2" * 64,
                    "platforms": [["linux", "amd64"], ["linux", "arm64"]],
                }},
                "awebai/awid": {"0.5.16": {
                    "digest": "sha256:" + "1" * 64,
                    "platforms": [["linux", "amd64"], ["linux", "arm64"]],
                }, "latest": {
                    "digest": "sha256:" + "1" * 64,
                    "platforms": [["linux", "amd64"], ["linux", "arm64"]],
                }},
            },
            "ghcr_index_revisions": {
                "awebai/awid:0.5.16": sha,
                "awebai/awid:latest": sha,
                "awebai/a2a-gateway:1.27.2": sha,
                "awebai/a2a-gateway:latest": sha,
            },
            "ghcr_dynamic": {
                "awebai/ac": {
                    "tag": "0.7.13",
                    "digest": "sha256:" + "3" * 64,
                    "revision_file": str(rev_file),
                }
            },
            "github_releases": {
                "awebai/aw": {"v1.34.4": aw_assets},
                "awebai/aweb": {"skills-v0.2.13": [
                    "aweb-coordination.zip", "aweb-messaging.zip",
                    "aweb-team-membership.zip", "aweb-bootstrap.zip",
                    "aweb-identity.zip",
                ]},
            },
            "github_commits": {
                "awebai/aw": {"v1.34.4": {
                    "sha": "e" * 40,
                    # INERT. Nothing reads this message: the binding
                    # compares the published TREE against aweb's cli/go
                    # from the local checkout, not a stamp the commit
                    # makes about itself. Kept only so the stand-in
                    # answers the commits endpoint at all - a reader who
                    # infers from it that the stamp is verified would be
                    # re-deriving a guarantee from a fixture field.
                    "message": f"Sync exact aweb {sha}",
                }},
            },
            "health_git_sha_file": str(rev_file),
        }
        world["ghcr_index"]["awebai/a2a-gateway"]["latest"] = world[
            "ghcr_index"
        ]["awebai/a2a-gateway"]["1.27.2"]
        if getattr(self, "_capstone_mutation", None) == "wrong-stamp":
            # PORTED, not dropped. The binding used to read the tag's
            # COMMIT MESSAGE over the API, so falsifying the sync stamp
            # falsified it. It now compares the published TREE against
            # aweb's cli/go from the local checkout, so the equivalent
            # falsification is a published tree that does not match -
            # one extra file, which is precisely what a bad sync would
            # leave behind. Falsifying the old stamp would no longer
            # falsify anything, and this control would have passed
            # while proving nothing.
            (self.aw / "smuggled.go").write_text("package main // not ours\n")
            git("add", ".", cwd=self.aw)
            git("commit", "-m", "smuggle", cwd=self.aw)
            git("tag", "-f", "-a", "v1.34.4", "-m", "v1.34.4", cwd=self.aw)
        with RegistryStandIn(world) as registry:
            summary = rt.continue_train(
                self.aweb,
                rederive=lambda environment: [],
                marketplace_command=self.marketplace_command,
                correction_command=self.correction_command,
                marketplace_read_command=(
                    sys.executable, str(marketplace_read),
                ),
                read_standing_command=(sys.executable, str(standing)),
                health_url=f"{registry.base}/health",
                marketplace_gate=lambda card, bases, timeout: [],
                ac_predecessor_gate=lambda card, bases, timeout: [],
                bases={
                    "pypi": registry.base,
                    "npm": registry.base,
                    "ghcr": registry.base,
                    "github": registry.base,
                },
                workflow_command=self.workflow_command,
                derive_command=self.derive_command,
                ac_gate_command=(sys.executable, str(gate_with_rev)),
                migrate_command=self.migrate_command,
                deploy_command=self.deploy_command,
                verify_command=self.verify_command,
                digest_command=self.digest_command,
                timeout=60,
                work_timeout=30,
            )
        self.assertEqual(summary["status"], "DONE")

    def test_default_gate_refuses_a_lying_external_binding(self) -> None:
        # The capstone's mutation control: the same fully-served world
        # with ONE fact falsified (the external sync stamp naming a
        # foreign source) must refuse DONE through the DEFAULT gate,
        # naming the binding row - the false-publication direction.
        self._capstone_mutation = "wrong-stamp"
        try:
            with self.assertRaises(rt.ValidationError) as caught:
                self.test_full_fixture_continue_reaches_done_through_the_default_terminal_gate()
            self.assertIn("DONE refused", str(caught.exception))
            self.assertIn("tree binding", str(caught.exception))
        finally:
            self._capstone_mutation = None

    def test_marketplace_edge_follows_the_card_not_command_presence(self) -> None:
        # C1: the pointer edge runs because the CARD moves channel or
        # skills - an unbound command is a named refusal, never a silent
        # skip, and a card moving neither runs nothing.
        self._prepare()
        with self.assertRaises(rt.ValidationError) as caught:
            rt.continue_train(
                self.aweb,
                rederive=lambda environment: [],
                marketplace_command=None,
                correction_command=self.correction_command,
                marketplace_gate=lambda card, bases, timeout: [],
                ac_predecessor_gate=lambda card, bases, timeout: [],
                terminal_gate=lambda environment, ac_derived, effect_rows, bases, timeout: [],
                bases={
                    "pypi": self.spool_base,
                    "npm": self.spool_base,
                    "ghcr": self.spool_base,
                    "github": self.spool_base,
                },
                workflow_command=self.workflow_command,
                derive_command=self.derive_command,
                ac_gate_command=self.ac_gate_command,
                migrate_command=self.migrate_command,
                deploy_command=self.deploy_command,
                verify_command=self.verify_command,
                digest_command=self.digest_command,
                timeout=60,
                work_timeout=30,
            )
        self.assertIn("no marketplace command is bound", str(caught.exception))
        self.marketplace_marker.unlink(missing_ok=True)
        summary = self._continue()
        self.assertEqual(summary["status"], "DONE")
        self.assertTrue(
            self.marketplace_marker.exists(),
            "a card moving channel/skills must run the pointer edge",
        )

    def test_unbound_correction_refuses_when_the_card_needs_it(self) -> None:
        # release-review's C1 note closed: correction_command defaults
        # to None (inert), and a pending card with no binding refuses by
        # name before the production step - the marketplace shape, not a
        # silent default into a live production write.
        self._prepare()
        with self.assertRaises(rt.ValidationError) as caught:
            rt.continue_train(
                self.aweb,
                rederive=lambda environment: [],
                marketplace_command=self.marketplace_command,
                correction_command=None,
                marketplace_gate=lambda card, bases, timeout: [],
                ac_predecessor_gate=lambda card, bases, timeout: [],
                terminal_gate=lambda environment, ac_derived, effect_rows, bases, timeout: [],
                bases={
                    "pypi": self.spool_base,
                    "npm": self.spool_base,
                    "ghcr": self.spool_base,
                    "github": self.spool_base,
                },
                workflow_command=self.workflow_command,
                derive_command=self.derive_command,
                ac_gate_command=self.ac_gate_command,
                migrate_command=self.migrate_command,
                deploy_command=self.deploy_command,
                verify_command=self.verify_command,
                digest_command=self.digest_command,
                timeout=60,
                work_timeout=30,
            )
        self.assertIn("no correction command is bound", str(caught.exception))
        self.assertIn("at continue entry", str(caught.exception))
        # alice's tripwire form: the refusal precedes EVERY edge - the
        # release pointer never moved and no provider command ran.
        listed = git(
            "ls-remote", "origin", "refs/heads/release", cwd=self.aweb
        )
        self.assertEqual(listed, "", "the release pointer must not move")
        self.assertFalse(
            self.provider_log.exists(),
            "no provider command (migrate included) may run past the refusal",
        )

    def test_pending_correction_is_executed_not_recorded(self) -> None:
        # C1: production_correction_pending is READ - the pending card's
        # production step is first-correction with the digest, and the
        # plain deploy stub must NOT run.
        self._prepare()
        summary = self._continue()
        self.assertEqual(summary["status"], "DONE")
        steps = [
            line.split()[0]
            for line in self.provider_log.read_text().splitlines()
        ]
        self.assertIn("correction", steps)
        self.assertNotIn("deploy", steps)

    def test_derive_receives_the_complete_card_projection(self) -> None:
        # A8, the gate's :1967 finding: the train itself binds
        # --card-artifacts and --card-ac-version from the live card.
        self._prepare()
        argv_dump = Path(self.tmp.name) / "derive-argv.json"
        dumper = Path(self.tmp.name) / "derive-dump.py"
        dumper.write_text(
            "import json, sys\n"
            "from pathlib import Path\n"
            f"Path({str(argv_dump)!r}).write_text(json.dumps(sys.argv[1:]))\n"
            "root = Path(sys.argv[1])\n"
            "(root / 'backend/pyproject.toml').write_text("
            "'[project]\\nversion = \"0.7.13\"\\n# floors bumped\\n')\n"
            "(root / 'backend/uv.lock').write_text('lock v2\\n')\n"
        )
        self._continue_with_derive((sys.executable, str(dumper), str(self.ac)))
        argv = json.loads(argv_dump.read_text())
        self.assertIn("--card-artifacts", argv)
        self.assertIn("--card-ac-version", argv)
        rows = json.loads(argv[argv.index("--card-artifacts") + 1])
        self.assertEqual(len(rows), 9)
        self.assertEqual(
            {row["name"] for row in rows},
            set(rt.CARD_ARTIFACT_ORDER),
        )
        self.assertEqual(argv[argv.index("--card-ac-version") + 1], "0.7.13")

    def _continue_with_derive(self, derive_command):
        return rt.continue_train(
            self.aweb,
            rederive=lambda environment: [],
            marketplace_command=self.marketplace_command,
            correction_command=self.correction_command,
            marketplace_gate=lambda card, bases, timeout: [],
            ac_predecessor_gate=lambda card, bases, timeout: [],
            terminal_gate=lambda environment, ac_derived, effect_rows, bases, timeout: [],
            bases={
                "pypi": self.spool_base,
                "npm": self.spool_base,
                "ghcr": self.spool_base,
                "github": self.spool_base,
            },
            workflow_command=self.workflow_command,
            derive_command=derive_command,
            ac_gate_command=self.ac_gate_command,
            migrate_command=self.migrate_command,
            deploy_command=self.deploy_command,
            verify_command=self.verify_command,
            digest_command=self.digest_command,
            timeout=60,
            work_timeout=30,
        )

    def test_continue_failure_path_preserves_the_refusal_through_the_entry(self) -> None:
        # A7: the real entry's failure path goes through the
        # failure-preserving reporter - the refusal is primary, a probe
        # that cannot even read a card becomes a diagnostic line, and
        # exit stays nonzero. Run as the operator runs it.
        import subprocess as _subprocess
        import tempfile as _tempfile

        with _tempfile.TemporaryDirectory() as tmp:
            _subprocess.run(["git", "init", "-q", tmp], check=True, capture_output=True)
            env = dict(os.environ)
            for name in (
                "AWEB_RELEASE_WORKFLOW_COMMAND", "AWEB_RELEASE_DERIVE_COMMAND",
                "AWEB_RELEASE_AC_GATE_COMMAND", "AWEB_RELEASE_MIGRATE_COMMAND",
                "AWEB_RELEASE_DEPLOY_COMMAND", "AWEB_RELEASE_VERIFY_COMMAND",
                "AWEB_RELEASE_DIGEST_COMMAND",
            ):
                env[name] = "true"
            completed = _subprocess.run(
                [sys.executable, str(Path(rt.__file__)), "continue"],
                cwd=tmp,
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertIn("release-continue stopped:", completed.stderr)
        self.assertIn("status reporting failed", completed.stderr)

    def test_terminal_gate_refusal_keeps_the_card_and_names_the_rows(self) -> None:
        # A7: DONE is the complete intended world; a blocking row
        # refuses by name and the card survives for the retry.
        self._prepare()
        with self.assertRaises(rt.ValidationError) as caught:
            self._continue(
                terminal_gate=lambda environment, ac_derived, effect_rows, bases, timeout: [
                    "ABSENT pypi:aweb wheel (registry 404)"
                ]
            )
        self.assertIn("DONE refused", str(caught.exception))
        self.assertIn("pypi:aweb wheel", str(caught.exception))
        rt.read_card(self.aweb)  # the card is intact

    def test_default_terminal_gate_is_the_real_status_sweep(self) -> None:
        # The seam exists for fixtures; the default must be the real
        # sweep - proven by monkeypatching the assembly it consumes and
        # watching the refusal carry the assembly's row.
        from unittest import mock

        import release_status_gates as gates
        from release_status import Row

        self._prepare()
        with mock.patch.object(
            gates,
            "rows_for_artifacts",
            return_value=[
                Row(fact="tripwire fact", state="observed-absent", evidence="wired")
            ],
        ):
            with self.assertRaises(rt.ValidationError) as caught:
                # Direct call, terminal_gate OMITTED - the default must
                # be the real sweep (the fixture helper's empty-gate
                # convenience must not be what production runs).
                rt.continue_train(
                    self.aweb,
                    marketplace_command=self.marketplace_command,
                    correction_command=self.correction_command,
                    rederive=lambda environment: [],
                    marketplace_gate=lambda card, bases, timeout: [],
                    ac_predecessor_gate=lambda card, bases, timeout: [],
                    bases={
                        "pypi": self.spool_base,
                        "npm": self.spool_base,
                        "ghcr": self.spool_base,
                        "github": self.spool_base,
                    },
                    workflow_command=self.workflow_command,
                    derive_command=self.derive_command,
                    ac_gate_command=self.ac_gate_command,
                    migrate_command=self.migrate_command,
                    deploy_command=self.deploy_command,
                    verify_command=self.verify_command,
                    digest_command=self.digest_command,
                    timeout=60,
                    work_timeout=30,
                )
        self.assertIn("DONE refused", str(caught.exception))
        self.assertIn("tripwire fact", str(caught.exception))

    def test_digest_edge_waits_for_the_ac_image_the_release_push_builds(self) -> None:
        import threading

        card = self._prepare()
        manifest = self.spool / urllib_quote("/v2/awebai/ac/manifests/0.7.13")
        manifest.unlink()
        gated = Path(self.tmp.name) / "digest-when-present.py"
        gated.write_text(
            "from pathlib import Path\n"
            f"if not Path({str(manifest)!r}).exists():\n"
            "    raise SystemExit(1)\n"
            f"print('{DIGEST}')\n"
        )
        timer = threading.Timer(
            2.0, lambda: manifest.write_text(json.dumps({"manifests": []}))
        )
        timer.start()
        try:
            summary = rt.continue_train(
                self.aweb,
                rederive=lambda environment: [],
                marketplace_command=self.marketplace_command,
                correction_command=self.correction_command,
                marketplace_gate=lambda card, bases, timeout: [],
                ac_predecessor_gate=lambda card, bases, timeout: [],
                terminal_gate=lambda environment, ac_derived, effect_rows, bases, timeout: [],
                bases={
                    "pypi": self.spool_base,
                    "npm": self.spool_base,
                    "ghcr": self.spool_base,
                    "github": self.spool_base,
                },
                workflow_command=self.workflow_command,
                derive_command=self.derive_command,
                ac_gate_command=self.ac_gate_command,
                migrate_command=self.migrate_command,
                deploy_command=self.deploy_command,
                verify_command=self.verify_command,
                digest_command=(sys.executable, str(gated)),
                timeout=60,
                work_timeout=30,
            )
        finally:
            timer.cancel()
        self.assertEqual(summary["status"], "DONE")
        self.assertEqual(summary["ac_image_digest"], DIGEST)

    def test_partial_prior_derivation_is_adopted_on_retry(self) -> None:
        self._prepare()
        failing = Path(self.tmp.name) / "failing-ac-gate.py"
        failing.write_text("raise SystemExit(1)\n")
        with self.assertRaises(rt.CommandFailed):
            rt.continue_train(
                self.aweb,
                rederive=lambda environment: [],
                marketplace_command=self.marketplace_command,
                correction_command=self.correction_command,
                marketplace_gate=lambda card, bases, timeout: [],
                ac_predecessor_gate=lambda card, bases, timeout: [],
                terminal_gate=lambda environment, ac_derived, effect_rows, bases, timeout: [],
                bases={
                    "pypi": self.spool_base,
                    "npm": self.spool_base,
                    "ghcr": self.spool_base,
                    "github": self.spool_base,
                },
                workflow_command=self.workflow_command,
                derive_command=self.derive_command,
                ac_gate_command=(sys.executable, str(failing)),
                migrate_command=self.migrate_command,
                deploy_command=self.deploy_command,
                verify_command=self.verify_command,
                digest_command=self.digest_command,
                timeout=60,
            )
        # AC main has already advanced to the derived commit; the retry must
        # adopt that exact state and reach DONE.
        summary = self._continue()
        self.assertEqual(summary["status"], "DONE")


class WorkflowMonitorTests(unittest.TestCase):
    """The monitor maps each publishable artifact to its release-branch
    workflow file and refuses unmapped names before touching gh."""

    SCRIPT = REPO_ROOT / "scripts/release-workflow-monitor.sh"

    def test_every_publishable_artifact_maps_to_an_existing_workflow(self) -> None:
        expected = {
            "aw-cli": "aw-release.yml",
            "a2a-gateway-image": "a2a-gateway-release.yml",
            "aweb-server": "pypi-release.yml",
            "awid-service": "pypi-release.yml",
            "awid-image": "awid-image-release.yml",
            "channel-plugin": "npm-release.yml",
            "pi-extension": "npm-release.yml",
            "skills": "npm-release.yml",
        }
        for artifact, workflow in expected.items():
            result = subprocess.run(
                [str(self.SCRIPT), "--print-workflow", artifact],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), workflow, artifact)
            self.assertTrue(
                (REPO_ROOT / ".github/workflows" / workflow).exists(), workflow
            )

    def test_unmapped_artifact_refuses_naming_it(self) -> None:
        result = subprocess.run(
            [str(self.SCRIPT), "--print-workflow", "no-such-artifact"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("no-such-artifact", result.stderr)


class CompatPairingTests(unittest.TestCase):
    """At most one deterministically relevant last/new pairing adds a run:
    the cli-server pair, only when exactly one side moves."""

    def _selection(self, cli_moves: bool, server_moves: bool):
        rows = []
        for name in rt.CARD_ARTIFACT_ORDER:
            moves = {"aw-cli": cli_moves, "aweb-server": server_moves}.get(name, True)
            rows.append(
                rt.ArtifactSelection(
                    name=name,
                    version="1.2.3",
                    moves=moves,
                    disposition=None if moves else "unmoved",
                    previous_complete_anchor=(
                        None if moves else _test_anchor("1.2.3")
                    ),
                )
            )
        return tuple(rows)

    def test_pairing_fires_only_when_exactly_one_side_moves(self) -> None:
        self.assertEqual(
            rt.select_compat_pairing(self._selection(True, False)),
            ("aw-cli@new", "aweb-server@last"),
        )
        self.assertEqual(
            rt.select_compat_pairing(self._selection(False, True)),
            ("aw-cli@last", "aweb-server@new"),
        )
        self.assertIsNone(rt.select_compat_pairing(self._selection(True, True)))
        self.assertIsNone(rt.select_compat_pairing(self._selection(False, False)))


class PrepareCompatRunTests(_PipelineFixture):
    def test_prepare_adds_exactly_one_compat_gate_run_when_relevant(self) -> None:
        # Fixture: server moves (absent), aw-cli does not (its next version is
        # already served) - the mixed pairing.
        from urllib.parse import quote

        gate_log = Path(self.tmp.name) / "gate-invocations.txt"
        gate = Path(self.tmp.name) / "counting-gate.py"
        gate.write_text(
            "import json, sys\n"
            f"open({str(gate_log)!r}, 'a').write(' '.join(sys.argv[1:]) + chr(10))\n"
            'print(json.dumps({"suites": ["make-test"], "reference": "fixture.log"}))\n'
        )
        # aw-cli's next patch is already served, so its projection row
        # is unmoved - the mixed pairing.
        del quote
        environment = {"PURPOSE": "fixture", "COMPAT_BREAK": "none"}
        card = rt.prepare(
            self.aweb,
            environment,
            projection=_fixture_projection(
                self.aweb, environment, unmoved=("aw-cli",)
            ),
            gate_command=(sys.executable, str(gate)),
            timeout=30,
        )
        del card
        invocations = gate_log.read_text().splitlines()
        self.assertEqual(len(invocations), 2)
        self.assertIn("compat-pairing", invocations[1])


class PrepareGateWrapperTests(unittest.TestCase):
    """The prepare gate boundary emits only the JSON evidence on stdout and
    fails without evidence when the gate does not pass."""

    def _run(self, *args, gate_body: str, sha: str, env_extra=None):
        import os, subprocess as sp

        wrapper = REPO_ROOT / "scripts/release-prepare-gate.sh"
        with tempfile.TemporaryDirectory() as tmp:
            gate = Path(tmp) / "fake-gate.sh"
            gate.write_text("#!/usr/bin/env bash\nset -eu\n" + gate_body)
            gate.chmod(0o755)
            env = {
                **os.environ,
                "AWEB_PREPARE_GATE_SCRIPT": str(gate),
                "AWEB_SHA": sha,
                **(env_extra or {}),
            }
            return sp.run(
                [str(wrapper), *args], capture_output=True, text=True, env=env
            )

    def test_passing_gate_emits_the_row_names_and_reference(self) -> None:
        import shutil

        sha = "e" * 40
        log_dir = f"/tmp/aweb-release-gate-{sha}"
        # A leftover green dir from a prior run would be adopted; this test
        # pins the fresh-run path, so it starts from a clean slate.
        shutil.rmtree(log_dir, ignore_errors=True)
        self.addCleanup(shutil.rmtree, log_dir, ignore_errors=True)
        body = (
            f"mkdir -p {log_dir}\n"
            f"printf 'one\\tPASSED\\tcontract\\tt1\\ntwo\\tPASSED\\tunit\\tt2\\n' > {log_dir}/summary.tsv\n"
            f"printf 'release gate PASSED at {sha}; logs: {log_dir}\\n' > {log_dir}/wrapper-verdict.log\n"
            "echo gate-noise\n"
        )
        result = self._run(gate_body=body, sha=sha)
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(result.stdout)
        self.assertEqual(evidence["suites"], ["one", "two"])
        self.assertEqual(evidence["reference"], log_dir)
        self.assertIn("gate-noise", result.stderr)

    def test_failing_gate_emits_no_evidence(self) -> None:
        result = self._run(gate_body="echo failing >&2\nexit 1\n", sha="f" * 40)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_missing_pass_verdict_refuses(self) -> None:
        sha = "a" * 40
        log_dir = f"/tmp/aweb-release-gate-{sha}"
        body = (
            f"mkdir -p {log_dir}\n"
            f"printf 'one\\tPASSED\\tcontract\\tt1\\n' > {log_dir}/summary.tsv\n"
            f"printf 'release gate FAILED; logs: {log_dir}\\n' > {log_dir}/wrapper-verdict.log\n"
        )
        result = self._run(gate_body=body, sha=sha)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_green_evidence_at_the_exact_sha_is_adopted_without_rerunning(self) -> None:
        import shutil

        sha = "9" * 40
        log_dir = f"/tmp/aweb-release-gate-{sha}"
        marker = Path(tempfile.gettempdir()) / f"gate-invoked-{sha[:8]}"
        marker.unlink(missing_ok=True)
        shutil.rmtree(log_dir, ignore_errors=True)
        os.makedirs(log_dir, exist_ok=True)
        # Completeness is part of the predicate: the summary must carry
        # exactly the real suite map's rows, all PASSED.
        map_rows = [
            line.split("\t")
            for line in (REPO_ROOT / "release-gate/suite-map.tsv")
            .read_text()
            .splitlines()
            if line.strip() and not line.startswith("#")
        ]
        Path(log_dir, "summary.tsv").write_text(
            "".join(f"{row[0]}\tPASSED\tfixture\t{row[-1]}\n" for row in map_rows)
        )
        Path(log_dir, "wrapper-verdict.log").write_text(
            f"release gate PASSED at {sha}; logs: {log_dir}\n"
        )
        # A green NEIGHBOUR at a different SHA must not satisfy anything.
        neighbour = f"/tmp/aweb-release-gate-{'a1' * 20}"
        shutil.rmtree(neighbour, ignore_errors=True)
        os.makedirs(neighbour, exist_ok=True)
        Path(neighbour, "wrapper-verdict.log").write_text(
            f"release gate PASSED at {'a1' * 20}; logs: {neighbour}\n"
        )
        try:
            result = self._run(
                gate_body=f"touch {marker}\nexit 1\n",
                sha=sha,
                env_extra={"AWEB_PREPARE_INPUTS_CHECK": "true"},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            evidence = json.loads(result.stdout)
            self.assertEqual(len(evidence["suites"]), len(map_rows))
            self.assertEqual(evidence["suites"][0], map_rows[0][0])
            self.assertFalse(
                marker.exists(), "gate was invoked despite green evidence"
            )
            self.assertIn("adopting prior green gate evidence", result.stderr)
            self.assertIn("not compared: package-manager fetches", result.stderr)
        finally:
            marker.unlink(missing_ok=True)
            shutil.rmtree(log_dir, ignore_errors=True)
            shutil.rmtree(neighbour, ignore_errors=True)

    def test_adoption_fails_closed_on_red_mismatched_or_absent_evidence(self) -> None:
        import shutil

        sha = "8" * 40
        log_dir = f"/tmp/aweb-release-gate-{sha}"
        marker = Path(tempfile.gettempdir()) / f"gate-invoked-{sha[:8]}"
        arms = (
            "red-verdict",
            "other-sha-verdict",
            "absent",
            "not-run-row",
            "incomplete-summary",
            "stale-evidence",
            "inputs-mismatch",
        )
        for arm in arms:
            marker.unlink(missing_ok=True)
            shutil.rmtree(log_dir, ignore_errors=True)
            if arm != "absent":
                os.makedirs(log_dir, exist_ok=True)
                map_rows = [
                    line.split("\t")
                    for line in (REPO_ROOT / "release-gate/suite-map.tsv")
                    .read_text()
                    .splitlines()
                    if line.strip() and not line.startswith("#")
                ]
                rows = [f"{row[0]}\tPASSED\tfixture\t{row[-1]}" for row in map_rows]
                if arm == "not-run-row":
                    rows[-1] = rows[-1].replace("PASSED", "NOT RUN")
                if arm == "incomplete-summary":
                    rows = rows[:-1]
                Path(log_dir, "summary.tsv").write_text("\n".join(rows) + "\n")
                verdict = (
                    f"release gate FAILED; logs: {log_dir}"
                    if arm == "red-verdict"
                    else f"release gate PASSED at {sha}; logs: {log_dir}"
                    if arm
                    in (
                        "not-run-row",
                        "incomplete-summary",
                        "stale-evidence",
                        "inputs-mismatch",
                    )
                    else f"release gate PASSED at {'7' * 40}; logs: {log_dir}"
                )
                Path(log_dir, "wrapper-verdict.log").write_text(verdict + "\n")
                if arm == "stale-evidence":
                    import subprocess as _sp

                    _sp.run(
                        ["touch", "-t", "202501010000", f"{log_dir}/summary.tsv"],
                        check=True,
                    )
            try:
                check = "false" if arm == "inputs-mismatch" else "true"
                result = self._run(
                    gate_body=f"touch {marker}\nexit 1\n",
                    sha=sha,
                    env_extra={"AWEB_PREPARE_INPUTS_CHECK": check},
                )
                self.assertNotEqual(result.returncode, 0, arm)
                self.assertTrue(
                    marker.exists(), f"gate was not invoked for arm {arm}"
                )
            finally:
                marker.unlink(missing_ok=True)
                shutil.rmtree(log_dir, ignore_errors=True)

    def test_compat_mode_names_the_pairing_and_runs_the_cell(self) -> None:
        # The wrapper resolves the published aw CLI from PATH; the fixture
        # supplies its own so the test means the same thing on hosts and in
        # the gate container, where no aw is installed.
        import os

        with tempfile.TemporaryDirectory() as bin_dir:
            fake_aw = Path(bin_dir) / "aw"
            fake_aw.write_text("#!/usr/bin/env bash\necho 'aw 9.9.9-fixture'\n")
            fake_aw.chmod(0o755)
            result = self._run(
                "compat-pairing", "aw-cli@new", "aweb-server@last",
                gate_body="true\n",
                sha="b" * 40,
                env_extra={
                    "AWEB_PREPARE_COMPAT_COMMAND": "echo compat-cell-ran",
                    "PATH": f"{bin_dir}:{os.environ['PATH']}",
                },
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(result.stdout)
        self.assertIn("aw-cli@new aweb-server@last", evidence["suites"][0])
        self.assertIn("9.9.9-fixture", evidence["suites"][0])
        self.assertTrue(Path(evidence["reference"]).exists())

    def test_compat_mode_refuses_without_an_installed_aw(self) -> None:
        result = self._run(
            "compat-pairing", "aw-cli@new", "aweb-server@last",
            gate_body="true\n",
            sha="b" * 40,
            env_extra={
                "AWEB_PREPARE_COMPAT_COMMAND": "echo compat-cell-ran",
                "PATH": "/usr/bin:/bin",
            },
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("not installed", result.stderr)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
