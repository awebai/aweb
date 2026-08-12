#!/usr/bin/env python3
"""Behavioral contract for the fixed two-repository release train foundation.

The tests use real temporary git repositories, subprocesses, and a loopback HTTP
server.  Nothing contacts or mutates GitHub, a public registry, AC, Render, or a
production service.
"""

from __future__ import annotations

import dataclasses
import json
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_train as rt


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
    result = subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


class FixedContractTests(unittest.TestCase):
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
                ),
                rt.Artifact(
                    "awid-service",
                    "aweb",
                    "AWID service",
                    ("pypi:awid-service",),
                    "awid/pyproject.toml",
                ),
                rt.Artifact(
                    "awid-image",
                    "aweb",
                    "AWID image",
                    ("ghcr.io/awebai/awid",),
                    "awid/pyproject.toml",
                    platforms=rt.OCI_PLATFORMS,
                    bundled_inputs=("server-source",),
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
                ),
                rt.Artifact(
                    "channel-plugin",
                    "aweb",
                    "channel plugin",
                    ("npm:@awebai/claude-channel",),
                    "channel/package.json",
                    bundled_inputs=("channel-core",),
                ),
                rt.Artifact(
                    "pi-extension",
                    "aweb",
                    "Pi extension",
                    ("npm:@awebai/pi",),
                    "pi-extension/package.json",
                    bundled_inputs=("channel-core",) + rt.SKILL_SOURCES,
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
                ),
                rt.Artifact(
                    "a2a-gateway-image",
                    "aweb",
                    "a2a-gateway image",
                    ("ghcr.io/awebai/a2a-gateway",),
                    "equals:server/pyproject.toml",
                    platforms=rt.OCI_PLATFORMS,
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
            "first_release_correction_pending": True,
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
        selection[0] = dataclasses.replace(selection[0], moves=False)
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
            dataclasses.replace(item, moves=False)
            if item.name == "ac-image"
            else item
            for item in original.artifacts
        )
        with self.assertRaisesRegex(rt.ValidationError, "production deployment"):
            self.card(artifacts=ac_not_moving)
        with self.assertRaisesRegex(rt.ValidationError, "first release correction"):
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
        return rt.prepare(
            repo_root or self.aweb,
            self._environment(**overrides),
            registry_base="http://127.0.0.1:9",
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
        gate = Path(self.tmp.name) / "gate.py"
        gate.write_text(
            "import json\n"
            'print(json.dumps({"suites": ["make-test", "cli-e2e"], '
            '"reference": "fixture-gate.log"}))\n'
        )
        self.gate_command = (sys.executable, str(gate))

    def _prepare(self, **overrides: str):
        environment = {"PURPOSE": "fixture release", "COMPAT_BREAK": "none"}
        environment.update(overrides)
        return rt.prepare(
            self.aweb,
            environment,
            registry_base=self.registry,
            gate_command=self.gate_command,
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
        self.assertTrue(card.first_release_correction_pending)
        stored = rt.read_card(self.aweb)
        self.assertEqual(stored, card)
        for remote, listing in before.items():
            self.assertEqual(git("ls-remote", str(remote), cwd=self.aweb), listing)
        for repo in (self.aweb, self.ac):
            self.assertEqual(git("status", "--porcelain", cwd=repo), "")

    def test_present_versions_are_excluded_from_the_move_set(self) -> None:
        from urllib.parse import quote

        _PresenceHandler.present[
            "/" + quote("pypi:awid-service", safe="") + "/0.5.16"
        ] = {"state": "present", "version": "0.5.16", "digest": DIGEST}
        card = self._prepare()
        moves = {item.name: item.moves for item in card.artifacts}
        self.assertFalse(moves["awid-service"])
        self.assertTrue(moves["aweb-server"])

    def test_registry_version_conflict_stops_naming_it(self) -> None:
        from urllib.parse import quote

        _PresenceHandler.present[
            "/" + quote("pypi:awid-service", safe="") + "/0.5.16"
        ] = {"state": "present", "version": "0.5.99", "digest": DIGEST}
        with self.assertRaises(rt.ObservationMalformed) as caught:
            self._prepare()
        self.assertIn("same-version conflict", str(caught.exception))
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

    def test_gate_failure_leaves_no_card(self) -> None:
        gate = Path(self.tmp.name) / "failing-gate.py"
        gate.write_text("raise SystemExit(1)\n")
        with self.assertRaises(rt.CommandFailed):
            rt.prepare(
                self.aweb,
                {"PURPOSE": "fixture release", "COMPAT_BREAK": "none"},
                registry_base=self.registry,
                gate_command=(sys.executable, str(gate)),
                timeout=30,
            )
        with self.assertRaises(rt.CardUnavailable):
            rt.read_card(self.aweb)

    def test_retry_reuses_only_byte_identical_material(self) -> None:
        first = self._prepare()
        second = self._prepare()
        self.assertEqual(first, second)
        with self.assertRaises(rt.MaterialMismatch):
            self._prepare(PURPOSE="a different purpose")



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


if __name__ == "__main__":
    unittest.main()
