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
import re
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
                registry_base=self.registry,
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
            registry_base=self.registry,
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
'''


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

    @classmethod
    def tearDownClass(cls) -> None:
        cls.spool_server.shutdown()
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

    def _continue(self):
        return rt.continue_train(
            self.aweb,
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
        # Provider order: migrate before deploy before verify.
        provider = [
            line.split() for line in self.provider_log.read_text().splitlines()
        ]
        self.assertEqual(
            [line[0] for line in provider], ["migrate", "deploy", "verify"]
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

        for target, version in (("pypi:awid-service", "0.5.16"), ("pypi:aweb", "1.27.2")):
            _PresenceHandler.present["/" + quote(target, safe="") + f"/{version}"] = {
                "state": "present", "version": version, "digest": DIGEST,
            }
        card = self._prepare()
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

    def test_partial_prior_derivation_is_adopted_on_retry(self) -> None:
        self._prepare()
        failing = Path(self.tmp.name) / "failing-ac-gate.py"
        failing.write_text("raise SystemExit(1)\n")
        with self.assertRaises(rt.CommandFailed):
            rt.continue_train(
                self.aweb,
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
            rows.append(rt.ArtifactSelection(name=name, version="1.2.3", moves=moves))
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
        # aw-cli's next patch (1.34.4) is already served, so it does not move.
        _PresenceHandler.present[
            "/" + quote("github:awebai/aw:release", safe="") + "/1.34.4"
        ] = {"state": "present", "version": "1.34.4", "digest": DIGEST}
        card = rt.prepare(
            self.aweb,
            {"PURPOSE": "fixture", "COMPAT_BREAK": "none"},
            registry_base=self.registry,
            gate_command=(sys.executable, str(gate)),
            timeout=30,
        )
        del card
        invocations = gate_log.read_text().splitlines()
        self.assertEqual(len(invocations), 2)
        self.assertIn("compat-pairing", invocations[1])


class PrepareRealAdapterTests(_PipelineFixture):
    """prepare's sweep speaks the real per-kind read APIs when no fixture
    registry base is supplied - the shape the first real release runs."""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.api_server = ThreadingHTTPServer(("127.0.0.1", 0), _PublicApiHandler)
        cls.api_thread = threading.Thread(
            target=cls.api_server.serve_forever, daemon=True
        )
        cls.api_thread.start()
        base = f"http://127.0.0.1:{cls.api_server.server_port}"
        cls.adapter_bases = {"pypi": base, "npm": base, "ghcr": base, "github": base}

    @classmethod
    def tearDownClass(cls) -> None:
        cls.api_server.shutdown()
        cls.api_server.server_close()
        cls.api_thread.join(timeout=2)
        super().tearDownClass()

    def test_prepare_sweeps_through_the_per_kind_adapters(self) -> None:
        _PublicApiHandler.state = {
            "/pypi/awid-service/0.5.16/json": (200, {"info": {"version": "0.5.16"}}),
        }
        for repo in ("awebai/awid", "awebai/a2a-gateway", "awebai/ac"):
            _PublicApiHandler.state[
                f"/token?scope=repository:{repo}:pull&service=ghcr.io"
            ] = (200, {"token": "t"})
        card = rt.prepare(
            self.aweb,
            {"PURPOSE": "real-adapter sweep", "COMPAT_BREAK": "none"},
            bases=self.adapter_bases,
            gate_command=self.gate_command,
            timeout=30,
        )
        moves = {item.name: item.moves for item in card.artifacts}
        self.assertFalse(moves["awid-service"])
        self.assertTrue(moves["aweb-server"])
        self.assertTrue(moves["ac-image"])


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
        sha = "e" * 40
        log_dir = f"/tmp/aweb-release-gate-{sha}"
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
