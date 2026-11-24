#!/usr/bin/env python3
"""Focused contracts for the tag-only shipping surface."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest
import zipfile
from unittest.mock import patch
from email.message import Message
from pathlib import Path

from fixture_repo import fixture_env, init_fixture_repo, run_fixture

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CANDIDATE = load("release_candidate", "scripts/release_candidate.py")
PUBLISH = load("publish_release", "scripts/publish_release.py")
VERSIONS = sys.modules["release_versions"]


def command(root: Path, *argv: str) -> str:
    return subprocess.check_output(argv, cwd=root, text=True, env=fixture_env()).strip()


class TagContractTest(unittest.TestCase):
    def test_gateway_failure_cleanup_preserves_stderr_before_removal(self):
        source = (ROOT / "scripts/e2e-a2a-gateway-docker.sh").read_text()
        cleanup = source[source.index("cleanup() {"):source.index("\ntrap cleanup EXIT")]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "runtime"
            runtime.mkdir()
            calls = root / "docker-calls"
            docker = root / "docker"
            docker.write_text('#!/bin/bash\nprintf "%s\\n" "$*" >> "$DOCKER_CALLS"\n'
                              'case "$1" in\ninspect) echo running;;\n'
                              'logs) echo gateway-stdout; echo gateway-stderr >&2;;\nesac\n')
            docker.chmod(0o755)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                       DOCKER_CALLS=str(calls), TMP_ROOT=str(runtime),
                       GATEWAY_CONTAINER="fixture-gateway", GATEWAY_IMAGE="fixture-image",
                       PROJECT="fixture-project", ENV_FILE="fixture.env", COMPOSE_FILE="fixture.yml")
            result = run_fixture(["bash", "-c", "set -euo pipefail\nfail=1; pass=0\n" + cleanup + "\ncleanup"],
                                    env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn("gateway-stdout", result.stdout)
            self.assertIn("gateway-stderr", result.stdout)
            operations = calls.read_text().splitlines()
            self.assertLess(operations.index("logs fixture-gateway"),
                            operations.index("rm -f fixture-gateway"))
            self.assertFalse(runtime.exists())

    def test_federation_wheel_mode_accepts_rc_before_docker_build(self):
        # Execute the real journey's input checks; intercept only Docker so no
        # service, network or registry is used by this focused regression.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bind = root / "bind"
            bind.mkdir()
            binary = root / "docker"
            reached = root / "build-reached"
            binary.write_text('#!/bin/bash\nif [[ "$1" == compose && " $* " == *" build "* ]]; then\n'
                              '  echo build > "$BUILD_REACHED"; exit 86\nfi\nexit 0\n')
            binary.chmod(0o755)
            for version in ("1.27.34rc1", "1.27.34", "1.27.34rc0", "1.27.34rcbad", "1.27.34-rc.1"):
                with self.subTest(version=version):
                    wheel = root / f"aweb-{version}-py3-none-any.whl"
                    wheel.write_bytes(b"validation-only fixture; Docker build is intercepted")
                    reached.unlink(missing_ok=True)
                    env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                               BUILD_REACHED=str(reached), AWEB_DOCKER_BIND_ROOT=str(bind),
                               AWEB_FED_E2E_SERVER_MODE="wheel", AWEB_FED_E2E_KEEP="0",
                               AWEB_FED_E2E_BUILD="1", AWEB_FED_E2E_MCP_VERSION="1.0.0")
                    for side in ("ALPHA", "BETA"):
                        env[f"AWEB_{side}_WHEEL"] = str(wheel)
                        env[f"AWEB_{side}_WHEEL_SHA256"] = hashlib.sha256(wheel.read_bytes()).hexdigest()
                        env[f"AWEB_{side}_VERSION"] = version
                    result = run_fixture(["bash", str(ROOT / "scripts/e2e-oss-federation.sh")],
                                            env=env, text=True, capture_output=True)
                    if version in ("1.27.34rc1", "1.27.34"):
                        self.assertTrue(reached.exists(), result.stdout + result.stderr)
                        self.assertEqual(result.returncode, 86, result.stdout + result.stderr)
                    else:
                        self.assertFalse(reached.exists(), result.stdout + result.stderr)
                        self.assertIn("wheel version", result.stderr)
                        self.assertNotEqual(result.returncode, 0)

    def test_next_patch_version_ignores_rc_tags(self):
        temporary, root = self.repository()
        self.addCleanup(temporary.cleanup)
        command(root, "git", "tag", "server-v1.2.3")
        command(root, "git", "tag", "server-v99.0.0rc10")
        self.assertEqual(command(root, sys.executable, str(ROOT / "scripts/next_tag_version.py"),
                                 "server-v"), "1.2.4")

    def repository(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        init_fixture_repo(root)
        command(root, "git", "config", "user.name", "test")
        command(root, "git", "config", "user.email", "test@example.com")
        (root / "server").mkdir()
        (root / "server/pyproject.toml").write_text(
            '[project]\nname = "aweb"\nversion = "1.2.3"\n', encoding="utf-8"
        )
        (root / "awid").mkdir()
        (root / "awid/pyproject.toml").write_text(
            '[project]\nname = "awid-service"\nversion = "2.3.4"\n', encoding="utf-8"
        )
        (root / "naapp-contracts").mkdir()
        (root / "naapp-contracts/pyproject.toml").write_text(
            '[project]\nname = "aweb-naapp-contracts"\nversion = "0.1.0"\n', encoding="utf-8"
        )
        (root / "naapp-contracts/testing").mkdir()
        (root / "naapp-contracts/testing/pyproject.toml").write_text(
            '[project]\nname = "aweb-naapp-contracts-testing"\nversion = "0.1.0"\n', encoding="utf-8"
        )
        for directory, version in (
            ("channel", "3.4.5"),
            ("pi-extension", "4.5.6"),
            ("packages/claude-skills", "5.6.7"),
        ):
            (root / directory).mkdir(parents=True)
            (root / directory / "package.json").write_text(
                json.dumps({"name": directory, "version": version}) + "\n",
                encoding="utf-8",
            )
        command(root, "git", "add", ".")
        # Build a real RC tree and its version-only final, rather than relying
        # on the now-refused final-without-RC path in neighboring tests.
        manifests = [root / path for path in ("server/pyproject.toml", "awid/pyproject.toml",
                                             "naapp-contracts/pyproject.toml", "naapp-contracts/testing/pyproject.toml")]
        stable = {path: path.read_text() for path in manifests}
        for path in manifests:
            value = stable[path]
            import re
            path.write_text(re.sub(r'(version = "[^"]+)(")', r'\g<1>rc1\2', value))
        command(root, "git", "add", ".")
        command(root, "git", "commit", "-qm", "RC")
        for tag in ("server-v1.2.3rc1", "awid-service-v2.3.4rc1", "aweb-naapp-contracts-v0.1.0rc1", "aw-v1.2.3-rc.1"):
            command(root, "git", "tag", tag)
        for path, value in stable.items():
            path.write_text(value)
        command(root, "git", "add", ".")
        command(root, "git", "commit", "-qm", "candidate")
        return temporary, root

    def test_manifest_tags_must_match_the_tagged_commit(self):
        temporary, root = self.repository()
        self.addCleanup(temporary.cleanup)
        source, versions = CANDIDATE.validate_tags(
            root, ["server-v1.2.3", "awid-service-v2.3.4", "aweb-naapp-contracts-v0.1.0", "channel-v3.4.5"]
        )
        self.assertEqual(len(source), 40)
        self.assertEqual(versions["server-v"], "1.2.3")
        self.assertEqual(versions["aweb-naapp-contracts-v"], "0.1.0")
        with self.assertRaisesRegex(CANDIDATE.CandidateRefusal, "does not match"):
            CANDIDATE.validate_tags(root, ["server-v1.2.4"])

    def test_publisher_reads_version_from_the_tag_not_current_head(self):
        temporary, root = self.repository()
        self.addCleanup(temporary.cleanup)
        command(root, "git", "tag", "-a", "server-v1.2.3", "-m", "tested")
        (root / "server/pyproject.toml").write_text(
            '[project]\nname = "aweb"\nversion = "9.9.9"\n', encoding="utf-8"
        )
        command(root, "git", "add", ".")
        command(root, "git", "commit", "-qm", "later")
        prefix, version, source = PUBLISH.tag_identity(root, "server-v1.2.3")
        self.assertEqual((prefix, version), ("server-v", "1.2.3"))
        self.assertNotEqual(source, command(root, "git", "rev-parse", "HEAD"))

    def test_registry_image_rc_tag_is_bound_to_the_awid_manifest(self):
        # The registry image lane carries rc versions in awid's Python spelling;
        # the other image lanes keep final-only tags.
        self.assertEqual(VERSIONS.tag_parts("awid-v0.5.40rc2"), ("awid-v", "0.5.40rc2"))
        for tag in ("awid-v0.5.40-rc.2", "awid-v0.5.40rc0", "a2a-gw-v1.2.3rc1"):
            with self.subTest(tag=tag), self.assertRaises(VERSIONS.VersionRefusal):
                VERSIONS.tag_parts(tag)
        temporary, root = self.repository()
        self.addCleanup(temporary.cleanup)
        manifest = root / "awid" / "pyproject.toml"
        import re
        manifest.write_text(re.sub(r'version = "[^"]+"', 'version = "2.3.4rc2"', manifest.read_text()))
        command(root, "git", "commit", "-qam", "registry rc")
        command(root, "git", "tag", "awid-v2.3.4rc2")
        self.assertEqual(PUBLISH.tag_identity(root, "awid-v2.3.4rc2")[:2], ("awid-v", "2.3.4rc2"))
        command(root, "git", "tag", "awid-v2.3.4rc3")
        with self.assertRaisesRegex(PUBLISH.PublishRefusal, "does not match"):
            PUBLISH.tag_identity(root, "awid-v2.3.4rc3")

    def test_python_rc_tags_preserve_manifest_equality(self):
        temporary, root = self.repository()
        self.addCleanup(temporary.cleanup)
        for path, version in (("server", "1.2.3rc1"), ("awid", "2.3.4rc2"),
                              ("naapp-contracts", "0.1.0rc1"), ("naapp-contracts/testing", "0.1.0rc1")):
            manifest = root / path / "pyproject.toml"
            value = manifest.read_text()
            import re
            manifest.write_text(re.sub(r'version = "[^"]+"', f'version = "{version}"', value))
        command(root, "git", "commit", "-qam", "RC versions")
        for tag in command(root, "git", "tag", "--list").splitlines():
            command(root, "git", "tag", "-d", tag)
        tags = ["server-v1.2.3rc1", "awid-service-v2.3.4rc2", "aweb-naapp-contracts-v0.1.0rc1", "aw-v1.2.3-rc.1"]
        _source, versions = CANDIDATE.validate_tags(root, tags)
        self.assertEqual(versions["server-v"], "1.2.3rc1")
        for tag in tags:
            command(root, "git", "tag", tag)
            self.assertEqual(PUBLISH.tag_identity(root, tag)[1], VERSIONS.tag_parts(tag)[1])
        with self.assertRaisesRegex(CANDIDATE.CandidateRefusal, "does not match"):
            CANDIDATE.validate_tags(root, ["server-v1.2.3rc2"])

    def test_rc_spelling_and_positive_number_are_strict(self):
        for tag in ("server-v1.2.3rc0", "server-v1.2.3rc01", "server-v1.2.3-rc.1",
                    "aw-v1.2.3rc1", "aw-v1.2.3-rc.0", "aw-v1.2.3-rc.01",
                    "server-v01.2.3rc1", "aw-v1.2.3-beta.1", "channel-v1.2.3-rc.1"):
            with self.subTest(tag=tag), self.assertRaisesRegex(VERSIONS.VersionRefusal, "unsupported"):
                VERSIONS.tag_parts(tag)

    def test_final_without_prior_rc_is_accepted_by_candidate_and_publisher(self):
        # One gate qualifies the exact tree that is tagged; no published RC is required.
        for tag in ("server-v1.2.3", "awid-service-v2.3.4", "aweb-naapp-contracts-v0.1.0", "aw-v1.2.3"):
            with self.subTest(tag=tag):
                temporary, root = self.repository()
                self.addCleanup(temporary.cleanup)
                for rc_tag in command(root, "git", "tag", "--list", "*rc*").splitlines():
                    command(root, "git", "tag", "-d", rc_tag)
                with self.subTest(entry="candidate"):
                    _source, versions = CANDIDATE.validate_tags(root, [tag])
                    self.assertEqual(versions[VERSIONS.tag_parts(tag)[0]], VERSIONS.tag_parts(tag)[1])
                command(root, "git", "tag", tag)
                with self.subTest(entry="publisher"):
                    self.assertEqual(PUBLISH.tag_identity(root, tag)[1], VERSIONS.tag_parts(tag)[1])

    def test_pi_publisher_requires_its_declared_aw_floor_to_be_public(self):
        temporary, root = self.repository()
        self.addCleanup(temporary.cleanup)
        (root / "pi-extension/package.json").write_text(
            json.dumps(
                {
                    "name": "@awebai/pi",
                    "version": "4.5.6",
                    "dependencies": {"@awebai/aw": "^1.22.1"},
                }
            )
            + "\n",
            encoding="utf-8",
        )
        original = PUBLISH.request_json
        self.addCleanup(setattr, PUBLISH, "request_json", original)
        observed = []

        def present(url):
            observed.append(url)
            return 200, {"version": "1.22.1"}

        PUBLISH.request_json = present
        self.assertEqual(PUBLISH.require_pi_aw_floor(root), "1.22.1")
        self.assertEqual(observed, ["https://registry.npmjs.org/%40awebai%2Faw/1.22.1"])

        PUBLISH.request_json = lambda _url: (404, {})
        with self.assertRaisesRegex(PUBLISH.PublishRefusal, "not public"):
            PUBLISH.require_pi_aw_floor(root, timeout_seconds=0)


class PypiLaneContractTest(unittest.TestCase):
    def test_each_pypi_lane_publishes_the_package_its_manifest_names(self):
        import tomllib

        for prefix, (_needs_awid, packages) in PUBLISH.PYPI_LANES.items():
            manifest = PUBLISH.MANIFESTS[prefix]
            primary = Path(manifest).parent.as_posix()
            self.assertIn(primary, [directory for _, directory in packages], prefix)
            self.assertEqual(CANDIDATE.MANIFESTS[prefix], manifest, prefix)
            lockstep = [f"{directory}/pyproject.toml" for _, directory in packages if directory != primary]
            self.assertEqual(CANDIDATE.LOCKSTEP.get(prefix, []), lockstep, prefix)
            for package, directory in packages:
                project = tomllib.loads((ROOT / directory / "pyproject.toml").read_text(encoding="utf-8"))["project"]
                self.assertEqual(project["name"], package, prefix)

    def test_the_contracts_lane_waits_for_awid_then_builds_the_contracts(self):
        temporary, root = TagContractTest.repository(self)
        self.addCleanup(temporary.cleanup)
        originals = (PUBLISH.run, PUBLISH.request_json, os.environ.get("UV_PUBLISH_TOKEN"))

        def restore():
            PUBLISH.run, PUBLISH.request_json = originals[0], originals[1]
            if originals[2] is None:
                os.environ.pop("UV_PUBLISH_TOKEN", None)
            else:
                os.environ["UV_PUBLISH_TOKEN"] = originals[2]

        self.addCleanup(restore)
        os.environ["UV_PUBLISH_TOKEN"] = "test-token-not-a-secret"
        asked: list[str] = []
        built: list[tuple[str, ...]] = []

        class Built(Exception):
            pass

        def request_json(url):
            asked.append(url)
            return 200, {}

        def run(_root, *argv, **_kwargs):
            built.append(argv)
            raise Built

        PUBLISH.request_json, PUBLISH.run = request_json, run
        with self.assertRaises(Built):
            PUBLISH.publish_pypi(root, "aweb-naapp-contracts-v", "0.1.0")
        self.assertEqual(asked, ["https://pypi.org/pypi/awid-service/2.3.4/json"])
        self.assertEqual(built[0][:2], ("uv", "build"))
        self.assertEqual(built[0][-1], "naapp-contracts")


    def _recording_publisher(self):
        originals = (PUBLISH.run, PUBLISH.request_json, os.environ.get("UV_PUBLISH_TOKEN"))

        def restore():
            PUBLISH.run, PUBLISH.request_json = originals[0], originals[1]
            if originals[2] is None:
                os.environ.pop("UV_PUBLISH_TOKEN", None)
            else:
                os.environ["UV_PUBLISH_TOKEN"] = originals[2]

        self.addCleanup(restore)
        os.environ["UV_PUBLISH_TOKEN"] = "test-token-not-a-secret"
        commands: list[tuple[str, ...]] = []

        def run(_root, *argv, **_kwargs):
            commands.append(argv)
            return ""

        PUBLISH.run, PUBLISH.request_json = run, lambda _url: (200, {})
        return commands

    def test_the_contracts_lane_publishes_the_contracts_then_their_testing_package(self):
        temporary, root = TagContractTest.repository(self)
        self.addCleanup(temporary.cleanup)
        commands = self._recording_publisher()
        PUBLISH.publish_pypi(root, "aweb-naapp-contracts-v", "0.1.0")
        built = [argv[-1] for argv in commands if argv[:2] == ("uv", "build")]
        inspected = [argv[argv.index("--package") + 1] for argv in commands if "inspect-staged" in argv]
        self.assertEqual(built, ["naapp-contracts", "naapp-contracts/testing"])
        self.assertEqual(inspected, ["aweb-naapp-contracts", "aweb-naapp-contracts-testing"])

    def test_a_lane_package_at_another_version_refuses_the_tag(self):
        temporary, root = TagContractTest.repository(self)
        self.addCleanup(temporary.cleanup)
        (root / "naapp-contracts/testing/pyproject.toml").write_text(
            '[project]\nname = "aweb-naapp-contracts-testing"\nversion = "0.0.9"\n', encoding="utf-8"
        )
        command(root, "git", "commit", "-qam", "drifted")
        with self.assertRaisesRegex(CANDIDATE.CandidateRefusal, "naapp-contracts/testing"):
            CANDIDATE.validate_tags(root, ["aweb-naapp-contracts-v0.1.0"])
        command(root, "git", "tag", "-a", "aweb-naapp-contracts-v0.1.0", "-m", "tested")
        with self.assertRaisesRegex(PUBLISH.PublishRefusal, "naapp-contracts/testing"):
            PUBLISH.tag_identity(root, "aweb-naapp-contracts-v0.1.0")


class CandidateBrowserImageContractTest(unittest.TestCase):
    def test_integration_image_installs_the_locked_headless_shell(self):
        dockerfile = (ROOT / "candidate-gate/Dockerfile").read_text()
        commands = " ".join(dockerfile.replace("\\\n", " ").split())
        self.assertIn("ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright", dockerfile)
        sync = "uv sync --frozen --project naapp-lib"
        install = (
            "uv run --frozen --no-sync --project naapp-lib "
            "playwright install --with-deps --only-shell chromium"
        )
        self.assertIn(sync, commands)
        self.assertIn(install, commands)
        self.assertLess(commands.index(sync), commands.index(install))
        self.assertIn("chmod -R a+rX /opt/ms-playwright", commands)
        for project in ("awid", "naapp-lib"):
            self.assertIn(f"COPY {project} {project}", dockerfile)
        wrapper = (ROOT / "scripts/candidate-docker-gate.sh").read_text()
        self.assertIn('-f "$checkout/candidate-gate/Dockerfile" -t "$IMAGE" "$checkout"', wrapper)

    def test_integration_home_override_keeps_the_image_browser_path(self):
        wrapper = (ROOT / "scripts/candidate-docker-gate.sh").read_text()
        runner = wrapper.split("set +e\ndocker run --rm --init", 1)[1]
        runner = runner.split('bash scripts/candidate-suite.sh "$pending"', 1)[0]
        self.assertIn('-e HOME="$checkout/.candidate-home"', runner)
        self.assertIn("-e PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright", runner)


class NpmRcContractTest(unittest.TestCase):
    def test_candidate_declares_staged_final_before_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            init_fixture_repo(root)
            command(root, "git", "config", "user.name", "fixture")
            command(root, "git", "config", "user.email", "fixture@example.test")
            (root / "scripts").mkdir()
            gate = root / "scripts/candidate-docker-gate.sh"
            # Replace only the Docker qualification boundary. This checks tag
            # creation and its CLI_VERSION input, not a successful real gate.
            gate.write_text('#!/bin/sh\n[ "$CLI_VERSION" = 1.2.3 ]\n')
            gate.chmod(0o755)
            package = root / "cli/go/npm/aw/package.json"
            package.parent.mkdir(parents=True)
            package.write_text('{"name":"@awebai/aw","version":"1.2.3-rc.1"}')
            command(root, "git", "add", ".")
            command(root, "git", "commit", "-qm", "RC")
            command(root, "git", "tag", "aw-v1.2.3-rc.1")
            package.write_text('{"name":"@awebai/aw","version":"1.2.3"}')
            command(root, "git", "commit", "-qam", "final")
            command(root, "git", "remote", "add", "origin", ".")
            result = run_fixture(
                [sys.executable, str(ROOT / "scripts/release_candidate.py"),
                 "--stage-aw-final", "aw-v1.2.3"],
                cwd=root, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            message = command(root, "git", "tag", "-l", "aw-v1.2.3", "--format=%(contents)")
            self.assertIn("Npm-Publish-Channel: next", message)

    def test_exact_publisher_routes_staged_rc_to_next_and_final_to_latest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            npm = root / "npm"
            npm.write_text('#!/bin/sh\nset -eu\n'
                           'test "$NPM_CONFIG_UPDATE_NOTIFIER" = false\n'
                           'test "$npm_config_update_notifier" = false\n'
                           'printf "%s\\n" "$@" > "$CAPTURE_NPM"\n')
            npm.chmod(0o755)
            environment = {**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"], "CAPTURE_NPM": str(root / "args"),
                           "NPM_CONFIG_UPDATE_NOTIFIER": "true", "npm_config_update_notifier": "true"}
            for version, expected, staged in (("1.2.3-rc.1", "next", False), ("1.2.3", "latest", False), ("1.2.3", "next", True)):
                archive = root / "staged.tgz"
                raw = json.dumps({"name": "@awebai/aw", "version": version}).encode()
                with tarfile.open(archive, "w:gz") as tar:
                    entry = tarfile.TarInfo("package/package.json")
                    entry.size = len(raw)
                    tar.addfile(entry, io.BytesIO(raw))
                result = run_fixture(["bash", "scripts/npm-exact-publish.sh", "publish-exact", "--tgz", str(archive)] + (["--staged-final"] if staged else []),
                                        cwd=ROOT, env=environment, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                args = (root / "args").read_text().splitlines()
                self.assertEqual(args[args.index("--tag") + 1], expected)
                self.assertEqual(args[1], str(archive.resolve()))

    def test_synced_downstream_publisher_routes_all_seven_packages(self):
        # Real publisher, npm and platform archives; uploads stay inside an
        # owned loopback registry, including the new exact readback boundary.
        from test_npm_readback import Registry
        with tempfile.TemporaryDirectory() as directory, Registry().serve() as registry:
            root = Path(directory)
            npm_root, artifacts = root / "npm", root / "artifacts"
            npm_root.mkdir()
            artifacts.mkdir()
            init_fixture_repo(root)
            # A release checkout has a commit: the publisher records it as each package's gitHead.
            command(root, "git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.test",
                    "commit", "--allow-empty", "-qm", "source")
            shutil.copyfile(ROOT / "cli/go/npm/publish.sh", npm_root / "publish.sh")
            shutil.copyfile(ROOT / "cli/go/npm/readback.py", npm_root / "readback.py")
            helper = ROOT / "cli/go/npm/publication.py"
            if helper.exists():
                shutil.copyfile(helper, npm_root / helper.name)
            platforms = {"linux_amd64": "linux-x64", "linux_arm64": "linux-arm64",
                         "darwin_amd64": "darwin-x64", "darwin_arm64": "darwin-arm64",
                         "windows_amd64": "windows-x64", "windows_arm64": "windows-arm64"}
            for package in ["aw"] + ["aw-" + platform for platform in platforms.values()]:
                (npm_root / package).mkdir()
                shutil.copyfile(ROOT / "cli/go/npm" / package / "package.json", npm_root / package / "package.json")
            for platform in platforms:
                windows = platform.startswith("windows")
                binary_names = ["aw.exe", "aweb-a2a-gw.exe"] if windows else ["aw", "aweb-a2a-gw"]
                if windows:
                    with zipfile.ZipFile(artifacts / (platform + ".zip"), "w") as archive:
                        for name in binary_names:
                            archive.writestr(name, "fixture binary")
                else:
                    with tarfile.open(artifacts / (platform + ".tar.gz"), "w:gz") as archive:
                        for name in binary_names:
                            data = b"fixture binary"
                            info = tarfile.TarInfo(name)
                            info.size = len(data)
                            archive.addfile(info, io.BytesIO(data))
            (root / "bin").mkdir()
            if sys.platform == "darwin":
                # The production workflow runs Ubuntu; use GNU sed for that
                # same existing publisher on the author's macOS host.
                (root / "bin/sed").symlink_to(shutil.which("gsed") or "/usr/bin/sed")
            config = root / "npmrc"
            config.write_text(f"registry={registry.url}\n//{registry.url.split('//')[1]}/:_authToken=disposable-fixture\n")
            origin = root / "origin.git"
            command(root, "git", "init", "--bare", "-q", str(origin))
            command(root, "git", "remote", "add", "origin", str(origin))
            for version, expected, staged in (
                ("1.2.3-rc.1", "next", False), ("1.2.3", "latest", False),
                ("1.2.3", "next", True), ("1.2.4", "next", "tag"),
                ("1.2.5", "next", "checkout"), ("1.2.6", "latest", "ci-final"),
                ("1.2.7-rc.1", "next", "ci-rc"), ("1.2.8", None, "ci-missing"),
            ):
                registry.published.clear()
                environment = {k: v for k, v in os.environ.items() if not k.startswith(("NPM_", "npm_", "NODE_AUTH"))}
                environment.update(PATH=str(root / "bin") + os.pathsep + os.environ["PATH"],
                                   GITHUB_REF_NAME="v" + version, GITHUB_ACTIONS="false",
                                   NPM_CONFIG_USERCONFIG=str(config), NPM_CONFIG_REGISTRY=registry.url)
                tag = "v" + version
                if staged in ("tag", "checkout", "ci-final", "ci-rc"):
                    command(root, "git", "config", "user.name", "fixture")
                    command(root, "git", "config", "user.email", "fixture@example.test")
                    command(root, "git", "commit", "--allow-empty", "-qm", "fixture")
                    marker = "\n\nNpm-Publish-Channel: next" if staged in ("tag", "checkout") else ""
                    command(root, "git", "tag", "-a", tag, "-m", "release" + marker)
                if staged in ("checkout", "ci-final", "ci-rc"):
                    command(root, "git", "push", "-q", "origin", "refs/tags/" + tag)
                    if staged == "checkout":
                        # Actual checkout@v4 sequence from release run41529254431:
                        # its commit-specific fetch replaces the fetched annotation.
                        commit = command(root, "git", "rev-parse", tag + "^{commit}")
                        command(root, "git", "fetch", "--force", "--no-tags", "origin",
                                "+" + commit + ":refs/tags/" + tag)
                        self.assertEqual(command(root, "git", "cat-file", "-t", "refs/tags/" + tag), "commit")
                if staged in ("checkout", "ci-final", "ci-rc", "ci-missing"):
                    environment["GITHUB_ACTIONS"] = "true"
                result = run_fixture(["bash", str(npm_root / "publish.sh")] + (["--staged-final"] if staged is True else []), env=environment,
                                        text=True, capture_output=True)
                if staged == "ci-missing":
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertEqual(registry.published, [], "missing CI tag reached npm")
                    continue
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(registry.published), 7)
                self.assertTrue(all(tags == {expected: version} for _, _, tags in registry.published), registry.published)
                if staged == "checkout":
                    self.assertEqual(command(root, "git", "cat-file", "-t", "refs/tags/" + tag), "tag")
                wrapper = json.loads((npm_root / "aw/package.json").read_text())
                self.assertEqual(set(wrapper["optionalDependencies"].values()), {version})

    def test_upstream_tag_guard_accepts_only_final_or_aw_rc_spelling(self):
        workflow = (ROOT / ".github/workflows/aw-release.yml").read_text()
        guard = next(line.strip() for line in workflow.splitlines() if '[[ "$version" =~' in line)
        for version, accepted in (("1.2.3-rc.1", True), ("1.2.3", True), ("1.2.3rc1", False), ("1.2.3-rc.0", False)):
            result = run_fixture(["bash", "-c", 'version="$1"\n' + guard, "guard", version])
            self.assertEqual(result.returncode == 0, accepted, version)

    def test_aw_workflow_checks_rc_and_final_tags_before_downstream_clone(self):
        # Execute the actual workflow step. Only the first external side effect
        # (downstream clone) is intercepted; local Git inspection stays real.
        workflow = (ROOT / ".github/workflows/aw-release.yml").read_text()
        shell = textwrap.dedent(workflow.split("        run: |\n", 1)[1])
        for case in ("rc", "final", "final-without-rc"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                init_fixture_repo(root)
                command(root, "git", "config", "user.name", "test")
                command(root, "git", "config", "user.email", "test@example.com")
                (root / "scripts").mkdir()
                for script in ("release_versions.py", "publish_release.py"):
                    shutil.copyfile(ROOT / "scripts" / script, root / "scripts" / script)
                (root / "cli/go/npm/aw").mkdir(parents=True)
                shutil.copyfile(ROOT / "cli/go/npm/publication.py", root / "cli/go/npm/publication.py")
                manifest = root / "cli/go/npm/aw/package.json"
                manifest.write_text(json.dumps({"name": "@awebai/aw", "version": "1.36.48-rc.1"}))
                (root / "cli/go/implementation.go").write_text("package main\n")
                command(root, "git", "add", ".")
                command(root, "git", "commit", "-qm", "RC")
                if case != "final-without-rc":
                    command(root, "git", "tag", "aw-v1.36.48-rc.1")
                if case != "rc":
                    manifest.write_text(json.dumps({"name": "@awebai/aw", "version": "1.36.48"}))
                    command(root, "git", "commit", "-qam", "final")
                    command(root, "git", "tag", "aw-v1.36.48")
                side_effect = root / "downstream-side-effect"
                with tempfile.TemporaryDirectory() as binaries:
                    spy = Path(binaries) / "git"
                    spy.write_text('#!/bin/sh\nif [ "$1" = clone ]; then\n'
                                   '  printf "clone\\n" > "$SIDE_EFFECT"\n  exit 86\nfi\n'
                                   'exec "$REAL_GIT" "$@"\n')
                    spy.chmod(0o755)
                    environment = {**os.environ, "REAL_GIT": shutil.which("git"),
                                   "PATH": binaries + os.pathsep + os.environ["PATH"],
                                   "SIDE_EFFECT": str(side_effect), "RUNNER_TEMP": str(root / "runner"),
                                   "AW_REPO_TOKEN": "test-boundary-not-a-secret",
                                   "GITHUB_REF_NAME": "aw-v1.36.48-rc.1" if case == "rc" else "aw-v1.36.48"}
                    result = run_fixture(["bash", "-c", shell], cwd=root, env=environment,
                                            text=True, capture_output=True)
                # One gate qualifies the tagged tree; a final needs no prior RC.
                self.assertEqual(result.returncode, 86, result.stderr)
                self.assertEqual(side_effect.read_text(), "clone\n")

    def test_aw_workflow_carries_staged_final_declaration_to_distribution_tag(self):
        workflow = (ROOT / ".github/workflows/aw-release.yml").read_text()
        shell = textwrap.dedent(workflow.split("        run: |\n", 1)[1])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            upstream, seed, remote = root / "upstream", root / "seed", root / "remote.git"
            for repo in (upstream, seed):
                repo.mkdir()
                init_fixture_repo(repo)
                command(repo, "git", "config", "user.name", "fixture")
                command(repo, "git", "config", "user.email", "fixture@example.test")
            (seed / ".github").mkdir()
            (seed / ".github/fixture").write_text("keep distribution workflows\n")
            command(seed, "git", "add", ".")
            command(seed, "git", "commit", "-qm", "distribution")
            command(root, "git", "clone", "--bare", str(seed), str(remote))
            (upstream / "scripts").mkdir()
            for name in ("publish_release.py", "release_versions.py"):
                shutil.copyfile(ROOT / "scripts" / name, upstream / "scripts" / name)
            shutil.copytree(ROOT / "cli/go/npm", upstream / "cli/go/npm",
                            ignore=shutil.ignore_patterns("__pycache__"))
            manifest = upstream / "cli/go/npm/aw/package.json"
            package = json.loads(manifest.read_text())
            package["version"] = "1.2.3-rc.1"
            manifest.write_text(json.dumps(package))
            command(upstream, "git", "add", ".")
            command(upstream, "git", "commit", "-qm", "RC")
            command(upstream, "git", "tag", "aw-v1.2.3-rc.1")
            package["version"] = "1.2.3"
            manifest.write_text(json.dumps(package))
            command(upstream, "git", "commit", "-qam", "final")
            command(upstream, "git", "tag", "-a", "aw-v1.2.3", "-m",
                    "staged final\n\nNpm-Publish-Channel: next")
            binaries = root / "bin"
            binaries.mkdir()
            spy = binaries / "git"
            spy.write_text('#!/usr/bin/env python3\nimport os,sys\nargs=sys.argv[1:]\n'
                           'if args[0]=="clone": args=["clone","--branch","main",os.environ["OWN_REMOTE"],args[-1]]\n'
                           'os.execv(os.environ["REAL_GIT"],[os.environ["REAL_GIT"],*args])\n')
            spy.chmod(0o755)
            (root / "runner").mkdir()
            env = {**os.environ, "PATH": str(binaries) + os.pathsep + os.environ["PATH"],
                   "REAL_GIT": shutil.which("git"), "OWN_REMOTE": str(remote),
                   "RUNNER_TEMP": str(root / "runner"), "GITHUB_REF_NAME": "aw-v1.2.3",
                   "AW_REPO_TOKEN": "fixture-not-a-secret"}
            result = run_fixture(["bash", "-c", shell], cwd=upstream, env=env,
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            annotation = command(root, "git", "--git-dir", str(remote), "tag", "-l", "v1.2.3", "--format=%(contents)")
            self.assertIn("Npm-Publish-Channel: next", annotation)
            self.assertTrue((root / "runner/aw/.github/fixture").exists())

    def test_dispatch_refuses_bad_rc_spellings(self):
        for version in ("1.2.3rc1", "1.2.3-rc.0", "1.2.3-rc.01", "01.2.3", "1.2.3-beta.1"):
            with self.subTest(version=version):
                result = run_fixture(["bash", "scripts/npm-exact-publish.sh", "validate-inputs", "--version", version],
                                        cwd=ROOT, text=True, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
        result = run_fixture(["bash", "scripts/npm-exact-publish.sh", "validate-inputs", "--version", "1.2.3-rc.1"],
                                cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)


class ReleaseStampContractTest(unittest.TestCase):
    def test_failed_go_build_is_not_masked_by_binary_inspection(self):
        with tempfile.TemporaryDirectory() as directory:
            fake_go = Path(directory) / "go"
            fake_go.write_text(
                "#!/usr/bin/env bash\n"
                "if [[ \"$1 $2\" == \"env GOVERSION\" ]]; then\n"
                "  printf 'go1.26.11\\n'\n"
                "  exit 0\n"
                "fi\n"
                "printf 'sentinel go build failure\\n' >&2\n"
                "exit 42\n",
                encoding="utf-8",
            )
            fake_go.chmod(0o755)
            environment = os.environ.copy()
            environment["GO_BINARY"] = str(fake_go)
            result = run_fixture(
                ["bash", "scripts/check-cli-release-vcs-stamps.sh"],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("sentinel go build failure", result.stderr)
        self.assertIn(
            "FAIL: clean release build failed for darwin/amd64 aw", result.stderr
        )
        self.assertNotIn("no such file or directory", result.stderr.lower())


if __name__ == "__main__":
    unittest.main()
