#!/usr/bin/env python3
"""Focused contracts for the tag-only shipping surface."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest
import zipfile
from pathlib import Path


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
    return subprocess.check_output(argv, cwd=root, text=True).strip()


class TagContractTest(unittest.TestCase):
    def repository(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        command(root, "git", "init", "-q")
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
        (root / "naapp-lib").mkdir()
        (root / "naapp-lib/pyproject.toml").write_text(
            '[project]\nname = "aweb-naapp"\nversion = "0.1.0"\n', encoding="utf-8"
        )
        (root / "naapp-lib/testing").mkdir()
        (root / "naapp-lib/testing/pyproject.toml").write_text(
            '[project]\nname = "aweb-naapp-testing"\nversion = "0.1.0"\n', encoding="utf-8"
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
                                             "naapp-lib/pyproject.toml", "naapp-lib/testing/pyproject.toml")]
        stable = {path: path.read_text() for path in manifests}
        for path in manifests:
            value = stable[path]
            import re
            path.write_text(re.sub(r'(version = "[^"]+)(")', r'\g<1>rc1\2', value))
        command(root, "git", "add", ".")
        command(root, "git", "commit", "-qm", "RC")
        for tag in ("server-v1.2.3rc1", "awid-service-v2.3.4rc1", "aweb-naapp-v0.1.0rc1", "aw-v1.2.3-rc.1"):
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
            root, ["server-v1.2.3", "awid-service-v2.3.4", "aweb-naapp-v0.1.0", "channel-v3.4.5"]
        )
        self.assertEqual(len(source), 40)
        self.assertEqual(versions["server-v"], "1.2.3")
        self.assertEqual(versions["aweb-naapp-v"], "0.1.0")
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

    def test_python_rc_tags_preserve_manifest_equality(self):
        temporary, root = self.repository()
        self.addCleanup(temporary.cleanup)
        for path, version in (("server", "1.2.3rc1"), ("awid", "2.3.4rc2"),
                              ("naapp-lib", "0.1.0rc1"), ("naapp-lib/testing", "0.1.0rc1")):
            manifest = root / path / "pyproject.toml"
            value = manifest.read_text()
            import re
            manifest.write_text(re.sub(r'version = "[^"]+"', f'version = "{version}"', value))
        command(root, "git", "commit", "-qam", "RC versions")
        for tag in command(root, "git", "tag", "--list").splitlines():
            command(root, "git", "tag", "-d", tag)
        tags = ["server-v1.2.3rc1", "awid-service-v2.3.4rc2", "aweb-naapp-v0.1.0rc1", "aw-v1.2.3-rc.1"]
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

    def test_final_without_prior_rc_refuses_candidate_and_publisher(self):
        for tag in ("server-v1.2.3", "awid-service-v2.3.4", "aweb-naapp-v0.1.0", "aw-v1.2.3"):
            with self.subTest(tag=tag):
                temporary, root = self.repository()
                self.addCleanup(temporary.cleanup)
                for rc_tag in command(root, "git", "tag", "--list", "*rc*").splitlines():
                    command(root, "git", "tag", "-d", rc_tag)
                with self.subTest(entry="candidate"):
                    with self.assertRaisesRegex(CANDIDATE.CandidateRefusal, "final requires a prior RC"):
                        CANDIDATE.validate_tags(root, [tag])
                command(root, "git", "tag", tag)
                with self.subTest(entry="publisher"):
                    with self.assertRaisesRegex(PUBLISH.PublishRefusal, "final requires a prior RC"):
                        PUBLISH.tag_identity(root, tag)

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
            self.assertEqual(Path(manifest).parent.as_posix(), packages[0][1], prefix)
            self.assertEqual(CANDIDATE.MANIFESTS[prefix], manifest, prefix)
            lockstep = [f"{directory}/pyproject.toml" for _, directory in packages[1:]]
            self.assertEqual(CANDIDATE.LOCKSTEP.get(prefix, []), lockstep, prefix)
            for package, directory in packages:
                project = tomllib.loads((ROOT / directory / "pyproject.toml").read_text(encoding="utf-8"))["project"]
                self.assertEqual(project["name"], package, prefix)

    def test_the_aweb_naapp_lane_waits_for_awid_then_builds_naapp_lib(self):
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
            PUBLISH.publish_pypi(root, "aweb-naapp-v", "0.1.0")
        self.assertEqual(asked, ["https://pypi.org/pypi/awid-service/2.3.4/json"])
        self.assertEqual(built[0][:2], ("uv", "build"))
        self.assertEqual(built[0][-1], "naapp-lib")


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

    def test_the_aweb_naapp_lane_publishes_naapp_lib_then_its_testing_package(self):
        temporary, root = TagContractTest.repository(self)
        self.addCleanup(temporary.cleanup)
        commands = self._recording_publisher()
        PUBLISH.publish_pypi(root, "aweb-naapp-v", "0.1.0")
        built = [argv[-1] for argv in commands if argv[:2] == ("uv", "build")]
        inspected = [argv[argv.index("--package") + 1] for argv in commands if "inspect-staged" in argv]
        self.assertEqual(built, ["naapp-lib", "naapp-lib/testing"])
        self.assertEqual(inspected, ["aweb-naapp", "aweb-naapp-testing"])

    def test_a_lane_package_at_another_version_refuses_the_tag(self):
        temporary, root = TagContractTest.repository(self)
        self.addCleanup(temporary.cleanup)
        (root / "naapp-lib/testing/pyproject.toml").write_text(
            '[project]\nname = "aweb-naapp-testing"\nversion = "0.0.9"\n', encoding="utf-8"
        )
        command(root, "git", "commit", "-qam", "drifted")
        with self.assertRaisesRegex(CANDIDATE.CandidateRefusal, "naapp-lib/testing"):
            CANDIDATE.validate_tags(root, ["aweb-naapp-v0.1.0"])
        command(root, "git", "tag", "-a", "aweb-naapp-v0.1.0", "-m", "tested")
        with self.assertRaisesRegex(PUBLISH.PublishRefusal, "naapp-lib/testing"):
            PUBLISH.tag_identity(root, "aweb-naapp-v0.1.0")


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


class FinalPromotionContractTest(unittest.TestCase):
    def repository(self):
        temporary, root = TagContractTest.repository(self)
        self.addCleanup(temporary.cleanup)
        versions = {
            "awid": ("awid-service", "0.5.32rc1"),
            "naapp-lib": ("aweb-naapp", "0.4.1rc1"),
            "naapp-lib/testing": ("aweb-naapp-testing", "0.4.1rc1"),
            "server": ("aweb", "1.27.34rc1"),
        }
        for path, (name, version) in versions.items():
            dependencies = []
            if path == "server":
                dependencies = ['awid-service==0.5.32rc1', 'aweb-naapp[runtime]==0.4.1rc1; python_version >= "3.12"']
            elif path == "naapp-lib/testing":
                dependencies = ['aweb-naapp[hooks,runtime]==0.4.1rc1']
            # JSON strings are valid TOML basic strings here.
            (root / path / "pyproject.toml").write_text(
                f'[project]\nname = "{name}"\nversion = "{version}"\n'
                f'dependencies = {json.dumps(dependencies)}\n'
                '[project.scripts]\nentry = "aweb:main"\n'
            )
        for name in ("aw", "aw-linux-x64"):
            directory = root / "cli/go/npm" / name
            directory.mkdir(parents=True)
            manifest = {"name": "@awebai/" + name, "version": "1.36.48-rc.1"}
            if name == "aw":
                manifest["optionalDependencies"] = {"@awebai/aw-linux-x64": "1.36.48-rc.1"}
            (directory / "package.json").write_text(json.dumps(manifest))
        (root / "server/uv.lock").write_text('''version = 1
[[package]]
name = "aweb"
version = "1.27.34rc1"
source = { editable = "." }
dependencies = [{ name = "awid-service", version = "0.5.32rc1" }]
[package.metadata]
requires-dist = [{ name = "awid-service", specifier = "==0.5.32rc1" }]
[[package]]
name = "awid-service"
version = "0.5.32rc1"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.example/awid-0.5.32rc1.tar.gz", hash = "sha256:rc", size = 100 }
[[package]]
name = "unrelated"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.example/unrelated.tar.gz", hash = "sha256:unchanged", size = 100 }
''')
        (root / "cli/go/npm/aw/package-lock.json").write_text(json.dumps({
            "name": "@awebai/aw", "version": "1.36.48-rc.1", "lockfileVersion": 3,
            "packages": {
                "": {"name": "@awebai/aw", "version": "1.36.48-rc.1", "optionalDependencies": {"@awebai/aw-linux-x64": "1.36.48-rc.1"}},
                "node_modules/@awebai/aw-linux-x64": {"version": "1.36.48-rc.1", "resolved": "https://registry.example/rc.tgz", "integrity": "sha512:rc"},
            },
        }))
        (root / "implementation.py").write_text("value = 1\n")
        command(root, "git", "add", ".")
        command(root, "git", "commit", "-qm", "RC code")
        for tag in ("server-v1.27.34rc1", "awid-service-v0.5.32rc1", "aweb-naapp-v0.4.1rc1", "aw-v1.36.48-rc.1"):
            command(root, "git", "tag", tag)
        return root

    def promote(self, root):
        for path in root.rglob("*"):
            if ".git" in path.parts or not path.is_file():
                continue
            value = path.read_text()
            for before, after in (("1.27.34rc1", "1.27.34"), ("0.5.32rc1", "0.5.32"),
                                  ("0.4.1rc1", "0.4.1"), ("1.36.48-rc.1", "1.36.48")):
                value = value.replace(before, after)
            path.write_text(value)
        lock = root / "server/uv.lock"
        lock.write_text(lock.read_text().replace('hash = "sha256:rc", size = 100', 'hash = "sha256:final", size = 120'))
        lock = root / "cli/go/npm/aw/package-lock.json"
        lock.write_text(lock.read_text().replace("/rc.tgz", "/final.tgz").replace("sha512:rc", "sha512:final"))

    def commit(self, root):
        command(root, "git", "add", "-A")
        command(root, "git", "commit", "-qm", "promotion")

    def assert_both_refuse(self, root, pattern):
        self.commit(root)
        with self.assertRaisesRegex(CANDIDATE.CandidateRefusal, pattern):
            CANDIDATE.validate_tags(root, ["server-v1.27.34"])
        command(root, "git", "tag", "server-v1.27.34")
        with self.assertRaisesRegex(PUBLISH.PublishRefusal, pattern):
            PUBLISH.tag_identity(root, "server-v1.27.34")

    def test_promotes_all_five_packages_exact_pins_and_lock_artifacts(self):
        root = self.repository()
        self.promote(root)
        self.commit(root)
        tags = ["server-v1.27.34", "awid-service-v0.5.32", "aweb-naapp-v0.4.1", "aw-v1.36.48"]
        source, _versions = CANDIDATE.validate_tags(root, tags)
        for tag in tags:
            command(root, "git", "tag", tag)
            self.assertEqual(PUBLISH.tag_identity(root, tag)[2], source)

    def test_source_diff_uses_the_whole_tree_not_just_the_final_commit(self):
        root = self.repository()
        (root / "implementation.py").write_text("value = 2\n")
        command(root, "git", "commit", "-qam", "earlier hidden source change")
        self.promote(root)
        self.assert_both_refuse(root, "non-version file")

    def test_added_deleted_renamed_and_mode_changed_files_refuse(self):
        for change in ("add", "delete", "rename", "mode"):
            with self.subTest(change=change):
                root = self.repository()
                self.promote(root)
                path = root / "implementation.py"
                if change == "add":
                    (root / "new.py").write_text("pass\n")
                elif change == "delete":
                    path.unlink()
                elif change == "rename":
                    path.rename(root / "renamed.py")
                else:
                    path.chmod(0o755)
                self.assert_both_refuse(root, "additions, deletions, renames and mode")

    def test_same_base_only_and_manifest_extras_markers_scripts_unchanged(self):
        for old, new in (("1.27.34", "1.27.35"), ("[runtime]", "[other]"),
                         ('>= \\"3.12\\"', '>= \\"3.13\\"'), ("aweb:main", "aweb:other")):
            with self.subTest(change=old):
                root = self.repository()
                self.promote(root)
                manifest = root / "server/pyproject.toml"
                before = manifest.read_text()
                after = before.replace(old, new)
                self.assertNotEqual(before, after)
                manifest.write_text(after)
                self.assert_both_refuse(root, "version|exact promoted pins")

    def test_exact_pin_target_must_be_promoted_in_the_same_release(self):
        for target in ("python", "npm-platform"):
            with self.subTest(target=target):
                root = self.repository()
                self.promote(root)
                if target == "python":
                    path = root / "awid/pyproject.toml"
                    path.write_text(path.read_text().replace('version = "0.5.32"', 'version = "0.5.32rc1"'))
                else:
                    path = root / "cli/go/npm/aw-linux-x64/package.json"
                    path.write_text(path.read_text().replace("1.36.48", "1.36.48-rc.1"))
                self.assert_both_refuse(root, "exact promoted pins")

    def test_unpromoted_lock_artifact_and_added_removed_lock_records_refuse(self):
        for change in ("artifact", "add", "remove"):
            with self.subTest(change=change):
                root = self.repository()
                self.promote(root)
                path = root / "server/uv.lock"
                raw = path.read_text()
                if change == "artifact":
                    raw = raw.replace("sha256:unchanged", "sha256:tampered")
                elif change == "add":
                    raw += '\n[[package]]\nname="added"\nversion="1.0.0"\nsource={registry="https://pypi.org/simple"}\n'
                else:
                    raw = raw.split('[[package]]\nname = "unrelated"')[0]
                path.write_text(raw)
                self.assert_both_refuse(root, "lock record|exact promoted pins")

    def test_highest_numeric_rc_is_selected_and_ancestry_is_required(self):
        root = self.repository()
        command(root, "git", "tag", "server-v1.27.34rc2")
        command(root, "git", "tag", "server-v1.27.34rc10")
        self.promote(root)
        self.commit(root)
        self.assertEqual(VERSIONS.require_final_promotion(root, "server-v1.27.34", "HEAD"), "server-v1.27.34rc10")
        # A later RC cannot be used to bless an earlier final tree.
        final = command(root, "git", "rev-parse", "HEAD")
        (root / "implementation.py").write_text("later = 1\n")
        command(root, "git", "commit", "-qam", "later RC")
        command(root, "git", "tag", "server-v1.27.34rc11")
        with self.assertRaisesRegex(VERSIONS.VersionRefusal, "merge-base"):
            VERSIONS.require_final_promotion(root, "server-v1.27.34", final)


class NpmRcContractTest(unittest.TestCase):
    def test_exact_publisher_routes_staged_rc_to_next_and_final_to_latest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            npm = root / "npm"
            npm.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$CAPTURE_NPM"\n')
            npm.chmod(0o755)
            environment = {**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"], "CAPTURE_NPM": str(root / "args")}
            for version, expected in (("1.2.3-rc.1", "next"), ("1.2.3", "latest")):
                archive = root / "staged.tgz"
                raw = json.dumps({"name": "@awebai/aw", "version": version}).encode()
                with tarfile.open(archive, "w:gz") as tar:
                    entry = tarfile.TarInfo("package/package.json")
                    entry.size = len(raw)
                    tar.addfile(entry, io.BytesIO(raw))
                result = subprocess.run(["bash", "scripts/npm-exact-publish.sh", "publish-exact", "--tgz", str(archive)],
                                        cwd=ROOT, env=environment, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                args = (root / "args").read_text().splitlines()
                self.assertEqual(args[args.index("--tag") + 1], expected)
                self.assertEqual(args[1], str(archive.resolve()))

    def test_synced_downstream_publisher_routes_all_seven_packages(self):
        # Execute the real publisher with real platform archives. Only npm's
        # external publication boundary is replaced, so nothing is uploaded.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            npm_root, artifacts = root / "npm", root / "artifacts"
            npm_root.mkdir()
            artifacts.mkdir()
            shutil.copyfile(ROOT / "cli/go/npm/publish.sh", npm_root / "publish.sh")
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
            npm = root / "bin/npm"
            npm.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$CAPTURE_NPM"\n')
            npm.chmod(0o755)
            for version, expected in (("1.2.3-rc.1", "next"), ("1.2.3", "latest")):
                capture = root / "args"
                capture.write_text("")
                environment = {**os.environ, "PATH": str(root / "bin") + os.pathsep + os.environ["PATH"],
                               "CAPTURE_NPM": str(capture), "GITHUB_REF_NAME": "v" + version}
                result = subprocess.run(["bash", str(npm_root / "publish.sh")], env=environment,
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = capture.read_text().splitlines()
                self.assertEqual(len(calls), 7)
                self.assertTrue(all(call.endswith("--tag " + expected) for call in calls), calls)
                wrapper = json.loads((npm_root / "aw/package.json").read_text())
                self.assertEqual(set(wrapper["optionalDependencies"].values()), {version})

    def test_upstream_tag_guard_accepts_only_final_or_aw_rc_spelling(self):
        workflow = (ROOT / ".github/workflows/aw-release.yml").read_text()
        guard = next(line.strip() for line in workflow.splitlines() if '[[ "$version" =~' in line)
        for version, accepted in (("1.2.3-rc.1", True), ("1.2.3", True), ("1.2.3rc1", False), ("1.2.3-rc.0", False)):
            result = subprocess.run(["bash", "-c", 'version="$1"\n' + guard, "guard", version])
            self.assertEqual(result.returncode == 0, accepted, version)

    def test_aw_workflow_refuses_source_changed_final_before_downstream_clone(self):
        # Execute the actual workflow step. Only the first external side effect
        # (downstream clone) is intercepted; local Git inspection stays real.
        workflow = (ROOT / ".github/workflows/aw-release.yml").read_text()
        shell = textwrap.dedent(workflow.split("        run: |\n", 1)[1])
        for case in ("rc", "version-only-final", "source-changed-final", "final-without-rc"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                command(root, "git", "init", "-q")
                command(root, "git", "config", "user.name", "test")
                command(root, "git", "config", "user.email", "test@example.com")
                (root / "scripts").mkdir()
                for script in ("release_versions.py", "publish_release.py"):
                    shutil.copyfile(ROOT / "scripts" / script, root / "scripts" / script)
                (root / "cli/go/npm/aw").mkdir(parents=True)
                manifest = root / "cli/go/npm/aw/package.json"
                manifest.write_text(json.dumps({"name": "@awebai/aw", "version": "1.36.48-rc.1"}))
                (root / "implementation.go").write_text("package main\n")
                command(root, "git", "add", ".")
                command(root, "git", "commit", "-qm", "RC")
                if case != "final-without-rc":
                    command(root, "git", "tag", "aw-v1.36.48-rc.1")
                if case != "rc":
                    manifest.write_text(json.dumps({"name": "@awebai/aw", "version": "1.36.48"}))
                    if case == "source-changed-final":
                        (root / "implementation.go").write_text("package main\n// changed after RC\n")
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
                    result = subprocess.run(["bash", "-c", shell], cwd=root, env=environment,
                                            text=True, capture_output=True)
                if case in {"source-changed-final", "final-without-rc"}:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(side_effect.exists(), "workflow reached downstream clone before refusing the changed final")
                    diagnostic = "non-version file" if case == "source-changed-final" else "final requires a prior RC"
                    self.assertIn(diagnostic, result.stderr)
                else:
                    self.assertEqual(result.returncode, 86, result.stderr)
                    self.assertEqual(side_effect.read_text(), "clone\n")

    def test_dispatch_refuses_bad_rc_spellings(self):
        for version in ("1.2.3rc1", "1.2.3-rc.0", "1.2.3-rc.01", "01.2.3", "1.2.3-beta.1"):
            with self.subTest(version=version):
                result = subprocess.run(["bash", "scripts/npm-exact-publish.sh", "validate-inputs", "--version", version],
                                        cwd=ROOT, text=True, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
        result = subprocess.run(["bash", "scripts/npm-exact-publish.sh", "validate-inputs", "--version", "1.2.3-rc.1"],
                                cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)


class ReleaseStampContractTest(unittest.TestCase):
    def test_failed_go_build_is_not_masked_by_binary_inspection(self):
        with tempfile.TemporaryDirectory() as directory:
            fake_go = Path(directory) / "go"
            fake_go.write_text(
                "#!/usr/bin/env bash\n"
                "if [[ \"$1 $2\" == \"env GOVERSION\" ]]; then\n"
                "  printf 'go1.24.13\\n'\n"
                "  exit 0\n"
                "fi\n"
                "printf 'sentinel go build failure\\n' >&2\n"
                "exit 42\n",
                encoding="utf-8",
            )
            fake_go.chmod(0o755)
            environment = os.environ.copy()
            environment["GO_BINARY"] = str(fake_go)
            result = subprocess.run(
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
