#!/usr/bin/env python3
"""Focused contracts for the tag-only shipping surface."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
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
