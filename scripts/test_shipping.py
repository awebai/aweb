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
            root, ["server-v1.2.3", "awid-service-v2.3.4", "channel-v3.4.5"]
        )
        self.assertEqual(len(source), 40)
        self.assertEqual(versions["server-v"], "1.2.3")
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


class SurfaceContractTest(unittest.TestCase):
    def test_every_publisher_is_tag_only(self):
        expected = {
            "pypi-release.yml": ("server-v*", "awid-service-v*"),
            "npm-release.yml": ("channel-v*", "pi-v*", "skills-v*"),
            "awid-image-release.yml": ("awid-v*",),
            "a2a-gateway-release.yml": ("a2a-gw-v*",),
            "aw-release.yml": ("aw-v*",),
        }
        for name, tags in expected.items():
            text = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
            self.assertIn("tags:", text, name)
            self.assertNotIn("branches:", text, name)
            self.assertNotIn("refs/heads/release", text, name)
            for tag in tags:
                self.assertIn(tag, text, name)

    def test_obsolete_release_state_is_deleted(self):
        for path in (
            "scripts/release.py",
            "scripts/release-local-gate.sh",
            "scripts/release_gate_runner.py",
            "scripts/release-gate.sh",
            "scripts/candidate_gate_runner.py",
            "scripts/pointer-adapter-marketplace-pointer.py",
            "scripts/e2e/test_pointer_adapter_marketplace.py",
            "candidate-gate/suite-map.tsv",
            "release-gate",
            ".github/workflows/release-tooling.yml",
        ):
            self.assertFalse((ROOT / path).exists(), path)
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertNotIn("\nrelease:", makefile)
        self.assertNotIn("marketplace-pointer", makefile)
        self.assertIn("\nrelease-candidate:", makefile)
        self.assertIn("\nrelease-publish:", makefile)

    def test_candidate_suite_is_one_explicit_complete_list(self):
        lines = (ROOT / "scripts/candidate-suite.sh").read_text(encoding="utf-8").splitlines()
        targets = [line.removeprefix("run ") for line in lines if line.startswith("run ")]
        self.assertEqual(len(targets), 46)
        self.assertEqual(len(targets), len(set(targets)))
        for target in ("test-e2e", "test-federation-e2e", "cli-e2e"):
            self.assertIn(target, targets)

    def test_candidate_gate_has_bounded_host_daemon_controls(self):
        gate = (ROOT / "scripts/candidate-docker-gate.sh").read_text(encoding="utf-8")
        wrapper = (ROOT / "candidate-gate/bin/docker").read_text(encoding="utf-8")

        # Operator defaults requested for shared-machine runs.
        self.assertIn('runner_cpus="${AWEB_CANDIDATE_RUNNER_CPUS:-2}"', gate)
        self.assertIn('runner_memory="${AWEB_CANDIDATE_RUNNER_MEMORY:-8g}"', gate)
        self.assertIn('builder_cpus="${AWEB_CANDIDATE_BUILDER_CPUS:-2}"', gate)
        self.assertIn('builder_memory="${AWEB_CANDIDATE_BUILDER_MEMORY:-6g}"', gate)

        # The outer runner and direct database services are named/labeled and bounded.
        for needle in (
            '--name "$runner_name"',
            '--label "aweb.candidate-gate=$resource_label"',
            '--cpus "$runner_cpus"',
            '--memory "$runner_memory"',
            '--pids-limit "$runner_pids"',
            '--cpus "$service_cpus" --memory "$service_memory" --pids-limit "$service_pids"',
            '--cpus "$redis_cpus" --memory "$redis_memory" --pids-limit "$redis_pids"',
        ):
            self.assertIn(needle, gate)

        # The initial tool image is built by the bounded persistent BuildKit, and the
        # same builder is exported to nested release-image builds.
        self.assertIn('docker update --cpus "$builder_cpus" --memory "$builder_memory" --pids-limit "$builder_pids"', gate)
        self.assertIn('docker buildx build --builder "$builder_name" --load --pull', gate)
        self.assertIn('-e BUILDX_BUILDER="$builder_name"', gate)
        self.assertNotIn('\ndocker build --pull -f "$checkout/candidate-gate/Dockerfile"', gate)

        # Docker-socket siblings inside the runner go through a PATH wrapper that
        # labels/limits direct `docker run` and routes plain `docker build` through BuildKit.
        self.assertIn('-e PATH="$checkout/candidate-gate/bin:', gate)
        self.assertIn('--label "aweb.candidate-gate=$label"', wrapper)
        self.assertIn('--cpus "$sibling_cpus"', wrapper)
        self.assertIn('buildx build --builder "$BUILDX_BUILDER" --load', wrapper)
        self.assertIn('compose_with_limits()', wrapper)
        self.assertIn('config --services', wrapper)
        self.assertIn('compose_prefix+=("-f" "$search_dir/$default_file")', wrapper)
        self.assertIn('compose_prefix=("${prefix[@]}")', wrapper)
        self.assertIn('aweb.candidate-gate: %s', wrapper)
        self.assertIn('mem_limit: "%s"', wrapper)
        self.assertIn('pids_limit: %s', wrapper)

        # Cleanup removes and verifies all containers carrying the run label, including
        # signal-triggered cleanup, without sweeping unrelated Docker resources.
        self.assertIn("trap 'cleanup 130' INT", gate)
        self.assertIn("trap 'cleanup 143' TERM", gate)
        self.assertIn('docker ps -aq --filter "label=aweb.candidate-gate=$resource_label"', gate)
        self.assertIn('resource-limits.tsv', gate)

    def test_candidate_docker_wrapper_preserves_compose_base_files(self):
        wrapper = ROOT / "candidate-gate/bin/docker"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / "fake-docker.py"
            fake.write_text(
                "#!/usr/bin/env python3\n"
                "import pathlib, sys\n"
                "args = sys.argv[1:]\n"
                "if args[:1] == ['compose'] and args[-2:] == ['config', '--services']:\n"
                "    print('web')\n"
                "    raise SystemExit(0)\n"
                "if args[:1] == ['compose']:\n"
                "    files = []\n"
                "    it = iter(range(len(args)))\n"
                "    for i in it:\n"
                "        if args[i] == '-f' and i + 1 < len(args):\n"
                "            files.append(args[i + 1])\n"
                "    for path in files:\n"
                "        print(f'--- {path}')\n"
                "        print(pathlib.Path(path).read_text())\n"
                "    raise SystemExit(0)\n"
                "raise SystemExit(0)\n",
                encoding="utf-8",
            )
            fake.chmod(0o755)
            env = os.environ.copy()
            env.update(
                {
                    "AWEB_CANDIDATE_REAL_DOCKER": str(fake),
                    "AWEB_CANDIDATE_RESOURCE_LABEL": "test-run",
                    "AWEB_CANDIDATE_SIBLING_CPUS": "2",
                    "AWEB_CANDIDATE_SIBLING_MEMORY": "4g",
                    "AWEB_CANDIDATE_SIBLING_PIDS": "1024",
                }
            )

            implicit = root / "implicit"
            implicit.mkdir()
            (implicit / "compose.yml").write_text(
                "services:\n  web:\n    image: nginx:alpine\n", encoding="utf-8"
            )
            (implicit / ".env.e2e").write_text("X=1\n", encoding="utf-8")
            out = subprocess.check_output(
                [str(wrapper), "compose", "-p", "proj", "--env-file", ".env.e2e", "config"],
                cwd=implicit,
                env=env,
                text=True,
            )
            self.assertIn("image: nginx:alpine", out)
            self.assertIn("aweb.candidate-gate: test-run", out)
            self.assertIn('mem_limit: "4g"', out)

            explicit = root / "explicit"
            explicit.mkdir()
            (explicit / "base.yml").write_text(
                "services:\n  web:\n    build:\n      context: .\n", encoding="utf-8"
            )
            out = subprocess.check_output(
                [str(wrapper), "compose", "-p", "proj", "-f", "base.yml", "config"],
                cwd=explicit,
                env=env,
                text=True,
            )
            self.assertIn("build:", out)
            self.assertIn("context: .", out)
            self.assertIn("aweb.candidate-gate: test-run", out)


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
