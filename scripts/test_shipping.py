#!/usr/bin/env python3
"""Focused contracts for the tag-only shipping surface."""

from __future__ import annotations

import importlib.util
import json
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


if __name__ == "__main__":
    unittest.main()
