#!/usr/bin/env python3
"""Contract and mutation controls for the clean local-Docker release gate."""

from __future__ import annotations

import contextlib
import csv
import io
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import release_gate_runner as runner

MAKEFILE = ROOT / "Makefile"
MAP = ROOT / "release-gate" / "suite-map.tsv"
MIGRATION_MAP = ROOT / "release-gate" / "migration-map.tsv"
DOCKERFILE = ROOT / "release-gate" / "Dockerfile"
ENTRYPOINT = SCRIPTS / "release-local-gate.sh"
OLD_FILES = (
    ROOT / ".github" / "workflows" / ("ship" + ".yml"),
    SCRIPTS / ("run-" + "ship-suites.sh"),
    SCRIPTS / ("ship-" + "env.sh"),
    Path(__file__).with_name("test_ship_ci_contract.py"),
)
MAIN_TRIGGER_WORKFLOWS = (
    "library-ci.yml",
    "federation-e2e.yml",
    "server-ci.yml",
    "a2a-copy-guardrails.yml",
    "cli-e2e.yml",
)

EXPECTED_STEPS = (
    ("version-authority", "contract", "_release-gate-version-authority"),
    ("aw-repository-stamp", "contract", "check-aw-commit-repo-stamp"),
    ("cli-tidy", "contract", "check-cli-go-tidy"),
    ("cli-vcs-release-matrix", "artifact", "check-cli-release-vcs-stamps"),
    ("python-locks", "contract", "test-python-locks"),
    ("sot-inventories", "contract", "test-sot-source-inventories"),
    ("vector-provenance", "contract", "test-vector-provenance"),
    ("federation-error-reference", "contract", "test-federation-error-reference"),
    ("federation-authority-mutations", "contract", "test-federation-authority-mutations"),
    ("federation-harness", "contract", "test-federation-harness"),
    ("cli-reference", "contract", "test-cli-reference"),
    ("mcp-reference", "contract", "test-mcp-tools-reference"),
    ("channel-version-equality", "contract", "_release-gate-channel-version"),
    ("node-dependencies", "contract", "_release-node-deps"),
    ("release-train-foundation", "unit", "test-release-train"),
    ("server-unit", "unit", "test-server"),
    ("awid-unit", "unit", "test-awid"),
    ("cli-unit", "unit", "test-cli"),
    ("channel-unit", "unit", "_release-unit-channel"),
    ("channel-live-name", "unit", "test-channel-name-live-contract"),
    ("channel-core-unit", "unit", "_release-unit-channel-core"),
    ("pi-unit", "unit", "_release-unit-pi"),
    ("a2a-unit", "unit", "test-a2a"),
    ("go-audit-unit", "unit", "test-go-vulnerability-audit"),
    ("server-package", "artifact", "_release-artifact-server"),
    ("awid-package", "artifact", "_release-artifact-awid-package"),
    ("awid-image", "artifact", "_release-artifact-awid-image"),
    ("channel-package", "artifact", "_release-artifact-channel"),
    ("pi-package", "artifact", "_release-artifact-pi"),
    ("skills-package-zips", "artifact", "_release-artifact-skills"),
    ("a2a-image", "artifact", "_release-artifact-a2a-image"),
    ("freshness", "contract", "freshness"),
    ("channel-process-guard", "contract", "test-channel-core-process-guard"),
    ("oas", "journey", "_release-oas"),
    ("oas-proof-helpers", "journey", "test-oas-proof-helpers"),
    ("tmux-guard", "journey", "test-tmux-guard"),
    ("channel-integration", "journey", "test-channel-integration"),
    ("oss-user", "journey", "test-e2e"),
    ("oss-federation", "journey", "test-federation-e2e"),
    ("cli-library", "journey", "cli-e2e"),
    ("marketplace-pointer", "contract", "_release-marketplace-pointer"),
    ("npm-exact-publish", "contract", "test-npm-exact-publish"),
    ("pypi-exact-publish", "contract", "test-pypi-exact-publish"),
    ("oci-exact-publish", "contract", "test-oci-exact-publish"),
    ("node-vulnerability-audit", "audit", "check-node-audit"),
    ("go-vulnerability-audit", "audit", "check-go-vulnerability-audit"),
)


def workflow_events(text: str) -> tuple[str, ...]:
    header = text.split("\njobs:", 1)[0]
    start = re.search(r"(?m)^on:\s*$", header)
    if start is None:
        raise AssertionError("workflow has no on block")
    events = []
    for line in header[start.end() :].splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith("  "):
            break
        if line.startswith("   "):
            continue
        match = re.match(r'^  "?([A-Za-z_][A-Za-z_-]*)"?:', line)
        if match is None:
            raise AssertionError(f"unparsed event: {line!r}")
        events.append(match.group(1))
    return tuple(events)


class ReleaseLocalGateContractTests(unittest.TestCase):
    def read_map(self, path: Path = MAP) -> list[tuple[str, ...]]:
        with path.open(newline="", encoding="utf-8") as handle:
            return [
                tuple(row)
                for row in csv.reader(
                    (line for line in handle if not line.startswith("#")),
                    delimiter="\t",
                )
                if row
            ]

    def test_old_ship_mechanism_is_deleted(self) -> None:
        self.assertFalse([str(path) for path in OLD_FILES if path.exists()])
        makefile = MAKEFILE.read_text()
        for term in (
            "SHIP" + "_SUITES",
            "ship-" + "suites:",
            "check-" + "ship-invocation:",
            "check-" + "ship-owner:",
            "ship-" + "gate:",
            "ship" + ":",
        ):
            with self.subTest(term=term):
                self.assertNotIn(term, makefile)

    def test_exact_suite_map_is_unique_and_every_target_exists(self) -> None:
        rows = self.read_map()
        self.assertEqual(rows, list(EXPECTED_STEPS))
        self.assertEqual(len({row[0] for row in rows}), len(rows))
        self.assertEqual(len({row[2] for row in rows}), len(rows))
        makefile = MAKEFILE.read_text()
        for _name, _category, target in rows:
            with self.subTest(target=target):
                self.assertRegex(makefile, rf"(?m)^{re.escape(target)}:")

    def test_migration_map_accounts_for_every_old_unique_command(self) -> None:
        rows = self.read_map(MIGRATION_MAP)
        self.assertTrue(rows)
        self.assertEqual(len({row[0] for row in rows}), len(rows))
        self.assertEqual(
            {row[1] for row in rows}, {"run", "task-6", "task-10-delete"}
        )
        run_targets = {row[2] for row in rows if row[1] == "run"}
        self.assertEqual(run_targets, {row[2] for row in EXPECTED_STEPS})
        deleted = {row[2] for row in rows if row[1] == "task-10-delete"}
        task_6 = {row[2] for row in rows if row[1] == "task-6"}
        self.assertEqual(task_6, {"test-pointer-adapter-ac-pin"})
        self.assertIn("test-release-driver", deleted)
        self.assertIn("test-release-skew-cli-server", deleted)
        self.assertIn("test-release-runnerless", deleted)

    def test_version_guard_is_explicit_and_precedes_artifact_builds(self) -> None:
        makefile = MAKEFILE.read_text()
        match = re.search(
            r"(?m)^_release-gate-version-authority:\n((?:\t.*\n)+)", makefile
        )
        self.assertIsNotNone(match)
        recipe = match.group(1) if match else ""
        self.assertIn("./scripts/check-server-version-bump-test.sh", recipe)
        self.assertIn('./scripts/check-server-version-bump.sh "$(RELEASE_BASE_SHA)"', recipe)
        names = [row[0] for row in EXPECTED_STEPS]
        self.assertLess(names.index("version-authority"), names.index("server-package"))

    def test_all_release_shaped_artifacts_have_real_recipes(self) -> None:
        makefile = MAKEFILE.read_text()
        required = {
            "_release-artifact-server": ("uv build", "aweb-$(SERVER_VERSION)"),
            "_release-artifact-awid-package": ("uv build", "awid_service-$(AWID_VERSION)"),
            "_release-artifact-awid-image": ("linux/amd64,linux/arm64", "awid/Dockerfile.release"),
            "_release-artifact-channel": ("npm pack --ignore-scripts",),
            "_release-artifact-pi": ("npm pack --ignore-scripts",),
            "_release-artifact-skills": ("build-zips.sh", "npm pack --ignore-scripts"),
            "_release-artifact-a2a-image": ("linux/amd64,linux/arm64", "Dockerfile.a2a-gw"),
        }
        for target, commands in required.items():
            with self.subTest(target=target):
                match = re.search(rf"(?m)^{re.escape(target)}:\n((?:\t.*\n)+)", makefile)
                self.assertIsNotNone(match)
                recipe = match.group(1) if match else ""
                for command in commands:
                    self.assertIn(command, recipe)

    def test_five_workflows_keep_pr_and_lose_main_push(self) -> None:
        for name in MAIN_TRIGGER_WORKFLOWS:
            with self.subTest(workflow=name):
                text = (ROOT / ".github" / "workflows" / name).read_text()
                expected = (
                    ("pull_request", "workflow_dispatch")
                    if name == "library-ci.yml"
                    else ("pull_request",)
                )
                self.assertEqual(workflow_events(text), expected)
                self.assertNotRegex(text, r"(?m)^\s*push:\s*$")
        hosted = "\n".join(path.read_text() for path in (ROOT / ".github" / "workflows").glob("*.yml"))
        self.assertNotIn("make release-local-gate", hosted)
        self.assertNotIn("scripts/release-local-gate.sh", hosted)

    def test_cli_pr_inputs_follow_current_public_defaults_without_stale_pins(self) -> None:
        text = (ROOT / ".github" / "workflows" / "cli-e2e.yml").read_text()
        for repository in ("awebai/library", "awebai/blueprints"):
            with self.subTest(repository=repository):
                match = re.search(
                    rf"repository:\s*{re.escape(repository)}(?P<body>.*?)(?=\n\s*- name:|\n\s*- uses:)",
                    text,
                    re.S,
                )
                self.assertIsNotNone(match)
                self.assertNotRegex(match.group("body") if match else "", r"(?m)^\s*ref:")

    def test_entrypoint_refuses_dirty_input_and_runs_one_clean_docker_checkout(self) -> None:
        text = ENTRYPOINT.read_text()
        for required in (
            "status --porcelain",
            "git clone --local --no-hardlinks",
            "checkout --detach",
            "diff --quiet",
            "docker build",
            "/var/run/docker.sock",
            "RELEASE_BASE_SHA",
            "LIBRARY_E2E_LIBRARY_CONTEXT",
            "LIBRARY_E2E_BLUEPRINT_SRC",
        ):
            self.assertIn(required, text)
        self.assertNotIn("git push", text)
        self.assertNotIn("gh ", text)

    def test_entrypoint_refuses_a_real_dirty_checkout_before_docker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            (repo / "scripts").mkdir(parents=True)
            script = repo / "scripts" / "release-local-gate.sh"
            script.write_text(ENTRYPOINT.read_text())
            script.chmod(0o755)
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "gate@example.invalid"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Gate"], cwd=repo, check=True)
            subprocess.run(["git", "add", "."], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "fixture"], cwd=repo, check=True)
            sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
            (repo / "untracked").write_text("dirty\n")
            result = subprocess.run(
                [str(script)],
                cwd=repo,
                env={**os.environ, "RELEASE_SOURCE_SHA": sha, "RELEASE_BASE_SHA": sha},
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("dirty or has untracked files", result.stderr)
            self.assertNotIn("docker", result.stdout + result.stderr)

    def test_entrypoint_refuses_missing_sibling_input_before_docker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            (repo / "scripts").mkdir(parents=True)
            script = repo / "scripts" / "release-local-gate.sh"
            script.write_text(ENTRYPOINT.read_text())
            script.chmod(0o755)
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "gate@example.invalid"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Gate"], cwd=repo, check=True)
            subprocess.run(["git", "add", "."], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "fixture"], cwd=repo, check=True)
            sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
            result = subprocess.run(
                [str(script)],
                cwd=repo,
                env={
                    **os.environ,
                    "RELEASE_SOURCE_SHA": sha,
                    "RELEASE_BASE_SHA": sha,
                    "LIBRARY_E2E_LIBRARY_CONTEXT": str(repo / "missing-library"),
                    "LIBRARY_E2E_BLUEPRINT_SRC": str(repo / "missing-blueprint"),
                },
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Library input is missing", result.stderr)

    def test_gate_image_pins_required_toolchain_and_no_publisher_credentials(self) -> None:
        text = DOCKERFILE.read_text()
        for required in ("python:3.12", "node_22.x", "go1.24.13", "docker-ce-cli", "tmux", "uv"):
            self.assertIn(required, text)
        for forbidden in ("GITHUB_TOKEN", "NPM_TOKEN", "PYPI", "RENDER", "AWS_"):
            self.assertNotIn(forbidden, text)

    def test_runner_continues_after_failure_and_summary_is_complete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make = root / "make"
            calls = root / "calls"
            make.write_text(
                "#!/usr/bin/env bash\n"
                f"echo \"$1\" >> {calls}\n"
                "[[ \"$1\" == two ]] && exit 3\n"
                "exit 0\n"
            )
            make.chmod(0o755)
            suite_map = root / "map.tsv"
            suite_map.write_text("one\tunit\tone\ntwo\tunit\ttwo\nthree\tunit\tthree\n")
            logs = root / "logs"
            with contextlib.redirect_stdout(io.StringIO()):
                status = runner.run(suite_map, logs, [str(make)])
            self.assertEqual(status, 1)
            self.assertEqual(calls.read_text().splitlines(), ["one", "two", "three"])
            summary = (logs / "summary.tsv").read_text()
            self.assertIn("one\tPASSED", summary)
            self.assertIn("two\tFAILED", summary)
            self.assertIn("three\tPASSED", summary)
            self.assertNotIn("NOT RUN", summary)

    def test_runner_rejects_duplicates_empty_maps_and_unobserved_steps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs = root / "logs"
            for label, body in (
                ("duplicate", "one\tunit\tt\none\tunit\tu\n"),
                ("target", "one\tunit\tt\ntwo\tunit\tt\n"),
                ("empty", "# none\n"),
                ("hidden skip", "one\tskip\tt\n"),
            ):
                with self.subTest(label=label):
                    path = root / f"{label}.tsv"
                    path.write_text(body)
                    with self.assertRaises(runner.MapError):
                        runner.run(path, logs / label, ["true"])

    def test_make_help_exposes_no_release_operator_command(self) -> None:
        result = subprocess.run(
            ["make", "help"], cwd=ROOT, capture_output=True, text=True, check=True
        )
        self.assertNotIn("ship", result.stdout.lower())
        self.assertNotIn("release-prepare", result.stdout)
        self.assertNotIn("release-continue", result.stdout)
        self.assertNotIn("release-local-gate", result.stdout)


if __name__ == "__main__":
    unittest.main()
