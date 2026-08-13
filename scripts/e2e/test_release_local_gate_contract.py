#!/usr/bin/env python3
"""Contract and mutation controls for the clean local-Docker release gate."""

from __future__ import annotations

import contextlib
import csv
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import check_release_gate_residue as residue
import release_gate_runner as runner

MAKEFILE = ROOT / "Makefile"
MAP = ROOT / "release-gate" / "suite-map.tsv"
DOCKERFILE = ROOT / "release-gate" / "Dockerfile"
ENTRYPOINT = SCRIPTS / "release-local-gate.sh"
BOUNDARY_HARNESSES = (
    ROOT / "channel" / "test" / "integration.test.ts",
    SCRIPTS / "e2e-oss-user-journey.sh",
    SCRIPTS / "e2e-oss-federation.sh",
    SCRIPTS / "e2e-federation-authority.sh",
    ROOT / "cli" / "scripts" / "e2e.sh",
    SCRIPTS / "e2e-library-stack.sh",
)
BIND_ROOT_HARNESSES = frozenset(
    {
        BOUNDARY_HARNESSES[0].as_posix(),
        BOUNDARY_HARNESSES[2].as_posix(),
        BOUNDARY_HARNESSES[3].as_posix(),
    }
)
OLD_FILES = (
    ROOT / ".github" / "workflows" / "ship.yml",
    SCRIPTS / "run-ship-suites.sh",
    SCRIPTS / "ship-env.sh",
    Path(__file__).with_name("test_ship_ci_contract.py"),
)
FORBIDDEN_RESIDUE_LITERALS = (
    "ship.yml",
    "run-ship-suites.sh",
    "ship-env.sh",
    "SHIP_SUITES",
    "ship-suites:",
    "check-ship-invocation:",
    "check-ship-owner:",
    "ship-gate:",
    "ship:",
    "make ship",
    "release-all-check",
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
    ("a2a-copy-contract", "contract", "check-a2a-copy-guardrails"),
    ("go-audit-unit", "unit", "test-go-vulnerability-audit"),
    ("cli-version-contract", "contract", "test-release-cli-version"),
    ("aw-binary", "artifact", "build"),
    ("server-package", "artifact", "_release-artifact-server"),
    ("awid-package", "artifact", "_release-artifact-awid-package"),
    ("awid-image", "artifact", "_release-artifact-awid-image"),
    ("channel-package", "artifact", "_release-artifact-channel"),
    ("pi-package", "artifact", "_release-artifact-pi"),
    ("skills-package-zips", "artifact", "_release-artifact-skills"),
    ("a2a-image", "artifact", "_release-artifact-a2a-image"),
    ("freshness", "contract", "freshness"),
    ("release-residue", "contract", "check-release-gate-residue"),
    ("local-gate-contract", "contract", "test-release-local-gate-contract"),
    ("publication-workflow-contract", "contract", "test-release-gate-contract"),
    ("channel-process-guard", "contract", "test-channel-core-process-guard"),
    ("oats", "journey", "_release-oats"),
    ("oats-proof-helpers", "journey", "_release-oats-proof-helpers"),
    ("tmux-guard", "journey", "test-tmux-guard"),
    ("a2a-gateway-e2e", "journey", "test-a2a-gateway-e2e"),
    ("channel-integration", "journey", "test-channel-integration"),
    ("oss-user", "journey", "test-e2e"),
    ("oss-federation", "journey", "test-federation-e2e"),
    ("cli-library", "journey", "cli-e2e"),
    ("marketplace-pointer", "contract", "_release-marketplace-pointer"),
    ("npm-exact-publish", "contract", "test-npm-exact-publish"),
    ("pypi-exact-publish", "contract", "test-pypi-exact-publish"),
    ("oci-exact-publish", "contract", "test-oci-exact-publish"),
    ("ac-pointer-primary-moves", "contract", "test-pointer-adapter-ac-pin"),
)


def boundary_contract_errors(
    entrypoint: str, harnesses: dict[str, str]
) -> tuple[str, ...]:
    errors: list[str] = []
    required_entrypoint = {
        "non-root user": '--user "$(id -u):$(id -g)"',
        "Docker socket group": '--group-add "$socket_gid"',
        "container buildx builder": "--driver docker-container",
        "external buildx config": 'buildx_config="$work/buildx-config"',
        "shared buildx config": 'BUILDX_CONFIG="$buildx_config" docker buildx create',
        "shared builder cleanup": 'BUILDX_CONFIG="$buildx_config" docker buildx rm',
        "container buildx config": '-e BUILDX_CONFIG="$buildx_config"',
        "dedicated bind root": 'docker_bind_root="$checkout/.release-docker-bind"',
        "fixed bind-root input": '-e AWEB_DOCKER_BIND_ROOT="$docker_bind_root"',
        "host-visible checkout": '-v "$checkout:$checkout"',
        "canonical Library input": 'canonical_git_input library',
        "canonical blueprint input": 'canonical_git_input blueprints',
        "requested blueprint subdirectory": 'blueprints/team}',
        "checkout identity passed to runner": 'RELEASE_GATE_SOURCE_SHA="$SOURCE_SHA"',
        "checkout root passed to runner": 'RELEASE_GATE_CHECKOUT_ROOT="$checkout"',
        "exact builder state volume cleanup": 'docker volume rm -f "buildx_buildkit_${owned_builder}0_state"',
        "exact gate image cleanup": 'docker image rm "$IMAGE"',
        "suite project cleanup": 'for project in "${suite_projects[@]}"',
        "fixed Docker host mapping": "--add-host aweb-docker.test:host-gateway",
        "fixed Docker host input": "-e AWEB_DOCKER_PUBLISHED_HOST=aweb-docker.test",
    }
    for label, literal in required_entrypoint.items():
        if literal not in entrypoint:
            errors.append(label)
    if "--privileged" in entrypoint or "dockerd" in entrypoint:
        errors.append("no privileged nested daemon")
    if 'buildx_config="$checkout/' in entrypoint:
        errors.append("buildx config outside disposable checkout")
    if "docker system prune" in entrypoint:
        errors.append("no general Docker janitor")
    if "-v /tmp:/tmp" in entrypoint:
        errors.append("container-native /tmp")
    for name, body in harnesses.items():
        for label, literal in (
            ("fixed input", "AWEB_DOCKER_PUBLISHED_HOST"),
            ("fixed Docker hostname", "aweb-docker.test"),
            ("local default/fixture", "127.0.0.1"),
            ("unsupported-value refusal", "unsupported"),
        ):
            if literal not in body:
                errors.append(f"{name}: {label}")
        has_bind_root = "AWEB_DOCKER_BIND_ROOT" in body
        if has_bind_root != (name in BIND_ROOT_HARNESSES):
            errors.append(f"{name}: exact bind-root scope")
    channel = harnesses[BOUNDARY_HARNESSES[0].as_posix()]
    if 'server.listen(0, "127.0.0.1"' not in channel:
        errors.append("channel process-local loopback fixture")
    federation = harnesses[BOUNDARY_HARNESSES[2].as_posix()]
    for label, literal in (
        ("native federation client root", 'mktemp -d "${TMPDIR:-/tmp}/${prefix}.XXXXXX"'),
        ("federation compose bind root", 'COMPOSE_FILE="$DOCKER_RUNTIME/docker-compose.yml"'),
        ("federation DNS bind root", 'DNS_DIR="$DOCKER_RUNTIME/dns"'),
        ("native alpha wheel build context", 'ALPHA_SERVER_CONTEXT="$E2E_ROOT/'),
        ("native beta wheel build context", 'BETA_SERVER_CONTEXT="$E2E_ROOT/'),
    ):
        if literal not in federation:
            errors.append(label)
    return tuple(errors)


def local_bridge_contract_errors(journey: str, dockerfile: str) -> tuple[str, ...]:
    errors = []
    for label, literal in (
        ("AWID same-port socat listener", "TCP4-LISTEN:$AWID_PORT,bind=127.0.0.1,reuseaddr,fork"),
        ("aweb same-port socat listener", "TCP4-LISTEN:$AWEB_PORT,bind=127.0.0.1,reuseaddr,fork"),
        ("fixed AWID target", '"TCP4:aweb-docker.test:$AWID_PORT"'),
        ("fixed aweb target", '"TCP4:aweb-docker.test:$AWEB_PORT"'),
        ("phase-local AWID URL", '--awid-registry "$local_awid_url"'),
        ("phase-local aweb URL", '--aweb-url "$local_aweb_url"'),
        ("current init name flag", '--name "$local_alias"'),
        ("exact AWID PID", "QUICKSTART_AWID_SOCAT_PID=$!"),
        ("exact aweb PID", "QUICKSTART_AWEB_SOCAT_PID=$!"),
        ("kill both before waits", 'kill "${pids[@]}"'),
        ("wait both after kill", 'for pid in "${pids[@]}"; do'),
        ("post-phase AWID removal", "phase-only AWID loopback endpoint removed"),
        ("post-phase aweb removal", "phase-only aweb loopback endpoint removed"),
    ):
        if literal not in journey:
            errors.append(label)
    cleanup = re.search(r"(?ms)^cleanup\(\) \{.*?^\}", journey)
    if cleanup is None or "stop_quickstart_bridges" not in cleanup.group(0):
        errors.append("EXIT listener cleanup")
    if "socat" not in dockerfile:
        errors.append("gate image socat")
    return tuple(errors)


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
        self.assertEqual(residue.FORBIDDEN, FORBIDDEN_RESIDUE_LITERALS)
        self.assertEqual(
            residue.PRODUCTION_EXCLUSIONS,
            frozenset(
                {
                    "docs/release.md",
                    "scripts/e2e/test_release_local_gate_contract.py",
                }
            ),
        )
        self.assertEqual(residue.find_residue(ROOT), [])

    def test_residue_detector_exercises_every_complete_literal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
            for index, literal in enumerate(FORBIDDEN_RESIDUE_LITERALS):
                name = "Makefile" if literal == "ship:" else f"probe-{index}"
                (repo / name).write_text(literal + "\n")
            subprocess.run(["git", "add", "."], cwd=repo, check=True)
            findings = residue.find_residue(repo, excluded=())
            self.assertEqual({literal for _path, literal in findings}, set(FORBIDDEN_RESIDUE_LITERALS))
            self.assertEqual(len(findings), len(FORBIDDEN_RESIDUE_LITERALS))

    def test_reachable_file_mutation_makes_maintained_make_check_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "scripts").mkdir()
            shutil.copy2(SCRIPTS / "check_release_gate_residue.py", repo / "scripts")
            (repo / "Makefile").write_text(
                "check-release-gate-residue:\n"
                "\tpython3 scripts/check_release_gate_residue.py\n"
            )
            (repo / "reachable.txt").write_text("SHIP_SUITES\n")
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
            subprocess.run(["git", "add", "."], cwd=repo, check=True)
            result = subprocess.run(
                ["make", "check-release-gate-residue"],
                cwd=repo,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("reachable.txt: SHIP_SUITES", result.stderr)

    def test_exact_suite_map_is_unique_and_every_target_exists(self) -> None:
        rows = self.read_map()
        self.assertEqual(len(EXPECTED_STEPS), 51)
        self.assertEqual(
            rows,
            [
                ("docker-boundaries", "contract", "_release-gate-docker-boundaries"),
                *[tuple(row) for row in EXPECTED_STEPS],
            ],
        )
        self.assertEqual(len(rows), 52)
        self.assertEqual(len({row[0] for row in rows}), len(rows))
        self.assertEqual(len({row[2] for row in rows}), len(rows))
        makefile = MAKEFILE.read_text()
        for _name, _category, target in rows:
            with self.subTest(target=target):
                self.assertRegex(makefile, rf"(?m)^{re.escape(target)}:")

    def test_map_carries_membership_only(self) -> None:
        rows = self.read_map()
        self.assertFalse((ROOT / "release-gate" / "migration-map.tsv").exists())
        self.assertTrue(all(len(row) == 3 for row in rows))
        self.assertNotIn("test-a2a", {row[2] for row in rows})
        self.assertIn(
            ("ac-pointer-primary-moves", "contract", "test-pointer-adapter-ac-pin"),
            rows,
        )
        self.assertIn(
            ("local-gate-contract", "contract", "test-release-local-gate-contract"),
            rows,
        )

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
        # The authoritative Replace list must name exactly this five-file set;
        # a doc or constant that drops one file makes them disagree here.
        specification = (ROOT / "docs" / "release.md").read_text()
        replace_sentence = specification.split("publication remains);", 1)[1].split(
            "lose their `push: main` triggers", 1
        )[0]
        for name in MAIN_TRIGGER_WORKFLOWS:
            self.assertIn(f"`{name}`", replace_sentence, name)
        self.assertEqual(len(MAIN_TRIGGER_WORKFLOWS), 5)
        self.assertEqual(
            sorted(re.findall(r"`([a-z0-9-]+\.yml)`", replace_sentence)),
            sorted(MAIN_TRIGGER_WORKFLOWS),
            "the doc sentence and the enforced constant must name the same set",
        )

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
            "--user \"$(id -u):$(id -g)\"",
            "--group-add \"$socket_gid\"",
            "docker buildx create",
            "docker buildx rm",
            "--add-host aweb-docker.test:host-gateway",
            "-e AWEB_DOCKER_PUBLISHED_HOST=aweb-docker.test",
            "RELEASE_BASE_SHA",
            "LIBRARY_E2E_LIBRARY_CONTEXT",
            "LIBRARY_E2E_BLUEPRINT_SRC",
        ):
            self.assertIn(required, text)
        self.assertNotIn("--privileged", text)
        self.assertNotIn(
            "test_release_gate_docker_boundaries.py",
            text,
        )
        self.assertIn('RELEASE_GATE_IMAGE="$IMAGE"', text)
        self.assertIn("wrapper-verdict.log", text)
        self.assertNotIn("dockerd", text)
        self.assertNotIn("git push", text)
        self.assertNotIn("gh ", text)

    def test_only_published_docker_endpoints_use_the_fixed_host_input(self) -> None:
        entrypoint = ENTRYPOINT.read_text()
        harnesses = {path.as_posix(): path.read_text() for path in BOUNDARY_HARNESSES}
        self.assertEqual(boundary_contract_errors(entrypoint, harnesses), ())
        self.assertNotIn("AWEB_DOCKER_PUBLISHED_HOST:-", entrypoint)
        self.assertNotIn("RELEASE_GATE_LOG_DIR:-", entrypoint)
        self.assertNotIn("docker compose --env-file .env.e2e", (SCRIPTS / "e2e-oss-user-journey.sh").read_text())
        project_inputs = {
            "AWEB_SKEW_PROJECT_TOKEN": BOUNDARY_HARNESSES[0],
            "AWEB_E2E_PROJECT": BOUNDARY_HARNESSES[1],
            "AWEB_FED_E2E_PROJECT": BOUNDARY_HARNESSES[2],
            "AWEB_FED_AUTH_PROJECT": BOUNDARY_HARNESSES[3],
            "LIBRARY_E2E_PROJECT": BOUNDARY_HARNESSES[5],
        }
        for name, harness in project_inputs.items():
            self.assertIn(f'-e {name}=', entrypoint)
            self.assertIn(name, harness.read_text())
        match = re.search(r'^  "(aweb-fed-e2e-[^"]+)"$', entrypoint, re.MULTILINE)
        self.assertIsNotNone(match)
        identities = [
            match.group(1).replace("${SOURCE_SHA:0:12}", "93b4112f69d5").replace("$$", pid)
            for pid in ("101", "202")
        ]
        self.assertEqual(len(set(identities)), 2)
        self.assertIn('[[ "$PROJECT" =~ ^aweb-fed-e2e-[a-z0-9]+$ ]]', harnesses[BOUNDARY_HARNESSES[2].as_posix()])
        for identity in identities:
            self.assertRegex(identity, r"^aweb-fed-e2e-[a-z0-9]+$")
        runner_text = (SCRIPTS / "release_gate_runner.py").read_text()
        self.assertEqual(runner_text.count("START_REQUIRED_KIB ="), 1)
        self.assertNotIn("START_REQUIRED_KIB", entrypoint)
        self.assertFalse((SCRIPTS / "release_gate_capacity.py").exists())
        for path in (
            BOUNDARY_HARNESSES[0],
            BOUNDARY_HARNESSES[2],
            BOUNDARY_HARNESSES[3],
            BOUNDARY_HARNESSES[5],
        ):
            self.assertIn("--rmi", path.read_text())
            self.assertIn("local", path.read_text())
        self.assertIn("--rmi local", (SCRIPTS / "e2e-oss-user-journey.sh").read_text())
        library_stack = harnesses[BOUNDARY_HARNESSES[5].as_posix()]
        for assignment in (
            'LIBRARY_E2E_AWEB_PUBLIC_ORIGIN="${LIBRARY_E2E_AWEB_PUBLIC_ORIGIN:-$AWEB_URL}"',
            'LIBRARY_E2E_AWID_PUBLIC_REGISTRY_URL="${LIBRARY_E2E_AWID_PUBLIC_REGISTRY_URL:-$AWID_URL}"',
            'LIBRARY_E2E_LIBRARY_PUBLIC_ORIGIN="${LIBRARY_E2E_LIBRARY_PUBLIC_ORIGIN:-$LIBRARY_URL}"',
        ):
            self.assertIn(assignment, library_stack)
        compose = (ROOT / "docker-compose.e2e.yml").read_text()
        self.assertIn('"http://localhost:8000/health"', compose)
        self.assertIn('"http://localhost:8010/health"', compose)
        self.assertIn("http://localhost:8765/health", compose)
        user_journey = harnesses[BOUNDARY_HARNESSES[1].as_posix()]
        self.assertIn("AWEB_PUBLIC_ORIGIN=$AWEB_URL", user_journey)
        self.assertIn("AWID_PUBLIC_REGISTRY_URL=$AWID_URL", user_journey)
        federation = harnesses[BOUNDARY_HARNESSES[2].as_posix()]
        self.assertIn('mktemp -d "${TMPDIR:-/tmp}/${prefix}.XXXXXX"', federation)
        self.assertIn('DOCKER_RUNTIME="$(mktemp -d "$DOCKER_BIND_ROOT/', federation)
        self.assertIn('COMPOSE_FILE="$DOCKER_RUNTIME/docker-compose.yml"', federation)
        self.assertIn('DNS_DIR="$DOCKER_RUNTIME/dns"', federation)
        self.assertIn('ALPHA_SERVER_CONTEXT="$E2E_ROOT/', federation)
        self.assertIn('BETA_SERVER_CONTEXT="$E2E_ROOT/', federation)
        authority = harnesses[BOUNDARY_HARNESSES[3].as_posix()]
        self.assertIn('RUNTIME="$(mktemp -d "$DOCKER_BIND_ROOT/', authority)
        channel = harnesses[BOUNDARY_HARNESSES[0].as_posix()]
        self.assertIn('mkdtemp(join(bindRoot, "channel-e2e-"))', channel)

    def test_boundary_mutations_are_each_rejected(self) -> None:
        entrypoint = ENTRYPOINT.read_text()
        harnesses = {path.as_posix(): path.read_text() for path in BOUNDARY_HARNESSES}
        mutations = {
            "root": (
                entrypoint.replace('--user "$(id -u):$(id -g)"', "", 1),
                harnesses,
                "non-root user",
            ),
            "builder": (
                entrypoint.replace("--driver docker-container", "--driver docker", 1),
                harnesses,
                "container buildx builder",
            ),
            "shared buildx config": (
                entrypoint.replace('-e BUILDX_CONFIG="$buildx_config"', "", 1),
                harnesses,
                "container buildx config",
            ),
            "dedicated host-visible path": (
                entrypoint.replace('-e AWEB_DOCKER_BIND_ROOT="$docker_bind_root"', "", 1),
                harnesses,
                "fixed bind-root input",
            ),
            "host tmp replaces native tmp": (
                entrypoint + "\n-v /tmp:/tmp\n",
                harnesses,
                "container-native /tmp",
            ),
            "all loopback rewritten": (
                entrypoint,
                {
                    name: body.replace("127.0.0.1", "aweb-docker.test")
                    for name, body in harnesses.items()
                },
                "local default/fixture",
            ),
            "uncanonical Library input": (
                entrypoint.replace(
                    'LIBRARY_E2E_LIBRARY_CONTEXT="$(canonical_git_input library "$LIBRARY_E2E_LIBRARY_CONTEXT")"',
                    'LIBRARY_E2E_LIBRARY_CONTEXT="$LIBRARY_E2E_LIBRARY_CONTEXT"',
                    1,
                ),
                harnesses,
                "canonical Library input",
            ),
            "blueprint widened to repo root": (
                entrypoint.replace("blueprints/team}", "blueprints}", 1),
                harnesses,
                "requested blueprint subdirectory",
            ),
            "bind root leaks to user journey": (
                entrypoint,
                {
                    **harnesses,
                    BOUNDARY_HARNESSES[1].as_posix(): (
                        harnesses[BOUNDARY_HARNESSES[1].as_posix()]
                        + "\nAWEB_DOCKER_BIND_ROOT\n"
                    ),
                },
                "exact bind-root scope",
            ),
            "federation client root moves to host bind": (
                entrypoint,
                {
                    **harnesses,
                    BOUNDARY_HARNESSES[2].as_posix(): harnesses[
                        BOUNDARY_HARNESSES[2].as_posix()
                    ].replace(
                        'mktemp -d "${TMPDIR:-/tmp}/${prefix}.XXXXXX"',
                        'mktemp -d "$DOCKER_BIND_ROOT/${prefix}.XXXXXX"',
                        1,
                    ),
                },
                "native federation client root",
            ),
            "wheel context moves onto Docker bind root": (
                entrypoint,
                {
                    **harnesses,
                    BOUNDARY_HARNESSES[2].as_posix(): harnesses[
                        BOUNDARY_HARNESSES[2].as_posix()
                    ].replace(
                        'ALPHA_SERVER_CONTEXT="$E2E_ROOT/',
                        'ALPHA_SERVER_CONTEXT="$DOCKER_RUNTIME/',
                        1,
                    ),
                },
                "native alpha wheel build context",
            ),
        }
        for name, (mutated_entrypoint, mutated_harnesses, expected) in mutations.items():
            with self.subTest(mutation=name):
                errors = boundary_contract_errors(mutated_entrypoint, mutated_harnesses)
                self.assertTrue(errors, f"{name} mutation escaped the boundary contract")
                self.assertTrue(
                    any(expected in error for error in errors),
                    f"{name} mutation failed for the wrong reason: {errors}",
                )

    def test_local_quickstart_socats_are_phase_scoped_and_mutation_protected(self) -> None:
        journey = (SCRIPTS / "e2e-oss-user-journey.sh").read_text()
        dockerfile = DOCKERFILE.read_text()
        self.assertEqual(local_bridge_contract_errors(journey, dockerfile), ())
        mutated = journey.replace("TCP4-LISTEN:$AWID_PORT", "listener-removed", 1)
        errors = local_bridge_contract_errors(mutated, dockerfile)
        self.assertIn("AWID same-port socat listener", errors)
        cleanup_mutated = journey.replace("  stop_quickstart_bridges\n", "", 1)
        cleanup_errors = local_bridge_contract_errors(cleanup_mutated, dockerfile)
        self.assertIn("EXIT listener cleanup", cleanup_errors)
        self.assertNotIn('--alias "$local_alias"', journey)
        self.assertNotIn("start_quickstart_socat", journey)
        self.assertIn("AWEB_URL=\"http://$DOCKER_PUBLISHED_HOST", journey)

    def test_oss_temp_allocation_failure_preserves_sentinel_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            scripts = repo / "scripts"
            fake_bin = root / "bin"
            scratch = root / "scratch"
            scripts.mkdir(parents=True)
            fake_bin.mkdir()
            scratch.mkdir()
            harness = scripts / "e2e-oss-user-journey.sh"
            shutil.copy2(SCRIPTS / "e2e-oss-user-journey.sh", harness)
            sentinel = repo / "SENTINEL"
            sentinel.write_text("preserve\n")
            mktemp = fake_bin / "mktemp"
            mktemp.write_text("#!/usr/bin/env bash\necho forced-mktemp-failure >&2\nexit 1\n")
            mktemp.chmod(0o755)
            result = subprocess.run(
                ["bash", str(harness)],
                cwd=repo,
                env={
                    **os.environ,
                    "PATH": f"{fake_bin}:{os.environ['PATH']}",
                    "TMPDIR": str(scratch),
                },
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("could not allocate aw-e2e", result.stderr)
            self.assertEqual(sentinel.read_text(), "preserve\n")
            self.assertTrue(harness.exists())

            mktemp.write_text(
                "#!/bin/bash\n"
                "template=\"${@: -1}\"\n"
                "target=\"${template%.XXXXXX}.forced\"\n"
                "mkdir \"$target\"\n"
                "printf '%s\\n' \"$target\"\n"
            )
            state = root / "bash-count"
            fake_bash = fake_bin / "bash"
            fake_bash.write_text(
                "#!/bin/bash\n"
                f"state={state}\n"
                "if [[ ! -e \"$state\" ]]; then echo 1 >\"$state\"; exec /bin/bash \"$@\"; fi\n"
                "echo forced-validation-failure >&2\n"
                "exit 1\n"
            )
            fake_bash.chmod(0o755)
            result = subprocess.run(
                ["/bin/bash", str(harness)],
                cwd=repo,
                env={
                    **os.environ,
                    "PATH": f"{fake_bin}:{os.environ['PATH']}",
                    "TMPDIR": str(scratch),
                },
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unexpected temp allocation", result.stderr)
            self.assertFalse((scratch / "aw-e2e.forced").exists())
            self.assertEqual(sentinel.read_text(), "preserve\n")

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
                env={
                    **os.environ,
                    "RELEASE_SOURCE_SHA": sha,
                    "RELEASE_BASE_SHA": sha,
                    "LIBRARY_E2E_LIBRARY_CONTEXT": str(repo),
                    "LIBRARY_E2E_BLUEPRINT_SRC": str(repo),
                },
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
            self.assertIn("library input is not a git checkout", result.stderr)

    def test_gate_image_pins_required_toolchain_and_no_publisher_credentials(self) -> None:
        text = DOCKERFILE.read_text()
        for required in ("python:3.12", "node_22.x", "go1.24.13", "docker-ce-cli", "socat", "tmux", "uv"):
            self.assertIn(required, text)
        for forbidden in ("GITHUB_TOKEN", "NPM_TOKEN", "PYPI", "RENDER", "AWS_"):
            self.assertNotIn(forbidden, text)

    def test_capacity_refusal_and_between_row_stop_are_observable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make = root / "make"
            calls = root / "calls"
            make.write_text(
                "#!/usr/bin/env bash\n"
                f"echo \"$1\" >> {calls}\n"
                "exit 0\n"
            )
            make.chmod(0o755)
            suite_map = root / "map.tsv"
            suite_map.write_text(
                "one\tunit\tone\n"
                "two\tunit\ttwo\n"
                "three\tunit\tthree\n"
            )

            low_start = lambda _phase: "required_kib=100 available_kib=7"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = runner.run(suite_map, root / "start-logs", [str(make)], low_start)
            self.assertEqual(status, 1)
            self.assertFalse(calls.exists())
            self.assertIn("required_kib=100 available_kib=7", output.getvalue())
            start_states = [line.split("\t")[1] for line in (root / "start-logs/summary.tsv").read_text().splitlines()]
            self.assertEqual(start_states, ["NOT RUN", "NOT RUN", "NOT RUN"])

            probes = iter((None, "required_kib=50 available_kib=3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = runner.run(
                    suite_map,
                    root / "between-logs",
                    [str(make)],
                    lambda _phase: next(probes),
                )
            self.assertEqual(status, 1)
            self.assertEqual(calls.read_text().splitlines(), ["one"])
            self.assertIn("required_kib=50 available_kib=3", output.getvalue())
            between_states = [line.split("\t")[1] for line in (root / "between-logs/summary.tsv").read_text().splitlines()]
            self.assertEqual(between_states, ["PASSED", "NOT RUN", "NOT RUN"])

            deleted_checkout = root / "deleted-checkout"
            deleted_checkout.mkdir()
            deleted_checkout.rmdir()
            with patch.dict(
                os.environ,
                {"RELEASE_GATE_CHECKOUT_ROOT": str(deleted_checkout)},
            ):
                self.assertIn(
                    "checkout is unavailable",
                    runner.infrastructure_refusal("between"),
                )

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
            suite_map.write_text(
                "one\tunit\tone\n"
                "two\tunit\ttwo\n"
                "three\tunit\tthree\n"
            )
            logs = root / "logs"
            with contextlib.redirect_stdout(io.StringIO()):
                status = runner.run(suite_map, logs, [str(make)], probe=lambda _phase: None)
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
            accepted = root / "membership.tsv"
            accepted.write_text("".join(
                f"row-{index}\tunit\ttarget-{index}\n"
                for index in range(4)
            ))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    runner.run(accepted, logs / "membership", ["true"], probe=lambda _phase: None),
                    0,
                )

    def test_make_help_exposes_exactly_the_two_release_commands(self) -> None:
        result = subprocess.run(
            ["make", "help"], cwd=ROOT, capture_output=True, text=True, check=True
        )
        self.assertNotIn("ship", result.stdout.lower())
        self.assertIn("make release-prepare", result.stdout)
        self.assertIn("release-continue", result.stdout)
        self.assertNotIn("release-plan", result.stdout)
        self.assertNotIn("release-run", result.stdout)
        self.assertNotIn("release-receipt", result.stdout)
        self.assertNotIn("release-local-gate", result.stdout)


if __name__ == "__main__":
    unittest.main()
