from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = REPO_ROOT / "Makefile"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ship.yml"
TEST_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "test.yml"
CONTRIBUTING = REPO_ROOT / "docs" / "contributing.md"


class ShipCIContractTests(unittest.TestCase):
    def assert_ship_job_context(self, workflow: str) -> None:
        jobs = workflow[workflow.index("jobs:\n") + len("jobs:\n") :]
        ship = re.search(r"(?m)^  ship:\s*$", jobs)
        self.assertIsNotNone(ship, "workflow must define jobs.ship")
        remainder = jobs[ship.end() :]
        next_job = re.search(r"(?m)^  [A-Za-z0-9_-]+:\s*$", remainder)
        ship_block = remainder[: next_job.start()] if next_job else remainder
        self.assertRegex(
            ship_block,
            r"(?m)^    name:\s*Comprehensive ship gate\s*$",
            "jobs.ship.name must preserve the required status context",
        )

    def ship_trigger_events(self, workflow: str) -> list:
        """The events in ship.yml's `on:` block, in order.

        Read structurally rather than by searching the whole file, so a trigger
        named in a comment is not mistaken for one that fires - and so an added
        trigger is visible as an extra element rather than hidden behind a
        passing search for the ones that were expected.
        """
        body = workflow.split("\njobs:", 1)[0]
        start = re.search(r"(?m)^on:\s*$", body)
        self.assertIsNotNone(start, "ship.yml must declare an on: block")
        events = []
        for line in body[start.end() :].splitlines():
            if line.strip().startswith("#") or not line.strip():
                continue
            if not line.startswith("  "):
                break
            if line.startswith("   "):
                continue  # nested under an event, not an event itself
            # Quoted keys are real keys to YAML: "pull_request": is a trigger.
            # A bare-identifier regex silently ignored them, so the exact-set
            # assertion could be bypassed by quoting. Anything at this
            # indentation that is not a comment must be recognised or refused.
            event = re.match(r'^  "?([A-Za-z_][A-Za-z_-]*)"?:', line)
            if not event:
                raise AssertionError(f"unparsed trigger line: {line!r}")
            events.append(event.group(1))
        return events

    def ship_push_keys(self, workflow: str) -> list:
        """The keys nested under `push:`, in order."""
        body = workflow.split("\njobs:", 1)[0]
        push = re.search(r"(?m)^  push:\s*$", body)
        self.assertIsNotNone(push, "ship.yml must trigger on push")
        keys = []
        for line in body[push.end() :].splitlines():
            if line.strip().startswith("#") or not line.strip():
                continue
            if not line.startswith("    "):
                break
            if line.startswith("     "):
                continue  # nested under a push key, not a push key itself
            key = re.match(r'^    "?([A-Za-z_][A-Za-z_-]*)"?:', line)
            if not key:
                raise AssertionError(f"unparsed push key line: {line!r}")
            keys.append(key.group(1))
        return keys

    def assert_exact_ship_triggers(self, workflow: str) -> None:
        # Exactly these events, and nothing else. Asserting only that push and
        # workflow_dispatch are present would pass with pull_request added
        # back, which is the regression this contract exists to prevent.
        self.assertEqual(self.ship_trigger_events(workflow), ["push", "workflow_dispatch"])
        # And exactly this INSIDE push. Checking only that `branches: [main]`
        # appears somewhere left `tags:` free to be added beside it, which would
        # run the whole gate on every release tag - the tag-triggered publishing
        # this repository deliberately moved away from. No `paths:` either: a
        # release proof that skipped itself for touching the wrong directory
        # would prove nothing about the commit being released.
        self.assertEqual(self.ship_push_keys(workflow), ["branches"])
        self.assertRegex(workflow, r"(?m)^    branches: \[main\]\s*$")

    def test_workflow_runs_the_canonical_ship_gate_on_main_and_on_demand(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assert_exact_ship_triggers(workflow)
        trigger_mutations = {
            "pull_request re-added": workflow.replace(
                "on:\n  push:", "on:\n  pull_request:\n  push:", 1
            ),
            "schedule added": workflow.replace(
                "  workflow_dispatch:", "  workflow_dispatch:\n  schedule:", 1
            ),
            "dispatch removed": workflow.replace("\n  workflow_dispatch:", "", 1),
            "tag filter added": workflow.replace(
                "  push:\n    branches: [main]",
                '  push:\n    branches: [main]\n    tags: ["*"]', 1
            ),
            "quoted pull_request added": workflow.replace(
                "on:\n  push:", 'on:\n  "pull_request":\n  push:', 1
            ),
            "quoted tag filter added": workflow.replace(
                "  push:\n    branches: [main]",
                '  push:\n    branches: [main]\n    "tags": ["*"]', 1
            ),
            "path filter added": workflow.replace(
                "  push:\n    branches: [main]",
                "  push:\n    branches: [main]\n    paths: [\"server/**\"]", 1
            ),
        }
        for name, mutation in trigger_mutations.items():
            with self.subTest(mutation=name):
                self.assertNotEqual(mutation, workflow, f"the {name} mutation changed nothing")
                with self.assertRaises(AssertionError):
                    self.assert_exact_ship_triggers(mutation)

        self.assertIn("run: make ship", workflow)
        self.assertNotIn("run: make release-all-check", workflow)
        self.assert_ship_job_context(workflow)

        job_name = "    name: Comprehensive ship gate"
        mutations = {
            "missing job context": workflow.replace(f"{job_name}\n", "", 1),
            "renamed job context": workflow.replace(
                job_name, "    name: Renamed ship gate", 1
            ),
        }
        for mutation_name, mutation in mutations.items():
            with self.subTest(mutation=mutation_name):
                with self.assertRaises(AssertionError):
                    self.assert_ship_job_context(mutation)

    def test_pull_requests_still_run_the_test_suite(self) -> None:
        """Ship stopped running on pull requests, so something else has to run
        `make test` there. Without this the trigger diet reads as a saving and
        is a silent loss of every unit suite on every pull request."""
        workflow = TEST_WORKFLOW.read_text(encoding="utf-8")

        self.assertRegex(workflow, r"(?m)^  pull_request:\s*$")
        self.assertNotRegex(workflow, r"(?m)^  pull_request:\n\s+paths:")
        self.assertIn("run: make test", workflow)
        # Cheapness is the point, so assert on what it runs rather than on what
        # it says: the expensive suites are covered by ship and by the focused
        # workflows, and adding one here would rebuild what they already run.
        executable = "\n".join(
            line for line in workflow.splitlines() if not line.lstrip().startswith("#")
        )
        for target in ("make ship", "test-e2e", "test-federation-e2e", "cli-e2e"):
            with self.subTest(target=target):
                self.assertNotIn(target, executable)

    def assert_release_all_checks_cli_vcs_stamps(self, makefile: str) -> None:
        target = self.require_match(
            r"(?m)^check-cli-release-vcs-stamps:\n\t([^\n]+)$",
            makefile,
            "Makefile must define the CLI release VCS-stamp gate",
        )
        self.assertEqual(
            target.group(1),
            "./scripts/check-cli-release-vcs-stamps.sh",
            "the VCS-stamp target must execute the release-boundary regression",
        )

        start = makefile.index("release-all-check:")
        end = makefile.index("# `make ship`", start)
        release_all_check = makefile[start:end]
        self.assertEqual(
            release_all_check.count("$(MAKE) check-cli-release-vcs-stamps"),
            1,
            "release-all-check must run the CLI VCS-stamp gate exactly once",
        )

    def test_release_all_check_gates_cli_vcs_stamps(self) -> None:
        makefile = MAKEFILE.read_text(encoding="utf-8")
        self.assert_release_all_checks_cli_vcs_stamps(makefile)

        mutation = makefile.replace("\t$(MAKE) check-cli-release-vcs-stamps\n", "", 1)
        with self.assertRaises(AssertionError):
            self.assert_release_all_checks_cli_vcs_stamps(mutation)

    def test_makefile_defines_no_all_product_tag_or_push_target(self) -> None:
        makefile = MAKEFILE.read_text(encoding="utf-8")
        for target in ("release-all-tag", "release-all-push"):
            self.assertNotIn(
                target,
                makefile,
                f"{target} must not exist: release tagging is per-component through"
                " each artifact's own tag lane, never one commit tagging every product",
            )

    def test_workflow_materializes_exact_cross_repo_inputs(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        for repository, path in (
            ("awebai/library", "library"),
            ("awebai/blueprints", "blueprints"),
        ):
            with self.subTest(repository=repository):
                checkout = re.search(
                    rf"repository:\s*{re.escape(repository)}\s+"
                    rf"ref:\s*([0-9a-f]{{40}})\s+"
                    rf"path:\s*{path}\b",
                    workflow,
                )
                self.assertIsNotNone(
                    checkout,
                    f"{repository} must be checked out at an exact commit into {path}",
                )

        self.assertRegex(
            workflow,
            r"(?s)Checkout aweb.*?fetch-depth:\s*0.*?path:\s*aweb\b",
        )
        self.assertIn("working-directory: aweb", workflow)
        self.assertIn("LIBRARY_E2E_LIBRARY_CONTEXT: ${{ github.workspace }}/library", workflow)
        self.assertIn(
            "LIBRARY_E2E_BLUEPRINT_SRC: ${{ github.workspace }}/blueprints/team",
            workflow,
        )

    def test_workflow_provisions_the_existing_real_docker_journeys(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("docker/setup-buildx-action@v4", workflow)
        self.assertIn("crazy-max/ghaction-github-runtime@v4", workflow)
        self.assertIn("mirror.gcr.io", workflow)
        self.assertIn("LIBRARY_E2E_COMPOSE_OVERLAY:", workflow)
        self.assertRegex(workflow, r"(?m)^    timeout-minutes:\s*\d+\s*$")
        cli_build = workflow.index("\n          make build\n")
        cli_path = workflow.index("$GITHUB_PATH")
        ship_run = workflow.index("run: make ship")
        self.assertLess(cli_build, cli_path)
        self.assertLess(cli_path, ship_run)

        makefile = MAKEFILE.read_text(encoding="utf-8")
        self.assertRegex(
            makefile,
            r"(?m)^test-oas:\s+check-oas-launch-environment-contract\s+check-oas-pi-launch-order\s+build\s+test-node-deps$",
        )
        self.assertIn(
            'PATH="$(CURDIR)/cli/go:$(CURDIR)/pi-extension/node_modules/.bin:$$PATH"',
            makefile,
        )
        self.assert_ship_runs_every_suite_independently(makefile)

    # The suites used to be recipe lines in `ship`, where make stops at the first
    # failure and takes the remaining suites' coverage with it. They are now a list
    # handed to a runner. So the contract is no longer "these lines appear
    # somewhere in the recipe" - it is that the gate's suite list is exactly the
    # expected set, that each name is a real target, and that the runner is what
    # consumes the list.
    EXPECTED_SHIP_SUITES = frozenset(
        # test-channel-integration added deliberately: channel/package.json
        # excludes test/integration.test.ts from `npm test`, so the one test
        # driving Channel against a real aweb server ran nowhere. It was green
        # by absence and failed the first time it was executed.
        {"release-awid-check", "test-channel-integration",
         "test-federation-e2e", "test-e2e", "cli-e2e"}
    )

    def require_match(self, pattern: str, text: str, message: str) -> re.Match[str]:
        """Assert the pattern matches and hand back the match, narrowed."""
        found = re.search(pattern, text)
        self.assertIsNotNone(found, message)
        assert found is not None
        return found

    def assert_ship_runs_every_suite_independently(self, makefile: str) -> None:
        # := rather than ?= so the environment cannot change what the gate runs.
        suites = self.require_match(
            r"(?m)^SHIP_SUITES\s*:=\s*(.+)$", makefile, "Makefile must define SHIP_SUITES"
        )
        listed = set(suites.group(1).split())
        self.assertEqual(
            listed,
            set(self.EXPECTED_SHIP_SUITES),
            "SHIP_SUITES must be exactly the expected suites; adding or dropping "
            "one is a deliberate edit to this contract",
        )

        # A name in the list that is not a target would fail only at gate time.
        for suite in sorted(listed):
            with self.subTest(suite=suite):
                self.assertRegex(
                    makefile,
                    rf"(?m)^{re.escape(suite)}:",
                    f"SHIP_SUITES names {suite}, which is not a Makefile target",
                )

        # The list is only meaningful if the runner receives it, and the runner is
        # what makes the suites independent of each other.
        ship_suites = self.require_match(
            r"(?m)^ship-suites:\n(?:\t.*\n)+",
            makefile,
            "Makefile must define a ship-suites target",
        )
        self.assertIn(
            "./scripts/run-ship-suites.sh $(SHIP_SUITES)",
            ship_suites.group(0),
            "ship-suites must hand the whole suite list to the runner",
        )

        ship = self.require_match(
            r"(?m)^ship: check-ship-invocation\n(?:\t.*\n)+",
            makefile,
            "ship must refuse overridden invocations before anything else runs",
        )
        self.assertIn(
            "./scripts/ship-env.sh",
            ship.group(0),
            "ship must run the gate under the environment owner so ambient services"
            " are provisioned or reused deterministically",
        )
        gate = self.require_match(
            r"(?m)^ship-gate: check-ship-owner\n(?:\t.*\n)+",
            makefile,
            "ship-gate's only prerequisite is the owner check: a sibling"
            " prerequisite races it under parallel make",
        )
        self.assertIn(
            "$(MAKE) release-all-check",
            gate.group(0),
            "ship-gate must run release-all-check from its recipe, after the"
            " owner check has succeeded",
        )
        self.assertIn(
            "$(MAKE) ship-suites",
            gate.group(0),
            "ship-gate must run the suites through ship-suites rather than as recipe lines",
        )

        # cli-e2e could exist as a name while doing nothing.
        cli_e2e = self.require_match(
            r"(?m)^cli-e2e:\n(?:\t.*\n)+", makefile, "Makefile must define a cli-e2e target"
        )
        self.assertIn("$(MAKE) -C cli e2e", cli_e2e.group(0))

        runner = REPO_ROOT / "scripts" / "run-ship-suites.sh"
        self.assertTrue(runner.is_file(), f"{runner} must exist")

    ENV_SCRIPT = REPO_ROOT / "scripts" / "ship-env.sh"

    def refuse(self, cmd: list[str], env: dict[str, str], must_name: str) -> None:
        result = subprocess.run(
            cmd, cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=60
        )
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, f"{cmd} must refuse")
        self.assertIn("refuses", output, f"{cmd} must refuse, not fail incidentally")
        self.assertIn(must_name, output, "the refusal must name the cause")

    def test_ship_invocation_guard_refuses_release_variable_overrides(self) -> None:
        """Any command-line override rides MAKEOVERRIDES into nested makes:
        CLI_VERSION contaminates the version scenario fixtures, and SHIP_SUITES=
        can silently empty the suite list while the run still reports green."""
        base_env = {k: v for k, v in os.environ.items() if k != "CLI_VERSION"}
        for override in (
            "CLI_VERSION=9.9.9",
            "SERVER_VERSION=9.9.9",
            "AWID_VERSION=9.9.9",
            "CHANNEL_VERSION=9.9.9",
            "SHIP_SUITES=",
        ):
            self.refuse(
                ["make", "-s", "check-ship-invocation", override],
                base_env,
                override.split("=")[0],
            )
        self.refuse(
            ["make", "-s", "check-ship-invocation"],
            {**base_env, "CLI_VERSION": "9.9.9"},
            "CLI_VERSION",
        )
        clean = subprocess.run(
            ["make", "-s", "check-ship-invocation"],
            cwd=REPO_ROOT,
            env=base_env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(clean.returncode, 0, clean.stdout + clean.stderr)

    def test_internal_gate_targets_cannot_bypass_the_guard(self) -> None:
        """release-all-check and ship-gate are reachable by name, so each must
        carry the envelope itself: the override guard on release-all-check, the
        environment-owner marker on ship-gate."""
        base_env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("CLI_VERSION", "AWEB_SHIP_ENV_READY")
        }
        self.refuse(
            ["make", "-s", "release-all-check", "CLI_VERSION=9.9.9"],
            base_env,
            "CLI_VERSION",
        )
        self.refuse(
            ["make", "-s", "release-all-check", "SHIP_SUITES="],
            base_env,
            "SHIP_SUITES",
        )
        self.refuse(["make", "-s", "ship-gate"], base_env, "ship-env")
        self.refuse(
            ["make", "-s", "check-ship-invocation", "MAKEOVERRIDES="],
            base_env,
            "MAKEOVERRIDES",
        )
        self.refuse(
            [
                "make",
                "-s",
                "check-ship-invocation",
                "MAKEOVERRIDES=",
                "OAS_TEST_ROOT=/tmp/not-canonical",
            ],
            base_env,
            "MAKEOVERRIDES",
        )
        self.refuse(
            ["make", "-s", "ship-gate", "SHIP_SUITES="],
            {**base_env, "AWEB_SHIP_ENV_READY": "1"},
            "SHIP_SUITES",
        )
        parallel = subprocess.run(
            ["make", "-j2", "ship-gate"],
            cwd=REPO_ROOT,
            env=base_env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        output = parallel.stdout + parallel.stderr
        self.assertNotEqual(parallel.returncode, 0)
        self.assertIn("refuses", output)
        self.assertNotIn(
            "Validating versions",
            output,
            "under parallel make the gate must not start before the owner refusal",
        )

    def test_ship_environment_owner_proves_its_arms(self) -> None:
        """Exit 0 alone would pass a self-test gutted to a no-op; require each
        arm's evidence line, like the suite runner's self-test."""
        result = subprocess.run(
            ["bash", str(self.ENV_SCRIPT), "--self-test"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        self.assertEqual(
            result.returncode,
            0,
            f"ship-env self-test failed:\n{result.stdout}\n{result.stderr}",
        )
        for arm in (
            "reachable services are reused and no container is started",
            "a plain local run provisions even when a foreign service is listening",
            "provisioning never touches containers it did not create",
            "cleanup removes exactly the created container ids",
            "cleanup runs even when the gate fails",
            "concurrent provisioning runs do not collide",
            "a mismatched Go toolchain is refused with the fix",
        ):
            self.assertIn(arm, result.stdout, f"self-test must prove: {arm}")

    def test_workflow_provisions_the_production_postgres_major(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            "postgres:17",
            workflow,
            "the hosted gate must run the PostgreSQL major production runs (17)",
        )
        self.assertNotIn("postgres:16", workflow)

    def test_cli_version_scenarios_carry_the_override_leak_probe(self) -> None:
        harness = (REPO_ROOT / "scripts" / "check-cli-release-version-test.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "leaked into scenario fixtures",
            harness,
            "the scenario harness must probe that an outer CLI_VERSION cannot"
            " reach its fixtures through MAKEFLAGS or the environment",
        )

    RUNNER = REPO_ROOT / "scripts" / "run-ship-suites.sh"

    # What the runner's self-test must be seen to have proved. Requiring exit 0
    # alone would pass a self-test gutted to a no-op.
    RUNNER_SELF_TEST_ARMS = (
        "suite-b failed, suite-c still ran",
        "an unlaunchable suite reports FAILED and the run is red",
        "an interrupted run reports suite-a PASSED and suite-c NOT RUN",
        "a lost summary is red and says so",
    )

    def run_runner_self_test(self, runner: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(runner), "--self-test"],
            capture_output=True,
            text=True,
            timeout=300,
        )

    def test_runner_self_test_is_not_optional(self) -> None:
        """The runner's behaviour is what this task delivers, so verifying it runs here.

        The contract assertions above check the wiring - which suites, which target,
        which script. They pass with the runner reverted to stopping at the first
        failure, which is the whole defect. Only the runner's own self-test catches
        that, so it cannot be a script somebody remembers to run.
        """
        result = self.run_runner_self_test(self.RUNNER)
        self.assertEqual(
            result.returncode,
            0,
            f"the ship suite runner's self-test failed:\n{result.stdout}\n{result.stderr}",
        )
        for arm in self.RUNNER_SELF_TEST_ARMS:
            with self.subTest(arm=arm):
                self.assertIn(
                    arm,
                    result.stdout,
                    "the self-test passed without reporting this arm, so it proved less than it claims",
                )

    # Each arm's sensitivity has to be provable on its own. Requiring the four
    # confirmation lines proves they were PRINTED: an arm whose assertion is
    # neutered still prints its line, which was measured. So for each arm, break
    # the behaviour that arm guards and require the self-test to go red naming
    # that arm - and pick a mutation narrow enough that an earlier arm does not
    # fail first and mask it.
    #
    # Arm 4, the lost-summary arm, is deliberately absent. Its property is held
    # three times over - init_state refuses at creation, record refuses rather
    # than blocking, summarize exits from the trap as a backstop - so no single
    # mutation makes it fail, and a redundantly-held property cannot be
    # mutation-tested. Recorded rather than faked.
    RUNNER_ARM_MUTATIONS = (
        (
            "independence: stop at the first failing suite",
            '    "$MAKE" "$suite" && status=0 || status=$?',
            '    "$MAKE" "$suite" || return 1',
            "suite-c never executed",
        ),
        (
            "unlaunchable suite counted as passing",
            '    if [[ "$status" -eq 0 ]]; then\n      record "$suite" "PASSED"',
            '    if [[ "$status" -eq 0 || "$status" -eq 127 ]]; then\n      record "$suite" "PASSED"',
            "every suite failed to launch and the run still exited 0",
        ),
        (
            "NOT RUN rows omitted from the summary",
            "    printf '  %-10s %s\\n' \"$result\" \"$suite\"",
            "    [[ \"$result\" == \"NOT RUN\" ]] || printf '  %-10s %s\\n' \"$result\" \"$suite\"",
            "not reported as NOT RUN",
        ),
    )

    def test_each_self_test_arm_can_fail(self) -> None:
        """Every arm must go red when the behaviour it guards breaks, and name itself."""
        original = self.RUNNER.read_text(encoding="utf-8")

        for label, anchor, replacement, expected in self.RUNNER_ARM_MUTATIONS:
            with self.subTest(mutation=label):
                self.assertEqual(
                    original.count(anchor),
                    1,
                    f"the anchor for '{label}' is not unique; update it if the runner moved",
                )
                mutated = original.replace(anchor, replacement, 1)
                self.assertNotEqual(mutated, original, f"the '{label}' mutation changed nothing")

                with tempfile.TemporaryDirectory() as work:
                    probe = Path(work) / "run-ship-suites.sh"
                    probe.write_text(mutated, encoding="utf-8")
                    shutil.copymode(self.RUNNER, probe)
                    # Assert the mutation is really gone from what will run: a probe
                    # that never applied reports exit 0 and reads as "cannot detect".
                    self.assertNotIn(anchor, probe.read_text(encoding="utf-8"))
                    result = self.run_runner_self_test(probe)

                self.assertNotEqual(
                    result.returncode,
                    0,
                    f"the self-test passed with '{label}' broken, so no arm covers it",
                )
                self.assertIn(
                    expected,
                    result.stdout + result.stderr,
                    f"the self-test went red for '{label}' but did not name it, "
                    "so the red does not identify which property broke",
                )

    def test_ship_suite_contract_rejects_a_dropped_or_renamed_suite(self) -> None:
        """The assertions above must fail when the property they name is broken."""
        makefile = MAKEFILE.read_text(encoding="utf-8")
        self.assert_ship_runs_every_suite_independently(makefile)

        original = self.require_match(
            r"(?m)^SHIP_SUITES\s*:=\s*.+$", makefile, "Makefile must define SHIP_SUITES"
        ).group(0)
        mutations = {
            "a dropped suite": makefile.replace(
                original, original.replace(" test-e2e", ""), 1
            ),
            "a suite that is not a target": makefile.replace(
                original, original + " test-e2e-typo", 1
            ),
            "an environment-overridable list": makefile.replace(
                original, original.replace(":=", "?=", 1), 1
            ),
            "the runner bypassed": makefile.replace(
                "./scripts/run-ship-suites.sh $(SHIP_SUITES)", "true", 1
            ),
            "ship not calling ship-suites": makefile.replace(
                "\t$(MAKE) ship-suites\n", "", 1
            ),
        }
        for name, mutation in mutations.items():
            with self.subTest(mutation=name):
                # A replace that silently matched nothing would leave the text
                # unchanged, and the mutation would be testing the clean file.
                self.assertNotEqual(
                    mutation, makefile, f"the {name} mutation did not change the Makefile"
                )
                with self.assertRaises(AssertionError):
                    self.assert_ship_runs_every_suite_independently(mutation)

    # Branch protection is not asserted here. aweb main is the shared sync
    # branch and cannot be protected - the protection endpoint returns 404, as
    # .github/workflows/library-ci.yml records against the same check name in
    # awebai/library, where it IS enforced. Where protection is enforceable the
    # GitHub API is the thing to query; prose cannot stand in for it, and
    # pinning a policy this repository cannot have made writing the truth the
    # failing action.
    def test_docs_name_the_canonical_ship_gate(self) -> None:
        contributing = CONTRIBUTING.read_text(encoding="utf-8")

        self.assertIn("make ship", contributing)
        self.assertIn("Comprehensive ship gate", contributing)


if __name__ == "__main__":
    unittest.main()
