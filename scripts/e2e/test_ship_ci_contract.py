from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = REPO_ROOT / "Makefile"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ship.yml"
CONTRIBUTING = REPO_ROOT / "docs" / "contributing.md"
CHANNEL_PACKAGE = REPO_ROOT / "channel" / "package.json"
CHANNEL_INTEGRATION_TEST = REPO_ROOT / "channel" / "test" / "integration.test.ts"
CHANNEL_INTEGRATION_RUNNER = REPO_ROOT / "scripts" / "run-channel-integration.sh"


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

    def test_workflow_runs_the_canonical_ship_gate_on_every_change(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertRegex(workflow, r"(?m)^  pull_request:\s*$")
        self.assertRegex(workflow, r"(?m)^  push:\s*$")
        self.assertNotRegex(workflow, r"(?m)^  pull_request:\n\s+paths:")
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
            r"(?m)^test-oas:\s+check-oas-launch-environment-contract\s+build\s+test-node-deps$",
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
        {
            "release-awid-check",
            "test-channel-integration",
            "test-federation-e2e",
            "test-e2e",
            "cli-e2e",
        }
    )

    def require_match(self, pattern: str, text: str, message: str) -> re.Match[str]:
        """Assert the pattern matches and hand back the match, narrowed."""
        found = re.search(pattern, text)
        self.assertIsNotNone(found, message)
        assert found is not None
        return found

    def assert_ship_runs_every_suite_independently(self, makefile: str) -> None:
        # `override :=` defeats both environment values and make -e.
        suites = self.require_match(
            r"(?m)^override SHIP_SUITES\s*:=\s*(.+)$",
            makefile,
            "Makefile must define a non-overridable SHIP_SUITES",
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
            "SHIP_SUITE_MAKE=make ./scripts/run-ship-suites.sh $(SHIP_SUITES)",
            ship_suites.group(0),
            "ship-suites must hand the whole suite list to the runner",
        )

        ship = makefile[makefile.index("ship: release-all-check") :]
        self.assertIn(
            "+@make ship-suites",
            ship,
            "ship must use literal make to reach ship-suites rather than inherited MAKE",
        )

        # cli-e2e could exist as a name while doing nothing.
        cli_e2e = self.require_match(
            r"(?m)^cli-e2e:\n(?:\t.*\n)+", makefile, "Makefile must define a cli-e2e target"
        )
        self.assertIn("$(MAKE) -C cli e2e", cli_e2e.group(0))

        runner = REPO_ROOT / "scripts" / "run-ship-suites.sh"
        self.assertTrue(runner.is_file(), f"{runner} must exist")

    def test_channel_real_stack_suite_is_complete_and_release_connected(self) -> None:
        makefile = MAKEFILE.read_text(encoding="utf-8")
        package = json.loads(CHANNEL_PACKAGE.read_text(encoding="utf-8"))
        integration = CHANNEL_INTEGRATION_TEST.read_text(encoding="utf-8")
        runner = CHANNEL_INTEGRATION_RUNNER.read_text(encoding="utf-8")

        self.assertEqual(
            package["scripts"]["test"],
            "vitest run --exclude test/integration.test.ts",
            "the normal channel unit gate must remain separate from the real-stack suite",
        )
        self.assertEqual(
            package["scripts"]["test:integration"],
            "vitest run test/integration.test.ts",
            "test:integration must execute the real-stack test file rather than a broader or empty selector",
        )

        target = self.require_match(
            r"(?m)^test-channel-integration:[^\n]*\n(?:\t.*\n)+",
            makefile,
            "Makefile must own a channel real-stack release target",
        )
        self.assertIn(
            "./scripts/run-channel-integration.sh",
            target.group(0),
            "the release target must use the cleanup-owning integration runner",
        )

        for marker in (
            'npm run test:integration',
            'CHANNEL_INTEGRATION_COMPOSE_PROJECT="$PROJECT"',
            'CHANNEL_INTEGRATION_TEMP_ROOT="$RUNTIME"',
            'trap cleanup EXIT',
            'down -v --remove-orphans',
            'com.docker.compose.project="$PROJECT"',
        ):
            with self.subTest(runner_marker=marker):
                self.assertIn(marker, runner)
        self.assertIn("AWEB_TEST_URL", runner)
        self.assertIn("AWID_TEST_URL", runner)
        self.assertNotIn("docker system prune", runner)
        self.assertNotIn("docker kill", runner)

        self.assertIn('"--project-name", server.projectName', integration)
        self.assertIn("projectName,", integration)

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
            '    env -u MAKEFLAGS -u MFLAGS "$SUITE_MAKE" "$suite" && status=0 || status=$?',
            '    env -u MAKEFLAGS -u MFLAGS "$SUITE_MAKE" "$suite" || return 1',
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
            r"(?m)^override SHIP_SUITES\s*:=\s*.+$",
            makefile,
            "Makefile must define SHIP_SUITES",
        ).group(0)
        mutations = {
            "a dropped suite": makefile.replace(
                original, original.replace(" test-e2e", ""), 1
            ),
            "a suite that is not a target": makefile.replace(
                original, original + " test-e2e-typo", 1
            ),
            "an environment-overridable list": makefile.replace(
                original, original.replace("override ", "", 1), 1
            ),
            "the runner bypassed": makefile.replace(
                "SHIP_SUITE_MAKE=make ./scripts/run-ship-suites.sh $(SHIP_SUITES)",
                "true",
                1,
            ),
            "ship not calling ship-suites": makefile.replace(
                "\t+@make ship-suites\n", "", 1
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

    def test_docs_state_that_hosted_success_must_be_required(self) -> None:
        contributing = CONTRIBUTING.read_text(encoding="utf-8")

        self.assertIn("make ship", contributing)
        self.assertIn("Comprehensive ship gate", contributing)
        self.assertIn("required status check", contributing)
        self.assertIn("strict up-to-date", contributing)
        self.assertIn("administrators", contributing)


if __name__ == "__main__":
    unittest.main()
