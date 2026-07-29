from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = REPO_ROOT / "Makefile"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ship.yml"
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
        {"release-awid-check", "test-federation-e2e", "test-e2e", "cli-e2e"}
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

        ship = makefile[makefile.index("ship: release-all-check") :]
        self.assertIn(
            "$(MAKE) ship-suites",
            ship,
            "ship must run the suites through ship-suites rather than as recipe lines",
        )

        # cli-e2e could exist as a name while doing nothing.
        cli_e2e = self.require_match(
            r"(?m)^cli-e2e:\n(?:\t.*\n)+", makefile, "Makefile must define a cli-e2e target"
        )
        self.assertIn("$(MAKE) -C cli e2e", cli_e2e.group(0))

        runner = REPO_ROOT / "scripts" / "run-ship-suites.sh"
        self.assertTrue(runner.is_file(), f"{runner} must exist")

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

    def test_docs_state_that_hosted_success_must_be_required(self) -> None:
        contributing = CONTRIBUTING.read_text(encoding="utf-8")

        self.assertIn("make ship", contributing)
        self.assertIn("Comprehensive ship gate", contributing)
        self.assertIn("required status check", contributing)
        self.assertIn("strict up-to-date", contributing)
        self.assertIn("administrators", contributing)


if __name__ == "__main__":
    unittest.main()
