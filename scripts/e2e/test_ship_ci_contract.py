from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = REPO_ROOT / "Makefile"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release-all-check.yml"
CONTRIBUTING = REPO_ROOT / "docs" / "contributing.md"


class ShipCIContractTests(unittest.TestCase):
    def test_workflow_runs_the_canonical_ship_gate_on_every_change(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertRegex(workflow, r"(?m)^  pull_request:\s*$")
        self.assertRegex(workflow, r"(?m)^  push:\s*$")
        self.assertNotRegex(workflow, r"(?m)^  pull_request:\n\s+paths:")
        self.assertIn("name: Comprehensive ship gate", workflow)
        self.assertIn("run: make ship", workflow)
        self.assertNotIn("run: make release-all-check", workflow)

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
        ship = makefile[makefile.index("ship: release-all-check") :]
        self.assertIn("$(MAKE) release-awid-check", ship)
        self.assertIn("$(MAKE) test-federation-e2e", ship)
        self.assertIn("$(MAKE) test-e2e", ship)
        self.assertIn("$(MAKE) -C cli e2e", ship)

    def test_docs_state_that_hosted_success_must_be_required(self) -> None:
        contributing = CONTRIBUTING.read_text(encoding="utf-8")

        self.assertIn("make ship", contributing)
        self.assertIn("Comprehensive ship gate", contributing)
        self.assertIn("required status check", contributing)
        self.assertIn("strict up-to-date", contributing)
        self.assertIn("administrators", contributing)


if __name__ == "__main__":
    unittest.main()
