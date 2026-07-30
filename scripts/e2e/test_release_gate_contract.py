"""The three unrecoverable publishes refuse unless their suite passed here.

PyPI never lets a version be re-uploaded and a container tag that consumers have
already pulled cannot be recalled, so aweb on PyPI, awid-service on PyPI and the
awid image on GHCR each have to establish that the artifact's own suite passed on
the commit being published - not on main, not on a recent run.

Each of those three workflows triggers only on its tag push, and a tag push runs
the workflow file, and checks out the tree, at the tagged commit. So a gate step
placed before the publishing step in the same job runs against exactly the commit
that is about to be published, and GitHub's fail-fast step semantics mean the
publish is never reached when it fails. This asserts that wiring, and mutates it
to show the assertions can fail.
"""

from __future__ import annotations

import os
import re
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

CHECKOUT_STEP = "      - uses: actions/checkout@v7\n"
CHECKOUT_ON_MAIN = (
    "      - uses: actions/checkout@v7\n        with:\n          ref: main\n\n"
)

STEP_START = re.compile(r"(?m)^      - ")
STEP_CONDITION = re.compile(r"(?m)^        if:")
STEP_CONTINUE_ON_ERROR = re.compile(r"(?m)^        continue-on-error:")
JOB_NAME = re.compile(r"(?m)^  ([A-Za-z0-9_-]+):\s*$")


class Surface:
    """One unrecoverable publishing surface and the gate that must precede it."""

    def __init__(
        self,
        name: str,
        workflow: str,
        tag_pattern: str,
        gate_command: str,
        publish_markers: tuple[str, ...],
        gate_must_run: tuple[str, ...],
        gate_must_not_run: tuple[str, ...] = (),
    ) -> None:
        self.name = name
        self.workflow = workflow
        self.tag_pattern = tag_pattern
        self.gate_command = gate_command
        self.publish_markers = publish_markers
        self.gate_must_run = gate_must_run
        self.gate_must_not_run = gate_must_not_run

    def read(self) -> str:
        return (WORKFLOWS / self.workflow).read_text(encoding="utf-8")


SURFACES = (
    Surface(
        name="aweb server on PyPI",
        workflow="server-release.yml",
        tag_pattern="server-v*",
        gate_command="run: make release-server-gate",
        publish_markers=("run: uv publish",),
        gate_must_run=("uv lock --check", "pytest", "uv build"),
    ),
    Surface(
        name="awid-service on PyPI",
        workflow="awid-pypi-release.yml",
        tag_pattern="awid-service-v*",
        gate_command="run: make release-awid-pypi-gate",
        publish_markers=("run: uv publish",),
        gate_must_run=("uv lock --check", "pytest", "uv build"),
    ),
    Surface(
        name="awid image on GHCR",
        workflow="awid-release.yml",
        tag_pattern="awid-v*",
        gate_command="run: make release-awid-image-gate",
        publish_markers=("docker/build-push-action",),
        gate_must_run=("uv lock --check", "pytest"),
        # The publishing build is the gating build: build-push-action cannot push
        # an image that failed to build, and it is the only build that covers both
        # published platforms. A separate gate build would verify amd64 only.
        gate_must_not_run=("docker build",),
    ),
)


class ReleaseGateContractTests(unittest.TestCase):
    def steps_of_single_job(self, workflow: str) -> list[str]:
        """Ordered step blocks of the workflow's only job."""

        jobs = workflow[workflow.index("jobs:\n") + len("jobs:\n") :]
        self.assertEqual(
            JOB_NAME.findall(jobs),
            ["publish"],
            "the gate and the publish must share one job, so they share one checkout",
        )
        marker = "\n    steps:\n"
        body = jobs[jobs.index(marker) + len(marker) :]
        starts = [match.start() for match in STEP_START.finditer(body)]
        self.assertTrue(starts, "the job must declare steps")
        bounds = starts + [len(body)]
        return [body[bounds[i] : bounds[i + 1]] for i in range(len(starts))]

    def assert_publish_is_gated(self, surface: Surface, workflow: str) -> None:
        steps = self.steps_of_single_job(workflow)

        gate_positions = [i for i, step in enumerate(steps) if surface.gate_command in step]
        self.assertEqual(
            len(gate_positions),
            1,
            f"{surface.workflow} must run '{surface.gate_command}' exactly once",
        )
        gate = gate_positions[0]

        self.assertIsNone(
            STEP_CONDITION.search(steps[gate]),
            "a conditional gate is a gate that can be skipped",
        )
        self.assertIsNone(
            STEP_CONTINUE_ON_ERROR.search(steps[gate]),
            "continue-on-error would let the publish run after the gate failed",
        )

        # The tree under the gate has to be the tree that gets published, which is
        # what a tag push checks out by default. One checkout, taking that default,
        # is the only arrangement in which that needs no further argument: a second
        # checkout could replace the tested tree before the publish, and an explicit
        # ref could name a different tree from the outset.
        checkouts = [i for i, step in enumerate(steps) if "actions/checkout" in step]
        self.assertEqual(
            len(checkouts),
            1,
            "the job must check out once; a later checkout can replace the tested tree",
        )
        self.assertLess(
            checkouts[0],
            gate,
            "the gate must run against the checked-out tagged commit",
        )
        self.assertNotIn(
            "ref:",
            steps[checkouts[0]],
            "the checkout must take the tag's own commit, not name a ref",
        )

        publishes = [
            i
            for i, step in enumerate(steps)
            if any(marker in step for marker in surface.publish_markers)
        ]
        self.assertTrue(
            publishes,
            f"{surface.workflow} must contain a publishing step to gate",
        )
        self.assertLess(
            gate,
            min(publishes),
            "every publishing step must come after the gate",
        )

    def test_each_surface_gates_its_publish_on_its_own_suite(self) -> None:
        for surface in SURFACES:
            with self.subTest(surface=surface.name):
                self.assert_publish_is_gated(surface, surface.read())

    def test_the_gate_assertions_fail_when_the_wiring_is_broken(self) -> None:
        """Without this, a passing contract proves only that it was never asked."""

        for surface in SURFACES:
            workflow = surface.read()
            steps = self.steps_of_single_job(workflow)
            gate_step = next(step for step in steps if surface.gate_command in step)
            publish_step = next(
                step
                for step in steps
                if any(marker in step for marker in surface.publish_markers)
            )

            mutations = {
                "gate removed": workflow.replace(gate_step, "", 1),
                "gate skipped by a condition": workflow.replace(
                    gate_step,
                    gate_step.rstrip("\n") + "\n        if: false\n\n",
                    1,
                ),
                "gate failure tolerated": workflow.replace(
                    gate_step,
                    gate_step.rstrip("\n") + "\n        continue-on-error: true\n\n",
                    1,
                ),
                # These two are the substitution the whole task exists to prevent:
                # the gate runs, passes, and reports on a tree other than the one
                # the tag points at. Neither changes the step ORDER.
                "checkout pinned to main": workflow.replace(
                    CHECKOUT_STEP, CHECKOUT_ON_MAIN, 1
                ),
                "second checkout of main after the gate": workflow.replace(
                    gate_step, gate_step + CHECKOUT_ON_MAIN, 1
                ),
                "gate moved after the publish": workflow.replace(
                    gate_step, "", 1
                ).replace(publish_step, publish_step + gate_step, 1),
            }
            for name, mutation in mutations.items():
                with self.subTest(surface=surface.name, mutation=name):
                    with self.assertRaises(AssertionError):
                        self.assert_publish_is_gated(surface, mutation)

    def test_the_suites_have_the_services_they_need_to_run(self) -> None:
        """A gate that cannot reach Postgres errors instead of gating."""

        for surface in SURFACES:
            with self.subTest(surface=surface.name):
                workflow = surface.read()
                self.assertIn("image: postgres:16", workflow)
                for setting in (
                    "PGHOST: localhost",
                    "PGPORT:",
                    "PGUSER: postgres",
                    "PGPASSWORD: postgres",
                    "PGDATABASE: postgres",
                ):
                    self.assertIn(setting, workflow)

    def test_the_tag_push_is_the_only_way_in(self) -> None:
        """A second trigger would be a publish path the gate was never asked about."""

        for surface in SURFACES:
            with self.subTest(surface=surface.name):
                workflow = surface.read()
                start = re.search(r"(?m)^on:$", workflow)
                if start is None:
                    self.fail(f"{surface.workflow} must declare triggers")
                triggers = workflow[start.start() : workflow.index("jobs:\n")]
                self.assertRegex(triggers, r"(?m)^  push:\s*$")
                self.assertRegex(triggers, r"(?m)^    tags:\s*$")
                self.assertIn(surface.tag_pattern, triggers)
                for other in ("workflow_dispatch", "pull_request", "schedule", "branches:"):
                    self.assertNotIn(other, triggers)

    def test_the_gate_target_runs_the_artifact_suite_against_the_committed_lock(
        self,
    ) -> None:
        """Resolved through make itself, so prerequisites count as coverage."""

        for surface in SURFACES:
            with self.subTest(surface=surface.name):
                target = surface.gate_command.split("make ", 1)[1]
                # Run the child make free of the parent's MAKEFLAGS, so the plan
                # asserted below is the committed Makefile's rather than one
                # bent by how the caller happened to invoke `make test` -
                # command-line variable overrides propagate through MAKEFLAGS.
                #
                # --dry-run DOES NOT MEAN NOTHING RUNS. make executes two things
                # regardless of -n: a recipe line containing $(MAKE), and every
                # $(shell ...) in a := assignment, which is evaluated when the
                # Makefile is PARSED. This test is safe today because the gate
                # targets' recipes contain no $(MAKE) - they are rm -rf, uv build
                # and test -f, which -n prints - and because the four := $(shell)
                # assignments only read files (two sed, two node -p). CLI_VERSION
                # calls a script but is recursive (=), so it expands only where it
                # is used.
                #
                # ADDING A $(MAKE) LINE TO A GATE TARGET WOULD MAKE THIS TEST RUN
                # IT. That is the condition to preserve; the flag's name will not
                # warn you. aweb-aaxk.
                env = {
                    key: value
                    for key, value in os.environ.items()
                    if key not in ("MAKEFLAGS", "MFLAGS", "MAKELEVEL")
                }
                plan = subprocess.run(
                    ["make", "--dry-run", target],
                    cwd=REPO_ROOT,
                    capture_output=True,
                    text=True,
                    check=True,
                    env=env,
                ).stdout
                for command in surface.gate_must_run:
                    self.assertIn(command, plan, f"{target} must run {command}")
                for command in surface.gate_must_not_run:
                    self.assertNotIn(command, plan, f"{target} must not run {command}")
                self.assertNotIn(
                    "uv lock\n",
                    plan,
                    f"{target} must verify the committed lock, never repair it",
                )
                self.assertNotIn(
                    "uv publish",
                    plan,
                    f"{target} is a gate and must not publish anything",
                )


if __name__ == "__main__":
    unittest.main()
