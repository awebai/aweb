"""The three unrecoverable publishes refuse unless their suite passed here.

PyPI never lets a version be re-uploaded and a container tag that consumers
have already pulled cannot be recalled, so aweb on PyPI, awid-service on PyPI
and the awid image on GHCR each have to establish that the artifact's own
suite passed on the commit being published - not on main, not on a recent run.

In the dispatch-only three-mode lanes that property has two halves. The STAGE
job checks out the exact declared source, runs the gate suite inside that
checkout unconditionally, and only then seals and uploads digests of the built
artifacts; GitHub's fail-fast step semantics mean nothing is sealed when the
gate fails. The PUBLISH job never builds: it may only run in
publish-continuation mode, and before any outward step it proves the staged
artifact's provenance (this repository, this exact workflow file, a
successful run) and digest identity, then re-inspects the bytes. So the only
bytes that can publish are bytes the gate passed beside. This asserts that
wiring, and mutates it to show the assertions can fail.
"""

from __future__ import annotations

import os
import re
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

STEP_CONDITION = re.compile(r"(?m)^        if:")
STEP_CONTINUE_ON_ERROR = re.compile(r"(?m)^        continue-on-error:")


class Surface:
    """One unrecoverable publishing workflow: its gates and publish markers."""

    def __init__(
        self,
        name: str,
        workflow: str,
        gate_step_marker: str,
        gate_targets: tuple[str, ...],
        publish_markers: tuple[str, ...],
        gate_must_run: tuple[str, ...],
        gate_must_not_run: tuple[str, ...] = (),
    ) -> None:
        self.name = name
        self.workflow = workflow
        self.gate_step_marker = gate_step_marker
        self.gate_targets = gate_targets
        self.publish_markers = publish_markers
        self.gate_must_run = gate_must_run
        self.gate_must_not_run = gate_must_not_run

    def read(self) -> str:
        return (WORKFLOWS / self.workflow).read_text(encoding="utf-8")


SURFACES = (
    Surface(
        name="aweb server and awid-service on PyPI",
        workflow="pypi-release.yml",
        gate_step_marker='run: make "$GATE"',
        gate_targets=("release-server-gate", "release-awid-pypi-gate"),
        publish_markers=("uv publish",),
        gate_must_run=("uv lock --check", "pytest", "uv build"),
    ),
    Surface(
        name="awid image on GHCR",
        workflow="awid-image-release.yml",
        gate_step_marker="run: make release-awid-image-gate",
        gate_targets=("release-awid-image-gate",),
        publish_markers=("skopeo copy",),
        gate_must_run=("uv lock --check", "pytest"),
        gate_must_not_run=("docker build\n",),
    ),
)


def split_jobs(workflow: str) -> tuple[str, str]:
    """(stage job block, publish job block) of a two-job lane workflow."""
    jobs = workflow[workflow.index("\njobs:\n") :]
    stage_at = jobs.index("\n  stage:\n")
    publish_at = jobs.index("\n  publish:\n")
    assert stage_at < publish_at, "stage must precede publish"
    return jobs[stage_at:publish_at], jobs[publish_at:]


def step_block(job: str, marker: str) -> str:
    """The full step block containing the marker line."""
    at = job.index(marker)
    start = job.rindex("\n      - ", 0, at)
    try:
        end = job.index("\n      - ", at)
    except ValueError:
        end = len(job)
    return job[start:end]


class ReleaseGateContractTests(unittest.TestCase):
    def assert_publish_is_gated(self, surface: Surface, workflow: str) -> None:
        stage, publish = split_jobs(workflow)

        # The gate runs in the stage job: exactly once, unconditionally, with
        # failure fatal, inside the exact-source checkout, before anything is
        # sealed or uploaded.
        self.assertEqual(
            stage.count(surface.gate_step_marker),
            1,
            f"{surface.workflow} stage must run '{surface.gate_step_marker}' exactly once",
        )
        gate = step_block(stage, surface.gate_step_marker)
        self.assertIsNone(
            STEP_CONDITION.search(gate),
            "a conditional gate is a gate that can be skipped",
        )
        self.assertIsNone(
            STEP_CONTINUE_ON_ERROR.search(gate),
            "continue-on-error would let staging seal after the gate failed",
        )
        self.assertIn(
            "working-directory: source",
            gate,
            "the gate must run inside the exact source checkout",
        )
        self.assertLess(
            stage.index("path: source"),
            stage.index(surface.gate_step_marker),
            "the exact source checkout must precede the gate",
        )
        self.assertLess(
            stage.index(surface.gate_step_marker),
            stage.index("upload-artifact"),
            "nothing may be sealed or uploaded before the gate passed",
        )
        for marker in surface.publish_markers:
            self.assertNotIn(
                marker, stage, "the stage job must never publish anything"
            )

        # The publish job never builds and is triple-locked: mode-gated,
        # provenance-proven against this exact workflow file, and digest-bound
        # before any outward step.
        self.assertIn(
            "if: inputs.mode == 'publish-continuation'",
            publish,
            "the publish job must be mode-gated",
        )
        self.assertIn(
            f'".github/workflows/{surface.workflow}"',
            publish,
            "continuation must prove the staging run used this exact workflow",
        )
        publish_positions = [
            publish.index(marker)
            for marker in surface.publish_markers
            if marker in publish
        ]
        self.assertTrue(
            publish_positions,
            f"{surface.workflow} publish job must contain a publishing step",
        )
        for guard in (
            "does not equal declared $STAGE_ZIP_DIGEST",
            "require-publishable",
        ):
            self.assertIn(guard, publish)
            self.assertLess(
                publish.index(guard),
                min(publish_positions),
                f"'{guard}' must precede every publishing step",
            )
        self.assertNotIn(
            surface.gate_step_marker,
            publish,
            "the publish job must not rebuild; the gate ran beside the staged bytes",
        )

    def test_each_surface_gates_its_publish_on_its_own_suite(self) -> None:
        for surface in SURFACES:
            with self.subTest(surface=surface.name):
                self.assert_publish_is_gated(surface, surface.read())

    def test_the_gate_assertions_fail_when_the_wiring_is_broken(self) -> None:
        """Without this, a passing contract proves only that it was never asked."""

        for surface in SURFACES:
            workflow = surface.read()
            stage, _ = split_jobs(workflow)
            gate_step = step_block(stage, surface.gate_step_marker)

            mutations = {
                "gate removed": workflow.replace(gate_step, "\n", 1),
                "gate skipped by a condition": workflow.replace(
                    gate_step,
                    gate_step.replace(
                        "\n        run:", "\n        if: false\n        run:", 1
                    ),
                    1,
                ),
                "gate failure tolerated": workflow.replace(
                    gate_step,
                    gate_step.replace(
                        "\n        run:",
                        "\n        continue-on-error: true\n        run:",
                        1,
                    ),
                    1,
                ),
                "publish smuggled into the stage job": workflow.replace(
                    gate_step,
                    gate_step
                    + f"\n      - name: smuggle\n        run: {surface.publish_markers[0]} x\n",
                    1,
                ),
                "gate moved after the upload": workflow.replace(
                    gate_step, "\n", 1
                ).replace(
                    "\n      - name: Staged identity",
                    gate_step + "\n      - name: Staged identity",
                    1,
                ),
            }
            for name, mutation in mutations.items():
                with self.subTest(surface=surface.name, mutation=name):
                    with self.assertRaises((AssertionError, ValueError)):
                        self.assert_publish_is_gated(surface, mutation)

    def test_the_suites_have_the_services_they_need_to_run(self) -> None:
        """A gate that cannot reach Postgres errors instead of gating."""

        for surface in SURFACES:
            with self.subTest(surface=surface.name):
                stage, _ = split_jobs(surface.read())
                self.assertIn("image: postgres:16", stage)
                for setting in (
                    "PGHOST: localhost",
                    "PGPORT:",
                    "PGUSER: postgres",
                    "PGPASSWORD: postgres",
                    "PGDATABASE: postgres",
                ):
                    self.assertIn(setting, stage)

    def test_dispatch_is_the_only_way_in(self) -> None:
        """A tag or branch trigger would be a publish path the mode gate and
        provenance checks were never asked about."""

        for surface in SURFACES:
            with self.subTest(surface=surface.name):
                workflow = surface.read()
                start = re.search(r"(?m)^on:$", workflow)
                if start is None:
                    self.fail(f"{surface.workflow} must declare triggers")
                triggers = workflow[start.start() : workflow.index("jobs:\n")]
                self.assertIn("workflow_dispatch:", triggers)
                for other in ("push:", "pull_request", "schedule", "tags:", "branches:"):
                    self.assertNotIn(other, triggers)

    def test_the_dry_run_targets_carry_no_recursive_make(self) -> None:
        """The `make --dry-run` above is only a dry run while these targets stay free of $(MAKE).

        make exempts any recipe LINE containing $(MAKE) from -n and executes it in full,
        and a backslash-continued block is one line. So a recursive make added to a gate
        target would turn the test above into a real release build - uv build, rm -rf
        dist/, a full pytest - inside a unit test, against whatever checkout it runs in.

        30aadbec recorded that condition as a comment. This asserts it, because a
        constraint that depends on being read fails silently and only for the person who
        did not read it.
        """
        makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")

        def recipe_of(target: str) -> str:
            lines, collecting = [], False
            for line in makefile.splitlines():
                if line.startswith(f"{target}:"):
                    collecting = True
                    continue
                if collecting:
                    if line and not line[0].isspace():
                        break
                    lines.append(line)
            return "\n".join(lines)

        def prerequisites_of(target: str) -> list[str]:
            for line in makefile.splitlines():
                if line.startswith(f"{target}:"):
                    return line.split(":", 1)[1].split()
            return []

        targets = [t for surface in SURFACES for t in surface.gate_targets]
        # A wrong extraction yields an empty list, and every assertion below then passes
        # vacuously. The list is the detector; assert it counted before trusting a zero.
        self.assertTrue(targets, "no dry-run targets extracted - the surface table is broken")

        for target in targets:
            with self.subTest(target=target):
                # The named target, AND its prerequisite chain: -n expands the whole
                # chain, so a recursive make one level up executes just as surely. This
                # second half is the part that reads as redundant and is not.
                for name in [target, *prerequisites_of(target)]:
                    self.assertNotIn(
                        "$(MAKE)",
                        recipe_of(name),
                        f"{name} contains $(MAKE), so `make --dry-run {target}` would EXECUTE it "
                        "rather than print it. Either drop the recursive make, or stop using "
                        "--dry-run to inspect this target.",
                    )

    def test_the_gate_target_runs_the_artifact_suite_against_the_committed_lock(
        self,
    ) -> None:
        """Resolved through make itself, so prerequisites count as coverage."""

        for surface in SURFACES:
            for target in surface.gate_targets:
                with self.subTest(surface=surface.name, target=target):
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
