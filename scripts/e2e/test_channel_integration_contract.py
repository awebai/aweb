from __future__ import annotations

import json
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
PACKAGE = REPO_ROOT / "channel" / "package.json"
INTEGRATION = REPO_ROOT / "channel" / "test" / "integration.test.ts"
RUNNER = REPO_ROOT / "scripts" / "run-channel-integration.sh"
SHIP_RUNNER = REPO_ROOT / "scripts" / "run-ship-suites.sh"
EXPECTED_TESTS = (
    "reports a live stream outage once and reconnects with durable catch-up guidance",
    "bridges live aw mail and chat from certificate workspaces into Claude channel notifications",
)


class ChannelIntegrationContractTests(unittest.TestCase):
    def assert_source_contract(
        self,
        *,
        makefile: str,
        workflow: str,
        package: dict[str, object],
        integration: str,
        runner: str,
    ) -> None:
        scripts = package["scripts"]
        assert isinstance(scripts, dict)
        self.assertEqual(
            scripts["test"], "vitest run --exclude test/integration.test.ts"
        )
        self.assertEqual(
            scripts["test:integration"], "vitest run test/integration.test.ts"
        )
        self.assertEqual(
            tuple(re.findall(r'(?m)^\s*test\("([^"]+)"', integration)),
            EXPECTED_TESTS,
            "the managed release inventory must remain exactly two tests",
        )
        self.assertNotRegex(integration, r"\b(?:test|describe)\.(?:skip|todo)\b")

        target = re.search(
            r"(?m)^test-channel-integration:[^\n]*\n(?:\t.*\n)+", makefile
        )
        self.assertIsNotNone(target)
        assert target is not None
        self.assertIn("./scripts/run-channel-integration.sh", target.group(0))
        root_test = re.search(r"(?m)^test:\s+(.+)$", makefile)
        self.assertIsNotNone(root_test)
        assert root_test is not None
        self.assertIn("test-channel-integration-contract", root_test.group(1).split())

        self.assertRegex(
            makefile,
            r"(?m)^override SHIP_SUITES := release-awid-check "
            r"test-channel-integration test-federation-e2e test-e2e cli-e2e$",
        )
        ship_target = re.search(r"(?m)^ship-suites:\n(?:\t.*\n)+", makefile)
        self.assertIsNotNone(ship_target)
        assert ship_target is not None
        self.assertIn(
            "+@SHIP_SUITE_MAKE=make ./scripts/run-ship-suites.sh $(SHIP_SUITES)",
            ship_target.group(0),
        )
        self.assertIn("# BEGIN ship make mode guard", makefile)
        self.assertIn("# END ship make mode guard", makefile)
        self.assertRegex(
            makefile,
            r"(?m)^ship: release-all-check\n\t@echo \"\"\n\t\+@make ship-suites$",
        )

        self.assertLess(runner.index("trap cleanup EXIT"), runner.index("RUNTIME_OWNED=1"))
        self.assertLess(runner.index("RUNTIME_OWNED=1"), runner.index('mkdir -m 700 -- "$RUNTIME"'))
        self.assertIn("trap 'exit 143' TERM", runner)
        self.assertIn("down -v --remove-orphans --rmi local", runner)
        self.assertIn('reference="$PROJECT-awid"', runner)
        self.assertIn('reference="$PROJECT-aweb"', runner)
        self.assertIn('CHANNEL_INTEGRATION_COMPOSE_PROJECT="$PROJECT"', runner)
        self.assertIn('CHANNEL_INTEGRATION_TEMP_ROOT="$RUNTIME"', runner)
        self.assertRegex(
            runner,
            r"(?m)^  npm run test:integration -- --reporter=json --outputFile=\"\$RESULTS\"; then$",
            "the exact npm selector must be an executable command, not a comment/no-op",
        )
        cleanup = re.search(r"(?ms)^cleanup\(\) \{\n(.*?)^\}\n", runner)
        self.assertIsNotNone(cleanup)
        assert cleanup is not None
        self.assertTrue(
            cleanup.group(1).lstrip().startswith("local status=$? cleanup_failed=0"),
            "cleanup must not return before owning teardown",
        )
        self.assertRegex(
            runner,
            r'(?m)^if \[\[ -n "\$\{AWEB_TEST_URL:-\}" \|\| -n "\$\{AWID_TEST_URL:-\}" \]\]; then$',
            "managed-mode refusal must be active control flow",
        )
        self.assertIn("testResults.length", runner)
        self.assertIn("numTotalTestSuites", runner)
        self.assertIn("numTotalTests", runner)
        self.assertIn("numPendingTests", runner)
        self.assertIn("AWEB_TEST_URL", runner)
        self.assertIn("AWID_TEST_URL", runner)
        self.assertNotIn("docker system prune", runner)
        self.assertNotIn("docker kill", runner)

        self.assertNotRegex(
            workflow, r"(?m)^\s+(?:MAKE|MAKEFLAGS|MFLAGS):\s*",
            "the canonical workflow must not inject Make control variables",
        )

    def current_sources(self) -> dict[str, object]:
        return {
            "makefile": MAKEFILE.read_text(encoding="utf-8"),
            "workflow": WORKFLOW.read_text(encoding="utf-8"),
            "package": json.loads(PACKAGE.read_text(encoding="utf-8")),
            "integration": INTEGRATION.read_text(encoding="utf-8"),
            "runner": RUNNER.read_text(encoding="utf-8"),
        }

    def test_source_contract_is_complete_and_connected(self) -> None:
        self.assert_source_contract(**self.current_sources())

    def test_source_contract_kills_reviewed_disconnections(self) -> None:
        sources = self.current_sources()
        mutations = {
            "npm invocation disconnected": {
                "runner": str(sources["runner"]).replace(
                    "npm run test:integration -- --reporter=json",
                    ': "npm run test:integration -- --reporter=json"',
                    1,
                )
            },
            "outage arm skipped": {
                "integration": str(sources["integration"]).replace(
                    'test("reports a live stream outage',
                    'test.skip("reports a live stream outage',
                    1,
                )
            },
            "unexpected third test": {
                "integration": str(sources["integration"])
                + '\ntest("unexpected third test", () => {});\n'
            },
            "cleanup disabled": {
                "runner": str(sources["runner"]).replace(
                    "cleanup() {", "cleanup() {\n  return 0", 1
                )
            },
            "managed refusal bypassed": {
                "runner": str(sources["runner"]).replace(
                    'if [[ -n "${AWEB_TEST_URL:-}"',
                    'if false && [[ -n "${AWEB_TEST_URL:-}"',
                    1,
                )
            },
            "image cleanup dropped": {
                "runner": str(sources["runner"]).replace(
                    "down -v --remove-orphans --rmi local",
                    "down -v --remove-orphans",
                    1,
                )
            },
            "trap installed after acquisition": {
                "runner": str(sources["runner"]).replace("trap cleanup EXIT\n", "", 1)
                + "\ntrap cleanup EXIT\n"
            },
            "suite set environment-overridable": {
                "makefile": str(sources["makefile"]).replace(
                    "override SHIP_SUITES :=", "SHIP_SUITES :=", 1
                )
            },
            "recursive Make replaceable": {
                "makefile": str(sources["makefile"]).replace(
                    "SHIP_SUITE_MAKE=make", 'SHIP_SUITE_MAKE="$(MAKE)"', 1
                )
            },
            "ship parent uses inherited Make": {
                "makefile": str(sources["makefile"]).replace(
                    "+@make ship-suites", "+@$(MAKE) ship-suites", 1
                )
            },
            "workflow dry-run injection": {
                "workflow": str(sources["workflow"]).replace(
                    "    env:\n", "    env:\n      MAKEFLAGS: n\n", 1
                )
            },
            "workflow environment override injection": {
                "workflow": str(sources["workflow"]).replace(
                    "    env:\n",
                    "    env:\n      MAKEFLAGS: e\n      SHIP_SUITES: test-channel-integration\n",
                    1,
                )
            },
            "workflow Make replacement": {
                "workflow": str(sources["workflow"]).replace(
                    "    env:\n", "    env:\n      MAKE: /usr/bin/true\n", 1
                )
            },
        }
        for name, changes in mutations.items():
            with self.subTest(mutation=name):
                mutated = dict(sources)
                mutated.update(changes)
                self.assertNotEqual(mutated, sources)
                with self.assertRaises((AssertionError, ValueError)):
                    self.assert_source_contract(**mutated)

    def make_probe(
        self,
        guard: str,
        args: list[str],
        makeflags: str | None = None,
        make_override: str | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], bool]:
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            marker = root / "body-ran"
            probe = root / "Makefile"
            probe.write_text(
                guard
                + "\nship-suites:\n"
                + f"\t+@printf body > {marker}\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            if makeflags is None:
                env.pop("MAKEFLAGS", None)
                env.pop("MFLAGS", None)
            else:
                env["MAKEFLAGS"] = makeflags
            if make_override is None:
                env.pop("MAKE", None)
            else:
                env["MAKE"] = make_override
            result = subprocess.run(
                ["make", "-f", str(probe), *args],
                text=True,
                capture_output=True,
                env=env,
                timeout=30,
            )
            return result, marker.exists()

    def test_make_mode_guard_fails_before_any_recipe_body(self) -> None:
        makefile = MAKEFILE.read_text(encoding="utf-8")
        match = re.search(
            r"(?ms)^# BEGIN ship make mode guard\n(.*?)^# END ship make mode guard$",
            makefile,
        )
        self.assertIsNotNone(match)
        assert match is not None
        guard = match.group(1)

        safe, body_ran = self.make_probe(guard, ["ship-suites"])
        self.assertEqual(safe.returncode, 0, safe.stdout + safe.stderr)
        self.assertTrue(body_ran)

        for args, inherited in (
            (["-n", "ship-suites"], None),
            (["--just-print", "ship-suites"], None),
            (["--dry-run", "ship-suites"], None),
            (["-t", "ship-suites"], None),
            (["-i", "ship-suites"], None),
            (["-e", "ship-suites"], None),
            (["-q", "ship-suites"], None),
            (["ship-suites"], "n"),
            (["ship-suites"], "t"),
            (["ship-suites"], "i"),
            (["ship-suites"], "e"),
        ):
            with self.subTest(args=args, inherited=inherited):
                result, body_ran = self.make_probe(guard, args, inherited)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(body_ran, "unsafe mode reached a recipe body")

        replaced, body_ran = self.make_probe(
            guard, ["ship-suites"], make_override="/usr/bin/true"
        )
        self.assertNotEqual(replaced.returncode, 0, replaced.stdout + replaced.stderr)
        self.assertFalse(body_ran, "MAKE replacement reached a recipe body")

    def test_ship_runner_rejects_inherited_modes_and_ignores_make_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            marker = root / "child.log"
            stub = root / "make-stub"
            stub.write_text(
                """#!/usr/bin/env bash
printf 'suite=%s MAKEFLAGS=%s MFLAGS=%s\\n' "$1" "${MAKEFLAGS:-}" "${MFLAGS:-}" >> "$MARKER"
exit 0
""",
                encoding="utf-8",
            )
            stub.chmod(0o755)
            base_env = os.environ.copy()
            base_env.update(
                {
                    "SHIP_SUITE_MAKE": str(stub),
                    "MAKE": "/usr/bin/true",
                    "MARKER": str(marker),
                }
            )
            base_env.pop("MAKEFLAGS", None)
            base_env.pop("MFLAGS", None)

            safe = subprocess.run(
                ["bash", str(SHIP_RUNNER), "suite-a"],
                text=True,
                capture_output=True,
                env=base_env,
                timeout=30,
            )
            self.assertEqual(safe.returncode, 0, safe.stdout + safe.stderr)
            self.assertEqual(
                marker.read_text(), "suite=suite-a MAKEFLAGS= MFLAGS=\n"
            )

            for variable, value in (
                ("MAKEFLAGS", "n"),
                ("MAKEFLAGS", "t"),
                ("MAKEFLAGS", "i"),
                ("MAKEFLAGS", "e"),
                ("MAKEFLAGS", "q"),
                ("MFLAGS", "--just-print"),
            ):
                with self.subTest(variable=variable, value=value):
                    marker.unlink(missing_ok=True)
                    env = dict(base_env)
                    env[variable] = value
                    result = subprocess.run(
                        ["bash", str(SHIP_RUNNER), "suite-a"],
                        text=True,
                        capture_output=True,
                        env=env,
                        timeout=30,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(marker.exists())

    def build_fake_repo(
        self, runner_text: str | None = None
    ) -> tuple[tempfile.TemporaryDirectory[str], Path, dict[str, str]]:
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        (root / "scripts").mkdir()
        (root / "server").mkdir()
        (root / "channel").mkdir()
        (root / "tmp").mkdir()
        (root / "server" / "docker-compose.yml").write_text("services: {}\n")
        runner = root / "scripts" / "run-channel-integration.sh"
        runner.write_text(runner_text or RUNNER.read_text(encoding="utf-8"))
        runner.chmod(0o755)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        log = root / "calls.log"

        (bin_dir / "npm").write_text(
            """#!/usr/bin/env bash
set -eu
printf 'npm:%s\\n' "$*" >> "$MOCK_LOG"
printf 'runtime:%s\\n' "$CHANNEL_INTEGRATION_TEMP_ROOT" >> "$MOCK_LOG"
printf 'project:%s\\n' "$CHANNEL_INTEGRATION_COMPOSE_PROJECT" >> "$MOCK_LOG"
if [[ "${MOCK_CANCEL:-0}" == 1 ]]; then
  kill -TERM "$PPID"
  exit 0
fi
status="${MOCK_NPM_STATUS:-0}"
if [[ "$status" != 0 ]]; then exit "$status"; fi
output=""
for arg in "$@"; do
  case "$arg" in --outputFile=*) output="${arg#*=}";; esac
done
[[ -n "$output" ]]
if [[ "${MOCK_NO_REPORT:-0}" == 1 ]]; then exit 0; fi
test_results='[{}]'
if [[ "${MOCK_FILE_COUNT:-1}" == 2 ]]; then test_results='[{},{}]'; fi
cat > "$output" <<JSON
{"testResults":$test_results,
 "numTotalTestSuites":${MOCK_TOTAL_SUITES:-1},
 "numPassedTestSuites":${MOCK_PASSED_SUITES:-1},
 "numFailedTestSuites":0,
 "numPendingTestSuites":${MOCK_PENDING_SUITES:-0},
 "numTotalTests":${MOCK_TOTAL_TESTS:-2},
 "numPassedTests":${MOCK_PASSED_TESTS:-2},
 "numFailedTests":0,
 "numPendingTests":${MOCK_PENDING_TESTS:-0}}
JSON
""",
            encoding="utf-8",
        )
        (bin_dir / "docker").write_text(
            """#!/usr/bin/env bash
set -u
printf 'docker:%s\\n' "$*" >> "$MOCK_LOG"
if [[ "${1:-}" == compose ]]; then exit "${MOCK_DOWN_STATUS:-0}"; fi
if [[ "${1:-} ${2:-}" == 'image ls' ]]; then
  if [[ "${MOCK_IMAGE_QUERY_FAILURE:-0}" == 1 ]]; then exit 6; fi
  if [[ "${MOCK_IMAGE_RESIDUE:-0}" == 1 ]]; then echo owned-image-id; fi
  exit 0
fi
if [[ "${MOCK_QUERY_FAILURE:-0}" == 1 ]]; then exit 5; fi
if [[ "${MOCK_RESIDUE:-0}" == 1 ]]; then echo owned-resource-id; fi
exit 0
""",
            encoding="utf-8",
        )
        (bin_dir / "mkdir").write_text(
            """#!/usr/bin/env bash
set -u
printf 'mkdir:%s\\n' "$*" >> "$MOCK_LOG"
if [[ "${MOCK_MKDIR_STATUS:-0}" != 0 ]]; then exit "$MOCK_MKDIR_STATUS"; fi
/bin/mkdir "$@"
if [[ "${MOCK_MKDIR_CANCEL:-0}" == 1 ]]; then
  kill -TERM "$PPID"
fi
""",
            encoding="utf-8",
        )
        for stub in (bin_dir / "npm", bin_dir / "docker", bin_dir / "mkdir"):
            stub.chmod(0o755)
        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{bin_dir}:{env['PATH']}",
                "TMPDIR": str(root / "tmp"),
                "MOCK_LOG": str(log),
            }
        )
        env.pop("AWEB_TEST_URL", None)
        env.pop("AWID_TEST_URL", None)
        return temp, runner, env

    def run_fake(
        self, runner_text: str | None = None, **overrides: str
    ) -> tuple[subprocess.CompletedProcess[str], str, bool]:
        temp, runner, env = self.build_fake_repo(runner_text)
        try:
            env.update(overrides)
            result = subprocess.run(
                ["bash", str(runner)],
                text=True,
                capture_output=True,
                env=env,
                timeout=30,
            )
            log_path = Path(env["MOCK_LOG"])
            log = log_path.read_text() if log_path.exists() else ""
            runtime = next(
                (
                    Path(line.removeprefix("runtime:"))
                    for line in log.splitlines()
                    if line.startswith("runtime:")
                ),
                None,
            )
            if runtime is None:
                runtime = next(
                    (
                        Path(line.split()[-1])
                        for line in log.splitlines()
                        if line.startswith("mkdir:")
                    ),
                    None,
                )
            runtime_exists = runtime.exists() if runtime else False
            return result, log, runtime_exists
        finally:
            temp.cleanup()

    def test_mocked_runner_lifecycle_and_inventory(self) -> None:
        success, log, runtime_exists = self.run_fake()
        self.assertEqual(success.returncode, 0, success.stdout + success.stderr)
        self.assertIn("npm:run test:integration -- --reporter=json", log)
        self.assertIn("--rmi local", log)
        self.assertIn("reference=aweb-channel-integration-", log)
        self.assertNotIn("docker:image rm", log)
        self.assertNotRegex(log, r"reference=.*(?:postgres|redis)")
        self.assertFalse(runtime_exists)

        failure, _, runtime_exists = self.run_fake(MOCK_NPM_STATUS="7")
        self.assertEqual(failure.returncode, 7)
        self.assertFalse(runtime_exists)

        partial_startup, partial_log, runtime_exists = self.run_fake(
            MOCK_NPM_STATUS="9"
        )
        self.assertEqual(partial_startup.returncode, 9)
        self.assertIn("docker:compose", partial_log)
        self.assertFalse(runtime_exists)

        startup_failure, startup_log, runtime_exists = self.run_fake(
            MOCK_MKDIR_STATUS="11"
        )
        self.assertEqual(startup_failure.returncode, 11)
        self.assertNotIn("npm:", startup_log)
        self.assertFalse(runtime_exists)

        boundary_cancel, boundary_log, runtime_exists = self.run_fake(
            MOCK_MKDIR_CANCEL="1"
        )
        self.assertEqual(boundary_cancel.returncode, 143)
        self.assertNotIn("npm:", boundary_log)
        self.assertFalse(runtime_exists)

        cancellation, _, runtime_exists = self.run_fake(MOCK_CANCEL="1")
        self.assertEqual(cancellation.returncode, 143)
        self.assertFalse(runtime_exists)

        cleanup_failure, _, _ = self.run_fake(MOCK_DOWN_STATUS="5")
        self.assertNotEqual(cleanup_failure.returncode, 0)
        primary_preserved, _, _ = self.run_fake(
            MOCK_NPM_STATUS="7", MOCK_DOWN_STATUS="5"
        )
        self.assertEqual(primary_preserved.returncode, 7)

        for override in (
            {"MOCK_IMAGE_RESIDUE": "1"},
            {"MOCK_IMAGE_QUERY_FAILURE": "1"},
            {"MOCK_RESIDUE": "1"},
            {"MOCK_QUERY_FAILURE": "1"},
            {"MOCK_NO_REPORT": "1"},
            {"MOCK_FILE_COUNT": "2"},
            {"MOCK_TOTAL_TESTS": "3", "MOCK_PASSED_TESTS": "3"},
            {"MOCK_PENDING_TESTS": "1", "MOCK_PASSED_TESTS": "1"},
        ):
            with self.subTest(override=override):
                result, _, _ = self.run_fake(**override)
                self.assertNotEqual(result.returncode, 0)

        external, log, _ = self.run_fake(
            AWEB_TEST_URL="http://external", AWID_TEST_URL="http://external"
        )
        self.assertEqual(external.returncode, 2)
        self.assertNotIn("npm:", log)

    def test_mock_contract_kills_a_noop_cleanup(self) -> None:
        original = RUNNER.read_text(encoding="utf-8")
        cleanup = re.search(r"(?ms)^cleanup\(\) \{\n.*?^\}\n", original)
        self.assertIsNotNone(cleanup)
        assert cleanup is not None
        mutated = (
            original[: cleanup.start()]
            + "cleanup() {\n  return 0\n}\n"
            + original[cleanup.end() :]
        )
        self.assertNotEqual(mutated, original)

        result, _, runtime_exists = self.run_fake(mutated)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(runtime_exists, "mutation did not disable owned cleanup")
        with self.assertRaises(AssertionError):
            self.assertFalse(runtime_exists, "no-op cleanup left its owned runtime")


if __name__ == "__main__":
    unittest.main()
