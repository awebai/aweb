from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

import check_go_test_accounting as accounting


REPO_ROOT = Path(__file__).resolve().parents[1]


class GoTestAccountingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = accounting.load_policy(REPO_ROOT)

    def fixture(self, suite: str) -> str:
        spec = self.policy["suites"][suite]
        events: list[dict[str, str]] = []
        for package in spec["packages"]:
            events.append({"Action": "start", "Package": package})
            for test in spec["required_tests"]:
                if test["package"] != package:
                    continue
                events.append({"Action": "run", "Package": package, "Test": test["name"]})
                events.append({"Action": "pass", "Package": package, "Test": test["name"]})
            events.append({"Action": "pass", "Package": package})
        return "".join(json.dumps(event) + "\n" for event in events)

    def test_checked_in_source_inventory_and_invocation_wiring_are_exact(self) -> None:
        accounting.verify_source_inventory(REPO_ROOT, self.policy)
        accounting.verify_invocation_wiring(REPO_ROOT)

    def test_wiring_checker_rejects_disconnected_invocations(self) -> None:
        mutations = (
            ("Makefile", "go test -json ./... -count=1", "go test ./... -count=1"),
            ("Makefile", "ship: override AW_GO_TEST_RELEASE_PLATFORM := linux-amd64", "ship: AW_GO_TEST_RELEASE_PLATFORM :="),
            ("cli/scripts/e2e.sh", "go test -json -tags e2e ./e2e -count=1", "go test -tags e2e ./e2e -count=1"),
            (".github/workflows/ship.yml", "run: make ship", "run: make test"),
            (".github/workflows/cli-e2e.yml", "run: make -C cli e2e", "run: true"),
        )
        required_files = {
            "Makefile",
            "cli/scripts/e2e.sh",
            ".github/workflows/ship.yml",
            ".github/workflows/cli-e2e.yml",
        }
        for relative, anchor, replacement in mutations:
            with self.subTest(path=relative, anchor=anchor):
                with tempfile.TemporaryDirectory() as work:
                    root = Path(work)
                    for required in required_files:
                        destination = root / required
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(REPO_ROOT / required, destination)
                    target = root / relative
                    source = target.read_text(encoding="utf-8")
                    self.assertEqual(source.count(anchor), 1)
                    target.write_text(source.replace(anchor, replacement, 1), encoding="utf-8")
                    with self.assertRaises(accounting.AccountingError):
                        accounting.verify_invocation_wiring(root)

    def test_source_inventory_rejects_an_unaccounted_skip_site(self) -> None:
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            shutil.copytree(REPO_ROOT / "cli" / "go", root / "cli" / "go")
            target = root / "cli" / "go" / "chat" / "dedup_concurrency_test.go"
            source = target.read_text(encoding="utf-8")
            anchor = "func TestConcurrentWritersKeepEveryDeliveryMark(t *testing.T) {\n"
            self.assertEqual(source.count(anchor), 1)
            target.write_text(
                source.replace(anchor, anchor + '\tt.Skip("mutation: mandatory test skipped")\n', 1),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(accounting.AccountingError, "runtime skip inventory"):
                accounting.verify_source_inventory(root, self.policy)

    def test_source_inventory_rejects_an_unaccounted_build_exclusion(self) -> None:
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            shutil.copytree(REPO_ROOT / "cli" / "go", root / "cli" / "go")
            target = root / "cli" / "go" / "cmd" / "aw" / "mutation_linux.go"
            target.write_text("//go:build linux\n\npackage main\n", encoding="utf-8")
            with self.assertRaisesRegex(accounting.AccountingError, "build-constraint inventory"):
                accounting.verify_source_inventory(root, self.policy)

    def test_source_inventory_rejects_a_legacy_build_exclusion(self) -> None:
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            shutil.copytree(REPO_ROOT / "cli" / "go", root / "cli" / "go")
            target = root / "cli" / "go" / "cmd" / "aw" / "mutation_legacy.go"
            target.write_text("// +build windows\n\npackage main\n", encoding="utf-8")
            with self.assertRaisesRegex(accounting.AccountingError, "build-constraint inventory"):
                accounting.verify_source_inventory(root, self.policy)

    def test_source_inventory_keeps_the_exact_tagged_e2e_test_set(self) -> None:
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            shutil.copytree(REPO_ROOT / "cli" / "go", root / "cli" / "go")
            target = root / "cli" / "go" / "e2e" / "real_stack_e2e_test.go"
            target.write_text(
                target.read_text(encoding="utf-8")
                + "\nfunc TestMutationUnaccountedE2E(t *testing.T) {}\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(accounting.AccountingError, "e2e required-test inventory"):
                accounting.verify_source_inventory(root, self.policy)

    def test_parser_accepts_complete_default_and_exact_e2e_results(self) -> None:
        for suite in ("default", "e2e"):
            with self.subTest(suite=suite):
                summary = accounting.parse_json_stream(
                    self.fixture(suite), self.policy, suite, reject_skips=True
                )
                self.assertEqual(summary.packages_passed, len(self.policy["suites"][suite]["packages"]))
                self.assertEqual(summary.required_tests_passed, len(self.policy["suites"][suite]["required_tests"]))

    def test_parser_rejects_a_mandatory_test_skip(self) -> None:
        fixture = self.fixture("default")
        required = self.policy["suites"]["default"]["required_tests"][0]
        passing = json.dumps(
            {"Action": "pass", "Package": required["package"], "Test": required["name"]}
        )
        skipped = json.dumps(
            {"Action": "skip", "Package": required["package"], "Test": required["name"]}
        )
        self.assertEqual(fixture.count(passing), 1)
        with self.assertRaisesRegex(accounting.AccountingError, "unexpected test skip"):
            accounting.parse_json_stream(
                fixture.replace(passing, skipped, 1), self.policy, "default", reject_skips=True
            )

    def test_parser_rejects_missing_package_or_result(self) -> None:
        fixture = self.fixture("default")
        package = self.policy["suites"]["default"]["packages"][0]
        lines = fixture.splitlines(keepends=True)
        without_package = "".join(
            line for line in lines if json.loads(line).get("Package") != package
        )
        without_result = "".join(
            line
            for line in lines
            if not (
                json.loads(line).get("Package") == package
                and json.loads(line).get("Action") == "pass"
                and "Test" not in json.loads(line)
            )
        )
        for label, mutation in (
            ("package", without_package),
            ("result", without_result),
        ):
            with self.subTest(mutation=label):
                with self.assertRaisesRegex(accounting.AccountingError, "package"):
                    accounting.parse_json_stream(
                        mutation, self.policy, "default", reject_skips=True
                    )

    def test_parser_rejects_missing_mandatory_test_result(self) -> None:
        fixture = self.fixture("default")
        required = self.policy["suites"]["default"]["required_tests"][0]
        result = json.dumps(
            {"Action": "pass", "Package": required["package"], "Test": required["name"]}
        ) + "\n"
        self.assertEqual(fixture.count(result), 1)
        with self.assertRaisesRegex(accounting.AccountingError, "required test"):
            accounting.parse_json_stream(
                fixture.replace(result, "", 1), self.policy, "default", reject_skips=True
            )

    def test_parser_rejects_malformed_and_truncated_output(self) -> None:
        fixture = self.fixture("default")
        for label, mutation in (
            ("malformed", fixture + "not-json\n"),
            ("truncated", fixture + '{"Action":"pass"'),
        ):
            with self.subTest(mutation=label):
                with self.assertRaisesRegex(accounting.AccountingError, "malformed go test JSON"):
                    accounting.parse_json_stream(
                        mutation, self.policy, "default", reject_skips=True
                    )

    def test_release_preflight_fails_when_a_required_tool_disappears(self) -> None:
        with tempfile.TemporaryDirectory() as work:
            bindir = Path(work)
            for tool in self.policy["release_preconditions"]["tools"]:
                path = bindir / tool
                path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                path.chmod(path.stat().st_mode | stat.S_IXUSR)
            accounting.verify_release_preconditions(
                self.policy, system="Linux", machine="x86_64", effective_uid=1000, path=str(bindir)
            )
            for tool in self.policy["release_preconditions"]["tools"]:
                with self.subTest(tool=tool):
                    removed = bindir / tool
                    backup = bindir / f"{tool}.off"
                    removed.rename(backup)
                    try:
                        with self.assertRaisesRegex(accounting.AccountingError, tool):
                            accounting.verify_release_preconditions(
                                self.policy,
                                system="Linux",
                                machine="x86_64",
                                effective_uid=1000,
                                path=str(bindir),
                            )
                    finally:
                        backup.rename(removed)

    def test_invocation_contract_rejects_any_command_drift(self) -> None:
        for suite in ("default", "e2e"):
            expected = self.policy["suites"][suite]["command"]
            accounting.verify_command(expected, self.policy, suite)
            for label, mutation in (
                ("missing json", [arg for arg in expected if arg != "-json"]),
                ("wrong package", ["./wrong" if arg in ("./...", "./e2e") else arg for arg in expected]),
                ("missing count", expected[:-1]),
            ):
                with self.subTest(suite=suite, mutation=label):
                    with self.assertRaisesRegex(accounting.AccountingError, "exact invocation"):
                        accounting.verify_command(mutation, self.policy, suite)

    def test_runner_catches_invocation_failure_without_invoking_go(self) -> None:
        with tempfile.TemporaryDirectory() as work:
            env = dict(os.environ)
            env["PATH"] = work
            with self.assertRaisesRegex(accounting.AccountingError, "could not start"):
                accounting.run_accounted_command(
                    REPO_ROOT,
                    self.policy,
                    "default",
                    self.policy["suites"]["default"]["command"],
                    release_platform="",
                    env=env,
                )


if __name__ == "__main__":
    unittest.main()
