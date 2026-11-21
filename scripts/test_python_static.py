"""Real-tool controls for the Python diagnostic ceiling, without services."""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from python_static import (
    CEILINGS_PATH,
    VERSIONS,
    DiagnosticGroup,
    Package,
    StaticCheckError,
    Tool,
    exceeded_ceilings,
    load_ceilings,
    scan_package,
    verify_versions,
)

ROOT = Path(__file__).resolve().parents[1]


class PythonStaticControls(unittest.TestCase):
    def setUp(self) -> None:
        verify_versions()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        directory = self.root / "server"
        directory.mkdir()
        shutil.copyfile(ROOT / "server/pyproject.toml", directory / "pyproject.toml")
        self.source = directory / "src/aweb"
        self.source.mkdir(parents=True)
        (self.source / "__init__.py").write_text("")
        self.package = Package(directory=directory, interpreter=Path(sys.executable))

    def scan(self) -> Counter[DiagnosticGroup]:
        return scan_package(root=self.root, package=self.package)

    def write_budget(self, groups: list[dict[str, object]]) -> Path:
        path = self.root / CEILINGS_PATH
        path.parent.mkdir(exist_ok=True)
        path.write_text(
            json.dumps({"schema_version": 1, "versions": VERSIONS, "groups": groups})
        )
        return path

    def test_same_file_and_rule_growth_exceeds_existing_ceiling(self) -> None:
        path = self.source / "defaults.py"
        path.write_text("def first(value=[]):\n    return value\n")
        baseline = self.scan()
        group = DiagnosticGroup(
            tool=Tool.RUFF, file="server/src/aweb/defaults.py", code="B006"
        )
        self.assertEqual(baseline[group], 1)
        path.write_text(
            path.read_text() + "\ndef second(value=[]):\n    return value\n"
        )
        failures = exceeded_ceilings(observed=self.scan(), ceilings=dict(baseline))
        self.assertIn("ruff server/src/aweb/defaults.py [B006]: 2 > 1", failures)

    def test_new_module_has_zero_allowance_and_checks_untyped_function_body(
        self,
    ) -> None:
        (self.source / "new_module.py").write_text(
            'def takes_int(value: int) -> int:\n    return value\n\ndef untyped():\n    return takes_int("bad")\n'
        )
        observed = self.scan()
        group = DiagnosticGroup(
            tool=Tool.MYPY, file="server/src/aweb/new_module.py", code="arg-type"
        )
        self.assertEqual(observed[group], 1)
        self.assertIn(
            "mypy server/src/aweb/new_module.py [arg-type]: 1 > 0",
            exceeded_ceilings(observed=observed, ceilings={}),
        )

    def test_selected_files_catch_missing_attributes_without_unrelated_findings(
        self,
    ) -> None:
        selected = self.source / "mail.py"
        selected.write_text(
            "class MailSender:\n    did: str\n\ndef deliver(sender: MailSender):\n    return sender.team_id\n"
        )
        (self.source / "unrelated.py").write_text("result = missing_name\n")
        observed = scan_package(root=self.root, package=self.package, files=(selected,))
        group = DiagnosticGroup(
            tool=Tool.MYPY, file="server/src/aweb/mail.py", code="attr-defined"
        )
        self.assertEqual(observed, Counter({group: 1}))
        self.assertIn(
            "mypy server/src/aweb/mail.py [attr-defined]: 1 > 0",
            exceeded_ceilings(observed=observed, ceilings={}),
        )
        selected.write_text(
            selected.read_text().replace("sender.team_id", "sender.did")
        )
        self.assertEqual(
            scan_package(root=self.root, package=self.package, files=(selected,)),
            Counter(),
        )
        self.assertTrue(self.scan())

    def test_blind_handler_is_checked_in_new_module(self) -> None:
        (self.source / "blind_handler.py").write_text(
            'def read():\n    try:\n        return int("x")\n    except Exception:\n        return None\n'
        )
        observed = self.scan()
        self.assertEqual(
            observed[
                DiagnosticGroup(
                    tool=Tool.RUFF,
                    file="server/src/aweb/blind_handler.py",
                    code="BLE001",
                )
            ],
            1,
        )

    def test_cleared_group_passes_and_can_be_removed_from_budget(self) -> None:
        path = self.source / "defaults.py"
        path.write_text("def first(value=[]):\n    return value\n")
        baseline = dict(self.scan())
        self.assertTrue(baseline)
        path.write_text(
            "def first(value=None):\n    return [] if value is None else value\n"
        )
        observed = self.scan()
        self.assertEqual(exceeded_ceilings(observed=observed, ceilings=baseline), [])
        self.assertEqual(exceeded_ceilings(observed=observed, ceilings={}), [])

    def test_fastapi_declaration_is_valid(self) -> None:
        (self.source / "declarations.py").write_text(
            "from fastapi import Body, Depends\n\ndef dependency() -> int:\n    return 1\n\ndef route(value=Body(), dep=Depends(dependency)):\n    return value, dep\n"
        )
        self.assertEqual(self.scan(), Counter())

    def test_noqa_does_not_hide_growth_from_raw_scan(self) -> None:
        (self.source / "defaults.py").write_text(
            "def first(value=[]):  # noqa: B006\n    return value\n"
        )
        self.assertEqual(
            self.scan()[
                DiagnosticGroup(
                    tool=Tool.RUFF, file="server/src/aweb/defaults.py", code="B006"
                )
            ],
            1,
        )

    def test_invalid_tool_config_is_setup_failure(self) -> None:
        path = self.package.directory / "pyproject.toml"
        path.write_text(path.read_text() + "\n[tool.ruff.nonexistent]\nvalue = true\n")
        with self.assertRaisesRegex(StaticCheckError, "ruff failed"):
            self.scan()

    def test_narrowed_type_scope_and_module_suppression_refuse(self) -> None:
        path = self.package.directory / "pyproject.toml"
        original = path.read_text()
        for changed, refusal in [
            (
                original.replace('files = ["src/aweb"]', 'files = ["src/aweb/one.py"]'),
                "every declared",
            ),
            (
                original
                + '\n[[tool.mypy.overrides]]\nmodule = "aweb.*"\ndisable_error_code = ["arg-type"]\n',
                "instead of module",
            ),
        ]:
            with self.subTest(refusal=refusal):
                path.write_text(changed)
                with self.assertRaisesRegex(StaticCheckError, refusal):
                    self.scan()

    def test_boolean_ceiling_is_not_an_integer_allowance(self) -> None:
        path = self.write_budget(
            [
                {
                    "tool": "ruff",
                    "file": "server/src/aweb/example.py",
                    "code": "B006",
                    "count": True,
                }
            ]
        )
        with self.assertRaisesRegex(StaticCheckError, "positive integer"):
            load_ceilings(path)

    def test_unknown_group_fields_and_duplicate_groups_refuse(self) -> None:
        group: dict[str, object] = {
            "tool": "ruff",
            "file": "server/src/aweb/example.py",
            "code": "B006",
            "count": 1,
        }
        for groups, expected in [
            ([dict(group, extra=1)], "exactly"),
            ([group, group], "duplicate"),
        ]:
            with self.subTest(expected=expected):
                with self.assertRaisesRegex(StaticCheckError, expected):
                    load_ceilings(self.write_budget(groups))

    def test_budget_path_cannot_escape_or_exempt_new_file_patterns(self) -> None:
        for file in (
            "../example.py",
            "/tmp/example.py",
            "server/src/aweb/*.py",
            "other/example.py",
        ):
            with self.subTest(file=file):
                path = self.write_budget(
                    [{"tool": "ruff", "file": file, "code": "B006", "count": 1}]
                )
                with self.assertRaises(StaticCheckError):
                    load_ceilings(path)

    def test_setup_refusal_ends_with_tested_recovery_action(self) -> None:
        command = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/python_static.py"),
                "--root",
                str(self.root),
            ],
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(command.returncode, 2, command.stdout + command.stderr)
        self.assertIn("cannot read", command.stderr)
        self.assertTrue(
            command.stderr.rstrip().endswith(
                "Prepare the frozen package environments and correct the reported configuration, then run make check-python-static."
            ),
            command.stderr,
        )

    def prepare_cli_packages(self) -> None:
        """Build empty package roots so CLI refusal controls run actual tools."""
        for name in ("awid",):
            package = self.root / name
            shutil.copytree(self.package.directory, package)
            roots = '["src/awid", "src/awid_service"]'
            config = package / "pyproject.toml"
            config.write_text(config.read_text().replace('["src/aweb"]', roots))
            modules = ("awid", "awid_service")
            for module in modules:
                source = package / "src" / module
                source.mkdir()
                (source / "__init__.py").write_text("")
        for name in ("server", "awid"):
            runtime = self.root / name / ".venv/bin"
            runtime.mkdir(parents=True)
            (runtime / "python").symlink_to(sys.executable)

    def test_growth_refusal_ends_with_tested_recovery_action(self) -> None:
        self.prepare_cli_packages()
        (self.source / "defaults.py").write_text(
            "def first(value=[]):\n    return value\n"
        )
        self.write_budget([])
        command = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/python_static.py"),
                "--root",
                str(self.root),
            ],
            text=True,
            capture_output=True,
            timeout=90,
        )
        self.assertEqual(command.returncode, 1, command.stdout + command.stderr)
        self.assertIn("[B006]: 1 > 0", command.stderr)
        self.assertTrue(
            command.stderr.rstrip().endswith(
                "Fix the reported findings and lower cleared ceilings in the same change."
            ),
            command.stderr,
        )

    def prepare_reviewed_reference(self) -> None:
        """Record the actual reviewed ceiling in a disposable Git repository."""
        commands = [
            ["git", "init", "--quiet"],
            ["git", "add", CEILINGS_PATH.as_posix()],
            [
                "git",
                "-c",
                "user.name=Static control",
                "-c",
                "user.email=static-control@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
                "commit",
                "--quiet",
                "-m",
                "Reviewed ceiling",
            ],
            ["git", "update-ref", "refs/remotes/origin/main", "HEAD"],
        ]
        for command in commands:
            subprocess.run(
                command, cwd=self.root, check=True, capture_output=True, timeout=10
            )

    def test_changed_file_cli_checks_only_selected_files_against_the_ceiling(
        self,
    ) -> None:
        self.prepare_cli_packages()
        self.write_budget([])
        self.prepare_reviewed_reference()
        path = self.source / "mail.py"
        path.write_text(
            "class MailSender:\n    did: str\n\ndef deliver(sender: MailSender):\n    return sender.team_id\n"
        )
        (self.source / "unrelated.py").write_text("result = missing_name\n")
        arguments = [
            sys.executable,
            str(ROOT / "scripts/python_static.py"),
            "--root",
            str(self.root),
            "--files",
            "server/src/aweb/mail.py",
        ]
        refused = subprocess.run(arguments, text=True, capture_output=True, timeout=90)
        self.assertEqual(refused.returncode, 1, refused.stdout + refused.stderr)
        self.assertIn("server/src/aweb/mail.py [attr-defined]: 1 > 0", refused.stderr)
        path.write_text(path.read_text().replace("sender.team_id", "sender.did"))
        accepted = subprocess.run(arguments, text=True, capture_output=True, timeout=90)
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
        self.assertIn("0 diagnostics", accepted.stdout)

    def test_gate_checkout_requires_the_supplied_reviewed_main_reference(self) -> None:
        def git(*arguments: str) -> str:
            return subprocess.run(
                ["git", *arguments],
                cwd=self.root,
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout.strip()

        def check() -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/python_static.py"),
                    "--root",
                    str(self.root),
                ],
                capture_output=True,
                text=True,
                timeout=90,
            )

        self.prepare_cli_packages()
        self.write_budget([])
        self.prepare_reviewed_reference()
        reviewed_sha = git("rev-parse", "refs/remotes/origin/main")
        path = self.source / "defaults.py"
        path.write_text("def first(value=[]):\n    return value\n")
        self.write_budget(
            [
                {
                    "tool": "ruff",
                    "file": "server/src/aweb/defaults.py",
                    "code": "B006",
                    "count": 1,
                }
            ]
        )
        git(
            "-c",
            "user.name=Static control",
            "-c",
            "user.email=static-control@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "--quiet",
            "--all",
            "-m",
            "Candidate budget",
        )
        git("checkout", "--detach", "HEAD")
        self.assertNotEqual(git("rev-parse", "HEAD"), reviewed_sha)
        git("update-ref", "-d", "refs/remotes/origin/main")
        self.assertEqual(git("for-each-ref", "refs/remotes/"), "")
        missing = check()
        self.assertEqual(missing.returncode, 2, missing.stdout + missing.stderr)
        self.assertIn(
            "cannot inspect synchronized main ceilings: fatal: Needed a single revision",
            missing.stderr,
        )
        # The gate supplies the reviewed SHA, not the candidate's committed budget.
        git("update-ref", "refs/remotes/origin/main", reviewed_sha)
        inflated = check()
        self.assertEqual(inflated.returncode, 1, inflated.stdout + inflated.stderr)
        self.assertIn("[B006]: 1 > 0", inflated.stderr)
        self.assertIn(
            "Reviewed Python diagnostic ceilings cannot increase", inflated.stderr
        )
        path.write_text("def first(value=None):\n    return value\n")
        self.write_budget([])
        accepted = check()
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
        self.assertIn("0 diagnostics", accepted.stdout)
        self.assertEqual(git("rev-parse", "refs/remotes/origin/main"), reviewed_sha)

    def test_changed_file_refusal_names_how_to_recover(self) -> None:
        self.write_budget([])
        (self.root / "outside.py").write_text("value = 1\n")
        for selected in ("outside.py", "server/src/aweb/missing.py"):
            with self.subTest(selected=selected):
                refused = subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "scripts/python_static.py"),
                        "--root",
                        str(self.root),
                        "--files",
                        selected,
                    ],
                    text=True,
                    capture_output=True,
                    timeout=30,
                )
                self.assertEqual(refused.returncode, 2, refused.stdout + refused.stderr)
                self.assertIn(selected, refused.stderr)
                self.assertTrue(
                    refused.stderr.rstrip().endswith(
                        "Prepare the frozen package environments and correct the reported configuration, then run make check-python-static."
                    ),
                    refused.stderr,
                )

    def test_source_suppressions_cannot_hide_a_new_missing_attribute(self) -> None:
        self.prepare_cli_packages()
        self.write_budget([])
        self.prepare_reviewed_reference()
        path = self.source / "mail.py"
        invalid = "class MailSender:\n    did: str\n\ndef deliver(sender: MailSender):\n    return sender.team_id\n"
        variants = [
            (
                invalid.rstrip() + "  # type: ignore[attr-defined]\n",
                "source-type-ignore",
            ),
            ("# mypy: ignore-errors\n" + invalid, "source-mypy-directive"),
            (
                '# mypy: disable-error-code="attr-defined"\n' + invalid,
                "source-mypy-directive",
            ),
            ('"""\n# mypy: ignore-errors\n"""\n' + invalid, "source-mypy-directive"),
        ]
        for source, code in variants:
            with self.subTest(code=code, source=source):
                path.write_text(source)
                refused = self.run_selected_file(path)
                self.assertEqual(refused.returncode, 1, refused.stdout + refused.stderr)
                self.assertIn(f"[{code}]: 1 > 0", refused.stderr)
                self.assertTrue(
                    refused.stderr.rstrip().endswith(
                        "Fix the reported findings and lower cleared ceilings in the same change."
                    ),
                    refused.stderr,
                )
                path.write_text(invalid.replace("sender.team_id", "sender.did"))
                accepted = self.run_selected_file(path)
                self.assertEqual(
                    accepted.returncode, 0, accepted.stdout + accepted.stderr
                )

    def test_reviewed_type_ignore_is_counted_without_unused_ignore_noise(self) -> None:
        self.prepare_cli_packages()
        path = self.source / "mail.py"
        path.write_text(
            "class MailSender:\n    did: str\n\ndef deliver(sender: MailSender):\n    return sender.did  # type: ignore[attr-defined]\n"
        )
        self.write_budget(
            [
                {
                    "tool": "mypy",
                    "file": "server/src/aweb/mail.py",
                    "code": "source-type-ignore",
                    "count": 1,
                }
            ]
        )
        self.prepare_reviewed_reference()
        accepted = self.run_selected_file(path)
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
        self.assertIn("1 diagnostics in 1 groups", accepted.stdout)

    def test_real_cli_ignores_inline_and_module_ruff_noqa(self) -> None:
        self.prepare_cli_packages()
        self.write_budget([])
        self.prepare_reviewed_reference()
        path = self.source / "defaults.py"
        for source in (
            "def first(value=[]):  # noqa: B006\n    return value\n",
            "# ruff: noqa: B006\ndef first(value=[]):\n    return value\n",
        ):
            with self.subTest(source=source):
                path.write_text(source)
                refused = self.run_selected_file(path)
                self.assertEqual(refused.returncode, 1, refused.stdout + refused.stderr)
                self.assertIn("[B006]: 1 > 0", refused.stderr)
                path.write_text(source.replace("value=[]", "value=None"))
                accepted = self.run_selected_file(path)
                self.assertEqual(
                    accepted.returncode, 0, accepted.stdout + accepted.stderr
                )

    def run_selected_file(self, path: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/python_static.py"),
                "--root",
                str(self.root),
                "--files",
                str(path.relative_to(self.root)),
            ],
            text=True,
            capture_output=True,
            timeout=90,
        )

    def test_relocated_allowance_requires_a_strict_total_decrease(self) -> None:
        self.prepare_cli_packages()
        old_group: dict[str, object] = {
            "tool": "ruff",
            "file": "server/src/aweb/mail.py",
            "code": "BLE001",
            "count": 2,
        }
        old_path = self.source / "mail.py"
        old_source = 'def read():\n    try:\n        return int("x")\n    except Exception:\n        return None\n'
        old_path.write_text(old_source + old_source.replace("read()", "other()"))
        self.assertEqual(
            self.scan(),
            Counter(
                {
                    DiagnosticGroup(
                        tool=Tool.RUFF,
                        file="server/src/aweb/mail.py",
                        code="BLE001",
                    ): 2
                }
            ),
        )
        self.write_budget([old_group])
        self.prepare_reviewed_reference()
        old_path.unlink()
        path = self.source / "errors.py"
        path.write_text(
            'def read():\n    try:\n        return int("x")\n    except Exception:\n        return None\n'
        )
        new_group = dict(old_group, file="server/src/aweb/errors.py", count=1)
        # A moved group with an unchanged total is still refused.
        self.write_budget([dict(new_group, count=2)])
        refused = self.run_selected_file(path)
        self.assertEqual(refused.returncode, 1, refused.stdout + refused.stderr)
        self.assertIn("[BLE001]: 2 > 0", refused.stderr)
        self.assertTrue(
            refused.stderr.rstrip().endswith(
                "Restore the reviewed allowances and fix the additional findings."
            ),
            refused.stderr,
        )
        # Two removed allowances pay for one relocated allowance, leaving less debt.
        self.write_budget([new_group])
        accepted = self.run_selected_file(path)
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
        self.assertIn("Reviewed allowance relocation: total 2 -> 1", accepted.stdout)
        self.assertIn("ruff server/src/aweb/mail.py [BLE001]: 2 -> 0", accepted.stdout)
        self.assertIn(
            "ruff server/src/aweb/errors.py [BLE001]: 0 -> 1", accepted.stdout
        )
        self.assertIn("1 diagnostics in 1 groups", accepted.stdout)
        # Budget relocation never excuses an actual finding above its new ceiling.
        path.write_text(
            path.read_text() + path.read_text().replace("read()", "other()")
        )
        growth = self.run_selected_file(path)
        self.assertEqual(growth.returncode, 1, growth.stdout + growth.stderr)
        self.assertIn("[BLE001]: 2 > 1", growth.stderr)

    def test_raising_reviewed_allowance_refuses_even_when_tools_fit_the_new_budget(
        self,
    ) -> None:
        self.prepare_cli_packages()
        group: dict[str, object] = {
            "tool": "ruff",
            "file": "server/src/aweb/defaults.py",
            "code": "B006",
            "count": 1,
        }
        self.write_budget([group])
        self.prepare_reviewed_reference()
        (self.source / "defaults.py").write_text(
            "def first(value=[]):\n    return value\n"
        )
        self.write_budget([dict(group, count=2)])
        command = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/python_static.py"),
                "--root",
                str(self.root),
            ],
            text=True,
            capture_output=True,
            timeout=90,
        )
        self.assertEqual(command.returncode, 1, command.stdout + command.stderr)
        self.assertIn(
            "Reviewed Python diagnostic ceilings cannot increase", command.stderr
        )
        self.assertIn("[B006]: 2 > 1", command.stderr)
        self.assertTrue(
            command.stderr.rstrip().endswith(
                "Restore the reviewed allowances and fix the additional findings."
            ),
            command.stderr,
        )


if __name__ == "__main__":
    unittest.main()
