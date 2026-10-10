from __future__ import annotations

import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from generate_cli_reference import (
    RootCoverageError,
    main,
    parse_help,
    render_reference,
    validate_root_coverage,
)


ROOT_HELP_WITH_ADDITIONAL = """Coordinate independent AI agents.

Usage:
  aw [command]

Identity & Teams
  id          Identity lifecycle
  team        Manage teams

Additional Commands:
  blueprint   Inspect and manage Library blueprints
  session     Session-scoped coordination

Flags:
  -h, --help   help for aw
"""


class CLIReferenceGeneratorTests(unittest.TestCase):
    def test_inherited_aweb_settings_do_not_change_live_reference(self) -> None:
        binary = os.environ.get("AW_CLI_REFERENCE_BIN")
        if not binary:
            self.skipTest("AW_CLI_REFERENCE_BIN is set by the generator self-test")
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "reference.md"
            result = subprocess.run(
                [sys.executable, str(Path(__file__).with_name("generate_cli_reference.py")),
                 "--binary", binary, "--output", str(output)],
                env={
                    **os.environ,
                    "AWEB_IDENTITY_HOME": str(Path(temp_dir).resolve()),
                    "AWEB_DELIVERY": "session",
                    "AWEB_CHANNEL_DEBUG": "1",
                    "AWEB_CHANNEL_DEBUG_FILE": str(Path(temp_dir) / "unexpected-debug"),
                },
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                output.read_bytes(),
                (Path(__file__).resolve().parents[1] / "docs/cli-command-reference.md").read_bytes(),
            )
            self.assertEqual(list(Path(temp_dir).iterdir()), [output])

    def test_additional_commands_are_parsed_as_a_visible_group(self) -> None:
        parsed = parse_help(ROOT_HELP_WITH_ADDITIONAL)

        self.assertEqual(
            parsed["groups"],
            [
                ("Identity & Teams", [("id", "Identity lifecycle"), ("team", "Manage teams")]),
                (
                    "Additional Commands",
                    [
                        ("blueprint", "Inspect and manage Library blueprints"),
                        ("session", "Session-scoped coordination"),
                    ],
                ),
            ],
        )

    def test_visible_root_command_addition_fails_until_rendered(self) -> None:
        with self.assertRaisesRegex(
            RootCoverageError,
            "visible root command not rendered: session",
        ):
            validate_root_coverage(["mail"], ["mail", "session"])

    def test_removed_root_command_fails_while_still_rendered(self) -> None:
        with self.assertRaisesRegex(
            RootCoverageError,
            "rendered root command absent from completion: session",
        ):
            validate_root_coverage(["mail", "session"], ["mail"])

    def test_live_reference_contains_blueprint_and_session_families(self) -> None:
        binary = os.environ.get("AW_CLI_REFERENCE_BIN")
        if not binary:
            self.skipTest("AW_CLI_REFERENCE_BIN is set by the generator self-test")

        reference = render_reference(Path(binary))

        self.assertIn("## `blueprint`", reference)
        self.assertIn("### `blueprint inspect`", reference)
        self.assertIn("## `session`", reference)
        self.assertIn("### `session lease`", reference)
        self.assertIn("### `session lease acquire`", reference)
        self.assertIn("### `team admin`", reference)
        self.assertIn("### `team admin add`", reference)
        self.assertNotIn("### `team add`", reference)

    def test_check_rejects_stale_output_without_rewriting_it(self) -> None:
        binary = os.environ.get("AW_CLI_REFERENCE_BIN")
        if not binary:
            self.skipTest("AW_CLI_REFERENCE_BIN is set by the generator self-test")
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "reference.md"
            stale = b"stale CLI reference\n"
            output.write_bytes(stale)
            stdout = io.StringIO()
            stderr = io.StringIO()

            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = main(
                    [
                        "--binary",
                        binary,
                        "--output",
                        str(output),
                        "--check",
                    ]
                )

            self.assertEqual(status, 1)
            self.assertIn("CLI command reference is stale", stderr.getvalue())
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(output.read_bytes(), stale)


if __name__ == "__main__":
    unittest.main()
