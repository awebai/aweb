from __future__ import annotations

import asyncio
import io
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import regenerate_mcp_reference as generator


class MCPReferenceGeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tools = asyncio.run(generator.load_registered_tools())

    def test_live_registration_renders_complete_mail_chat_schema(self) -> None:
        rendered = generator.render_reference(self.tools)

        def row(name: str) -> str:
            return next(
                line
                for line in rendered.splitlines()
                if line.startswith(f"| `{name}`")
            )

        send_mail = row("send_mail")
        check_mail = row("check_mail")
        send_chat = row("send_chat")

        self.assertIn("`plaintext=False`", send_mail)
        self.assertIn("`plaintext=False`", send_chat)
        self.assertIn("Hosted custodial sends encrypt by default", send_mail)
        self.assertIn("marks returned unread messages read", check_mail)
        self.assertIn("Hosted custodial sends encrypt by default", send_chat)
        read_chat = row("read_chat")
        task_create = row("task_create")
        self.assertIn("`conversation_id`, `unread_only=False`, `limit=50`", read_chat)
        self.assertIn("`title`, `description=\"\"`", task_create)
        self.assertIn("`labels=None`", task_create)
        self.assertNotIn("aweb_welcome_guide", rendered)
        self.assertNotIn("create_invite_link", rendered)

    def test_new_registered_tool_fails_closed_until_classified(self) -> None:
        tools = dict(self.tools)
        tools["unclassified_tool"] = SimpleNamespace(name="unclassified_tool")

        with self.assertRaisesRegex(
            generator.CoverageError,
            "unclassified registered tool: unclassified_tool",
        ):
            generator.validate_coverage(tools)

    def test_documented_tool_absent_from_registration_fails_closed(self) -> None:
        tools = dict(self.tools)
        del tools["whoami"]

        with self.assertRaisesRegex(
            generator.CoverageError,
            "documented tool absent from registration: whoami",
        ):
            generator.validate_coverage(tools)

    def test_check_rejects_stale_output_without_rewriting_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "mcp-tools-reference.md"
            original = b"stale\n"
            output.write_bytes(original)
            stdout = io.StringIO()
            stderr = io.StringIO()

            with (
                mock.patch.object(generator, "OUTPUT", output),
                mock.patch.object(sys, "argv", ["regenerate_mcp_reference.py", "--check"]),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                exit_code = generator.main()

            self.assertEqual(exit_code, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("MCP tools reference is stale", stderr.getvalue())
            self.assertEqual(output.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
