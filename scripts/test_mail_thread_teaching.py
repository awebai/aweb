#!/usr/bin/env python3
"""Every surface that teaches mail carries the aw help's reply rule, word for word."""

from pathlib import Path
import re
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "cli/go/cmd/aw/mail.go"
# Each copy, and whether it is Markdown that may set commands in code spans.
COPIES = {
    "channel-core/src/channel.ts": False,
    "skills/aweb-messaging/SKILL.md": False,
    "packages/codex-plugin/skills/aweb-messaging/SKILL.md": False,
    "docs/mail-and-chat.md": True,
}


def aw_help_teaching(root: Path) -> str:
    match = re.search(
        r'^const mailThreadTeaching = "([^"\\]+)"$',
        (root / SOURCE).read_text(),
        re.MULTILINE,
    )
    if match is None:
        raise AssertionError(f"{SOURCE} defines no mailThreadTeaching constant")
    return match.group(1)


def copies_without_teaching(root: Path) -> list[str]:
    teaching = aw_help_teaching(root)
    missing = []
    for path, markdown in COPIES.items():
        text = (root / path).read_text()
        if markdown:
            text = text.replace("`", "")
        if teaching not in text:
            missing.append(path)
    return missing


class MailThreadTeachingTest(unittest.TestCase):
    def test_every_copy_carries_the_aw_help_teaching(self):
        self.assertEqual(copies_without_teaching(ROOT), [])

    def test_a_stale_copy_is_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for path in [SOURCE, *COPIES]:
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / path, root / path)
            stale = root / "skills/aweb-messaging/SKILL.md"
            stale.write_text(stale.read_text().replace(" --body-file <file>.", ".", 1))
            self.assertEqual(
                copies_without_teaching(root), ["skills/aweb-messaging/SKILL.md"]
            )

    def test_a_missing_copy_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for path in [SOURCE, *COPIES]:
                if path == "docs/mail-and-chat.md":
                    continue
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / path, root / path)
            with self.assertRaises(FileNotFoundError):
                copies_without_teaching(root)


if __name__ == "__main__":
    unittest.main()
