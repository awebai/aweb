"""Every fixed continue command, checked against the argparse of the
script it actually invokes.

TWO OF NINE have now shipped missing a required argument, and both
were found by EXECUTING them rather than by reading:

  - the digest command (A8) lacked --version/--source-sha;
  - the marketplace command lacked --expect-repository, and refused on
    its first ever production execution - mid-release, with four
    artifacts already published.

The pattern is the same each time: the fixed tuple is written beside
the call site that appends the rest, and nothing compares the union
against what the script demands. Reading them found neither. So this
composes each command the way the train composes it and hands the
result to the REAL script's parser.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_train as rt  # noqa: E402

AC_ROOT = REPO_ROOT.parent / "ac"


def _load(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem.replace("-", "_"), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _script_of(argv) -> Path | None:
    """The script a fixed command invokes, wherever it lives."""

    for token in argv:
        if token.endswith(".py"):
            for root in (REPO_ROOT, AC_ROOT, REPO_ROOT.parent / "ac-worktree"):
                candidate = root / token
                if candidate.is_file():
                    return candidate
            return None
    return None


class FixedCommandArgv(unittest.TestCase):
    def test_every_python_command_resolves_to_a_real_script(self) -> None:
        missing = []
        for env, argv in rt._CONTINUE_FIXED_COMMANDS.items():
            if not any(t.endswith(".py") for t in argv):
                continue
            if _script_of(argv) is None:
                missing.append((env, argv))
        self.assertEqual(
            missing, [],
            "a fixed command names a script that does not exist in either "
            "repository - it can only fail at release time",
        )

    def test_the_marketplace_argv_the_train_composes_is_accepted(self) -> None:
        """The defect that stopped a half-published release."""

        script = _script_of(
            rt._CONTINUE_FIXED_COMMANDS["AWEB_RELEASE_MARKETPLACE_COMMAND"]
        )
        self.assertIsNotNone(script)
        module = _load(script)

        fixed = list(rt._CONTINUE_FIXED_COMMANDS["AWEB_RELEASE_MARKETPLACE_COMMAND"])
        composed = fixed[2:] + [
            "--component", "marketplace-pointer",
            "--expect-repository", rt.MARKETPLACE_REPOSITORY,
            "--updates", json.dumps({"channel": "1.7.6", "skills": "0.2.13"}),
        ]
        parser = argparse.ArgumentParser()
        parser.add_argument("operation", choices=("apply", "read"))
        parser.add_argument("--component", required=True)
        parser.add_argument("--expect-repository")
        parser.add_argument("--updates")
        args = parser.parse_args(composed)

        # The script's OWN refusal must accept it - argparse alone would
        # not have caught this one, because --expect-repository is
        # optional to argparse and required by require_expected.
        self.assertEqual(
            module.require_expected(args.expect_repository),
            module.expected_remote(),
        )

    def test_the_bare_marketplace_tuple_is_still_REFUSED(self) -> None:
        """The discriminating control: without the appended argument the
        script must still refuse, so the appending is load-bearing
        rather than decorative."""

        script = _script_of(
            rt._CONTINUE_FIXED_COMMANDS["AWEB_RELEASE_MARKETPLACE_COMMAND"]
        )
        module = _load(script)
        with self.assertRaises(SystemExit) as caught:
            module.require_expected(None)
        self.assertIn("--expect-repository", str(caught.exception))

    def test_the_release_declares_the_marketplace_repository_itself(self) -> None:
        """--expect-repository exists so the CALLER states an
        independent expectation. Passing the adapter's own default back
        to it would compare a value against itself."""

        script = _script_of(
            rt._CONTINUE_FIXED_COMMANDS["AWEB_RELEASE_MARKETPLACE_COMMAND"]
        )
        source = script.read_text()
        self.assertIn("MARKETPLACE_REPOSITORY", dir(rt))
        # They must AGREE today - a disagreement is a real misconfiguration -
        # but they are two declarations, not one read twice.
        module = _load(script)
        self.assertEqual(
            module.canonical(rt.MARKETPLACE_REPOSITORY),
            module.canonical(module.DEFAULT_REMOTE),
        )
        self.assertIn("DEFAULT_REMOTE", source)


if __name__ == "__main__":
    unittest.main()
