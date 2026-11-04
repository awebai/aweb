#!/usr/bin/env python3
"""The ledger fixture's nested make must not inherit the release's overrides."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CandidateMakeEnvironmentTests(unittest.TestCase):
    def test_real_make_environment_and_command_line_forms(self):
        for command_line in (False, True):
            with self.subTest(command_line=command_line), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                (root / "nested.mk").write_text(
                    "candidate-gate:\n\t@printf '%s\\n' '$(CLI_VERSION)' '$(STAGE_AW_FINAL)' '$(MAKELEVEL)'\n")
                (root / "probe.py").write_text(
                    "import os, sys\n"
                    f"sys.path.insert(0, {str(ROOT / 'scripts')!r})\n"
                    "from test_candidate_gate_ledger import run\n"
                    "from pathlib import Path\n"
                    "env = dict(os.environ, CLI_VERSION='1.2.3', STAGE_AW_FINAL='0')\n"
                    "result = run(Path.cwd(), 'make', '--no-print-directory', '-f', 'nested.mk', 'candidate-gate', env=env)\n"
                    "assert result.returncode == 0, result.stderr\n"
                    "assert result.stdout.splitlines() == ['1.2.3', '0', '0'], result.stdout\n")
                (root / "Makefile").write_text("release-candidate:\n\t@python3 probe.py\n")
                env = {k: v for k, v in os.environ.items() if k not in
                       {'MAKEFLAGS', 'MAKELEVEL', 'MAKEOVERRIDES', 'MFLAGS'}}
                args = ['make', '--no-print-directory', 'release-candidate']
                if command_line:
                    args += ['CLI_VERSION=9.9.9', 'STAGE_AW_FINAL=1']
                else:
                    env.update(CLI_VERSION='9.9.9', STAGE_AW_FINAL='1')
                result = subprocess.run(args, cwd=root, env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
