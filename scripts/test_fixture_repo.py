"""Real Git and Python checks for the shared host fixture boundary."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from fixture_repo import init_fixture_repo, run_fixture


class FixtureRepoTests(unittest.TestCase):
    def test_import_bytecode_is_ignored_but_untracked_source_is_not(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".gitignore").write_text("existing-output")
            init_fixture_repo(root)
            (root / "fixture_module.py").write_text("value = 42\n")
            run_fixture(["git", "add", "."], cwd=root, check=True, capture_output=True)
            run_fixture(["git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.test",
                         "commit", "-qm", "fixture"], cwd=root, check=True, capture_output=True)
            run_fixture([sys.executable, "-c", "import fixture_module"], cwd=root, check=True)
            self.assertTrue(list((root / "__pycache__").glob("fixture_module.*.pyc")))
            (root / "existing-output").touch()
            status = ["git", "status", "--porcelain", "--untracked-files=all"]
            self.assertEqual(run_fixture(status, cwd=root, capture_output=True, text=True,
                                         check=True).stdout, "")
            (root / "untracked.py").touch()
            self.assertEqual(run_fixture(status, cwd=root, capture_output=True, text=True,
                                         check=True).stdout, "?? untracked.py\n")

    def test_inherited_and_explicit_environments_do_not_configure_fixture_python(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            poison = root / "pythonpath"
            poison.mkdir()
            (poison / "ambient_only.py").touch()
            startup = root / "startup.py"
            startup.write_text("raise RuntimeError('ambient startup')\n")
            env = dict(os.environ, PYTHONPYCACHEPREFIX=str(root / "cache"),
                       PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(poison),
                       PYTHONSTARTUP=str(startup), FIXTURE_SETTING="preserved")
            child = """import importlib.util, os, sys
assert sys.pycache_prefix is None
assert not sys.dont_write_bytecode
assert importlib.util.find_spec('ambient_only') is None
assert all(name not in os.environ for name in
           ('PYTHONPYCACHEPREFIX', 'PYTHONDONTWRITEBYTECODE', 'PYTHONPATH', 'PYTHONSTARTUP'))
assert os.environ['FIXTURE_SETTING'] == 'preserved'
"""
            for explicit in (False, True):
                with self.subTest(explicit=explicit):
                    # The outer process really starts in the polluted environment.
                    # Its fixture child must start with ordinary Python defaults.
                    driver = (f"import os, sys\nsys.path.insert(0, {str(Path(__file__).parent)!r})\n"
                              "from fixture_repo import run_fixture\n"
                              f"run_fixture([sys.executable, '-c', {child!r}], check=True, "
                              f"env={'dict(os.environ)' if explicit else 'None'})\n")
                    result = subprocess.run([sys.executable, "-c", driver], env=env,
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(result.stdout + result.stderr, "")


if __name__ == "__main__":
    unittest.main()
