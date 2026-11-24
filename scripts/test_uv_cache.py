"""Cache control covers all targets and the operational assignment forms."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from check_uv_cache import check_repository, temporary, violations

ROOT = Path(__file__).resolve().parents[1]
BAD = "/" + "tmp/uv-cache"


class UvCacheTests(unittest.TestCase):
    def test_repository_uses_persistent_cache_locations(self):
        self.assertEqual(check_repository(ROOT), [])

    def test_all_pinned_forms_refuse_temporary_cache(self):
        for value in (BAD, "/private" + BAD, "/opt/../" + BAD.lstrip("/")):
            for expression in (
                "UV_CACHE_DIR={path} uv run test",
                'UV_CACHE_DIR="{path}" uv sync',
                "UV_CACHE_DIR := {path}",
                "UV_CACHE_DIR ?= {path}",
                'export UV_CACHE_DIR="${{UV_CACHE_DIR:-{path}}}"',
                'env.update(UV_CACHE_DIR="{path}")',
                '{{"UV_CACHE_DIR": "{path}"}}',
                'os.environ.get("UV_CACHE_DIR", "{path}")',
                'os.getenv("UV_CACHE_DIR", "{path}")',
                'env.setdefault("UV_CACHE_DIR", "{path}")',
                "ENV UV_CACHE_DIR={path}",
                "ENV UV_CACHE_DIR {path}",
            ):
                with self.subTest(value=value, expression=expression):
                    self.assertTrue(
                        violations(Path("target"), expression.format(path=value))
                    )

    def test_persistent_and_dynamic_caches_and_other_temporary_files_stay_valid(self):
        for source in (
            "UV_CACHE_DIR=/opt/uv-cache PYTHONPYCACHEPREFIX=" + BAD,
            'export UV_CACHE_DIR="${UV_CACHE_DIR:-$HOME/.cache/uv}"',
            'cmd.Env = append(env, "UV_CACHE_DIR="+cacheDir)',
            'cache = exec.Command("uv", "cache", "dir")',
            "UV_CACHE_DIR=/tmp-other/cache",
        ):
            with self.subTest(source=source):
                self.assertEqual(violations(Path("target"), source), [])
        self.assertTrue(temporary("/tmp"))
        self.assertFalse(temporary("/tmp-other"))

    def test_new_make_target_and_gate_operator_are_checked(self):
        with tempfile.TemporaryDirectory() as temporary_root:
            root = Path(temporary_root)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            for name, source in (
                (
                    "Makefile",
                    "future-target:\n\tUV_CACHE_DIR=" + BAD + " uv run pytest\n",
                ),
                (
                    "scripts/vm-gate/operator.py",
                    'env = {"UV_CACHE_DIR": "' + BAD + '"}',
                ),
                ("Dockerfile.runner", "ENV UV_CACHE_DIR=" + BAD),
            ):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(source)
            problems = check_repository(root)
            self.assertEqual(len(problems), 3, problems)
            self.assertTrue(any("Makefile:2:" in problem for problem in problems))

    def test_make_target_inherits_the_parent_uv_default(self):
        # The real recipe must let uv choose its persistent cache, including
        # when make changes into a package or invokes a sub-make.
        with tempfile.TemporaryDirectory() as home:
            env = dict(os.environ, HOME=home)
            for key in ("UV_CACHE_DIR", "XDG_CACHE_HOME"):
                env.pop(key, None)
            expected = subprocess.check_output(
                ["uv", "cache", "dir"], env=env, text=True
            ).strip()
            recipe = subprocess.check_output(
                ["make", "-n", "lint-naapp-contracts"], cwd=ROOT, env=env, text=True
            )
            self.assertNotIn("UV_CACHE_DIR=", recipe)
            self.assertFalse(violations(Path("Makefile"), recipe))
            self.assertEqual(Path(expected).parent.parent, Path(home))


if __name__ == "__main__":
    unittest.main()
