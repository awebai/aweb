#!/usr/bin/env python3
"""The shell entrypoint keeps the full readback deadline across the process boundary.

It needs more than two minutes of real time, so it runs in test-npm-exact-publish
and not in test-scripts' discovery.
"""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from test_npm_readback import Registry  # noqa: E402


class RealDeadlineTests(unittest.TestCase):
    def test_bounded_entrypoint_survives_real_old_deadline(self):
        # Actual elapsed time and real HTTP: the old two-minute default fails.
        # The curl adapter only selects our owned endpoint for the old shell
        # implementation, whose registry URL was not configurable.
        with tempfile.TemporaryDirectory() as temp, Registry().serve() as registry:
            root = Path(temp)
            package = "@awebai/lag-fixture"
            staged = root / "p.tgz"
            staged.write_bytes(b"exact staged bytes")
            registry.packages[package] = staged.read_bytes()
            started = time.monotonic()
            registry.visible = lambda: time.monotonic() - started >= 125
            curl = shutil.which("curl")
            adapter = root / "curl"
            adapter.write_text(
                "#!/usr/bin/env python3\nimport os,sys\n"
                + f'args=[v.replace("https://registry.npmjs.org", {registry.url!r}) for v in sys.argv[1:]]\n'
                + f"os.execv({curl!r}, [{curl!r}]+args)\n"
            )
            adapter.chmod(0o755)
            env = dict(
                os.environ,
                PATH=str(root) + os.pathsep + os.environ["PATH"],
                NPM_CONFIG_REGISTRY=registry.url,
            )
            result = subprocess.run(
                [
                    "bash",
                    str(ROOT / "scripts/npm-exact-publish.sh"),
                    "verify-published-bounded",
                    "--tgz",
                    str(staged),
                    "--package",
                    package,
                    "--version",
                    "1.2.3",
                    "--post-action",
                    "publish",
                ],
                env=env,
                capture_output=True,
                text=True,
                timeout=170,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
