"""The AC digest contract, executed against the REAL AC script.

Kept out of the release gate DELIBERATELY, and this module exists so
that exclusion is a declaration rather than a silent omission.

The test needs a checkout of the AC repository beside this one. The
gate container mounts only the aweb checkout at an absolute path, so
no AC sibling can exist inside it under any host layout - the same
condition that made the column-b row unable to pass where it ran. A
row that cannot run in its own environment is worse than an
acknowledged gap, so this runs in the PR lane (make
test-release-ac-digest) where the sibling genuinely exists, and it
FAILS rather than skips when it is absent there.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_train as rt  # noqa: E402


class AcDigestContract(unittest.TestCase):
    def test_digest_argv_composed_by_the_train_executes_the_real_ac_contract(self) -> None:
        # C1, the critic's probe in both directions: the FIXED digest
        # command plus the train-appended card arguments must be
        # accepted and answer digest= against the real AC script; the
        # bare fixed tuple (the A8 defect) must be refused by argparse -
        # pinning that the appending is load-bearing.
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from registry_stand_in import RegistryStandIn

        ac_root = Path(__file__).resolve().parents[2].parent / "ac-worktree"
        script = ac_root / "scripts" / "verify_registry_adoption.py"
        if not script.exists():
            ac_root = Path(__file__).resolve().parents[2].parent / "ac"
            script = ac_root / "scripts" / "verify_registry_adoption.py"
        if not script.exists():
            self.fail(
                "no AC checkout with verify_registry_adoption.py beside this "
                "repository; the digest contract cannot be executed"
            )
        digest_value = "sha256:" + "ab" * 32
        world = {
            "ghcr_index": {
                "awebai/ac": {
                    "0.7.15": {
                        "digest": digest_value,
                        "platforms": [
                            ["linux", "amd64"],
                            ["linux", "arm64"],
                        ],
                    }
                }
            }
        }
        fixed = rt._CONTINUE_FIXED_COMMANDS["AWEB_RELEASE_DIGEST_COMMAND"]
        with RegistryStandIn(world) as registry:
            env = {
                **os.environ,
                "AC_REGISTRY_BASE": registry.base,
                "GH_TOKEN": "fixture-token",
            }
            composed = subprocess.run(
                [
                    *fixed,
                    "--version",
                    "0.7.15",
                    "--source-sha",
                    "c" * 40,
                ],
                cwd=ac_root,
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )
            bare = subprocess.run(
                list(fixed),
                cwd=ac_root,
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )
        self.assertEqual(
            composed.returncode,
            0,
            f"stdout:{composed.stdout} stderr:{composed.stderr}",
        )
        self.assertIn(f"digest={digest_value}", composed.stdout)
        self.assertEqual(
            bare.returncode, 2, "the bare fixed tuple must be refused"
        )
        self.assertIn("--version", bare.stderr)


if __name__ == "__main__":
    unittest.main()
