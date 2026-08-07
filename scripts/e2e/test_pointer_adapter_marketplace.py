#!/usr/bin/env python3
"""The marketplace pointer adapter, against a real git repository.

Real clone, real commit, real push, real read-back into a local bare remote -
no network. The thing being proved is that the version an installed plugin
resolves actually changes, which is the whole reason the pointer exists.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ADAPTER = REPO_ROOT / "scripts" / "pointer-adapter-marketplace.py"
POINTER_FILE = ".claude-plugin/marketplace.json"

MARKETPLACE = {
    "name": "awebai-marketplace",
    "plugins": [
        {
            "name": "aweb-channel",
            "source": {
                "source": "npm",
                "package": "@awebai/claude-channel",
                "version": "1.7.3",
            },
        },
        {
            "name": "aweb-skills",
            "source": {
                "source": "npm",
                "package": "@awebai/claude-skills",
                "version": "0.2.12",
            },
        },
    ],
}


def git(*args, cwd):
    subprocess.run(["git", *args], cwd=str(cwd), check=True,
                   capture_output=True, text=True)


class MarketplaceAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.remote = root / "remote.git"
        seed = root / "seed"
        seed.mkdir()
        (seed / ".claude-plugin").mkdir()
        (seed / POINTER_FILE).write_text(json.dumps(MARKETPLACE, indent=2) + "\n")
        git("init", "-q", "-b", "main", cwd=seed)
        git("-c", "user.email=t@t", "-c", "user.name=t", "add", ".", cwd=seed)
        git("-c", "user.email=t@t", "-c", "user.name=t",
            "commit", "-qm", "seed", cwd=seed)
        git("init", "-q", "--bare", str(self.remote), cwd=root)
        git("remote", "add", "origin", str(self.remote), cwd=seed)
        git("push", "-q", "origin", "main", cwd=seed)
        self.addCleanup(self.tmp.cleanup)

    def run_adapter(self, operation, updates=None):
        command = [sys.executable, str(ADAPTER), operation,
                   "--component", "marketplace-pointer"]
        if updates is not None:
            command += ["--updates", json.dumps(updates)]
        env = {**os.environ, "MARKETPLACE_REMOTE": str(self.remote)}
        result = subprocess.run(command, capture_output=True, text=True, env=env)
        if result.returncode != 0:
            raise AssertionError(f"{operation} failed: {result.stderr}")
        return json.loads(result.stdout)

    def test_read_reports_what_the_remote_currently_advertises(self):
        self.assertEqual(
            self.run_adapter("read")["advertised"],
            {"channel": "1.7.3", "skills": "0.2.12"},
        )

    def test_apply_moves_the_advertised_version_and_read_sees_it(self):
        """The failure this prevents: the package is on npm, the marketplace
        still says the old version, and every installed plugin keeps resolving
        it."""
        before = self.run_adapter("read")["advertised"]
        self.assertEqual(before["channel"], "1.7.3")

        self.run_adapter("apply", {"channel": "1.7.4"})

        after = self.run_adapter("read")["advertised"]
        self.assertEqual(after["channel"], "1.7.4")
        self.assertEqual(after["skills"], "0.2.12", "untouched entries stay put")

    def test_apply_is_idempotent(self):
        self.run_adapter("apply", {"channel": "1.7.4"})
        self.run_adapter("apply", {"channel": "1.7.4"})
        self.assertEqual(self.run_adapter("read")["advertised"]["channel"], "1.7.4")

    def test_intent_touches_no_network_and_echoes_the_plan(self):
        self.assertEqual(
            self.run_adapter("intent", {"channel": "1.7.4"})["advertised"],
            {"channel": "1.7.4"},
        )

    def test_a_component_the_marketplace_does_not_list_is_refused(self):
        """Silently advertising nothing is how a release looks complete and
        reaches nobody."""
        command = [sys.executable, str(ADAPTER), "apply",
                   "--component", "marketplace-pointer",
                   "--updates", json.dumps({"pi": "0.3.4"})]
        env = {**os.environ, "MARKETPLACE_REMOTE": str(self.remote)}
        result = subprocess.run(command, capture_output=True, text=True, env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("@awebai/pi", result.stderr)


if __name__ == "__main__":
    unittest.main()
