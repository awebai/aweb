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
ADAPTER = REPO_ROOT / "scripts" / "pointer-adapter-marketplace-pointer.py"
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
                   "--component", "marketplace-pointer",
                   "--expect-repository", str(self.remote)]
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

    def test_run_plan_publishes_through_the_real_adapter(self):
        """The test whose absence let four independent blockers ship: a real
        PointerLane, driving the real adapter as an executable, through
        run_plan, against a real git remote. Every earlier test either used a
        fake that agreed with the implementation or invoked the script through
        sys.executable, so none of them touched the path an operator uses."""
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import release_driver as rd
        from test_release_driver import (
            FixtureLanes, FixtureSkew, FixtureAuthority, SOURCE_SHA,
        )

        graph = rd.Graph.from_dict({
            "component": {
                "channel": {
                    "source_paths": ["channel/"],
                    "version_source": {"type": "manifest", "path": "v"},
                    "tag_format": "channel-v{version}",
                    "publish_lane": {"workflow": "w"},
                    "verify": {"command": "true"},
                },
                "marketplace-pointer": {"publishable": False},
            },
            "edge": [{"type": "pointer", "from": "channel",
                      "to": ["marketplace-pointer"]}],
        })
        state = rd.FixtureState(
            changed_components={"channel": True}, versions={"channel": "1.7.4"},
            published_versions={"channel": "1.7.3"},
        )
        plan = rd.compute_plan(graph, state)
        os.environ["MARKETPLACE_REMOTE"] = str(self.remote)
        self.addCleanup(os.environ.pop, "MARKETPLACE_REMOTE", None)

        lane = rd.PointerLane(
            "marketplace-pointer",
            adapter=rd.SubprocessPointerAdapter(ADAPTER, repository=str(self.remote)),
            updates=rd.pointer_updates(plan, graph)["marketplace-pointer"],
            repository="github.com/awebai/claude-plugins",
        )
        rd.run_plan(
            plan, graph,
            rd.WorkflowLanes({
                "channel": FixtureLanes(available={"channel"}),
                "marketplace-pointer": lane,
            }),
            skew=FixtureSkew(), authority=FixtureAuthority(),
            providers=rd.Providers(
                store=rd._MemoryStore(), authority=FixtureAuthority(),
            ),
            source_sha=SOURCE_SHA, approvals={}, state=state,
        )

        after = self.run_adapter("read")["advertised"]
        self.assertEqual(after["channel"], "1.7.4")
        self.assertEqual(after["skills"], "0.2.12",
                         "a partial update must leave other entries alone")

    def test_a_substituted_remote_is_refused(self):
        """The binding must not be decorative. An ambient remote pointing
        somewhere else must refuse rather than be mutated under the graph's
        label - a test override is a test seam, not production authority."""
        other = Path(self.tmp.name) / "substituted.git"
        subprocess.run(["git", "init", "-q", "--bare", str(other)], check=True)
        command = [sys.executable, str(ADAPTER), "read",
                   "--component", "marketplace-pointer",
                   "--expect-repository", "github.com/awebai/claude-plugins"]
        env = {**os.environ, "MARKETPLACE_REMOTE": str(other)}
        result = subprocess.run(command, capture_output=True, text=True, env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to act on", result.stderr)

    def test_a_missing_expectation_is_refused(self):
        """Accepting a missing expectation made the flag decorative."""
        command = [sys.executable, str(ADAPTER), "read",
                   "--component", "marketplace-pointer"]
        env = {**os.environ, "MARKETPLACE_REMOTE": str(self.remote)}
        result = subprocess.run(command, capture_output=True, text=True, env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--expect-repository", result.stderr)

    def test_canonical_identity_survives_transport_spelling(self):
        """The graph says github.com/awebai/x; the transport says
        git@github.com:awebai/x.git. Comparing raw strings would refuse every
        real release."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import importlib.util
        spec = importlib.util.spec_from_file_location("mp_adapter", ADAPTER)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.assertEqual(
            mod.canonical("git@github.com:awebai/claude-plugins.git"),
            mod.canonical("github.com/awebai/claude-plugins"),
        )

    def test_the_adapter_is_executable(self):
        """SubprocessPointerAdapter execs the path directly. Committed 100644,
        the first thing a real release did was raise PermissionError."""
        self.assertTrue(os.access(ADAPTER, os.X_OK), f"{ADAPTER} must be executable")

    def test_a_component_the_marketplace_does_not_list_is_refused(self):
        """Silently advertising nothing is how a release looks complete and
        reaches nobody."""
        command = [sys.executable, str(ADAPTER), "apply",
                   "--component", "marketplace-pointer",
                   "--expect-repository", str(self.remote),
                   "--updates", json.dumps({"pi": "0.3.4"})]
        env = {**os.environ, "MARKETPLACE_REMOTE": str(self.remote)}
        result = subprocess.run(command, capture_output=True, text=True, env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("@awebai/pi", result.stderr)


if __name__ == "__main__":
    unittest.main()
