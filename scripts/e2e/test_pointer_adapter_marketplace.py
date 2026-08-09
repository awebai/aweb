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
        # -b main here as well as on the seed: a bare repository takes its HEAD
        # from init.defaultBranch, so leaving it implicit builds a remote whose
        # HEAD names a branch that was never pushed. Cloning that checks out
        # nothing, and the adapter reads the pointer from an empty tree. It
        # agrees with the seed only on a machine configured for main, which is
        # why this passed locally and failed on every runner.
        git("init", "-q", "--bare", "-b", "main", str(self.remote), cwd=root)
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

    def test_the_committed_graph_binds_a_real_repository(self):
        """Production composes the adapter through parse_pointer_adapters using
        the COMMITTED graph. Constructing SubprocessPointerAdapter directly in a
        test bypasses exactly the step that broke: the graph declared no
        repository, the driver sent the component name, and the adapter
        correctly refused - so every real channel pointer refused."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import release_driver as rd

        graph = rd.Graph.load(REPO_ROOT / "release" / "components.toml")
        state = rd.FixtureState(
            changed_components={"channel": True}, versions={"channel": "1.7.4"}
        )
        plan = rd.scope_plan(rd.compute_plan(graph, state), graph, ["channel"])
        lanes = rd.parse_pointer_adapters(
            [f"marketplace-pointer={ADAPTER}"],
            plan=plan, graph=graph, source_sha="a" * 40,
        )
        lane = lanes["marketplace-pointer"]
        self.assertEqual(
            lane.adapter.repository, "github.com/awebai/claude-plugins",
            "the expectation the driver sends must be a real repository, not "
            "the component name",
        )

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

    def test_a_changed_origin_after_clone_is_caught(self):
        """The guard must re-observe, not re-read its own input. Rewriting the
        checkout's origin after clone is the case that distinguishes the two -
        without this, comparing the passed-in string to itself would pass."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("mp_adapter", ADAPTER)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        work = Path(self.tmp.name) / "checkout"
        subprocess.run(["git", "clone", "-q", str(self.remote), str(work)], check=True)
        other = Path(self.tmp.name) / "elsewhere.git"
        subprocess.run(["git", "init", "-q", "--bare", str(other)], check=True)
        subprocess.run(["git", "remote", "set-url", "origin", str(other)],
                       cwd=str(work), check=True)
        with self.assertRaises(SystemExit) as caught:
            mod.verify_origin(work, str(self.remote), "after cloning")
        self.assertIn("origin is", str(caught.exception))

    def test_an_injected_url_rewrite_cannot_redirect_the_push(self):
        """The one origin attack that IS reachable through the real caller.

        The post-clone rewrite cannot be driven through SubprocessPointerAdapter
        at all: the adapter clones into a TemporaryDirectory created inside the
        subprocess and destroyed when it exits, so nothing outside has a window
        to rewrite that checkout's origin. What an operator's environment CAN do
        is carry a url.<base>.insteadOf rewrite, which redirects the clone and
        the push at the moment they are least examined. That is what git_env()'s
        GIT_CONFIG_GLOBAL=/dev/null exists to defeat, and it was untested.

        Driven through SubprocessPointerAdapter, asserting the legitimate
        repository moved and the attacker's received nothing.

        Measured, not assumed: deleting GIT_CONFIG_GLOBAL from git_env() turns
        this red, and the failure shows the rewrite really did redirect the
        clone - "the checkout's origin is .../attacker.git". The refusal comes
        from verify_origin, so the two guards are independent and the second
        catches what the first would miss. The attacker repository received
        nothing in either arm.
        """
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import release_driver as rd

        attacker = Path(self.tmp.name) / "attacker.git"
        git("init", "-q", "--bare", str(attacker), cwd=Path(self.tmp.name))

        home = Path(self.tmp.name) / "poisoned-home"
        home.mkdir()
        (home / ".gitconfig").write_text(
            f'[url "{attacker}"]\n\tinsteadOf = {self.remote}\n'
        )

        adapter = rd.SubprocessPointerAdapter(ADAPTER, repository=str(self.remote))
        saved = {k: os.environ.get(k) for k in
                 ("HOME", "GIT_CONFIG_GLOBAL", "MARKETPLACE_REMOTE")}

        def restore():
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

        self.addCleanup(restore)
        os.environ["HOME"] = str(home)
        os.environ["GIT_CONFIG_GLOBAL"] = str(home / ".gitconfig")
        os.environ["MARKETPLACE_REMOTE"] = str(self.remote)

        updates = {"channel": "1.7.4"}
        intent = adapter.intent("marketplace-pointer", updates)
        adapter.apply("marketplace-pointer", updates, intent)

        self.assertEqual(
            self.run_adapter("read")["advertised"]["channel"], "1.7.4",
            "the legitimate repository must be the one that moved",
        )
        refs = subprocess.run(["git", "for-each-ref"], cwd=str(attacker),
                              capture_output=True, text=True).stdout.strip()
        self.assertEqual(refs, "", f"the attacker repository received {refs!r}")

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




class RecordingAuthority:
    """FixtureAuthority plus recorded_ids, which resume needs to find the
    anchored staged manifest and published transitions."""

    def __init__(self):
        self.recorded: dict[str, str] = {}

    def record(self, artifact_id: str, digest: str) -> None:
        self.recorded[artifact_id] = digest

    def expected_digest(self, artifact_id: str) -> str | None:
        return self.recorded.get(artifact_id)

    def recorded_ids(self):
        return list(self.recorded)


class PublishedPackageLane:
    """The npm side of a forced-pointer release, as an already-published
    package. Counts publishes so 'adopted, never republished' is measurable
    rather than asserted."""

    def __init__(self, component="channel", version="1.7.4"):
        self.component = component
        self.version = version
        self.digest = "sha256:" + "c" * 64
        self.publishes = 0
        self.visible = True

    def has_lane(self, component):
        return component == self.component

    def _entry(self, phase):
        import release_driver as rd
        return rd.ReceiptEntry(
            version=self.version, digest=self.digest, phase=phase
        )

    def stage(self, node):
        return self._entry("staged")

    def publish(self, node, staged):
        self.publishes += 1
        return self._entry("published")

    def verify(self, node, published):
        return self._entry("verified")

    def observe(self, node, staged=None):
        return self._entry("published") if self.visible else None


class PointerCrashResumeTests(unittest.TestCase):
    """The crash window between staging a forced pointer and applying it.

    This window is the LIKELIEST one in a pointer release, because the pointer
    is applied last: the package is already on the registry and the marketplace
    still advertises the old version. Real PointerLane, real adapter executable,
    real git remote, real resume_plan.
    """

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
        # -b main here as well as on the seed: a bare repository takes its HEAD
        # from init.defaultBranch, so leaving it implicit builds a remote whose
        # HEAD names a branch that was never pushed. Cloning that checks out
        # nothing, and the adapter reads the pointer from an empty tree. It
        # agrees with the seed only on a machine configured for main, which is
        # why this passed locally and failed on every runner.
        git("init", "-q", "--bare", "-b", "main", str(self.remote), cwd=root)
        git("remote", "add", "origin", str(self.remote), cwd=seed)
        git("push", "-q", "origin", "main", cwd=seed)
        self.addCleanup(self.tmp.cleanup)
        os.environ["MARKETPLACE_REMOTE"] = str(self.remote)
        self.addCleanup(os.environ.pop, "MARKETPLACE_REMOTE", None)

        sys.path.insert(0, str(Path(__file__).resolve().parent))
        sys.path.insert(0, str(REPO_ROOT / "scripts"))

    def graph(self):
        import release_driver as rd
        return rd.Graph.from_dict({
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

    def compose(self, package_lane):
        """Real PointerLane over the real adapter, plus the package lane."""
        import release_driver as rd
        from test_release_driver import FixtureSkew, SOURCE_SHA

        graph = self.graph()
        state = rd.FixtureState(
            changed_components={"channel": True},
            versions={"channel": "1.7.4"},
            published_versions={"channel": "1.7.3"},
        )
        plan = rd.compute_plan(graph, state)
        pointer = rd.PointerLane(
            "marketplace-pointer",
            adapter=rd.SubprocessPointerAdapter(ADAPTER, repository=str(self.remote)),
            updates=rd.pointer_updates(plan, graph)["marketplace-pointer"],
            repository="github.com/awebai/claude-plugins",
        )
        lanes = rd.WorkflowLanes({
            "channel": package_lane, "marketplace-pointer": pointer,
        })
        store, authority = rd._MemoryStore(), RecordingAuthority()
        frozen_bytes, frozen_id = rd.freeze_plan(
            plan, graph, source_sha=SOURCE_SHA, state=state
        )
        artifact_id = f"plan:{SOURCE_SHA}:{frozen_id}"
        rd._put_content_addressed(
            store, authority, artifact_id, frozen_bytes, frozen_id
        )
        frozen = rd.load_frozen_plan(store.get(artifact_id), expected_id=frozen_id)
        return graph, plan, lanes, store, authority, frozen, state, FixtureSkew()

    def advertised(self):
        result = subprocess.run(
            [sys.executable, str(ADAPTER), "read",
             "--component", "marketplace-pointer",
             "--expect-repository", str(self.remote)],
            capture_output=True, text=True,
            env={**os.environ, "MARKETPLACE_REMOTE": str(self.remote)},
        )
        return json.loads(result.stdout)["advertised"]

    def block_pushes(self):
        """Make the marketplace push fail, which is the crash this is about."""
        hooks = self.remote / "hooks"
        hooks.mkdir(exist_ok=True)
        hook = hooks / "pre-receive"
        hook.write_text("#!/bin/sh\nexit 1\n")
        hook.chmod(0o755)
        return hook

    def crash_after_package_before_pointer(self, package_lane):
        """Round one: the package publishes, the pointer push fails."""
        import release_driver as rd
        from test_release_driver import SOURCE_SHA

        graph, plan, lanes, store, authority, frozen, state, skew = self.compose(
            package_lane
        )
        hook = self.block_pushes()
        with self.assertRaises(rd.ReceiptError):
            rd.run_plan(
                plan, graph, lanes, skew=skew, authority=authority, store=store,
                source_sha=SOURCE_SHA, approvals={}, state=state, frozen=frozen,
                providers=rd.Providers(store=store, authority=authority),
            )
        hook.unlink()
        self.assertEqual(
            self.advertised()["channel"], "1.7.3",
            "the crash must leave the marketplace stale, or this proves nothing",
        )
        return graph, plan, store, authority, frozen, state, skew

    def test_a_stale_unapplied_pointer_is_remaining_work_not_drift(self):
        """The blocker. After a crash between publishing the package and
        applying the pointer, NOTHING claims the pointer published - so it is
        work the resume must finish, not drift that must refuse. Refusing here
        makes the likeliest crash window unrecoverable."""
        import release_driver as rd
        from test_release_driver import SOURCE_SHA

        package = PublishedPackageLane()
        graph, plan, store, authority, frozen, state, skew = (
            self.crash_after_package_before_pointer(package)
        )
        published_before = package.publishes

        pointer = rd.PointerLane(
            "marketplace-pointer",
            adapter=rd.SubprocessPointerAdapter(ADAPTER, repository=str(self.remote)),
            updates=rd.pointer_updates(plan, graph)["marketplace-pointer"],
            repository="github.com/awebai/claude-plugins",
        )
        lanes = rd.WorkflowLanes({"channel": package, "marketplace-pointer": pointer})
        rd.resume_plan(
            plan, graph, lanes=lanes, skew=skew, store=store, authority=authority,
            source_sha=SOURCE_SHA, approvals={}, state=state, frozen=frozen,
        )
        self.assertEqual(
            self.advertised()["channel"], "1.7.4",
            "the resume must APPLY the pointer that was never applied",
        )
        self.assertEqual(
            self.advertised()["skills"], "0.2.12",
            "and must leave untouched entries alone",
        )
        self.assertEqual(
            package.publishes, published_before,
            "the already-published package must be adopted, never republished",
        )

    def test_an_exactly_advertised_pointer_is_adopted(self):
        """The pointer landed before the crash. Its observation equals what was
        staged, so the resume adopts it and pushes nothing further."""
        import release_driver as rd
        from test_release_driver import SOURCE_SHA

        package = PublishedPackageLane()
        graph, plan, store, authority, frozen, state, skew = (
            self.crash_after_package_before_pointer(package)
        )
        adapter = rd.SubprocessPointerAdapter(ADAPTER, repository=str(self.remote))
        updates = rd.pointer_updates(plan, graph)["marketplace-pointer"]
        adapter.apply("marketplace-pointer", updates,
                      adapter.intent("marketplace-pointer", updates))
        self.assertEqual(self.advertised()["channel"], "1.7.4")
        head_before = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=str(self.remote),
            capture_output=True, text=True).stdout.strip()

        pointer = rd.PointerLane(
            "marketplace-pointer", adapter=adapter, updates=updates,
            repository="github.com/awebai/claude-plugins",
        )
        lanes = rd.WorkflowLanes({"channel": package, "marketplace-pointer": pointer})
        rd.resume_plan(
            plan, graph, lanes=lanes, skew=skew, store=store, authority=authority,
            source_sha=SOURCE_SHA, approvals={}, state=state, frozen=frozen,
        )
        head_after = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=str(self.remote),
            capture_output=True, text=True).stdout.strip()
        self.assertEqual(head_before, head_after,
                         "an adopted pointer must not push again")

    def test_a_stale_pointer_refuses_when_a_transition_claims_publication(self):
        """The other direction, which must NOT be weakened by the fix. If an
        anchored transition claims the pointer published and the repository
        does not advertise it, that is drift and the resume must refuse."""
        import release_driver as rd
        from test_release_driver import SOURCE_SHA

        package = PublishedPackageLane()
        graph, plan, store, authority, frozen, state, skew = (
            self.crash_after_package_before_pointer(package)
        )
        updates = rd.pointer_updates(plan, graph)["marketplace-pointer"]
        pointer = rd.PointerLane(
            "marketplace-pointer",
            adapter=rd.SubprocessPointerAdapter(ADAPTER, repository=str(self.remote)),
            updates=updates,
            repository="github.com/awebai/claude-plugins",
        )
        lane_entry = pointer.stage(
            next(n for n in plan.moving if n.component == "marketplace-pointer")
        )
        manifest_id = next(
            i for i in authority.recorded_ids() if i.startswith("staged-manifest:")
        )
        record = json.dumps({
            "kind": "published",
            "component": "marketplace-pointer",
            "frozen_plan_id": frozen.frozen_id,
            "staged_manifest_id": manifest_id,
            "entry": {
                "version": lane_entry.version, "digest": lane_entry.digest,
                "phase": "published", "pointer_state": "advertised",
                "digest_set": None, "lane_ref": None,
            },
        }, sort_keys=True).encode()
        artifact_id = f"transition:{frozen.frozen_id}:marketplace-pointer"
        rd._put_content_addressed(
            store, authority, artifact_id, record,
            __import__("hashlib").sha256(record).hexdigest(),
        )

        lanes = rd.WorkflowLanes({"channel": package, "marketplace-pointer": pointer})
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.resume_plan(
                plan, graph, lanes=lanes, skew=skew, store=store,
                authority=authority, source_sha=SOURCE_SHA, approvals={},
                state=state, frozen=frozen,
            )
        self.assertIn("marketplace-pointer", str(caught.exception))
        self.assertEqual(
            self.advertised()["channel"], "1.7.3",
            "a refusal must not have mutated the repository",
        )


if __name__ == "__main__":
    unittest.main()
