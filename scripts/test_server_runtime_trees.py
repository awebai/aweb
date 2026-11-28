"""Exercise kept Node readers while another worker rebuilds its dist tree.

The npm transport emits controlled modules, not product bundles. Real Node and
kept host scripts exercise resolution/lifetime; this is filesystem isolation
coverage, not a substitute for the native seven-worker product measurement.
"""

from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import shutil
import select
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "js_runtime_tree", ROOT / "server/tests/js_runtime_tree.py"
)
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)

# Reproduce npm prebuild's core rebuild followed by a package rebuild. Real
# unlink/write/Node import boundaries; no services, network or product behavior.
BUILDER = r'''
import os, pathlib, shutil, sys
root = pathlib.Path.cwd().parent
for name in ("channel-core", pathlib.Path.cwd().name):
    shutil.rmtree(root / name / "dist", ignore_errors=True)
if os.environ.get("HOLD_DIST_GAP"):
    print("DIST_REMOVED", flush=True)
    assert sys.stdin.readline().strip() == "REBUILD"
core = root / "channel-core/dist"
for name, content in {
 "api/client.js": "export class APIClient {}",
 "activity/emitter.js": "export class ActivityEmitter { async drained() {} }",
 "activity/publish.js": "export async function publishActivity() {}",
 "index.js": """export function createActivityEmitter() {}
export function createChannelClient() {}
export function createRegistryResolver() {}
export class SenderTrustManager {}
export async function loadPinStore() {}
export async function resolveConfig() { return {}; }
export async function startChannelLoop() {}""",
}.items():
    path = core / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
package = pathlib.Path.cwd()
(package / "dist").mkdir(exist_ok=True)
(package / "dist/index.js").write_text(
    "export default function extension(pi) { pi.on('session_start', async () => {}); }"
    if package.name == "pi-extension" else "export const fixture = true;"
)
'''


# Imports the real consumer modules in a fresh interpreter as one xdist worker,
# and reports the runtime paths and launch commands they would use.
CONSUMERS = r"""
import inspect, json, sys
from pathlib import Path
sys.path[:0] = [sys.argv[1], sys.argv[1] + "/tests"]
import tests.test_agent_activity_emitter_e2e as emitter
import tests.test_e2ee_local_sender_read_trust as trust
import tests.test_connection_notice_restart as restart
top = sys.argv[2]
print(json.dumps({
    "emitter": str(emitter.REPO),
    "trust": str(trust.REPO),
    "restart": str(restart.REPO),
    "host": str(emitter.HOST),
    # restart reuses the trust module's worker-tree fixture, not a copy.
    "restart_uses_trust_runtime": inspect.getfile(restart.runtime_packages.__wrapped__)
    == trust.__file__,
    "commands": [
        ["node", str(emitter.HOST)],
        trust.channel_command(),
        trust.pi_command(top),
        restart.node_runtime_command("core", Path(top)),
    ],
}))
"""

# Runs each module fixture's own body as a worker, with no process creation.
FIXTURES = r"""
import subprocess, sys
sys.path[:0] = [sys.argv[1], sys.argv[1] + "/tests"]
import tests.test_agent_activity_emitter_e2e as emitter
import tests.test_e2ee_local_sender_read_trust as trust
def refuse(*args, **kwargs):
    raise AssertionError(f"a worker fixture started a process: {args}")
subprocess.run = refuse
for module, fixture in ((emitter, emitter.channel_core_build), (trust, trust.runtime_packages)):
    for _ in range(2):
        fixture.__wrapped__(module.REPO)
print("no build")
"""


def as_worker(program, worker, top):
    """Run a probe as xdist worker `worker`, with `top` as its temporary root."""
    result = subprocess.run(
        [sys.executable, "-c", program, str(ROOT / "server"), str(top)],
        env=dict(
            os.environ,
            PYTEST_XDIST_WORKER=worker,
            # xdist sets the count beside each worker's identity.
            PYTEST_XDIST_WORKER_COUNT="2",
            PYTEST_XDIST_TESTRUNUID="a" * 32,
            TMPDIR=str(top),
        ),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    return result.stdout


@unittest.skipUnless(shutil.which("node"), "Node is required for the reader boundary")
class RuntimeTrees(unittest.TestCase):
    def test_consumers_keep_reading_during_another_worker_and_shared_tree_rebuild(self):
        with tempfile.TemporaryDirectory() as temporary:
            top = Path(temporary)
            source = top / "source"
            for package in runtime.PACKAGES:
                directory = source / package
                (directory / "node_modules/dependency/dist").mkdir(parents=True)
                (directory / "node_modules/dependency/dist/kept").write_text("kept")
                (directory / "package.json").write_text('{"type":"module"}')
            for package in ("packages/channel", "packages/pi-extension"):
                link = source / package / "node_modules/@awebai/channel-core"
                link.parent.mkdir()
                # Both npm-relative links and absolute links must be private.
                link.symlink_to(
                    source / "packages/channel-core"
                    if package == "packages/channel"
                    else "../../../channel-core"
                )
            for name in runtime.FILES:
                destination = source / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, destination)
            bin_dir = top / "bin"
            bin_dir.mkdir()
            npm = bin_dir / "npm"
            npm.write_text(f"#!{sys.executable}\n" + BUILDER)
            npm.chmod(0o755)
            environment = dict(
                os.environ, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"]
            )
            with (
                patch.object(runtime.tempfile, "gettempdir", return_value=str(top)),
                patch.dict(os.environ, environment),
            ):
                values = json.loads(as_worker(CONSUMERS, "gw0", top))
                other = Path(json.loads(as_worker(CONSUMERS, "gw1", top))["trust"])
                reader = Path(values["emitter"])
                self.assertEqual(reader, Path(values["trust"]))
                self.assertEqual(reader, Path(values["restart"]))
                self.assertTrue(values["restart_uses_trust_runtime"])
                self.assertNotEqual(
                    reader, ROOT
                )  # Red if real consumers revert to shared REPO.
                self.assertNotEqual(reader, other)
                self.assertEqual(
                    Path(values["host"]),
                    reader / "server/tests/activity_emitter_host.mjs",
                )
                with ThreadPoolExecutor(max_workers=2) as pool:
                    jobs = [
                        pool.submit(runtime.prepare_runtime_tree, source, root)
                        for root in (reader, other)
                    ]
                    for job in jobs:
                        job.result(timeout=15)
                for root in (reader, other):
                    for package in ("packages/channel", "packages/pi-extension"):
                        self.assertEqual(
                            (
                                root / package / "node_modules/@awebai/channel-core"
                            ).resolve(),
                            (root / "packages/channel-core").resolve(),
                        )
                    self.assertEqual(
                        (
                            root / "packages/channel/node_modules/dependency/dist/kept"
                        ).read_text(),
                        "kept",
                    )
                # Establish the old shared reader then remove its core: it must
                # fail, while the kept readers below must succeed during the gap.
                subprocess.run(
                    [str(npm), "run", "build"],
                    cwd=source / "packages/channel",
                    check=True,
                )
                writer = subprocess.Popen(
                    [str(npm), "run", "build"],
                    cwd=other / "packages/channel",
                    env=dict(environment, HOLD_DIST_GAP="1"),
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                try:
                    self.assertTrue(
                        select.select([writer.stdout], [], [], 5)[0],
                        "writer never opened its dist gap",
                    )
                    self.assertEqual(writer.stdout.readline().strip(), "DIST_REMOVED")
                    shutil.rmtree(source / "packages/channel-core/dist")
                    old = subprocess.run(
                        [
                            "node",
                            str(source / "server/tests/activity_emitter_host.mjs"),
                        ],
                        input='{"seed_hex":"","steps":[]}',
                        text=True,
                        capture_output=True,
                        timeout=5,
                    )
                    self.assertNotEqual(old.returncode, 0)
                    self.assertIn("ERR_MODULE_NOT_FOUND", old.stderr)
                    # The launch arguments are the actual kept consumers', so a
                    # future shared-path regression fails this control.
                    commands = values["commands"]
                    # Every package a consumer launches comes from its own tree.
                    entries = [
                        Path(arg)
                        for command in commands
                        for arg in command
                        if arg.endswith("/dist/index.js")
                    ]
                    self.assertEqual(len(entries), 3, commands)
                    for entry in entries:
                        self.assertTrue(entry.is_relative_to(reader), entry)
                    self.assertEqual(
                        (
                            reader
                            / "cli/go/internal/wake/channel_core_runner_bundle.mjs"
                        ).read_bytes(),
                        (
                            ROOT / "cli/go/internal/wake/channel_core_runner_bundle.mjs"
                        ).read_bytes(),
                    )
                    for command in commands:
                        result = subprocess.run(
                            command,
                            input='{"seed_hex":"","steps":[]}',
                            text=True,
                            capture_output=True,
                            timeout=5,
                        )
                        self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIsNone(
                        writer.poll()
                    )  # Reads completed before rebuild resumes.
                finally:
                    writer.communicate("REBUILD\n", timeout=5)
                self.assertEqual(writer.returncode, 0)
                for root in (reader, other):
                    runtime.remove_runtime_tree(root)
                    self.assertFalse(root.exists())

    def test_module_fixtures_never_rebuild_an_active_worker_tree(self):
        # A worker's tree is built once by the session; its module fixtures
        # must only check it, never start another npm build.
        with tempfile.TemporaryDirectory() as temporary:
            self.assertEqual(
                as_worker(FIXTURES, "gw0", Path(temporary)).strip(), "no build"
            )

    def test_external_dependency_link_refuses_and_preserves_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            top = Path(temporary)
            source = top / "source"
            outside = top / "outside"
            outside.mkdir()
            for package in runtime.PACKAGES:
                (source / package / "node_modules").mkdir(parents=True)
            (source / "packages/channel/node_modules/escape").symlink_to(outside)
            for name in runtime.FILES:
                destination = source / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, destination)
            with self.assertRaisesRegex(RuntimeError, "escapes the worker tree"):
                runtime.prepare_runtime_tree(source, top / "worker")
            self.assertFalse((top / "worker").exists())
            self.assertTrue(outside.is_dir())

    def test_preexisting_tree_refuses_without_removing_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            top = Path(temporary)
            root = top / "existing"
            root.mkdir()
            sentinel = root / "keep"
            sentinel.write_text("keep")
            with self.assertRaises(FileExistsError):
                runtime.prepare_runtime_tree(top, root)
            self.assertEqual(sentinel.read_text(), "keep")
            self.assertEqual(runtime.runtime_repo(ROOT), ROOT)

    def test_every_worker_of_the_planned_count_owns_its_tree(self):
        uid = "a" * 32
        for count in (2, 7, 11, 64):
            for index in (0, count - 1):
                environ = {
                    "PYTEST_XDIST_WORKER": f"gw{index}",
                    "PYTEST_XDIST_WORKER_COUNT": str(count),
                    "PYTEST_XDIST_TESTRUNUID": uid,
                }
                with (
                    self.subTest(count=count, index=index),
                    mock.patch.dict(os.environ, environ),
                ):
                    self.assertEqual(
                        runtime.runtime_repo(ROOT).name,
                        f"aweb-server-runtime-{uid}-gw{index}",
                    )
        for worker, count in (("gw11", "11"), ("gw1", ""), ("gwx", "4"), ("gw0", "0")):
            environ = {
                "PYTEST_XDIST_WORKER": worker,
                "PYTEST_XDIST_WORKER_COUNT": count,
                "PYTEST_XDIST_TESTRUNUID": uid,
            }
            with (
                self.subTest(worker=worker, count=count),
                mock.patch.dict(os.environ, environ),
            ):
                with self.assertRaisesRegex(RuntimeError, "owned xdist identity"):
                    runtime.runtime_repo(ROOT)


if __name__ == "__main__":
    unittest.main()
