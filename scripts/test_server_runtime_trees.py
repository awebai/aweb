"""Exercise kept Node readers while another worker rebuilds its dist tree.

The npm transport emits controlled modules, not product bundles. Real Node and
kept host scripts exercise resolution/lifetime; this is filesystem isolation
coverage, not a substitute for the native seven-worker product measurement.
"""

import ast
from concurrent.futures import ThreadPoolExecutor
import importlib.util
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


def consumer_paths(filename, worker):
    """Evaluate the real module's path declarations, without product imports."""
    tree = ast.parse((ROOT / "server/tests" / filename).read_text())
    assignments = [
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name)
            and target.id in {"SOURCE_REPO", "REPO", "HOST"}
            for target in node.targets
        )
    ]
    values = {
        "__file__": str(ROOT / "server/tests" / filename),
        "Path": Path,
        "runtime_repo": runtime.runtime_repo,
    }
    with patch.dict(
        os.environ,
        {
            "PYTEST_XDIST_WORKER": worker,
            # xdist sets the count beside each worker's identity.
            "PYTEST_XDIST_WORKER_COUNT": "2",
            "PYTEST_XDIST_TESTRUNUID": "a" * 32,
        },
    ):
        exec(
            compile(ast.Module(body=assignments, type_ignores=[]), filename, "exec"),
            values,
        )
    return values


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
            for package in ("channel", "pi-extension"):
                link = source / package / "node_modules/@awebai/channel-core"
                link.parent.mkdir()
                # Both npm-relative links and absolute links must be private.
                link.symlink_to(
                    source / "channel-core"
                    if package == "channel"
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
                emitter = consumer_paths("test_agent_activity_emitter_e2e.py", "gw0")
                trust = consumer_paths("test_e2ee_local_sender_read_trust.py", "gw0")
                other = consumer_paths("test_e2ee_local_sender_read_trust.py", "gw1")[
                    "REPO"
                ]
                reader = emitter["REPO"]
                self.assertEqual(reader, trust["REPO"])
                self.assertNotEqual(
                    reader, ROOT
                )  # Red if real consumers revert to shared REPO.
                self.assertNotEqual(reader, other)
                self.assertEqual(
                    emitter["HOST"], reader / "server/tests/activity_emitter_host.mjs"
                )
                restart = ast.parse(
                    (
                        ROOT / "server/tests/test_connection_notice_restart.py"
                    ).read_text()
                )
                imported = next(
                    n
                    for n in restart.body
                    if isinstance(n, ast.ImportFrom)
                    and n.module == "test_e2ee_local_sender_read_trust"
                )
                self.assertIn("REPO", {n.name for n in imported.names})
                self.assertIn("runtime_packages", {n.name for n in imported.names})
                with ThreadPoolExecutor(max_workers=2) as pool:
                    jobs = [
                        pool.submit(runtime.prepare_runtime_tree, source, root)
                        for root in (reader, other)
                    ]
                    for job in jobs:
                        job.result(timeout=15)
                for root in (reader, other):
                    for package in ("channel", "pi-extension"):
                        self.assertEqual(
                            (
                                root / package / "node_modules/@awebai/channel-core"
                            ).resolve(),
                            (root / "channel-core").resolve(),
                        )
                    self.assertEqual(
                        (
                            root / "channel/node_modules/dependency/dist/kept"
                        ).read_text(),
                        "kept",
                    )
                # Establish the old shared reader then remove its core: it must
                # fail, while the kept readers below must succeed during the gap.
                subprocess.run(
                    [str(npm), "run", "build"], cwd=source / "channel", check=True
                )
                writer = subprocess.Popen(
                    [str(npm), "run", "build"],
                    cwd=other / "channel",
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
                    shutil.rmtree(source / "channel-core/dist")
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
                    # Take launch arguments from the actual kept consumers,
                    # so a future shared-path regression fails this control.
                    values = dict(trust, root=top, command_dir=top, name="core")
                    commands = [["node", str(emitter["HOST"])]]
                    trust_tree = ast.parse(
                        (
                            ROOT / "server/tests/test_e2ee_local_sender_read_trust.py"
                        ).read_text()
                    )
                    for function in ("_present_by_channel", "_present_by_pi"):
                        body = next(
                            n
                            for n in trust_tree.body
                            if isinstance(n, ast.AsyncFunctionDef)
                            and n.name == function
                        )
                        call = next(
                            n
                            for n in ast.walk(body)
                            if isinstance(n, ast.Call)
                            and isinstance(n.func, ast.Attribute)
                            and n.func.attr == "create_subprocess_exec"
                        )
                        commands.append(
                            eval(
                                compile(
                                    ast.fix_missing_locations(
                                        ast.Expression(
                                            ast.List(elts=call.args, ctx=ast.Load())
                                        )
                                    ),
                                    function,
                                    "eval",
                                ),
                                values,
                            )
                        )
                    body = next(
                        n
                        for n in restart.body
                        if isinstance(n, ast.AsyncFunctionDef) and n.name == "_runtime"
                    )
                    routing = next(
                        n
                        for n in body.body
                        if isinstance(n, ast.If)
                        and ast.unparse(n.test) == "name == 'wake'"
                    )
                    values["__file__"] = str(
                        ROOT / "server/tests/test_connection_notice_restart.py"
                    )
                    # The non-wake branch selects the kept core host and argv.
                    exec(
                        compile(
                            ast.Module(body=routing.orelse, type_ignores=[]),
                            "restart",
                            "exec",
                        ),
                        values,
                    )
                    commands.append(values["command"])
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
        for filename, function in [
            ("test_agent_activity_emitter_e2e.py", "channel_core_build"),
            ("test_e2ee_local_sender_read_trust.py", "runtime_packages"),
        ]:
            node = next(
                n
                for n in ast.parse((ROOT / "server/tests" / filename).read_text()).body
                if isinstance(n, ast.FunctionDef) and n.name == function
            )
            node.decorator_list = []
            values = {"REPO": Path("/owned/gw0"), "SOURCE_REPO": ROOT}
            exec(
                compile(ast.Module(body=[node], type_ignores=[]), filename, "exec"),
                values,
            )
            # No subprocess binding: any old npm build here fails the control.
            for _ in range(2):
                values[function](Path("/owned/gw0"))

    def test_external_dependency_link_refuses_and_preserves_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            top = Path(temporary)
            source = top / "source"
            outside = top / "outside"
            outside.mkdir()
            for package in runtime.PACKAGES:
                (source / package / "node_modules").mkdir(parents=True)
            (source / "channel/node_modules/escape").symlink_to(outside)
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
