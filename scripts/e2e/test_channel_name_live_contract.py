#!/usr/bin/env python3
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import time
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HARNESS_PATH = ROOT / "scripts" / "e2e" / "run_channel_name_live.py"
SPEC = importlib.util.spec_from_file_location("channel_name_live", HARNESS_PATH)
assert SPEC and SPEC.loader
harness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(harness)


class ChannelNameLiveHarnessContractTests(unittest.TestCase):
    def test_rejects_inherited_claude_plugin_or_auth_configuration(self):
        with self.assertRaisesRegex(ValueError, "refusing inherited"):
            harness.reject_ambient_configuration(
                "ANTHROPIC_API_KEY",
                {"ANTHROPIC_API_KEY": "dedicated", "CLAUDE_CONFIG_DIR": "/ambient"},
            )
        harness.reject_ambient_configuration(
            "ANTHROPIC_API_KEY", {"ANTHROPIC_API_KEY": "dedicated", "PATH": "/exact"}
        )

    def test_credential_selector_refuses_isolation_and_executable_injection_names(self):
        for name in (
            "HOME", "PATH", "CLAUDE_CONFIG_DIR", "XDG_CONFIG_HOME", "TMPDIR",
            "NODE_OPTIONS", "NODE_PATH", "DYLD_INSERT_LIBRARIES", "LD_PRELOAD",
        ):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "approved credential"):
                harness.reject_ambient_configuration(name, {name: "caller-controlled"})
            with self.subTest(build=name), tempfile.TemporaryDirectory() as raw, self.assertRaisesRegex(
                ValueError, "approved credential"
            ):
                harness.build_allowlisted_env(
                    Path(raw), name, "caller-controlled", [Path("/bin")], Path(raw) / "config.json"
                )

    def test_allowlisted_environment_has_only_isolated_state_and_exact_credential(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            env = harness.build_allowlisted_env(
                root,
                "ANTHROPIC_API_KEY",
                "dedicated",
                [Path("/bin")],
                root / "config.json",
            )
        self.assertEqual(set(env), {
            "HOME", "CLAUDE_CONFIG_DIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME",
            "XDG_STATE_HOME", "TMPDIR", "DOCKER_CONFIG", "PATH", "ANTHROPIC_API_KEY",
            "AWEB_CHANNEL_NAME_LIVE_CONFIG", "AWEB_CHANNEL_LIVE_INTEGRATION_ROOT",
            "AWEB_SKEW_PROJECT_TOKEN",
        })
        self.assertEqual(env["ANTHROPIC_API_KEY"], "dedicated")
        self.assertNotIn("AWEB_URL", env)
        self.assertEqual(
            Path(env["AWEB_CHANNEL_LIVE_INTEGRATION_ROOT"]).parent,
            Path(env["TMPDIR"]),
        )

    def test_tgz_extraction_requires_safe_exact_channel_package(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            tgz = root / "candidate.tgz"
            files = {
                "package/package.json": json.dumps({
                    "name": "@awebai/claude-channel", "version": "1.7.3"
                }),
                "package/.mcp.json": json.dumps({
                    "mcpServers": {"aweb-channel": {"command": "node"}}
                }),
                "package/dist/index.js": '{ name: "aweb-channel", version: "0.1.0" }',
            }
            with tarfile.open(tgz, "w:gz") as archive:
                for name, content in files.items():
                    data = content.encode()
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            digest = hashlib.sha256(tgz.read_bytes()).hexdigest()
            self.assertEqual(harness.require_exact_file(str(tgz), digest, "tgz"), tgz.resolve())
            package = harness.safe_extract_tgz(tgz, root / "out")
            harness.validate_package_identity(package)

    def test_tgz_extraction_refuses_escape_and_links(self):
        for name, link in (("../escape", None), ("package/link", "target")):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                tgz = root / "bad.tgz"
                with tarfile.open(tgz, "w:gz") as archive:
                    info = tarfile.TarInfo(name)
                    if link:
                        info.type = tarfile.SYMTYPE
                        info.linkname = link
                    else:
                        info.size = 1
                    archive.addfile(info, None if link else io.BytesIO(b"x"))
                with self.assertRaisesRegex(ValueError, "escapes|link"):
                    harness.safe_extract_tgz(tgz, root / "out")

    def test_supervisor_converts_handled_termination_into_cleanup_control_flow(self):
        with self.assertRaisesRegex(RuntimeError, "interrupted by signal"):
            with harness.RunnerSignalGuard():
                os.kill(os.getpid(), signal.SIGTERM)

    def test_supervisor_cleans_owned_group_after_runner_dies_before_its_descendant(self):
        fixture = ROOT / "scripts" / "e2e" / "fixtures" / "stubborn-process-tree.mjs"
        with tempfile.TemporaryDirectory() as raw:
            marker = Path(raw) / "pids.json"
            node = shutil.which("node")
            self.assertIsNotNone(node)
            runner = harness.start_owned_process_group(
                [str(node), str(fixture), str(marker)], cwd=ROOT, env={"PATH": os.defpath}
            )
            try:
                deadline = time.monotonic() + 5
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(marker.exists())
                pids = json.loads(marker.read_text())
                self.assertEqual(pids["parent_pid"], runner.pid)
                os.kill(runner.pid, signal.SIGTERM)
                runner.wait(timeout=5)
                self.assertTrue(harness.process_group_exists(runner.pid))

                proof = harness.cleanup_owned_process_group(runner, term_grace_seconds=0.2)

                self.assertIn(pids["descendant_pid"], proof["observed_pids"])
                self.assertTrue(proof["sigkill_required"])
                self.assertTrue(proof["termination_proven"])
                self.assertFalse(harness.process_group_exists(runner.pid))
            finally:
                if harness.process_group_exists(runner.pid):
                    os.killpg(runner.pid, signal.SIGKILL)

    def test_supervisor_removes_only_its_exact_compose_project_resources(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            state = root / "state.json"
            log = root / "docker.jsonl"
            state.write_text(json.dumps({
                "containers": ["container-1"],
                "networks": ["network-1"],
                "volumes": ["volume-1"],
            }))
            fake = root / "docker"
            fake.write_text("""#!/usr/bin/env python3
import json, os, pathlib, sys
state_path = pathlib.Path(os.environ['FAKE_DOCKER_STATE'])
log_path = pathlib.Path(os.environ['FAKE_DOCKER_LOG'])
args = sys.argv[1:]
with log_path.open('a') as stream:
    stream.write(json.dumps(args) + '\\n')
state = json.loads(state_path.read_text())
if args[:2] == ['ps', '-aq']:
    print('\\n'.join(state['containers']))
elif args[:3] == ['network', 'ls', '-q']:
    print('\\n'.join(state['networks']))
elif args[:3] == ['volume', 'ls', '-q']:
    print('\\n'.join(state['volumes']))
elif args[:2] == ['rm', '-f']:
    state['containers'] = []
elif args[:2] == ['network', 'rm']:
    state['networks'] = []
elif args[:2] == ['volume', 'rm']:
    state['volumes'] = []
else:
    raise SystemExit(f'unexpected docker args: {args}')
state_path.write_text(json.dumps(state))
""")
            fake.chmod(0o755)
            project = "aweb-channel-name-live-deadbeef"

            proof = harness.cleanup_compose_project(fake, project, {
                "PATH": os.defpath,
                "FAKE_DOCKER_STATE": str(state),
                "FAKE_DOCKER_LOG": str(log),
            })

            self.assertTrue(proof["termination_proven"])
            self.assertEqual(proof["observed_resources"]["containers"], ["container-1"])
            self.assertEqual(json.loads(state.read_text()), {
                "containers": [], "networks": [], "volumes": [],
            })
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            filters = [arg for call in calls for arg in call if arg.startswith("label=")]
            self.assertTrue(filters)
            self.assertEqual(set(filters), {f"label=com.docker.compose.project={project}"})

    def test_supervisor_preserves_integration_state_when_resource_cleanup_is_ambiguous(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            integration_root = root / "integration"
            integration_root.mkdir()
            identity = integration_root / "resource-identity"
            identity.write_text("keep for exact recovery\n")
            failing_docker = root / "docker"
            failing_docker.write_text("#!/bin/sh\nexit 17\n")
            failing_docker.chmod(0o755)

            with self.assertRaisesRegex(RuntimeError, "supervisor cleanup failed"):
                harness.cleanup_supervised_resources(
                    None,
                    failing_docker,
                    "aweb-channel-name-live-deadbeef",
                    {"PATH": os.defpath},
                    integration_root,
                )

            self.assertEqual(identity.read_text(), "keep for exact recovery\n")

    def test_collision_fixture_records_initialize_as_bare_aweb(self):
        fixture = ROOT / "scripts" / "e2e" / "fixtures" / "aweb-name-collision-mcp.mjs"
        with tempfile.TemporaryDirectory() as raw:
            log = Path(raw) / "attempts.jsonl"
            request = json.dumps({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-03-26"},
            }) + "\n"
            result = subprocess.run(
                ["node", str(fixture), str(log)], input=request, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            response = json.loads(result.stdout)
            self.assertEqual(response["result"]["serverInfo"]["name"], "aweb")
            self.assertIn('"method":"initialize"', log.read_text())

    def test_live_cell_contains_exact_name_strict_configuration_and_cleanup_contract(self):
        source = (ROOT / "channel" / "test" / "integration.test.ts").read_text()
        for marker in (
            '"--strict-mcp-config"', '"--plugin-dir"',
            '"--dangerously-load-development-channels"',
            'CLAUDE_CONFIG_DIR', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME',
            'XDG_STATE_HOME', 'plugin:aweb-channel:aweb-channel',
            'AWEB_CHANNEL_LIVE_INTEGRATION_ROOT', 'stopOwnedProcessTree',
            'process_tree_termination_proven: processTreeProof.termination_proven',
            'child_cleanup_complete: true', 'server_cleanup_complete = true',
        ):
            self.assertIn(marker, source)
        self.assertNotIn("tmux", source)
        supervisor = HARNESS_PATH.read_text()
        for marker in (
            "start_owned_process_group", "cleanup_owned_process_group",
            "cleanup_compose_project", "supervisor_integration_root_cleanup_complete",
        ):
            self.assertIn(marker, supervisor)


if __name__ == "__main__":
    unittest.main()
