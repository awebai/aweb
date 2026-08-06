#!/usr/bin/env python3
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
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
            "XDG_STATE_HOME", "TMPDIR", "PATH", "ANTHROPIC_API_KEY",
            "AWEB_CHANNEL_NAME_LIVE_CONFIG",
        })
        self.assertEqual(env["ANTHROPIC_API_KEY"], "dedicated")
        self.assertNotIn("AWEB_URL", env)

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
            'detached: true', 'stopOwnedProcessGroup',
            'process_group_termination_proven: processGroupProof.termination_proven',
            'child_cleanup_complete: true', 'server_cleanup_complete = true',
        ):
            self.assertIn(marker, source)
        self.assertNotIn("tmux", source)


if __name__ == "__main__":
    unittest.main()
