#!/usr/bin/env python3
"""Literal marketplace pointer against local npm and git fixtures only."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ADAPTER = REPO_ROOT / "scripts" / "pointer-adapter-marketplace-pointer.py"
POINTER_FILE = ".claude-plugin/marketplace.json"
MAPPING = {
    "channel": "@awebai/claude-channel",
    "skills": "@awebai/claude-skills",
}
MARKETPLACE = {
    "name": "awebai-marketplace",
    "plugins": [
        {"name": "aweb-channel", "source": {"source": "npm", "package": MAPPING["channel"], "version": "1.7.3"}},
        {"name": "aweb-skills", "source": {"source": "npm", "package": MAPPING["skills"], "version": "0.2.12"}},
        {"name": "unrelated", "source": {"source": "npm", "package": "@other/plugin", "version": "9.0.0"}},
    ],
}


def git(*args: str, cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=cwd, check=check, capture_output=True, text=True)


def load_adapter():
    spec = importlib.util.spec_from_file_location("marketplace_adapter", ADAPTER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


class RegistryHandler(BaseHTTPRequestHandler):
    served: dict[tuple[str, str], int] = {}
    requests: list[str] = []
    status = 200

    def do_GET(self):
        type(self).requests.append(self.path)
        if type(self).status != 200:
            self.send_response(type(self).status)
            self.end_headers()
            return
        parts = self.path.strip("/").rsplit("/", 1)
        package = urllib.parse.unquote(parts[0]) if len(parts) == 2 else ""
        version = parts[1] if len(parts) == 2 else ""
        if (package, version) not in type(self).served:
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps({"name": package, "version": version}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class MarketplaceAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.remote = root / "remote.git"
        self.seed = root / "seed"
        self.seed.mkdir()
        (self.seed / ".claude-plugin").mkdir()
        self.pointer = self.seed / POINTER_FILE
        self.pointer.write_text(json.dumps(MARKETPLACE, indent=2) + "\n")
        git("init", "-q", "-b", "main", cwd=self.seed)
        git("-c", "user.email=t@t", "-c", "user.name=t", "add", ".", cwd=self.seed)
        git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "seed", cwd=self.seed)
        git("init", "-q", "--bare", "-b", "main", str(self.remote), cwd=root)
        git("remote", "add", "origin", str(self.remote), cwd=self.seed)
        git("push", "-q", "origin", "main", cwd=self.seed)

        RegistryHandler.served = {(package, version): 1 for package, version in ((MAPPING["channel"], "1.7.4"), (MAPPING["skills"], "0.2.13"))}
        RegistryHandler.requests = []
        RegistryHandler.status = 200
        self.registry = ThreadingHTTPServer(("127.0.0.1", 0), RegistryHandler)
        self.thread = threading.Thread(target=self.registry.serve_forever, daemon=True)
        self.thread.start()
        self.registry_url = f"http://127.0.0.1:{self.registry.server_port}"
        self.addCleanup(self.registry.server_close)
        self.addCleanup(self.thread.join)
        self.addCleanup(self.registry.shutdown)

    def env(self):
        return {
            **os.environ,
            "MARKETPLACE_REMOTE": str(self.remote),
            "MARKETPLACE_NPM_REGISTRY": self.registry_url,
            "NO_PROXY": "127.0.0.1,localhost",
            "HTTP_PROXY": "http://127.0.0.1:1",
            "HTTPS_PROXY": "http://127.0.0.1:1",
        }

    def run_adapter(self, operation: str, updates=None, check=True, expected=None):
        command = [sys.executable, str(ADAPTER), operation, "--component", "marketplace-pointer"]
        if expected is not False:
            command += ["--expect-repository", str(self.remote) if expected is None else expected]
        if updates is not None:
            command += ["--updates", json.dumps(updates)]
        result = subprocess.run(command, capture_output=True, text=True, env=self.env())
        if check and result.returncode:
            self.fail(f"adapter failed: {result.stderr}")
        return result

    def head(self):
        return git("rev-parse", "refs/heads/main", cwd=self.remote).stdout.strip()

    def replace_marketplace(self, document):
        self.pointer.write_text(json.dumps(document, indent=2) + "\n")
        git("-c", "user.email=t@t", "-c", "user.name=t", "add", POINTER_FILE, cwd=self.seed)
        git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "shape", cwd=self.seed)
        git("push", "-q", "origin", "main", cwd=self.seed)

    def test_mapping_is_literal_and_has_only_public_pointer_components(self):
        module = load_adapter()
        self.assertEqual(module.PACKAGES, MAPPING)
        source = ADAPTER.read_text()
        self.assertNotIn("components.toml", source)
        self.assertNotIn("tomllib", source)

    def test_read_accepts_and_reports_the_exact_expected_live_shape(self):
        result = self.run_adapter("read")
        self.assertEqual(json.loads(result.stdout)["advertised"], {"channel": "1.7.3", "skills": "0.2.12"})

    def test_apply_waits_for_both_public_packages_then_pushes_and_rereads(self):
        before = self.head()
        result = self.run_adapter("apply", {"channel": "1.7.4", "skills": "0.2.13"})
        self.assertNotEqual(self.head(), before)
        self.assertEqual(json.loads(result.stdout)["advertised"], {"channel": "1.7.4", "skills": "0.2.13"})
        self.assertEqual(len(RegistryHandler.requests), 2)
        self.assertEqual(json.loads(self.run_adapter("read").stdout)["advertised"], {"channel": "1.7.4", "skills": "0.2.13"})

    def test_partial_update_preserves_other_and_unrelated_entries(self):
        self.run_adapter("apply", {"channel": "1.7.4"})
        clone = Path(self.tmp.name) / "inspect"
        git("clone", "-q", str(self.remote), str(clone), cwd=Path(self.tmp.name))
        document = json.loads((clone / POINTER_FILE).read_text())
        by_name = {entry["name"]: entry for entry in document["plugins"]}
        self.assertEqual(by_name["aweb-skills"]["source"]["version"], "0.2.12")
        self.assertEqual(by_name["unrelated"]["source"]["version"], "9.0.0")

    def test_exact_state_is_adopted_without_registry_read_or_commit(self):
        self.run_adapter("apply", {"channel": "1.7.4"})
        before = self.head()
        RegistryHandler.requests = []
        self.run_adapter("apply", {"channel": "1.7.4"})
        self.assertEqual(self.head(), before)
        self.assertEqual(RegistryHandler.requests, [])

    def test_marketplace_cannot_advance_before_package_is_public(self):
        RegistryHandler.served = {}
        before = self.head()
        result = self.run_adapter("apply", {"channel": "1.7.4"}, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not publicly served", result.stderr)
        self.assertEqual(self.head(), before)

    def test_registry_outage_is_not_publication(self):
        RegistryHandler.status = 503
        before = self.head()
        result = self.run_adapter("apply", {"channel": "1.7.4"}, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unavailable", result.stderr)
        self.assertEqual(self.head(), before)

    def test_wrong_shape_duplicate_missing_or_wrong_package_refuses(self):
        cases = [
            {"name": "wrong", "plugins": "no"},
            {"name": MARKETPLACE["name"], "plugins": [MARKETPLACE["plugins"][0], MARKETPLACE["plugins"][0], MARKETPLACE["plugins"][1]]},
            {"name": MARKETPLACE["name"], "plugins": [MARKETPLACE["plugins"][0]]},
            {"name": MARKETPLACE["name"], "plugins": [{**MARKETPLACE["plugins"][0], "source": {"source": "npm", "package": "@wrong/channel", "version": "1.7.3"}}, MARKETPLACE["plugins"][1]]},
        ]
        for index, document in enumerate(cases):
            with self.subTest(index=index):
                self.replace_marketplace(document)
                result = self.run_adapter("read", check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertRegex(result.stderr, "shape|exactly one|package")

    def test_unknown_component_and_malformed_version_refuse(self):
        for updates in ({"pi": "0.3.7"}, {"channel": "v1.7.4"}, {}):
            with self.subTest(updates=updates):
                result = self.run_adapter("apply", updates, check=False)
                self.assertNotEqual(result.returncode, 0)

    def test_substituted_or_missing_expected_remote_refuses(self):
        wrong = self.run_adapter("read", check=False, expected="github.com/elsewhere/repo")
        missing = self.run_adapter("read", check=False, expected=False)
        self.assertIn("refusing to act", wrong.stderr)
        self.assertIn("--expect-repository", missing.stderr)

    def test_extra_pointer_diff_is_refused(self):
        module = load_adapter()
        checkout = Path(self.tmp.name) / "diff"
        git("clone", "-q", str(self.remote), str(checkout), cwd=Path(self.tmp.name))
        (checkout / "extra").write_text("x")
        git("add", "extra", cwd=checkout)
        with self.assertRaises(SystemExit) as caught:
            module.require_only_pointer_diff(checkout)
        self.assertIn("only", str(caught.exception))

    def test_concurrent_conflict_refuses_without_overwriting(self):
        module = load_adapter()
        checkout = Path(self.tmp.name) / "conflict"
        git("clone", "-q", str(self.remote), str(checkout), cwd=Path(self.tmp.name))
        module.apply_updates(checkout, {"channel": "1.7.4"})
        self.pointer.write_text(self.pointer.read_text() + "\n")
        git("-c", "user.email=t@t", "-c", "user.name=t", "add", POINTER_FILE, cwd=self.seed)
        git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "concurrent", cwd=self.seed)
        git("push", "-q", "origin", "main", cwd=self.seed)
        with self.assertRaises(SystemExit):
            module.commit_and_push(checkout, {"channel": "1.7.4"}, str(self.remote))

    def test_adapter_is_executable_and_fixture_never_names_real_endpoints(self):
        self.assertTrue(os.access(ADAPTER, os.X_OK))
        self.run_adapter("apply", {"channel": "1.7.4"})
        self.assertTrue(RegistryHandler.requests)
        self.assertTrue(all(request.startswith("/%40awebai%2F") for request in RegistryHandler.requests))
        self.assertNotIn("github.com", str(self.remote))


if __name__ == "__main__":
    unittest.main()
