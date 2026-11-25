#!/usr/bin/env python3
"""The npm lane publishes an absent version, adopts identical bytes and refuses the rest.

The registry is an owned loopback server and npm publish is recorded, never sent.
Packing and inspection run the real npm-exact-publish.sh on a fixture package.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("publish_release", ROOT / "scripts/publish_release.py")
publish = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publish)

PACKAGE = "@awebai/fixture-skills"
VERSION = "1.2.3"


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def fixture_root(root: Path) -> None:
    for name in ("npm-exact-publish.sh", "skill-packaging.mjs"):
        write(root / "scripts" / name, (ROOT / "scripts" / name).read_text())
    write(root / "skills/shipped.json", '["aweb-fixture"]\n')
    write(root / "skills/aweb-fixture/SKILL.md", "fixture\n")
    package = root / "pkg"
    write(package / "package.json", json.dumps({
        "name": PACKAGE, "version": VERSION,
        "files": [".claude-plugin", "skills"], "pi": {"skills": ["./skills"]},
    }))
    write(package / ".claude-plugin/plugin.json", json.dumps({"name": "fixture", "version": VERSION}))
    write(package / "skills/aweb-fixture/SKILL.md", "fixture\n")


@contextmanager
def registry(status: int, tarball: bytes | None):
    class Registry(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == f"/%40awebai%2Ffixture-skills/{VERSION}":
                if status != 200:
                    self.send_response(status)
                    self.end_headers()
                    return
                dist = {} if tarball is None else {"tarball": f"{base}/fixture.tgz"}
                body = json.dumps({"version": VERSION, "dist": dist}).encode()
            elif self.path == "/fixture.tgz" and tarball is not None:
                body = tarball
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Registry)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield base
    finally:
        server.shutdown()
        server.server_close()


class NpmPublishStagedTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "root"
        fixture_root(self.root)
        # npm publish is recorded; every other npm command is the real npm.
        shims = Path(temporary.name) / "bin"
        self.published = Path(temporary.name) / "published"
        write(shims / "npm", f'#!/bin/sh\nif [ "$1" = publish ]; then printf "%s\\n" "$2" >> "{self.published}"; exit 0; fi\n'
                             f'exec "{shutil.which("npm")}" "$@"\n')
        (shims / "npm").chmod(0o755)
        self.environment = {"PATH": f"{shims}{os.pathsep}{os.environ['PATH']}", "NODE_AUTH_TOKEN": "fixture-not-a-secret"}
        staged = Path(temporary.name) / "staged"
        subprocess.run(["bash", "scripts/npm-exact-publish.sh", "pack-inspect", "--dir", "pkg", "--version", VERSION,
                        "--out", str(staged), "--profile", "skills", "--source-root", "."],
                       cwd=self.root, check=True, capture_output=True)
        self.staged_bytes = next(staged.glob("*.tgz")).read_bytes()

    def stage(self, status: int, tarball: bytes | None):
        with registry(status, tarball) as base, mock.patch.dict(os.environ, {**self.environment, "NPM_CONFIG_REGISTRY": base}):
            with publish._npm_publish_staged(self.root, "pkg", PACKAGE, "skills", VERSION) as (archive, action, _):
                return action, archive.read_bytes()

    def test_absent_version_is_published_from_the_staged_bytes(self):
        action, archive = self.stage(404, None)
        self.assertEqual(action, "publish")
        self.assertEqual(archive, self.staged_bytes)
        self.assertEqual(len(self.published.read_text().splitlines()), 1)

    def test_identical_present_version_is_adopted_without_publishing(self):
        action, archive = self.stage(200, self.staged_bytes)
        self.assertEqual(action, "adopt")
        self.assertEqual(archive, self.staged_bytes)
        self.assertFalse(self.published.exists())

    def test_present_version_with_other_bytes_refuses(self):
        with self.assertRaisesRegex(publish.PublishRefusal, "already exists with different bytes"):
            self.stage(200, self.staged_bytes + b"x")
        self.assertFalse(self.published.exists())

    def test_present_version_without_a_tarball_refuses(self):
        with self.assertRaisesRegex(publish.PublishRefusal, "no tarball URL"):
            self.stage(200, None)
        self.assertFalse(self.published.exists())

    def test_registry_outage_is_never_absence(self):
        with self.assertRaisesRegex(publish.PublishRefusal, "HTTP 503"):
            self.stage(503, None)
        self.assertFalse(self.published.exists())


if __name__ == "__main__":
    unittest.main()
