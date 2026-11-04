#!/usr/bin/env python3
"""Exercise channel selection and promotion; replace only npm's external API."""
from __future__ import annotations

import base64
import functools
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "cli/go/npm/publication.py"
PACKAGES = ["aw-linux-x64", "aw-linux-arm64", "aw-darwin-x64", "aw-darwin-arm64",
            "aw-windows-x64", "aw-windows-arm64", "aw"]


class PublicationTest(unittest.TestCase):
    def invoke(self, *args, **kwargs):
        return subprocess.run([sys.executable, str(HELPER), *args], text=True,
                              capture_output=True, **kwargs)

    def test_channel_defaults_and_explicit_staged_final_tag(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for args in [("init", "-q"), ("config", "user.name", "fixture"),
                         ("config", "user.email", "fixture@example.test"),
                         ("commit", "--allow-empty", "-qm", "fixture")]:
                subprocess.run(["git", "-C", str(root), *args], check=True)
            for version, marker, expected in [
                ("1.2.3", "", "latest"), ("1.2.3-rc.1", "", "next"),
                ("1.2.4", "Npm-Publish-Channel: next", "next"),
            ]:
                tag = "v" + version
                subprocess.run(["git", "-C", str(root), "tag", "-a", tag, "-m",
                                "release\n\n" + marker], check=True)
                result = self.invoke("channel", "--version", version, "--tag", tag,
                                     "--repository", str(root))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), expected)
            subprocess.run(["git", "-C", str(root), "commit", "--allow-empty", "-qm",
                            "commit text\n\nNpm-Publish-Channel: next"], check=True)
            subprocess.run(["git", "-C", str(root), "tag", "v1.2.5"], check=True)
            result = self.invoke("channel", "--version", "1.2.5", "--tag", "v1.2.5",
                                 "--repository", str(root))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "latest")

    def test_staged_final_does_not_make_an_rc_final(self):
        result = self.invoke("channel", "--version", "1.2.3-rc.1", "--staged-final")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("final version", result.stderr)

    def test_runnerless_publishes_and_checks_seven_exact_staged_tarballs(self):
        # Real pack/inspect/publish/read-back logic with a fixture compiler
        # and an owned HTTP registry. No binary/runtime claim is made.
        sys.path.insert(0, str(ROOT / "scripts"))
        import publish_release as publisher
        from test_npm_readback import Registry
        with tempfile.TemporaryDirectory() as directory, Registry().serve() as registry:
            root = Path(directory)
            shutil.copytree(ROOT / "cli/go/npm", root / "cli/go/npm",
                            ignore=shutil.ignore_patterns("__pycache__"))
            (root / "scripts").mkdir()
            shutil.copyfile(ROOT / "scripts/npm-exact-publish.sh", root / "scripts/npm-exact-publish.sh")
            binaries = root / "tools"
            binaries.mkdir()
            (binaries / "go").write_text('''#!/usr/bin/env python3
import pathlib, sys
pathlib.Path(sys.argv[sys.argv.index("-o")+1]).write_bytes(b"fixture compiler output")
''')
            for path in binaries.iterdir():
                path.chmod(0o755)
            config = root / "npmrc"
            config.write_text(f"registry={registry.url}\n//{registry.url.split('//')[1]}/:_authToken=disposable-fixture\n")
            env = {"PATH": str(binaries) + os.pathsep + os.environ["PATH"],
                   "NPM_CONFIG_REGISTRY": registry.url, "NPM_CONFIG_USERCONFIG": str(config),
                   "NODE_AUTH_TOKEN": "disposable-fixture"}
            # The pre-publish existence decision is isolated; npm PUTs and
            # every version, tag and tarball read use the actual local server.
            with mock.patch.dict(os.environ, env), mock.patch.object(publisher, "request_json", return_value=(404, {})):
                publisher.publish_aw_npm(root, "1.2.3", "a" * 40, staged_final=True)
            self.assertEqual([name for name, _, _ in registry.published], ["@awebai/" + p for p in PACKAGES])
            self.assertTrue(all(tags == {"next": "1.2.3"} for _, _, tags in registry.published))
            self.assertEqual(registry.reads, {("@awebai/" + p, kind) for p in PACKAGES for kind in ("version", "tag")})

    def promotion_fixture(self, root, base):
        metadata = {}
        for package in PACKAGES:
            name = "@awebai/" + package
            manifest = {"name": name, "version": "1.2.3"}
            if package == "aw":
                manifest["optionalDependencies"] = {
                    "@awebai/" + p: "1.2.3" for p in PACKAGES[:-1]}
            raw = json.dumps(manifest).encode()
            path = root / (package + ".tgz")
            with tarfile.open(path, "w:gz") as archive:
                entry = tarfile.TarInfo("package/package.json")
                entry.size = len(raw)
                archive.addfile(entry, io.BytesIO(raw))
            integrity = "sha512-" + base64.b64encode(hashlib.sha512(path.read_bytes()).digest()).decode()
            metadata[name + "@1.2.3"] = {
                **manifest, "dist": {"tarball": base + "/" + path.name, "integrity": integrity}}
        (root / "metadata.json").write_text(json.dumps(metadata))
        (root / "npm").write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ["PUBLICATION_FIXTURE"])
args = sys.argv[1:]
with (root / "calls").open("a") as f: f.write(json.dumps(args) + "\\n")
metadata = json.loads((root / "metadata.json").read_text())
if args[0] == "view" and args[2:] == ["--json"]:
    print(json.dumps(metadata.get(args[1], {})))
elif args[0:2] == ["dist-tag", "add"] and args[3:] == ["latest"]:
    with (root / "tags").open("a") as f: f.write(args[2] + "\\n")
elif args[0] == "view" and args[2:] == ["dist-tags.latest", "--json"]:
    promoted = (root / "tags").read_text().splitlines()
    print(json.dumps("1.2.3" if args[1] + "@1.2.3" in promoted else "old"))
else: raise SystemExit("unexpected npm operation: " + repr(args))
''')
        (root / "npm").chmod(0o755)
        return {**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                "PUBLICATION_FIXTURE": str(root)}

    def exercise_promotion(self, corrupt=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            class Handler(http.server.SimpleHTTPRequestHandler):
                def log_message(self, *args):
                    pass
            server = http.server.ThreadingHTTPServer(
                ("127.0.0.1", 0), functools.partial(Handler, directory=str(root)))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                env = self.promotion_fixture(root, f"http://127.0.0.1:{server.server_port}")
                if corrupt:
                    # The wrapper is last: even a late preflight failure must
                    # leave ALL seven latest tags untouched.
                    metadata = json.loads((root / "metadata.json").read_text())
                    if corrupt == "missing":
                        del metadata["@awebai/aw@1.2.3"]
                    elif corrupt == "integrity":
                        (root / "aw.tgz").write_bytes(b"different bytes")
                    elif corrupt == "version":
                        metadata["@awebai/aw@1.2.3"]["version"] = "9.9.9"
                    (root / "metadata.json").write_text(json.dumps(metadata))
                result = self.invoke("promote-latest", "--version", "1.2.3", env=env)
                calls = [json.loads(s) for s in (root / "calls").read_text().splitlines()] if (root / "calls").exists() else []
                mutations = [c for c in calls if c[0] == "dist-tag"]
                if corrupt:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(mutations, [], result.stdout + result.stderr)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(mutations, [["dist-tag", "add", "@awebai/" + p + "@1.2.3", "latest"] for p in PACKAGES])
                    self.assertEqual([c[0] for c in calls[:7]], ["view"] * 7)
                    self.assertFalse(any(c[0] in ("pack", "publish") for c in calls))
                    self.assertEqual(result.stdout.count("VERIFIED:"), 7)
                    self.assertEqual(result.stdout.count("PROMOTED:"), 7)
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_promotion_checks_all_seven_then_moves_only_their_tags(self):
        self.exercise_promotion()

    def test_promotion_missing_wrong_version_or_changed_tarball_changes_no_tag(self):
        for failure in ("missing", "version", "integrity"):
            with self.subTest(failure=failure):
                self.exercise_promotion(failure)


if __name__ == "__main__":
    unittest.main()
