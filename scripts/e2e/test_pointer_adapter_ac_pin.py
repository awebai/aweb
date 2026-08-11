#!/usr/bin/env python3
"""Local bare-remote/index proofs for AC public-dependency derivation."""

from __future__ import annotations

import functools
import hashlib
import http.server
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ADAPTER = REPO_ROOT / "scripts" / "pointer-adapter-ac-pin.py"
OLD_AWEB = "1.2.3"
NEW_AWEB = "1.2.4"
OLD_AWID = "2.3.4"
NEW_AWID = "2.3.5"


def run(*args: str, cwd: Path, env=None, check=True) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), cwd=str(cwd), env=env, check=check, capture_output=True, text=True)


def git(*args: str, cwd: Path) -> str:
    return run("git", *args, cwd=cwd).stdout.strip()


def write_package(index: Path, name: str, version: str) -> None:
    normalized = name.replace("-", "_")
    files = index / "files"
    files.mkdir(parents=True, exist_ok=True)
    wheel = files / f"{normalized}-{version}-py3-none-any.whl"
    dist_info = f"{normalized}-{version}.dist-info"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            f"{dist_info}/METADATA",
            f"Metadata-Version: 2.3\nName: {name}\nVersion: {version}\nRequires-Python: >=3.12\n",
        )
        archive.writestr(
            f"{dist_info}/WHEEL",
            "Wheel-Version: 1.0\nGenerator: aweb-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        archive.writestr(f"{dist_info}/RECORD", "")
    sdist = files / f"{normalized}-{version}.tar.gz"
    with tempfile.TemporaryDirectory() as tmp:
        package_root = Path(tmp) / f"{normalized}-{version}"
        package_root.mkdir()
        (package_root / "PKG-INFO").write_text(
            f"Metadata-Version: 2.3\nName: {name}\nVersion: {version}\n"
        )
        (package_root / "pyproject.toml").write_text(
            "[build-system]\nrequires = []\nbuild-backend = 'unused'\n"
        )
        with tarfile.open(sdist, "w:gz") as archive:
            archive.add(package_root, arcname=package_root.name)
    page = index / "simple" / name
    page.mkdir(parents=True, exist_ok=True)
    links = []
    for artifact in (sdist, wheel):
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        links.append(f'<a href="/files/{artifact.name}#sha256={digest}">{artifact.name}</a>')
    (page / "index.html").write_text("\n".join(links) + "\n")


class IndexHandler(http.server.SimpleHTTPRequestHandler):
    modes: dict[str, str] = {}
    counts: dict[str, int] = {}

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        match = re.fullmatch(r"/simple/(aweb|awid-service)/?", self.path)
        if match:
            name = match.group(1)
            self.counts[name] = self.counts.get(name, 0) + 1
            mode = self.modes.get(name, "serve")
            if mode == "lag" and self.counts[name] == 1:
                self.send_error(404)
                return
            if mode == "absent":
                self.send_error(404)
                return
            if mode == "auth":
                self.send_error(401)
                return
            if mode == "outage":
                self.send_error(503)
                return
            if mode == "malformed":
                body = b"<html>not package evidence</html>"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
        super().do_GET()


class PublicDependencyAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture_tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.fixture_tmp.name)
        cls.index = cls.root / "index"
        for name, versions in (("aweb", (OLD_AWEB, NEW_AWEB)), ("awid-service", (OLD_AWID, NEW_AWID))):
            for version in versions:
                write_package(cls.index, name, version)
        handler = functools.partial(IndexHandler, directory=str(cls.index))
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.index_url = f"http://127.0.0.1:{cls.server.server_port}/simple"
        cls.uv_cache = cls.root / "uv-cache"

        cls.seed = cls.root / "seed"
        backend = cls.seed / "backend"
        backend.mkdir(parents=True)
        (backend / "pyproject.toml").write_text(
            "[project]\n"
            "name = \"aweb-cloud\"\n"
            "version = \"0.1.0\"\n"
            "requires-python = \">=3.12\"\n"
            "dependencies = [\n"
            f"    \"aweb>={OLD_AWEB}\",\n"
            f"    \"awid-service>={OLD_AWID}\",\n"
            "]\n"
        )
        env = {**os.environ, "UV_CACHE_DIR": str(cls.uv_cache)}
        run("uv", "lock", "--no-config", "--default-index", cls.index_url, cwd=backend, env=env)
        git("init", "-q", "-b", "main", cwd=cls.seed)
        git("add", ".", cwd=cls.seed)
        run(
            "git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.com",
            "commit", "-qm", "AC reviewed base", cwd=cls.seed,
        )

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.fixture_tmp.cleanup()

    def setUp(self):
        IndexHandler.modes = {}
        IndexHandler.counts = {}
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.remote = root / "ac.git"
        run("git", "clone", "-q", "--bare", str(self.seed), str(self.remote), cwd=root)
        self.addCleanup(self.tmp.cleanup)

    def env(self, **extra) -> dict:
        return {
            **os.environ,
            "AC_REMOTE": str(self.remote),
            "AC_DEPENDENCY_TEST_INDEX": self.index_url,
            "AC_DEPENDENCY_POLL_TIMEOUT_SECONDS": "0",
            "AC_DEPENDENCY_POLL_BACKOFF_SECONDS": "0",
            "UV_CACHE_DIR": str(self.uv_cache),
            **extra,
        }

    def head(self) -> str:
        return git("--git-dir", str(self.remote), "rev-parse", "refs/heads/main", cwd=Path(self.tmp.name))

    def invoke(
        self,
        *,
        base: str | None = None,
        aweb: str = NEW_AWEB,
        awid: str = NEW_AWID,
        env=None,
        expected: str | None = None,
        fail: bool = False,
    ):
        command = [
            sys.executable,
            str(ADAPTER),
            "--expect-repository", expected or str(self.remote),
            "--base-sha", base or self.head(),
            "--aweb-version", aweb,
            "--awid-version", awid,
        ]
        result = subprocess.run(command, capture_output=True, text=True, env=env or self.env())
        if fail:
            self.assertNotEqual(result.returncode, 0)
            return result.stderr
        if result.returncode != 0:
            raise AssertionError(result.stderr)
        return json.loads(result.stdout)

    def checkout(self) -> Path:
        target = Path(self.tmp.name) / f"checkout-{len(list(Path(self.tmp.name).glob('checkout-*')))}"
        run("git", "clone", "-q", str(self.remote), str(target), cwd=Path(self.tmp.name))
        return target

    def test_derives_exact_two_file_commit_after_packages_are_observed(self):
        base = self.head()
        result = self.invoke(base=base)
        self.assertFalse(result["adopted"])
        self.assertEqual(result["base_sha"], base)
        self.assertEqual(result["commit_sha"], self.head())
        changed = git("diff", "--name-only", f"{base}..{self.head()}", cwd=self.checkout()).splitlines()
        self.assertEqual(changed, ["backend/pyproject.toml", "backend/uv.lock"])
        checkout = self.checkout()
        pyproject = (checkout / "backend/pyproject.toml").read_text()
        self.assertIn(f'"aweb>={NEW_AWEB}"', pyproject)
        self.assertIn(f'"awid-service>={NEW_AWID}"', pyproject)
        lock = (checkout / "backend/uv.lock").read_text()
        self.assertIn(self.index_url, lock)
        self.assertRegex(lock, r"sha256:[0-9a-f]{64}")

    def test_sequential_404_then_200_waits_before_deriving(self):
        IndexHandler.modes["aweb"] = "lag"
        base = self.head()
        result = self.invoke(
            base=base,
            env=self.env(
                AC_DEPENDENCY_POLL_TIMEOUT_SECONDS="2",
                AC_DEPENDENCY_POLL_BACKOFF_SECONDS="0",
            ),
        )
        self.assertNotEqual(result["commit_sha"], base)
        self.assertGreaterEqual(IndexHandler.counts["aweb"], 2)

    def test_absent_package_refuses_at_named_deadline_without_push(self):
        IndexHandler.modes["aweb"] = "absent"
        before = self.head()
        stderr = self.invoke(base=before, fail=True)
        self.assertIn("public package propagation deadline exceeded", stderr)
        self.assertEqual(self.head(), before)

    def test_auth_outage_and_malformed_evidence_refuse_without_push(self):
        for mode, expected in (("auth", "HTTP 401"), ("outage", "HTTP 503"), ("malformed", "propagation deadline")):
            with self.subTest(mode=mode):
                IndexHandler.modes = {"aweb": mode}
                IndexHandler.counts = {}
                before = self.head()
                stderr = self.invoke(base=before, fail=True)
                self.assertIn(expected, stderr)
                self.assertEqual(self.head(), before)

    def test_moved_base_refuses_without_commit_or_rebase(self):
        recorded = self.head()
        checkout = self.checkout()
        (checkout / "README.md").write_text("source change\n")
        git("add", "README.md", cwd=checkout)
        run(
            "git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.com",
            "commit", "-qm", "move main", cwd=checkout,
        )
        git("push", "-q", "origin", "HEAD:main", cwd=checkout)
        moved = self.head()
        stderr = self.invoke(base=recorded, fail=True)
        self.assertIn("AC main moved from recorded base", stderr)
        self.assertEqual(self.head(), moved)

    def test_extra_file_and_extra_project_version_refuse_without_push(self):
        for variable, expected in (
            ("AC_DEPENDENCY_TEST_EXTRA_FILE", "outside allowlist"),
            ("AC_DEPENDENCY_TEST_EXTRA_VERSION", "outside intended package floors"),
        ):
            with self.subTest(variable=variable):
                before = self.head()
                stderr = self.invoke(base=before, env=self.env(**{variable: "1"}), fail=True)
                self.assertIn(expected, stderr)
                self.assertEqual(self.head(), before)

    def test_exact_noop_adopts_without_another_commit(self):
        first = self.invoke()
        head = first["commit_sha"]
        second = self.invoke(base=head)
        self.assertEqual(second["commit_sha"], head)
        self.assertTrue(second["adopted"])
        self.assertEqual(self.head(), head)

    def test_wrong_remote_identity_refuses_without_push(self):
        before = self.head()
        stderr = self.invoke(base=before, expected="github.com/awebai/not-ac", fail=True)
        self.assertIn("refusing to act on", stderr)
        self.assertEqual(self.head(), before)

    def test_adapter_is_executable_and_driver_protocol_is_absent(self):
        self.assertTrue(os.access(ADAPTER, os.X_OK))
        help_result = run(sys.executable, str(ADAPTER), "--help", cwd=REPO_ROOT)
        for obsolete in ("{intent,apply,read}", "--component", "--updates"):
            self.assertNotIn(obsolete, help_result.stdout)


if __name__ == "__main__":
    unittest.main()
