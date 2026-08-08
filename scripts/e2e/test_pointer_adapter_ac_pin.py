#!/usr/bin/env python3
"""AC pin adapter against exact AC's real release and lock contract.

The fixture starts from exact AC main, is made into a coherent older release,
and is pushed to a local bare remote. Every assertion drives the executable
adapter through clone/intent/apply/read; successful state is checked with AC's
own release-model, uv-lock, and migration-manifest gates.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ADAPTER = REPO_ROOT / "scripts" / "pointer-adapter-ac-pin.py"
AC_CONTRACT_REMOTE = "https://github.com/awebai/ac.git"
AC_CONTRACT_SHA = "2451cfeac6b9e6076daf00c34eacb47cafdfba22"
OLD_SERVER_VERSION = "1.26.31"
NEW_SERVER_VERSION = "1.26.35"
OLD_AWID_VERSION = "0.5.13"
NEW_AWID_VERSION = "0.5.14"


def run(*args: str, cwd: Path, env=None, check=True) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(args), cwd=str(cwd), env=env, check=check,
        capture_output=True, text=True,
    )


def git(*args: str, cwd: Path) -> str:
    return run("git", *args, cwd=cwd).stdout.strip()


def replace_dependency(path: Path, package: str, version: str) -> None:
    text = path.read_text()
    updated, count = re.subn(
        rf'"{re.escape(package)}>=[^"]+"', f'"{package}>={version}"', text,
        count=1,
    )
    if count != 1:
        raise AssertionError(f"could not update {package} dependency in {path}")
    path.write_text(updated)


def write_release_pin(path: Path, *, version: str, sha: str) -> None:
    path.write_text(
        "# Exact aweb source identity used by AC release checks.\n\n"
        "[aweb]\n"
        f'version = "{version}"\n'
        f'git_sha = "{sha}"\n'
        f'git_ref = "server-v{version}"\n'
    )


def lock_package(path: Path, name: str) -> dict:
    lock = tomllib.loads(path.read_text())
    return next(package for package in lock["package"] if package["name"] == name)


class AcPinAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture_tmp = tempfile.TemporaryDirectory()
        root = Path(cls.fixture_tmp.name)
        cls.uv_cache = root / "uv-cache"

        contract = root / "ac-contract"
        run("git", "clone", "-q", AC_CONTRACT_REMOTE, str(contract), cwd=root)
        run("git", "checkout", "-q", "--detach", AC_CONTRACT_SHA, cwd=contract)
        actual = git("rev-parse", "HEAD", cwd=contract)
        if actual != AC_CONTRACT_SHA:
            raise AssertionError(f"AC contract checkout is {actual}, expected {AC_CONTRACT_SHA}")

        cls.aweb_remote = root / "aweb.git"
        run("git", "clone", "-q", "--mirror", str(REPO_ROOT), str(cls.aweb_remote), cwd=root)
        cls.old_server_sha = git("rev-parse", f"server-v{OLD_SERVER_VERSION}^{{}}", cwd=REPO_ROOT)
        cls.new_server_sha = git("rev-parse", f"server-v{NEW_SERVER_VERSION}^{{}}", cwd=REPO_ROOT)
        cls.old_server = {
            "version": OLD_SERVER_VERSION,
            "git_ref": f"server-v{OLD_SERVER_VERSION}",
            "git_sha": cls.old_server_sha,
        }
        cls.new_server = {
            "version": NEW_SERVER_VERSION,
            "git_ref": f"server-v{NEW_SERVER_VERSION}",
            "git_sha": cls.new_server_sha,
        }

        cls.seed = root / "seed"
        shutil.copytree(contract, cls.seed, ignore=shutil.ignore_patterns(".git"))
        replace_dependency(
            cls.seed / "backend" / "pyproject.toml", "aweb", OLD_SERVER_VERSION
        )
        replace_dependency(
            cls.seed / "backend" / "pyproject.toml", "awid-service", OLD_AWID_VERSION
        )
        write_release_pin(
            cls.seed / "release-pin.toml",
            version=OLD_SERVER_VERSION,
            sha=cls.old_server_sha,
        )
        env = {**os.environ, "UV_CACHE_DIR": str(cls.uv_cache)}
        run(
            "uv", "lock", "--no-config", "--default-index", "https://pypi.org/simple",
            "--upgrade-package", f"aweb=={OLD_SERVER_VERSION}",
            "--upgrade-package", f"awid-service=={OLD_AWID_VERSION}",
            cwd=cls.seed / "backend", env=env,
        )
        git("init", "-q", "-b", "main", cwd=cls.seed)
        git("add", ".", cwd=cls.seed)
        run(
            "git", "-c", "user.email=test@example.com", "-c", "user.name=Test",
            "commit", "-qm", "coherent old AC release", cwd=cls.seed,
        )

    @classmethod
    def tearDownClass(cls):
        cls.fixture_tmp.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.remote = root / "remote.git"
        run("git", "clone", "-q", "--bare", str(self.seed), str(self.remote), cwd=root)
        self.addCleanup(self.tmp.cleanup)

    def adapter_env(self, **extra) -> dict:
        return {
            **os.environ,
            "AC_REMOTE": str(self.remote),
            "AWEB_REMOTE": str(self.aweb_remote),
            "UV_CACHE_DIR": str(self.uv_cache),
            **extra,
        }

    def run_adapter(self, operation, updates=None, *, env=None, expect_failure=False):
        command = [
            sys.executable, str(ADAPTER), operation,
            "--component", "ac-pin",
            "--expect-repository", str(self.remote),
        ]
        if updates is not None:
            command += ["--updates", json.dumps(updates)]
        result = subprocess.run(
            command, capture_output=True, text=True,
            env=env or self.adapter_env(),
        )
        if expect_failure:
            self.assertNotEqual(result.returncode, 0)
            return result.stderr
        if result.returncode != 0:
            raise AssertionError(f"{operation} failed: {result.stderr}")
        return json.loads(result.stdout)

    def remote_head(self) -> str:
        return git("--git-dir", str(self.remote), "rev-parse", "refs/heads/main", cwd=Path(self.tmp.name))

    def checkout_remote(self) -> Path:
        root = Path(self.tmp.name) / f"observed-{len(list(Path(self.tmp.name).glob('observed-*')))}"
        ac = root / "ac"
        root.mkdir()
        run("git", "clone", "-q", str(self.remote), str(ac), cwd=root)
        return ac

    def run_ac_contract_checks(self, checkout: Path, source_sha: str) -> None:
        aweb = checkout.parent / "aweb"
        run("git", "clone", "-q", str(self.aweb_remote), str(aweb), cwd=checkout.parent)
        run("git", "checkout", "-q", "--detach", source_sha, cwd=aweb)
        env = {**os.environ, "UV_CACHE_DIR": str(self.uv_cache)}
        run("make", "release-verify-model", cwd=checkout, env=env)
        run("uv", "lock", "--check", "--no-config", cwd=checkout / "backend", env=env)
        run(
            sys.executable, "scripts/migration_manifest.py", "--verify",
            cwd=checkout / "backend", env=env,
        )

    @property
    def combined_updates(self) -> dict:
        return {"server": self.new_server, "awid-pypi": NEW_AWID_VERSION}

    def test_read_reports_complete_server_identity_and_awid_version(self):
        self.assertEqual(
            self.run_adapter("read")["advertised"],
            {"server": self.old_server, "awid-pypi": OLD_AWID_VERSION},
        )

    def test_combined_update_regenerates_real_lock_and_passes_ac_checks(self):
        before = self.remote_head()
        self.assertEqual(
            self.run_adapter("intent", self.combined_updates)["advertised"],
            self.combined_updates,
        )
        self.assertEqual(self.remote_head(), before, "intent must never push")
        self.assertEqual(
            self.run_adapter("apply", self.combined_updates)["applied"],
            self.combined_updates,
        )
        self.assertEqual(self.run_adapter("read")["advertised"], self.combined_updates)

        checkout = self.checkout_remote()
        self.run_ac_contract_checks(checkout, self.new_server_sha)
        pyproject = (checkout / "backend" / "pyproject.toml").read_text()
        self.assertIn(f'"aweb>={NEW_SERVER_VERSION}"', pyproject)
        self.assertIn(f'"awid-service>={NEW_AWID_VERSION}"', pyproject)
        for name, version, filename in (
            ("aweb", NEW_SERVER_VERSION, f"aweb-{NEW_SERVER_VERSION}"),
            ("awid-service", NEW_AWID_VERSION, f"awid_service-{NEW_AWID_VERSION}"),
        ):
            package = lock_package(checkout / "backend" / "uv.lock", name)
            self.assertEqual(package["version"], version)
            artifacts = [package["sdist"], *package["wheels"]]
            self.assertGreaterEqual(len(artifacts), 2)
            for artifact in artifacts:
                self.assertIn(filename, artifact["url"])
                self.assertRegex(artifact["hash"], r"^sha256:[0-9a-f]{64}$")

    def test_partial_and_mismatched_server_identities_refuse_without_push(self):
        before = self.remote_head()
        cases = [
            {"server": {"version": NEW_SERVER_VERSION, "git_sha": self.new_server_sha}},
            {"server": {**self.new_server, "git_ref": "server-v9.9.9"}},
            {"server": {**self.new_server, "git_sha": "0" * 40}},
        ]
        for updates in cases:
            with self.subTest(updates=updates):
                stderr = self.run_adapter("intent", updates, expect_failure=True)
                self.assertTrue(stderr.strip())
                self.assertEqual(self.remote_head(), before)

    def test_crash_after_checks_leaves_remote_unchanged(self):
        before = self.remote_head()
        stderr = self.run_adapter(
            "apply", self.combined_updates,
            env=self.adapter_env(AC_PIN_TEST_CRASH_AFTER_CHECKS="1"),
            expect_failure=True,
        )
        self.assertIn("injected crash", stderr)
        self.assertEqual(self.remote_head(), before)
        self.assertEqual(
            self.run_adapter("read")["advertised"],
            {"server": self.old_server, "awid-pypi": OLD_AWID_VERSION},
        )

    def test_identical_second_apply_adopts_without_another_commit(self):
        self.run_adapter("apply", self.combined_updates)
        first = self.remote_head()
        self.run_adapter("apply", self.combined_updates)
        self.assertEqual(self.remote_head(), first)
        self.assertEqual(self.run_adapter("read")["advertised"], self.combined_updates)

    def test_substituted_remote_unknown_pin_and_non_commit_refuse(self):
        other = Path(self.tmp.name) / "substituted.git"
        run("git", "init", "-q", "--bare", str(other), cwd=Path(self.tmp.name))
        result = subprocess.run(
            [
                sys.executable, str(ADAPTER), "read", "--component", "ac-pin",
                "--expect-repository", "github.com/awebai/ac",
            ],
            capture_output=True, text=True,
            env=self.adapter_env(AC_REMOTE=str(other)),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to act on", result.stderr)
        self.assertIn(
            "channel",
            self.run_adapter("intent", {"channel": "1.7.4"}, expect_failure=True),
        )
        self.assertTrue(
            self.run_adapter(
                "intent", {"server": "1.26.35"}, expect_failure=True
            ).strip()
        )

    def test_adapter_is_executable(self):
        self.assertTrue(os.access(ADAPTER, os.X_OK), f"{ADAPTER} must be executable")


if __name__ == "__main__":
    unittest.main()
