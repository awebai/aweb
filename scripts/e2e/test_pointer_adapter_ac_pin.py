#!/usr/bin/env python3
"""AC pin adapter against exact AC's real release and lock contract.

The fixture starts from exact AC main, is made into a coherent older release,
and is pushed to a local bare remote. Every assertion drives the executable
adapter through clone/intent/apply/read; successful state is checked with AC's
own release-model, uv-lock, and migration-manifest gates.
"""

from __future__ import annotations

import functools
import hashlib
import http.server
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import tomllib
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ADAPTER = REPO_ROOT / "scripts" / "pointer-adapter-ac-pin.py"
AC_REPOSITORY = "github.com/awebai/ac"
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


def declared_ac_checkout() -> Path | None:
    """AC's checkout as DECLARED, in the driver's own EXTERNAL_CONTEXT spelling.

    The release driver refuses to guess where AC is and takes
    `repository=checkout` entries, absolute, because "environment-relative
    guessing produced unsatisfiable checks". This suite reads the same
    declaration rather than reaching for a hardcoded remote, so there is one
    contract for where AC lives instead of two.

    A declaration that is present but malformed is an operator error and raises;
    only an ABSENT declaration is the environment this suite cannot run in.
    """
    for entry in os.environ.get("EXTERNAL_CONTEXT", "").split():
        repository, separator, checkout = entry.partition("=")
        if not separator or repository != AC_REPOSITORY:
            continue
        path = Path(checkout)
        if not path.is_absolute():
            raise AssertionError(
                f"EXTERNAL_CONTEXT checkout must be absolute, got {checkout!r}; "
                "a relative path lets the working directory decide identity"
            )
        if not (path / ".git").exists():
            raise AssertionError(
                f"EXTERNAL_CONTEXT names {path}, which is not a git checkout"
            )
        return path
    return None


def require_declared_ac_checkout() -> Path:
    """Skip with disclosure where AC has not been declared.

    This suite executes AC's own release-verify-model against AC's real tree, so
    it cannot be reduced to a fixture. AC is private and this repository's gate
    carries no credential for it by design -- the local gate uses public inputs
    only -- so on the runner there is no declaration and none can be made. It
    previously died at a hardcoded clone having run zero tests, which reads as a
    defect in the pin contract rather than as coverage the gate cannot have.

    Skipping ONLY on an absent declaration is the point: wherever AC is declared
    -- a credentialed machine, and AC's own CI once aweb-abcy moves primary
    coverage there -- all nine assertions still run against the real tree.

    A skip nobody reads is how a gate quietly stops covering something, which is
    the failure this task exists to correct, so the disclosure names what is
    uncovered, what tracks it, and what covers it meanwhile. It goes to the gate
    summary because a skipped run and the old blind failure both print
    "Ran 0 tests": the disclosure is the only thing that tells them apart.
    """
    checkout = declared_ac_checkout()
    if checkout is not None:
        return checkout
    disclosure = (
        f"ac-pin contract suite SKIPPED: no EXTERNAL_CONTEXT entry declares "
        f"{AC_REPOSITORY}, so AC's release-verify-model cannot run against AC's "
        "real tree. THIS GATE DOES NOT COVER THE AC PIN CONTRACT. Tracked by "
        "aweb-abcy, which moves primary coverage to where AC's tree exists. "
        "Covered meanwhile by: the suite passing 9/9 against the real AC tree on "
        "2026-08-09 (recorded on aweb-abce), and the release driver's ac-pin lane "
        "executing AC's real release-model gates at pin-advance time through the "
        "same EXTERNAL_CONTEXT declaration. To run it here, pass "
        f"EXTERNAL_CONTEXT='{AC_REPOSITORY}=/absolute/path/to/ac'."
    )
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        # The gate's own summary, so the disclosure is read without anyone
        # scrolling a make log to find it.
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write(f"### {disclosure}\n\n")
    print(f"\n{disclosure}\n", file=sys.stderr, flush=True)
    raise unittest.SkipTest(disclosure)


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


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass


def write_test_package(index_root: Path, name: str, version: str) -> None:
    normalized = name.replace("-", "_")
    files = index_root / "files"
    files.mkdir(parents=True, exist_ok=True)
    wheel = files / f"{normalized}-{version}-py3-none-any.whl"
    dist_info = f"{normalized}-{version}.dist-info"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            f"{dist_info}/METADATA",
            f"Metadata-Version: 2.3\nName: {name}\nVersion: {version}\n"
            "Requires-Python: >=3.12\n",
        )
        archive.writestr(
            f"{dist_info}/WHEEL",
            "Wheel-Version: 1.0\nGenerator: aweb-test\n"
            "Root-Is-Purelib: true\nTag: py3-none-any\n",
        )
        archive.writestr(f"{dist_info}/RECORD", "")
    sdist = files / f"{normalized}-{version}.tar.gz"
    package_root = f"{normalized}-{version}"
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / package_root
        root.mkdir()
        (root / "PKG-INFO").write_text(
            f"Metadata-Version: 2.3\nName: {name}\nVersion: {version}\n"
        )
        (root / "pyproject.toml").write_text(
            "[build-system]\nrequires = []\nbuild-backend = 'unused'\n"
        )
        with tarfile.open(sdist, "w:gz") as archive:
            archive.add(root, arcname=package_root)
    page = index_root / "simple" / name.replace("_", "-")
    page.mkdir(parents=True, exist_ok=True)
    links = []
    for artifact in (sdist, wheel):
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        links.append(f'<a href="/files/{artifact.name}#sha256={digest}">{artifact.name}</a>')
    (page / "index.html").write_text("\n".join(links))


class AcPinAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        declared = require_declared_ac_checkout()
        cls.fixture_tmp = tempfile.TemporaryDirectory()
        root = Path(cls.fixture_tmp.name)
        cls.uv_cache = root / "uv-cache"

        # Clone the declared checkout rather than working in it: this suite
        # detaches, rewrites pins and regenerates locks, and none of that is
        # allowed to touch the operator's own AC tree. The pinned SHA is still
        # asserted, so a declaration pointing somewhere that lacks it fails here
        # rather than silently measuring the wrong tree.
        contract = root / "ac-contract"
        run("git", "clone", "-q", str(declared), str(contract), cwd=root)
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

    def test_intent_precedes_future_tag_and_packages_then_apply_uses_them(self):
        root = Path(self.tmp.name)
        future_remote = root / "future-aweb.git"
        run("git", "clone", "-q", "--mirror", str(REPO_ROOT), str(future_remote), cwd=root)
        source = root / "future-source"
        run("git", "clone", "-q", str(future_remote), str(source), cwd=root)
        future_server = "9.8.7"
        future_awid = "8.7.6"
        pyproject = source / "server" / "pyproject.toml"
        text, count = re.subn(
            r'(?m)^version = "[^"]+"$', f'version = "{future_server}"',
            pyproject.read_text(), count=1,
        )
        self.assertEqual(count, 1)
        pyproject.write_text(text)
        run(
            "git", "-c", "user.email=test@example.com", "-c", "user.name=Test",
            "add", "server/pyproject.toml", cwd=source,
        )
        run(
            "git", "-c", "user.email=test@example.com", "-c", "user.name=Test",
            "commit", "-qm", "future unpublished server", cwd=source,
        )
        future_sha = git("rev-parse", "HEAD", cwd=source)
        run("git", "push", "-q", "origin", "HEAD:main", cwd=source)
        updates = {
            "server": {
                "version": future_server,
                "git_ref": f"server-v{future_server}",
                "git_sha": future_sha,
            },
            "awid-pypi": future_awid,
        }
        env = self.adapter_env(AWEB_REMOTE=str(future_remote))
        before = self.remote_head()
        self.assertEqual(
            self.run_adapter("intent", updates, env=env)["advertised"], updates
        )
        self.assertEqual(self.remote_head(), before)

        run("git", "tag", f"server-v{future_server}", future_sha, cwd=source)
        run("git", "push", "-q", "origin", f"refs/tags/server-v{future_server}", cwd=source)
        index = root / "index"
        write_test_package(index, "aweb", future_server)
        write_test_package(index, "awid-service", future_awid)
        handler = functools.partial(QuietHandler, directory=str(index))
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        index_url = f"http://127.0.0.1:{server.server_port}/simple"
        env = self.adapter_env(
            AWEB_REMOTE=str(future_remote), AC_PIN_TEST_INDEX=index_url
        )
        self.assertEqual(self.run_adapter("apply", updates, env=env)["applied"], updates)
        self.assertEqual(self.run_adapter("read")["advertised"], updates)

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

    def test_intent_refuses_missing_apply_time_ac_gate_surface(self):
        root = Path(self.tmp.name)
        drift = root / "contract-drift"
        run("git", "clone", "-q", str(self.remote), str(drift), cwd=root)
        omitted = drift / "scripts" / "check-aapj-e2e-contract.sh"
        omitted.unlink()
        run("git", "add", "scripts/check-aapj-e2e-contract.sh", cwd=drift)
        run(
            "git", "-c", "user.email=test@example.com", "-c", "user.name=Test",
            "commit", "-qm", "remove apply-time gate surface", cwd=drift,
        )
        run("git", "push", "-q", "origin", "HEAD:main", cwd=drift)
        before = self.remote_head()
        stderr = self.run_adapter(
            "intent", self.combined_updates, expect_failure=True
        )
        self.assertIn("check-aapj-e2e-contract.sh", stderr)
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
