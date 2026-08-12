#!/usr/bin/env python3
"""Derive AC's public-package dependency commit from a reviewed base.

This helper is intentionally narrower than a release driver. It waits for the
intended public package versions, clones the recorded AC base, changes only the
two dependency floors and backend/uv.lock, verifies the resulting package
versions/URLs/hashes, and pushes HEAD:main only while remote main still equals
the recorded base. It never rebases, forces, prompts, tags, deploys, or reads
provider state.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import unquote, urljoin, urlparse

DEFAULT_REMOTE = "git@github.com:awebai/ac.git"
PUBLIC_INDEX = "https://pypi.org/simple"
PUBLIC_FILES_HOST = "files.pythonhosted.org"
GIT = "/usr/bin/git"
PYPROJECT = "backend/pyproject.toml"
LOCK = "backend/uv.lock"
PACKAGES = {"aweb": "aweb", "awid-service": "awid_service"}
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
SHA_RE = re.compile(r"[0-9a-f]{40}")
HASH_RE = re.compile(r"sha256:[0-9a-f]{64}")


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def git_env() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_COUNT": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ALLOW_PROTOCOL": "ssh:https:file",
        "HOME": os.environ.get("HOME", "/tmp"),
        "SSH_AUTH_SOCK": os.environ.get("SSH_AUTH_SOCK", ""),
        "GIT_AUTHOR_NAME": "aweb release train",
        "GIT_AUTHOR_EMAIL": "release@aweb.ai",
        "GIT_COMMITTER_NAME": "aweb release train",
        "GIT_COMMITTER_EMAIL": "release@aweb.ai",
    }


def command_env() -> dict[str, str]:
    keep = ("HOME", "TMPDIR", "LANG", "LC_ALL", "UV_CACHE_DIR")
    env = {key: os.environ[key] for key in keep if key in os.environ}
    env["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
    return env


def run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(command, cwd=str(cwd), env=env, capture_output=True, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        fail(f"{' '.join(command)} failed: {detail}")
    return result.stdout


def git(*args: str, cwd: Path) -> str:
    return run([GIT, *args], cwd=cwd, env=git_env())


def canonical(remote: str) -> str:
    value = remote.strip()
    for prefix in ("git@github.com:", "https://github.com/", "ssh://git@github.com/"):
        if value.startswith(prefix):
            value = "github.com/" + value[len(prefix):]
            break
    return value[:-4] if value.endswith(".git") else value


def expected_remote() -> str:
    return os.environ.get("AC_REMOTE", DEFAULT_REMOTE)


def require_expected(expected: str | None) -> str:
    remote = expected_remote()
    if not expected:
        fail("refusing to act without --expect-repository")
    if canonical(expected) != canonical(remote):
        fail(f"refusing to act on {remote}: the release expects {expected}")
    return remote


def remote_main(remote: str, *, cwd: Path) -> str:
    output = git("ls-remote", remote, "refs/heads/main", cwd=cwd).strip()
    lines = output.splitlines()
    if len(lines) != 1:
        fail(f"AC remote main is not one commit: {output or 'absent'}")
    sha, ref = lines[0].split(maxsplit=1)
    if ref != "refs/heads/main" or not SHA_RE.fullmatch(sha):
        fail(f"AC remote main response is malformed: {output!r}")
    return sha


def index_url() -> str:
    test_index = os.environ.get("AC_DEPENDENCY_TEST_INDEX")
    if not test_index:
        return PUBLIC_INDEX
    if canonical(expected_remote()) == canonical(DEFAULT_REMOTE):
        fail("test package index is refused for the production AC remote")
    parsed = urlparse(test_index)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        fail("test package index must be loopback HTTP")
    return test_index.rstrip("/")


def _float_env(name: str, default: float) -> float:
    try:
        value = float(os.environ.get(name, str(default)))
    except ValueError:
        fail(f"{name} must be numeric")
    if value < 0:
        fail(f"{name} must be non-negative")
    return value


def observe_package(index: str, name: str, version: str) -> bool:
    normalized = name.replace("_", "-")
    url = f"{index.rstrip('/')}/{normalized}/"
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            if response.status != 200:
                fail(f"public package observation returned HTTP {response.status} for {name}")
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False
        fail(f"public package observation returned HTTP {exc.code} for {name}")
    except (OSError, UnicodeDecodeError) as exc:
        fail(f"public package observation failed for {name}: {exc}")
    filenames = [Path(unquote(urlparse(html.unescape(href)).path)).name for href in re.findall(r'href=["\']([^"\']+)', body)]
    identity = f"{PACKAGES[name]}-{version}"
    return any(identity in filename for filename in filenames)


def wait_for_packages(index: str, versions: dict[str, str]) -> None:
    timeout = _float_env("AC_DEPENDENCY_POLL_TIMEOUT_SECONDS", 600)
    backoff = _float_env("AC_DEPENDENCY_POLL_BACKOFF_SECONDS", 5)
    deadline = time.monotonic() + timeout
    pending = dict(versions)
    while pending:
        for name, version in list(pending.items()):
            if observe_package(index, name, version):
                del pending[name]
        if not pending:
            return
        if time.monotonic() >= deadline:
            waiting = ", ".join(f"{name}=={version}" for name, version in sorted(pending.items()))
            fail(f"public package propagation deadline exceeded: {waiting}")
        time.sleep(min(backoff, max(0.0, deadline - time.monotonic())))


def replace_floor(path: Path, package: str, version: str) -> None:
    text = path.read_text(encoding="utf-8")
    updated, count = re.subn(
        rf'(?m)^\s*"{re.escape(package)}>=[^"]+",\s*$',
        f'    "{package}>={version}",',
        text,
    )
    if count != 1:
        fail(f"{PYPROJECT} must carry exactly one {package} dependency floor")
    path.write_text(updated, encoding="utf-8")


def uv_binary() -> str:
    executable = shutil.which("uv") or shutil.which("uv", path=command_env()["PATH"])
    if executable is None:
        fail("uv is required to regenerate AC's exact lock")
    return executable


def regenerate_lock(checkout: Path, index: str, versions: dict[str, str]) -> None:
    command = [uv_binary(), "lock", "--no-config", "--default-index", index]
    for name, version in sorted(versions.items()):
        command += ["--upgrade-package", f"{name}=={version}"]
    run(command, cwd=checkout / "backend", env=command_env())


def _load(path: Path) -> dict[str, Any]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        fail(f"cannot read {path}: {exc}")


def verify_pyproject_change(before: dict[str, Any], after: dict[str, Any], versions: dict[str, str]) -> None:
    before_copy = json.loads(json.dumps(before))
    after_copy = json.loads(json.dumps(after))
    for data in (before_copy, after_copy):
        dependencies = data.get("project", {}).get("dependencies", [])
        data["project"]["dependencies"] = [
            value for value in dependencies
            if not any(re.match(rf"^{re.escape(name)}(?:[<>=!~;\s]|$)", str(value)) for name in PACKAGES)
        ]
    if before_copy != after_copy:
        fail("AC dependency derivation changed pyproject content outside intended package floors")
    dependencies = after.get("project", {}).get("dependencies", [])
    for name, version in versions.items():
        if dependencies.count(f"{name}>={version}") != 1:
            fail(f"derived pyproject does not carry exact {name}>={version}")


def verify_lock(checkout: Path, index: str, versions: dict[str, str]) -> None:
    lock = _load(checkout / LOCK)
    test_mode = index != PUBLIC_INDEX
    for name, version in versions.items():
        packages = [item for item in lock.get("package", []) if item.get("name") == name]
        if len(packages) != 1 or packages[0].get("version") != version:
            actual = packages[0].get("version") if len(packages) == 1 else "missing/duplicate"
            fail(f"regenerated lock has {name} {actual}, not {version}")
        package = packages[0]
        if package.get("source") != {"registry": index}:
            fail(f"regenerated lock source for {name} is not {index}: {package.get('source')!r}")
        artifacts = [package.get("sdist"), *(package.get("wheels") or [])]
        if len(artifacts) < 2 or any(not isinstance(item, dict) for item in artifacts):
            fail(f"regenerated lock lacks complete sdist/wheel artifacts for {name} {version}")
        identity = f"{PACKAGES[name]}-{version}"
        for artifact in artifacts:
            url = artifact.get("url")
            digest = artifact.get("hash")
            parsed = urlparse(url) if isinstance(url, str) else None
            filename = Path(parsed.path).name if parsed else ""
            host_ok = parsed is not None and (
                (test_mode and parsed.hostname in {"127.0.0.1", "localhost"})
                or (not test_mode and parsed.scheme == "https" and parsed.hostname == PUBLIC_FILES_HOST)
            )
            if not host_ok or identity not in filename:
                fail(f"regenerated lock artifact URL for {name} {version} is incoherent: {url!r}")
            if not isinstance(digest, str) or not HASH_RE.fullmatch(digest):
                fail(f"regenerated lock artifact hash for {name} {version} is incoherent: {digest!r}")


def changed_paths(checkout: Path) -> set[str]:
    changed = set(git("diff", "--name-only", cwd=checkout).splitlines())
    changed.update(git("ls-files", "--others", "--exclude-standard", cwd=checkout).splitlines())
    return {path for path in changed if path}


def derive(remote: str, base_sha: str, versions: dict[str, str]) -> dict[str, Any]:
    if remote_main(remote, cwd=Path.cwd()) != base_sha:
        fail(f"AC main moved from recorded base {base_sha}; release card is invalid")
    index = index_url()
    wait_for_packages(index, versions)

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        checkout = root / "ac"
        git("clone", "--branch", "main", "--single-branch", remote, str(checkout), cwd=root)
        actual_origin = git("remote", "get-url", "origin", cwd=checkout).strip()
        if canonical(actual_origin) != canonical(remote):
            fail(f"cloned AC origin is {actual_origin}, not {remote}")
        if git("rev-parse", "HEAD", cwd=checkout).strip() != base_sha:
            fail(f"cloned AC main is not recorded base {base_sha}")
        if git("status", "--porcelain", cwd=checkout).strip():
            fail("cloned AC base is dirty")

        before_pyproject = _load(checkout / PYPROJECT)
        for name, version in versions.items():
            replace_floor(checkout / PYPROJECT, name, version)
        regenerate_lock(checkout, index, versions)

        if os.environ.get("AC_DEPENDENCY_TEST_EXTRA_FILE") == "1":
            if canonical(remote) == canonical(DEFAULT_REMOTE):
                fail("test extra-file injection is refused for production AC")
            (checkout / "unexpected.txt").write_text("injected\n", encoding="utf-8")
        if os.environ.get("AC_DEPENDENCY_TEST_EXTRA_VERSION") == "1":
            if canonical(remote) == canonical(DEFAULT_REMOTE):
                fail("test extra-version injection is refused for production AC")
            path = checkout / PYPROJECT
            text, count = re.subn(r'(?m)^version = "[^"]+"$', 'version = "9.9.9"', path.read_text(), count=1)
            if count != 1:
                fail("could not inject extra project version")
            path.write_text(text)

        verify_pyproject_change(before_pyproject, _load(checkout / PYPROJECT), versions)
        verify_lock(checkout, index, versions)
        changed = changed_paths(checkout)
        allowed = {PYPROJECT, LOCK}
        if not changed.issubset(allowed):
            fail(f"AC dependency derivation changed files outside allowlist: {sorted(changed - allowed)}")
        if not changed:
            return {"base_sha": base_sha, "commit_sha": base_sha, "adopted": True, "versions": versions}
        if changed != allowed:
            fail(f"AC dependency derivation must change exactly {sorted(allowed)}, got {sorted(changed)}")

        git("add", PYPROJECT, LOCK, cwd=checkout)
        summary = ", ".join(f"{name} {version}" for name, version in sorted(versions.items()))
        git("commit", "-m", f"release: consume {summary}", cwd=checkout)
        commit_sha = git("rev-parse", "HEAD", cwd=checkout).strip()
        if remote_main(remote, cwd=checkout) != base_sha:
            fail(f"AC main moved from recorded base {base_sha}; release card is invalid")
        try:
            git("push", "origin", "HEAD:main", cwd=checkout)
        except SystemExit as exc:
            fail(f"AC main move refused while pushing derived dependency commit: {exc}")
        if remote_main(remote, cwd=checkout) != commit_sha:
            fail("derived dependency commit was not installed as exact AC main")
        return {"base_sha": base_sha, "commit_sha": commit_sha, "adopted": False, "versions": versions}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expect-repository", required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--aweb-version", required=True)
    parser.add_argument("--awid-version", required=True)
    args = parser.parse_args(argv)

    remote = require_expected(args.expect_repository)
    if not SHA_RE.fullmatch(args.base_sha):
        fail("--base-sha must be a full lowercase commit SHA")
    versions = {"aweb": args.aweb_version, "awid-service": args.awid_version}
    for name, version in versions.items():
        if not VERSION_RE.fullmatch(version):
            fail(f"{name} version must be strict X.Y.Z")
    print(json.dumps(derive(remote, args.base_sha, versions), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
