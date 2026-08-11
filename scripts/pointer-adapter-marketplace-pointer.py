#!/usr/bin/env python3
"""Advance the literal channel/skills npm pointers in claude-plugins.

The public packages must already be served before this executable changes the
single marketplace JSON file. Tests override both remotes with local fixtures;
production defaults remain the public npm registry and the one expected git
repository.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

POINTER_FILE = ".claude-plugin/marketplace.json"
DEFAULT_REMOTE = "git@github.com:awebai/claude-plugins.git"
DEFAULT_REGISTRY = "https://registry.npmjs.org"
PACKAGES = {
    "channel": "@awebai/claude-channel",
    "skills": "@awebai/claude-skills",
}
PLUGIN_NAMES = {"channel": "aweb-channel", "skills": "aweb-skills"}
MARKETPLACE_NAME = "awebai-marketplace"
GIT = "/usr/bin/git"
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


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
        "GIT_AUTHOR_NAME": "aweb release",
        "GIT_AUTHOR_EMAIL": "release@aweb.ai",
        "GIT_COMMITTER_NAME": "aweb release",
        "GIT_COMMITTER_EMAIL": "release@aweb.ai",
    }


def git(*args: str, cwd: Path) -> str:
    result = subprocess.run(
        [GIT, *args], cwd=cwd, env=git_env(), capture_output=True, text=True
    )
    if result.returncode:
        raise SystemExit(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def canonical(remote: str) -> str:
    value = remote.strip()
    for prefix in ("git@github.com:", "https://github.com/", "ssh://git@github.com/"):
        if value.startswith(prefix):
            value = "github.com/" + value[len(prefix) :]
            break
    return value[:-4] if value.endswith(".git") else value


def expected_remote() -> str:
    return os.environ.get("MARKETPLACE_REMOTE", DEFAULT_REMOTE)


def require_expected(expected: str | None) -> str:
    remote = expected_remote()
    if not expected:
        raise SystemExit(
            "refusing to act without --expect-repository: name the marketplace repository"
        )
    if canonical(expected) != canonical(remote):
        raise SystemExit(f"refusing to act on {remote}: the release expects {expected}")
    return remote


def verify_origin(checkout: Path, expected: str, when: str) -> None:
    actual = git("remote", "get-url", "origin", cwd=checkout).strip()
    if canonical(actual) != canonical(expected):
        raise SystemExit(
            f"refusing: {when} the checkout's origin is {actual}, not {expected}"
        )


def clone(into: Path, remote: str, name: str = "claude-plugins") -> Path:
    checkout = into / name
    git("clone", "--depth", "1", remote, str(checkout), cwd=into)
    verify_origin(checkout, remote, "after cloning")
    return checkout


def read_document(checkout: Path) -> dict:
    path = checkout / POINTER_FILE
    try:
        document = json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        raise SystemExit(f"marketplace shape invalid: {exc}") from exc
    if (
        not isinstance(document, dict)
        or document.get("name") != MARKETPLACE_NAME
        or not isinstance(document.get("plugins"), list)
    ):
        raise SystemExit(
            f"marketplace shape invalid: name must be {MARKETPLACE_NAME!r} and plugins an array"
        )
    return document


def advertised(checkout: Path) -> dict[str, str]:
    document = read_document(checkout)
    found: dict[str, str] = {}
    for component, package in PACKAGES.items():
        matches = []
        for plugin in document["plugins"]:
            if not isinstance(plugin, dict) or not isinstance(plugin.get("source"), dict):
                raise SystemExit("marketplace shape invalid: every plugin needs an object source")
            source = plugin["source"]
            if source.get("package") == package:
                if plugin.get("name") != PLUGIN_NAMES[component]:
                    raise SystemExit(
                        f"marketplace package {package} must use plugin name {PLUGIN_NAMES[component]}"
                    )
                matches.append(source)
        if len(matches) != 1:
            raise SystemExit(
                f"marketplace must contain exactly one npm package entry for {package}; found {len(matches)}"
            )
        source = matches[0]
        if source.get("source") != "npm" or not VERSION.fullmatch(
            str(source.get("version", ""))
        ):
            raise SystemExit(f"marketplace package {package} has invalid source/version shape")
        found[component] = source["version"]
    return found


def validate_updates(updates: object) -> dict[str, str]:
    if not isinstance(updates, dict) or not updates:
        raise SystemExit("updates must be a non-empty object")
    unknown = sorted(set(updates) - set(PACKAGES))
    if unknown:
        raise SystemExit(f"no literal marketplace package mapping for {unknown}")
    for component, version in updates.items():
        if not isinstance(version, str) or not VERSION.fullmatch(version):
            raise SystemExit(f"invalid version for {component}: {version!r}")
    return updates


def require_public_packages(updates: dict[str, str]) -> None:
    registry = os.environ.get("MARKETPLACE_NPM_REGISTRY", DEFAULT_REGISTRY).rstrip("/")
    timeout_text = os.environ.get("MARKETPLACE_REGISTRY_TIMEOUT", "30")
    if not timeout_text.isdigit() or int(timeout_text) <= 0:
        raise SystemExit("MARKETPLACE_REGISTRY_TIMEOUT must be a positive integer")
    timeout = int(timeout_text)
    for component, version in updates.items():
        package = PACKAGES[component]
        url = f"{registry}/{urllib.parse.quote(package, safe='')}/{version}"
        try:
            with urllib.request.urlopen(url, timeout=timeout) as response:
                status = response.status
                body = response.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise SystemExit(f"{package}@{version} is not publicly served") from exc
            raise SystemExit(
                f"npm registry unavailable for {package}@{version}: HTTP {exc.code}"
            ) from exc
        except OSError as exc:
            raise SystemExit(f"npm registry unavailable for {package}@{version}: {exc}") from exc
        if status != 200:
            raise SystemExit(f"npm registry unavailable for {package}@{version}: HTTP {status}")
        try:
            observed = json.loads(body)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"npm registry returned malformed evidence for {package}@{version}") from exc
        if observed.get("name") != package or observed.get("version") != version:
            raise SystemExit(
                f"npm registry evidence does not identify exact {package}@{version}"
            )


def apply_updates(checkout: Path, updates: dict[str, str]) -> None:
    document = read_document(checkout)
    for component, version in updates.items():
        package = PACKAGES[component]
        matches = [
            plugin["source"]
            for plugin in document["plugins"]
            if isinstance(plugin, dict)
            and isinstance(plugin.get("source"), dict)
            and plugin["source"].get("package") == package
        ]
        if len(matches) != 1:
            raise SystemExit(f"marketplace must contain exactly one package entry for {package}")
        matches[0]["version"] = version
    (checkout / POINTER_FILE).write_text(json.dumps(document, indent=2) + "\n")


def require_only_pointer_diff(checkout: Path) -> None:
    changed = git("status", "--porcelain", cwd=checkout).splitlines()
    paths = {line[3:] for line in changed if len(line) >= 4}
    if paths - {POINTER_FILE} or (changed and POINTER_FILE not in paths):
        raise SystemExit(f"only {POINTER_FILE} may change; found {sorted(paths)}")


def commit_and_push(checkout: Path, updates: dict[str, str], remote: str) -> None:
    verify_origin(checkout, remote, "before pushing")
    require_only_pointer_diff(checkout)
    if not git("status", "--porcelain", cwd=checkout).strip():
        return
    git("add", POINTER_FILE, cwd=checkout)
    staged = git("diff", "--cached", "--name-only", cwd=checkout).splitlines()
    if staged != [POINTER_FILE]:
        raise SystemExit(f"only {POINTER_FILE} may be committed; found {staged}")
    summary = ", ".join(f"{name} {version}" for name, version in sorted(updates.items()))
    git("commit", "-m", f"Advertise {summary}", cwd=checkout)
    git("push", "origin", "HEAD", cwd=checkout)
    verify_origin(checkout, remote, "after pushing")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("apply", "read"))
    parser.add_argument("--component", required=True)
    parser.add_argument("--expect-repository")
    parser.add_argument("--updates")
    args = parser.parse_args(argv)
    if args.component != "marketplace-pointer":
        raise SystemExit("only marketplace-pointer is supported")
    remote = require_expected(args.expect_repository)

    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        checkout = clone(root, remote)
        before = advertised(checkout)
        if args.operation == "read":
            print(json.dumps({"advertised": before}, sort_keys=True))
            return 0

        updates = validate_updates(json.loads(args.updates) if args.updates else {})
        expected = before | updates
        if before == expected:
            print(json.dumps({"advertised": before, "action": "adopt"}, sort_keys=True))
            return 0
        require_public_packages(updates)
        apply_updates(checkout, updates)
        commit_and_push(checkout, updates, remote)
        reread = clone(root, remote, "reread")
        observed = advertised(reread)
        if observed != expected:
            raise SystemExit(
                f"marketplace read-back {observed} does not equal intended {expected}"
            )
        print(json.dumps({"advertised": observed, "action": "push"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
