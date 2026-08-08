#!/usr/bin/env python3
"""Advertise published npm versions in the awebai/claude-plugins marketplace.

The pointer effect for `marketplace-pointer`: Claude Code re-resolves an npm
plugin source only when the marketplace entry advertises a version, so an
installed plugin never sees a publish until this file moves.

Three verbs, each printing JSON on stdout, per the PointerLane protocol:

    intent --component C --updates '{"channel": "1.7.4"}'
    apply  --component C --updates '{"channel": "1.7.4"}'
    read   --component C

`intent` and `read` print {"advertised": {component: version}}.

Component-to-package mapping comes from release/components.toml, so the package
name has one source of truth and cannot drift from what the release publishes.
The repository may be overridden with MARKETPLACE_REMOTE, which is what the
tests use to drive a local bare repository instead of the network.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
GRAPH = REPO_ROOT / "release" / "components.toml"
POINTER_FILE = ".claude-plugin/marketplace.json"
DEFAULT_REMOTE = "git@github.com:awebai/claude-plugins.git"
GIT = "/usr/bin/git"


def git_env() -> dict:
    """Built, not inherited: an injected insteadOf rewrite or a proxy command
    would otherwise redirect a push at the moment it is least examined."""
    return {
        "PATH": "/usr/bin:/bin",
        # Disable global AND system config, not just command-scope entries.
        # GIT_CONFIG_COUNT=0 alone leaves url.<base>.insteadOf in the operator's
        # ~/.gitconfig free to redirect the clone and the push at the moment it
        # is least examined - and HOME was still being inherited.
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_COUNT": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ALLOW_PROTOCOL": "ssh:https:file",
        "HOME": os.environ.get("HOME", "/tmp"),
        "SSH_AUTH_SOCK": os.environ.get("SSH_AUTH_SOCK", ""),
        "GIT_AUTHOR_NAME": "aweb release driver",
        "GIT_AUTHOR_EMAIL": "release@aweb.ai",
        "GIT_COMMITTER_NAME": "aweb release driver",
        "GIT_COMMITTER_EMAIL": "release@aweb.ai",
    }


def git(*args: str, cwd: Path) -> str:
    result = subprocess.run(
        [GIT, *args], cwd=str(cwd), env=git_env(),
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def package_for_component() -> dict[str, str]:
    graph = tomllib.loads(GRAPH.read_text())
    mapping = {}
    for name, component in graph.get("component", {}).items():
        registry = (component.get("publish_lane") or {}).get("registry") or {}
        if registry.get("type") == "npm" and registry.get("package"):
            mapping[name] = registry["package"]
    return mapping


def expected_remote() -> str:
    """The repository this adapter is allowed to mutate.

    The override exists so tests can drive a local bare repository. It is NOT
    production authority: --expect-repository is compared against it, so a
    substituted remote cannot be mutated under the graph's label.
    """
    return os.environ.get("MARKETPLACE_REMOTE", 'git@github.com:awebai/claude-plugins.git')


def canonical(remote: str) -> str:
    """Compare repositories by identity, not by transport spelling.

    The graph says github.com/awebai/x; the transport says
    git@github.com:awebai/x.git or a local path under test. Comparing raw
    strings would either refuse every real release or accept anything.
    """
    value = remote.strip()
    for prefix in ("git@github.com:", "https://github.com/", "ssh://git@github.com/"):
        if value.startswith(prefix):
            value = "github.com/" + value[len(prefix):]
            break
    return value[:-4] if value.endswith(".git") else value


def require_expected(expected: str | None) -> str:
    remote = expected_remote()
    # A missing expectation is refused, not waved through. Accepting it made the
    # binding decorative: an ambient remote could be mutated under the graph's
    # label with nothing comparing the two.
    if not expected:
        raise SystemExit(
            "refusing to act without --expect-repository: the release must name "
            "the repository it intends to mutate"
        )
    if canonical(expected) != canonical(remote):
        raise SystemExit(
            f"refusing to act on {remote}: the release expects {expected}"
        )
    return remote


def clone(into: Path, remote: str) -> Path:
    checkout = into / "claude-plugins"
    git("clone", "--depth", "1", remote, str(checkout), cwd=into)
    return checkout


def advertised(checkout: Path) -> dict[str, str]:
    document = json.loads((checkout / POINTER_FILE).read_text())
    by_package = {v: k for k, v in package_for_component().items()}
    found = {}
    for plugin in document.get("plugins", []):
        source = plugin.get("source") or {}
        component = by_package.get(source.get("package"))
        if component and source.get("version"):
            found[component] = source["version"]
    return found


def apply_updates(checkout: Path, updates: dict[str, str]) -> None:
    packages = package_for_component()
    path = checkout / POINTER_FILE
    document = json.loads(path.read_text())
    wanted = {packages[c]: v for c, v in updates.items() if c in packages}
    missing = [c for c in updates if c not in packages]
    if missing:
        raise SystemExit(f"no npm package declared for: {sorted(missing)}")

    touched = set()
    for plugin in document.get("plugins", []):
        source = plugin.get("source") or {}
        package = source.get("package")
        if package in wanted:
            source["version"] = wanted[package]
            touched.add(package)
    unlisted = sorted(set(wanted) - touched)
    if unlisted:
        raise SystemExit(f"marketplace lists no entry for: {unlisted}")

    path.write_text(json.dumps(document, indent=2) + "\n")
    git("add", POINTER_FILE, cwd=checkout)
    if not git("status", "--porcelain", cwd=checkout).strip():
        return
    summary = ", ".join(f"{c} {v}" for c, v in sorted(updates.items()))
    git("commit", "-m", f"Advertise {summary}", cwd=checkout)
    git("push", "origin", "HEAD", cwd=checkout)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("intent", "apply", "read"))
    parser.add_argument("--component", required=True)
    parser.add_argument("--expect-repository")
    parser.add_argument("--updates")
    args = parser.parse_args(argv)
    updates = json.loads(args.updates) if args.updates else {}
    remote = require_expected(args.expect_repository)

    if args.operation == "intent":
        # No network: the intent is what the plan asked for, and the driver
        # compares it against the plan itself.
        print(json.dumps({"advertised": updates}))
        return 0

    with tempfile.TemporaryDirectory() as tmp:
        checkout = clone(Path(tmp), remote)
        if args.operation == "apply":
            apply_updates(checkout, updates)
            print(json.dumps({"applied": updates}))
        else:
            print(json.dumps({"advertised": advertised(checkout)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
