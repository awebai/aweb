#!/usr/bin/env python3
"""Update aweb-cloud's source pins after an aweb server or AWID publication.

The pointer effect for `ac-pin`: AC picks up a published aweb server only when
`release-pin.toml` moves, and a published awid-service only when
`backend/uv.lock` moves. Publishing without updating them leaves AC on the old
code with nothing saying so.

Two pins, holding two different kinds of value:

    release-pin.toml   [aweb] git_sha = <commit>       for `server`
    backend/uv.lock    awid-service version            for `awid-pypi`

so the driver advertises a commit for one and a version for the other.

Three verbs, each printing JSON, per the PointerLane protocol:

    intent --component ac-pin --updates '{"server": "<40hex>"}'
    apply  --component ac-pin --updates '{...}'
    read   --component ac-pin

This updates AC's SOURCE POINTERS ONLY. It never deploys, never touches
production credentials or migration gates, and publication is never a claim
that AC adopted anything - that boundary is AC's.

AC_REMOTE overrides the repository, which is what the tests use to drive a
local bare repository instead of the network.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

PIN_FILE = "release-pin.toml"
LOCK_FILE = "backend/uv.lock"
DEFAULT_REMOTE = "git@github.com:awebai/ac.git"
GIT = "/usr/bin/git"


def git_env() -> dict:
    """Built, not inherited: an injected insteadOf rewrite would redirect a
    push at the moment it is least examined."""
    return {
        "PATH": "/usr/bin:/bin",
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
        [GIT, *args], cwd=str(cwd), env=git_env(), capture_output=True, text=True
    )
    if result.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def clone(into: Path) -> Path:
    remote = os.environ.get("AC_REMOTE", DEFAULT_REMOTE)
    checkout = into / "ac"
    git("clone", "--depth", "1", remote, str(checkout), cwd=into)
    return checkout


def read_pins(checkout: Path) -> dict[str, str]:
    found = {}
    pin = checkout / PIN_FILE
    if pin.exists():
        match = re.search(
            r"(?ms)^\[aweb\].*?^git_sha\s*=\s*\"([0-9a-f]{40})\"", pin.read_text()
        )
        if match:
            found["server"] = match.group(1)
    lock = checkout / LOCK_FILE
    if lock.exists():
        match = re.search(
            r'(?ms)^\[\[package\]\]\nname = "awid-service"\nversion = "([^"]+)"',
            lock.read_text(),
        )
        if match:
            found["awid-pypi"] = match.group(1)
    return found


def apply_updates(checkout: Path, updates: dict[str, str]) -> list[str]:
    touched = []
    if "server" in updates:
        commit = updates["server"]
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise SystemExit(
                f"the aweb pin holds a commit, refusing to write {commit!r}"
            )
        path = checkout / PIN_FILE
        if not path.exists():
            raise SystemExit(f"{PIN_FILE} is absent from the AC checkout")
        text = path.read_text()
        updated, count = re.subn(
            r'(?ms)(^\[aweb\].*?^git_sha\s*=\s*")[0-9a-f]{40}(")',
            lambda m: m.group(1) + commit + m.group(2),
            text,
            count=1,
        )
        if not count:
            raise SystemExit(f"{PIN_FILE} declares no [aweb] git_sha to update")
        path.write_text(updated)
        touched.append(PIN_FILE)

    if "awid-pypi" in updates:
        version = updates["awid-pypi"]
        path = checkout / LOCK_FILE
        if not path.exists():
            raise SystemExit(f"{LOCK_FILE} is absent from the AC checkout")
        text = path.read_text()
        updated, count = re.subn(
            r'(?ms)(^\[\[package\]\]\nname = "awid-service"\nversion = ")[^"]+(")',
            lambda m: m.group(1) + version + m.group(2),
            text,
            count=1,
        )
        if not count:
            raise SystemExit(f"{LOCK_FILE} pins no awid-service to update")
        path.write_text(updated)
        touched.append(LOCK_FILE)

    unknown = sorted(set(updates) - {"server", "awid-pypi"})
    if unknown:
        raise SystemExit(f"ac-pin holds no pin for: {unknown}")

    for path in touched:
        git("add", path, cwd=checkout)
    if not git("status", "--porcelain", cwd=checkout).strip():
        return touched
    summary = ", ".join(f"{k} {v}" for k, v in sorted(updates.items()))
    git("commit", "-m", f"Pin {summary}", cwd=checkout)
    git("push", "origin", "HEAD", cwd=checkout)
    return touched


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("intent", "apply", "read"))
    parser.add_argument("--component", required=True)
    parser.add_argument("--updates")
    args = parser.parse_args(argv)
    updates = json.loads(args.updates) if args.updates else {}

    if args.operation == "intent":
        print(json.dumps({"advertised": updates}))
        return 0

    with tempfile.TemporaryDirectory() as tmp:
        checkout = clone(Path(tmp))
        if args.operation == "apply":
            apply_updates(checkout, updates)
            print(json.dumps({"applied": updates}))
        else:
            print(json.dumps({"advertised": read_pins(checkout)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
