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
        [GIT, *args], cwd=str(cwd), env=git_env(), capture_output=True, text=True
    )
    if result.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def expected_remote() -> str:
    """The repository this adapter is allowed to mutate.

    The override exists so tests can drive a local bare repository. It is NOT
    production authority: --expect-repository is compared against it, so a
    substituted remote cannot be mutated under the graph's label.
    """
    return os.environ.get("AC_REMOTE", 'git@github.com:awebai/ac.git')


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


def verify_origin(checkout: Path, expected: str, when: str) -> None:
    """Re-observe the checkout's actual origin, rather than trusting the string
    we passed in. Comparing the input to itself proves nothing; what matters is
    what the working clone is really attached to, before and after mutation."""
    actual = git("remote", "get-url", "origin", cwd=checkout).strip()
    if canonical(actual) != canonical(expected):
        raise SystemExit(
            f"refusing: {when} the checkout's origin is {actual}, not {expected}"
        )


def clone(into: Path, remote: str) -> Path:
    checkout = into / "ac"
    git("clone", "--depth", "1", remote, str(checkout), cwd=into)
    verify_origin(checkout, remote, "after cloning")
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


def reject_unsupported(updates: dict[str, str]) -> None:
    """Both AC pins need contracts this adapter does not yet honour.

    release-pin.toml carries version and git_ref beside git_sha and AC's
    release-model check requires them to agree; backend/uv.lock pins the version
    AND that version's sdist/wheel URLs and hashes. Writing one field each
    produces a pin AC refuses - worse than none, because it looks applied.
    See aweb-abbe.39.
    """
    if "server" in updates:
        raise SystemExit(
            "ac-pin cannot yet update AC's release-pin through AC's real "
            "contract: release-pin.toml carries version and git_ref beside "
            "git_sha and AC's release-model check requires them to agree. "
            "See aweb-abbe.39."
        )
    if "awid-pypi" in updates:
        raise SystemExit(
            "ac-pin cannot yet update AC's lock through AC's real contract: "
            "backend/uv.lock also carries this version's sdist/wheel URLs and "
            "hashes. See aweb-abbe.39."
        )
    unknown = sorted(set(updates) - {"server", "awid-pypi"})
    if unknown:
        raise SystemExit(f"ac-pin holds no pin for: {unknown}")


def apply_updates(checkout: Path, updates: dict[str, str]) -> list[str]:
    reject_unsupported(updates)
    touched = []
    if "server" in updates:
        raise SystemExit(
            "ac-pin cannot yet update AC's release-pin through AC's real "
            "contract: release-pin.toml carries version and git_ref beside "
            "git_sha, and AC's release-model check requires them to agree. "
            "Moving git_sha alone produces a pin AC refuses. See aweb-abbe.39."
        )
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
        # AC's uv.lock pins a version AND the sdist/wheel URLs and hashes for
        # that exact version, and release-pin.toml carries version and git_ref
        # beside git_sha. Rewriting one field each leaves AC in a state its own
        # release-model check rejects - a pin that says 0.5.15 while still
        # holding 0.5.12 artifact hashes. Producing that is worse than producing
        # nothing, so this refuses until it updates AC through AC's real
        # contract (exact lock regeneration and every pin identity field).
        raise SystemExit(
            "ac-pin cannot yet update AC's lock and pin through AC's real "
            "contract: backend/uv.lock also carries this version's sdist/wheel "
            "URLs and hashes, and release-pin.toml carries version and git_ref "
            "beside git_sha. Writing one field each produces a pin AC's "
            "release-model check refuses. See aweb-abbe.39."
        )
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
    parser.add_argument("--expect-repository")
    parser.add_argument("--updates")
    args = parser.parse_args(argv)
    updates = json.loads(args.updates) if args.updates else {}
    remote = require_expected(args.expect_repository)

    if args.operation == "intent":
        # Refuse at INTENT, which is staging, not at apply. PointerLane stages
        # every node before run_plan publishes any of them, so a refusal that
        # lived only in apply let the server publish irreversibly and only then
        # discover its required pointer was impossible.
        reject_unsupported(updates)
        print(json.dumps({"advertised": updates}))
        return 0

    with tempfile.TemporaryDirectory() as tmp:
        checkout = clone(Path(tmp), remote)
        if args.operation == "apply":
            apply_updates(checkout, updates)
            print(json.dumps({"applied": updates}))
        else:
            print(json.dumps({"advertised": read_pins(checkout)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
